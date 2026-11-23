using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

namespace SecureVNC.Shared.Central;

/// <summary>
/// The computer's side of central mode. The auth server is trusted only if its certificate chains to the CA
/// whose fingerprint was given when joining (never trust-on-first-use: a fake auth server could say "OK" to anyone).
/// The computer proves itself with the certificate it got when joining.
/// </summary>
public static class CentralClient
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static DateTime _lastRenewAttemptUtc;

    /// <summary>Joins the auth server: new key pair, certificate from the organization CA, central mode on.</summary>
    public static void Join(string server, string caFingerprint, string joinKey, Action<string> log)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var response = Call(server, caFingerprint, clientCert: null, new CentralRequest
        {
            Op = "enroll",
            JoinKey = joinKey,
            MachineName = Environment.MachineName,
            MachineGuid = MachineIdentity.Current.MachineGuid,
            PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        });
        if (!response.Ok) throw new InvalidOperationException(response.Error ?? "The auth server refused to join.");

        using var ca = new X509Certificate2(Convert.FromBase64String(response.CaCertificate!));
        if (!CentralProtocol.SameFingerprint(CertificateManager.Fingerprint(ca), caFingerprint))
            throw new AuthenticationException("The auth server sent a different CA than the fingerprint you entered.");

        ServerPaths.EnsureDataDir();
        SaveIssued(response.Certificate!, key);
        File.WriteAllBytes(ServerPaths.CaCertFile, ca.Export(X509ContentType.Cert));
        if (File.Exists(ServerPaths.CaKeyFile)) File.Delete(ServerPaths.CaKeyFile);   // the local CA is no longer used

        var config = ServerConfig.Load();
        config.AuthServer = server.Trim();
        config.AuthServerFingerprint = CertificateManager.Fingerprint(ca);
        config.Save();
        File.WriteAllBytes(ServerPaths.JoinKeyFile, Dpapi.Protect(Encoding.UTF8.GetBytes(joinKey)));
        MachineIdentity.SaveCurrent();
        log($"Joined auth server {server} as {response.MachineName}");
    }

    /// <summary>Back to local users: removes the central settings and creates a local CA again.</summary>
    public static void Leave()
    {
        var config = ServerConfig.Load();
        config.AuthServer = null;
        config.AuthServerFingerprint = null;
        config.Save();
        if (File.Exists(ServerPaths.JoinKeyFile)) File.Delete(ServerPaths.JoinKeyFile);
        CertificateManager.InitializePki(force: true).Dispose();
    }

    /// <summary>Asks the auth server whether these credentials are valid. Throws when it cannot be reached.</summary>
    public static CentralResponse Verify(ServerConfig config, string user, string password, string code, string clientAddress)
    {
        using var cert = CertificateManager.LoadProtected(ServerPaths.ServerCertFile);
        return Call(config.AuthServer!, config.AuthServerFingerprint!, cert, new CentralRequest
        {
            Op = "verify", User = user, Password = password, Code = code, ClientAddress = clientAddress,
        });
    }

    /// <summary>Status check for SecureVNC Manager.</summary>
    public static CentralResponse Ping(ServerConfig config)
    {
        using var cert = CertificateManager.LoadProtected(ServerPaths.ServerCertFile);
        return Call(config.AuthServer!, config.AuthServerFingerprint!, cert, new CentralRequest { Op = "ping" });
    }

    /// <summary>
    /// Central-mode certificate: renewed at the auth server when it nears expiry or no longer covers any local
    /// address (the auth server puts the address it sees in the certificate). Renewal failures keep the old one.
    /// </summary>
    public static ServerCredentials EnsureCredentials(ServerConfig config, Action<string> log, bool forceReissue)
    {
        if (!File.Exists(ServerPaths.ServerCertFile))
            throw new InvalidOperationException("Not joined to the auth server yet.");
        var server = CertificateManager.LoadProtected(ServerPaths.ServerCertFile);
        if (server.NotAfter < DateTime.Now && File.Exists(ServerPaths.JoinKeyFile)
            && DateTime.UtcNow - _lastRenewAttemptUtc > TimeSpan.FromMinutes(10))
        {
            // Off for more than a week: an expired certificate cannot be renewed, join again with the saved key.
            _lastRenewAttemptUtc = DateTime.UtcNow;
            try
            {
                var joinKey = Encoding.UTF8.GetString(Dpapi.Unprotect(File.ReadAllBytes(ServerPaths.JoinKeyFile)));
                Join(config.AuthServer!, config.AuthServerFingerprint!, joinKey, log);
                server.Dispose();
                server = CertificateManager.LoadProtected(ServerPaths.ServerCertFile);
            }
            catch (Exception ex)
            {
                log($"Certificate expired and joining again failed: {ex.Message}");
            }
        }
        var (_, localIps) = CertificateManager.CurrentIdentity();
        var sanIps = CertificateManager.SanAddresses(server);
        bool needsRenewal = forceReissue || server.NotAfter < DateTime.Now + CentralProtocol.ComputerCertificateRenewBefore
                            || (sanIps.Count > 0 && !sanIps.Any(localIps.Contains));

        if (needsRenewal && (forceReissue || DateTime.UtcNow - _lastRenewAttemptUtc > TimeSpan.FromMinutes(10)))
        {
            _lastRenewAttemptUtc = DateTime.UtcNow;
            try
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var response = Call(config.AuthServer!, config.AuthServerFingerprint!, server, new CentralRequest
                {
                    Op = "renew", PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                });
                if (!response.Ok) throw new InvalidOperationException(response.Error);
                SaveIssued(response.Certificate!, key);
                server.Dispose();
                server = CertificateManager.LoadProtected(ServerPaths.ServerCertFile);
                log($"Certificate renewed by the auth server ({string.Join(", ", CertificateManager.SanAddresses(server))})");
            }
            catch (Exception ex)
            {
                log($"Certificate renewal failed: {ex.Message}");
                if (server.NotAfter < DateTime.Now) throw;
            }
        }

        var ca = new X509Certificate2(File.ReadAllBytes(ServerPaths.CaCertFile));
        var context = SslStreamCertificateContext.Create(server, [ca], offline: true);
        return new ServerCredentials(server, ca, context);
    }

    private static void SaveIssued(string certificateBase64, ECDsa key)
    {
        using var issued = new X509Certificate2(Convert.FromBase64String(certificateBase64));
        using var withKey = issued.CopyWithPrivateKey(key);
        CertificateManager.SaveProtected(withKey, ServerPaths.ServerCertFile);
    }

    /// <summary>One raw request (tests and diagnostics).</summary>
    public static CentralResponse Request(string server, string caFingerprint, X509Certificate2? clientCert, CentralRequest request) =>
        Call(server, caFingerprint, clientCert, request);

    private static CentralResponse Call(string server, string caFingerprint, X509Certificate2? clientCert, CentralRequest request)
    {
        var (host, port) = CentralProtocol.ParseAddress(server);
        using var tcp = new TcpClient();
        if (!tcp.ConnectAsync(host, port).Wait(ConnectTimeout))
            throw new IOException($"Auth server {host}:{port} did not answer.");
        var ns = tcp.GetStream();
        ns.ReadTimeout = ns.WriteTimeout = 15_000;
        using var ssl = new SslStream(ns, leaveInnerStreamOpen: false,
            (_, cert, chain, _) => IsTrustedAuthServer(cert, chain, host, caFingerprint));
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ClientCertificates = clientCert is null ? null : new X509CertificateCollection { clientCert },
            LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCert!,
        });
        CentralProtocol.Write(ssl, request);
        return CentralProtocol.Read<CentralResponse>(ssl);
    }

    /// <summary>The auth server's certificate must chain to the pinned CA and name the host we connected to.</summary>
    private static bool IsTrustedAuthServer(X509Certificate? cert, X509Chain? sentChain, string host, string caFingerprint)
    {
        if (cert is null || sentChain is null) return false;
        var leaf = new X509Certificate2(cert);
        var ca = sentChain.ChainElements.Cast<X509ChainElement>().Select(e => e.Certificate)
            .FirstOrDefault(c => CentralProtocol.SameFingerprint(CertificateManager.Fingerprint(c), caFingerprint));
        if (ca is null) return false;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        return chain.Build(leaf) && leaf.MatchesHostname(host, allowWildcards: false, allowCommonName: false);
    }
}
