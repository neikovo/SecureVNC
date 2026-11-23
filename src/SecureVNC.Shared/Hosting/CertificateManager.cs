using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Security;

namespace SecureVNC.Shared.Hosting;

public sealed record ServerCredentials(
    X509Certificate2 ServerCertificate,
    X509Certificate2 CaCertificate,
    SslStreamCertificateContext Context);

/// <summary>
/// Local mode: each server has its own CA ("SecureVNC CA &lt;machine&gt;") that signs a TLS certificate for the
/// machine's current names and IPv4 addresses; the leaf is re-issued whenever the IP changes.
/// Central mode: the certificate comes from the SecureVNC Auth Server (organization CA), see <see cref="CentralClient"/>.
/// Clients trust the CA, never a single leaf.
/// </summary>
public static class CertificateManager
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const string SanOid = "2.5.29.17";

    public static X509Certificate2 CreateCa() => CreateCa($"SecureVNC CA {Environment.MachineName}");

    public static X509Certificate2 CreateCa(string commonName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(new X500DistinguishedName($"CN={commonName}, O=SecureVNC"), key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return req.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));
    }

    /// <summary>Signs a certificate for a public key (generated elsewhere, e.g. on a computer joining the auth server).</summary>
    public static X509Certificate2 IssueCertificate(
        X509Certificate2 ca, PublicKey publicKey, string commonName,
        IEnumerable<string> dnsNames, IEnumerable<IPAddress> ips, bool clientAuth)
    {
        var req = new CertificateRequest(new X500DistinguishedName($"CN={commonName}, O=SecureVNC"), publicKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var eku = new OidCollection { new Oid(ServerAuthOid) };
        if (clientAuth) eku.Add(new Oid(ClientAuthOid));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
        var san = new SubjectAlternativeNameBuilder();
        foreach (var d in dnsNames) san.AddDnsName(d);
        foreach (var ip in ips) san.AddIpAddress(ip);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-10);
        var notAfter = notBefore.AddYears(1);
        if (notAfter > ca.NotAfter.AddDays(-1)) notAfter = ca.NotAfter.AddDays(-1);
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        return req.Create(ca, notBefore, notAfter, serial);
    }

    public static X509Certificate2 IssueServerCertificate(
        X509Certificate2 ca, IReadOnlyCollection<string> dnsNames, IReadOnlyCollection<IPAddress> ips)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _);
        using var cert = IssueCertificate(ca, publicKey, Environment.MachineName, dnsNames, ips, clientAuth: false);
        return cert.CopyWithPrivateKey(key);
    }

    /// <summary>Names and addresses the server certificate must cover right now.</summary>
    public static (List<string> Dns, List<IPAddress> Ips) CurrentIdentity()
    {
        var dns = new SortedSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Environment.MachineName, Environment.MachineName + ".local", "localhost",
        };
        var props = IPGlobalProperties.GetIPGlobalProperties();
        if (!string.IsNullOrEmpty(props.DomainName)) dns.Add($"{props.HostName}.{props.DomainName}");

        var ips = new SortedSet<string> { "127.0.0.1", "::1" };
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up ||
                ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                // IPv4 only: IPv6 temporary addresses rotate and would force constant re-issue.
                if (ua.Address.AddressFamily == AddressFamily.InterNetwork) ips.Add(ua.Address.ToString());
            }
        }
        return (dns.ToList(), ips.Select(IPAddress.Parse).ToList());
    }

    public static IReadOnlyList<IPAddress> SanAddresses(X509Certificate2 cert)
    {
        var ext = cert.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == SanOid);
        return ext is null ? [] : new X509SubjectAlternativeNameExtension(ext.RawData).EnumerateIPAddresses().ToList();
    }

    public static bool Covers(X509Certificate2 cert, IEnumerable<string> dns, IEnumerable<IPAddress> ips)
    {
        var ext = cert.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == SanOid);
        if (ext is null) return false;
        var san = new X509SubjectAlternativeNameExtension(ext.RawData);
        var haveDns = san.EnumerateDnsNames().ToHashSet(StringComparer.OrdinalIgnoreCase);
        var haveIps = san.EnumerateIPAddresses().ToHashSet();
        return dns.All(haveDns.Contains) && ips.All(haveIps.Contains);
    }

    public static void SaveProtected(X509Certificate2 certWithKey, string path) =>
        File.WriteAllBytes(path, Dpapi.Protect(certWithKey.Export(X509ContentType.Pkcs12)));

    public static X509Certificate2 LoadProtected(string path) =>
        new(Dpapi.Unprotect(File.ReadAllBytes(path)), (string?)null, X509KeyStorageFlags.Exportable);

    public static string Fingerprint(X509Certificate2 cert) =>
        string.Join(":", cert.GetCertHash(HashAlgorithmName.SHA256).Select(b => b.ToString("X2")));

    /// <summary>Local mode: creates the CA (if missing) and a server certificate; used by "SecureVNC.Admin init".</summary>
    public static X509Certificate2 InitializePki(bool force)
    {
        if (!force && ServerPaths.IsInitialized) return LoadPublicCa();
        using var ca = CreateCa();
        SaveProtected(ca, ServerPaths.CaKeyFile);
        File.WriteAllBytes(ServerPaths.CaCertFile, ca.Export(X509ContentType.Cert));
        if (File.Exists(ServerPaths.ServerCertFile)) File.Delete(ServerPaths.ServerCertFile);
        EnsureServerCredentials(_ => { }).ServerCertificate.Dispose();
        MachineIdentity.SaveCurrent();
        return LoadPublicCa();
    }

    public static X509Certificate2 LoadPublicCa() => new(File.ReadAllBytes(ServerPaths.CaCertFile));

    /// <summary>
    /// Loads the server certificate. Local mode: re-issues it from the own CA when it is missing, expiring, or no
    /// longer covers the current host names / IP addresses. Central mode: renews it at the auth server.
    /// </summary>
    public static ServerCredentials EnsureServerCredentials(Action<string> log, bool forceReissue = false)
    {
        if (ServerConfig.Load() is { IsCentral: true } config)
            return CentralClient.EnsureCredentials(config, log, forceReissue);
        return EnsureLeaf(ServerPaths.CaKeyFile, ServerPaths.ServerCertFile, log, forceReissue);
    }

    /// <summary>Keeps a TLS certificate, signed by the CA in <paramref name="caKeyFile"/>, valid for this machine.</summary>
    public static ServerCredentials EnsureLeaf(string caKeyFile, string leafFile, Action<string> log, bool forceReissue = false)
    {
        using var ca = LoadProtected(caKeyFile);
        var (dns, ips) = CurrentIdentity();
        X509Certificate2? server = !forceReissue && File.Exists(leafFile) ? LoadProtected(leafFile) : null;

        if (server is null || server.NotAfter < DateTime.Now.AddDays(30) ||
            server.Issuer != ca.Subject || !Covers(server, dns, ips))
        {
            server?.Dispose();
            using (var fresh = IssueServerCertificate(ca, dns, ips))
                SaveProtected(fresh, leafFile);
            // Reload from PFX: SChannel cannot use the ephemeral key of a freshly created certificate.
            server = LoadProtected(leafFile);
            log($"Issued server certificate for {string.Join(", ", dns)}, {string.Join(", ", ips)}");
        }

        var caPublic = new X509Certificate2(ca.Export(X509ContentType.Cert));
        var context = SslStreamCertificateContext.Create(server, [caPublic], offline: true);
        return new ServerCredentials(server, caPublic, context);
    }
}
