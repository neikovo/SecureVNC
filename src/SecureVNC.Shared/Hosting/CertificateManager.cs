using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureVNC.Shared.Security;

namespace SecureVNC.Shared.Hosting;

public sealed record ServerCredentials(
    X509Certificate2 ServerCertificate,
    X509Certificate2 CaCertificate,
    SslStreamCertificateContext Context);

/// <summary>
/// Local PKI: each server has its own CA ("SecureVNC CA &lt;machine&gt;") that signs a
/// short-lived TLS certificate for the machine's current names and IPv4 addresses.
/// Clients trust the CA, so the leaf can be re-issued whenever the IP changes.
/// </summary>
public static class CertificateManager
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string SanOid = "2.5.29.17";

    public static X509Certificate2 CreateCa()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(
            new X500DistinguishedName($"CN=SecureVNC CA {Environment.MachineName}, O=SecureVNC"),
            key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return req.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));
    }

    public static X509Certificate2 IssueServerCertificate(
        X509Certificate2 ca, IReadOnlyCollection<string> dnsNames, IReadOnlyCollection<IPAddress> ips)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(
            new X500DistinguishedName($"CN={Environment.MachineName}, O=SecureVNC"),
            key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid)], false));
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

        using var cert = req.Create(ca, notBefore, notAfter, serial);
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

    /// <summary>Creates the CA (if missing) and a server certificate; used by "SecureVNC.Admin init".</summary>
    public static X509Certificate2 InitializePki(bool force)
    {
        if (!force && ServerPaths.IsInitialized) return LoadPublicCa();
        using var ca = CreateCa();
        SaveProtected(ca, ServerPaths.CaKeyFile);
        File.WriteAllBytes(ServerPaths.CaCertFile, ca.Export(X509ContentType.Cert));
        if (File.Exists(ServerPaths.ServerCertFile)) File.Delete(ServerPaths.ServerCertFile);
        EnsureServerCredentials(_ => { }).ServerCertificate.Dispose();
        return LoadPublicCa();
    }

    public static X509Certificate2 LoadPublicCa() => new(File.ReadAllBytes(ServerPaths.CaCertFile));

    /// <summary>
    /// Loads the server certificate, re-issuing it from the CA when it is missing, expiring,
    /// or no longer covers the current host names / IP addresses.
    /// </summary>
    public static ServerCredentials EnsureServerCredentials(Action<string> log, bool forceReissue = false)
    {
        using var ca = LoadProtected(ServerPaths.CaKeyFile);
        var (dns, ips) = CurrentIdentity();
        X509Certificate2? server = !forceReissue && File.Exists(ServerPaths.ServerCertFile)
            ? LoadProtected(ServerPaths.ServerCertFile) : null;

        if (server is null || server.NotAfter < DateTime.Now.AddDays(30) ||
            server.Issuer != ca.Subject || !Covers(server, dns, ips))
        {
            server?.Dispose();
            using (var fresh = IssueServerCertificate(ca, dns, ips))
                SaveProtected(fresh, ServerPaths.ServerCertFile);
            // Reload from PFX: SChannel cannot use the ephemeral key of a freshly created certificate.
            server = LoadProtected(ServerPaths.ServerCertFile);
            log($"Issued server certificate for {string.Join(", ", dns)}, {string.Join(", ", ips)}");
        }

        var caPublic = new X509Certificate2(ca.Export(X509ContentType.Cert));
        var context = SslStreamCertificateContext.Create(server, [caPublic], offline: true);
        return new ServerCredentials(server, caPublic, context);
    }
}
