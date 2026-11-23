using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace SecureVNC.Client;

/// <summary>
/// Which server CAs this user trusts, per host (like SSH known_hosts), plus CAs imported from a file.
/// Stored in %AppData%\SecureVNC\trust.json.
/// </summary>
public sealed class TrustStore
{
    private static string Dir { get; set; } = ClientPaths.DataDir;
    private static string FilePath => Path.Combine(Dir, "trust.json");

    /// <summary>For the self-test only.</summary>
    public static void UseDirForTesting(string dir) => Dir = dir;

    public Dictionary<string, string> Hosts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> ImportedCas { get; set; } = [];

    public static TrustStore Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var t = JsonSerializer.Deserialize<TrustStore>(File.ReadAllText(FilePath)) ?? new();
                t.Hosts = new Dictionary<string, string>(t.Hosts, StringComparer.OrdinalIgnoreCase);
                return t;
            }
        }
        catch (JsonException) { /* corrupted: start empty */ }
        return new TrustStore();
    }

    public void Save()
    {
        Directory.CreateDirectory(Dir);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }

    public X509Certificate2? CaForHost(string host) =>
        Hosts.TryGetValue(host, out var b64) ? new X509Certificate2(Convert.FromBase64String(b64)) : null;

    public X509Certificate2Collection Imported() =>
        new(ImportedCas.Select(b => new X509Certificate2(Convert.FromBase64String(b))).ToArray());

    /// <summary>Every CA this viewer trusts: pinned for a host, or imported.</summary>
    public X509Certificate2Collection AllTrusted()
    {
        var all = new X509Certificate2Collection();
        foreach (var b64 in Hosts.Values.Concat(ImportedCas).Distinct()) all.Add(new X509Certificate2(Convert.FromBase64String(b64)));
        return all;
    }

    public void TrustHost(string host, X509Certificate2 ca)
    {
        Hosts[host] = Convert.ToBase64String(ca.RawData);
        Save();
    }

    public void Import(string cerPath)
    {
        var ca = new X509Certificate2(cerPath);
        if (!IsCa(ca)) throw new InvalidOperationException("This file is not a CA certificate.");
        var b64 = Convert.ToBase64String(ca.RawData);
        if (!ImportedCas.Contains(b64)) ImportedCas.Add(b64);
        Save();
    }

    public static bool IsCa(X509Certificate2 cert) =>
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority)
        && cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);

    public static string Fingerprint(X509Certificate2 cert) =>
        string.Join(":", cert.GetCertHash(HashAlgorithmName.SHA256).Select(b => b.ToString("X2")));

    /// <summary>True if the server certificate is a valid TLS server certificate issued by one of the roots.</summary>
    public static bool ChainsTo(X509Certificate2 leaf, X509Certificate2Collection roots)
    {
        if (roots.Count == 0) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        return chain.Build(leaf);
    }
}
