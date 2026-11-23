using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

namespace SecureVNC.Shared.Central;

/// <summary>Files of the SecureVNC Auth Server, in %ProgramData%\SecureVNC-Auth (Administrators and SYSTEM only).</summary>
public sealed class AuthPaths(string dataDir)
{
    public static string DefaultDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureVNC-Auth");

    public string DataDir => dataDir;
    /// <summary>Administrators (same format as the local users file).</summary>
    public string UsersFile => Path.Combine(dataDir, "users.json");
    public string CaKeyFile => Path.Combine(dataDir, "ca.pfx.protected");
    public string CaCertFile => Path.Combine(dataDir, "ca.cer");
    public string TlsCertFile => Path.Combine(dataDir, "server.pfx.protected");
    public string ConfigFile => Path.Combine(dataDir, "auth-config.json");
    public string ComputersFile => Path.Combine(dataDir, "computers.json");
    public string JoinKeyFile => Path.Combine(dataDir, "join.key.protected");
    public string LogDir => Path.Combine(dataDir, "logs");

    public bool IsInitialized => File.Exists(CaKeyFile) && File.Exists(JoinKeyFile);
}

public sealed class AuthConfig
{
    public int Port { get; set; } = CentralProtocol.DefaultPort;
    public string ListenAddress { get; set; } = "::";
    /// <summary>Computers allowed to ask (private networks by default).</summary>
    public List<string> AllowedNetworks { get; set; } = new ServerConfig().AllowedNetworks;
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 5;

    public static AuthConfig Load(AuthPaths paths) =>
        File.Exists(paths.ConfigFile)
            ? JsonSerializer.Deserialize<AuthConfig>(File.ReadAllText(paths.ConfigFile), ServerConfig.Json) ?? new()
            : new();

    public void Save(AuthPaths paths) => File.WriteAllText(paths.ConfigFile, JsonSerializer.Serialize(this, ServerConfig.Json));
}

public sealed class ComputerRecord
{
    public string Name { get; set; } = "";
    public string MachineGuid { get; set; } = "";
    /// <summary>Serial numbers of the certificates issued to this computer (hex).</summary>
    public List<string> Serials { get; set; } = [];
    public DateTime JoinedUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public string LastAddress { get; set; } = "";
    public bool Revoked { get; set; }
}

/// <summary>Computers that joined the auth server.</summary>
public sealed class ComputerStore
{
    private static readonly object FileLock = new();
    private string _file = "";

    public List<ComputerRecord> Computers { get; set; } = [];

    public static ComputerStore Load(AuthPaths paths)
    {
        lock (FileLock)
        {
            var store = File.Exists(paths.ComputersFile)
                ? JsonSerializer.Deserialize<ComputerStore>(File.ReadAllText(paths.ComputersFile), ServerConfig.Json) ?? new()
                : new();
            store._file = paths.ComputersFile;
            return store;
        }
    }

    public void Save()
    {
        lock (FileLock)
        {
            var tmp = _file + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this, ServerConfig.Json));
            File.Move(tmp, _file, overwrite: true);
        }
    }

    public ComputerRecord? BySerial(string serial) =>
        Computers.FirstOrDefault(c => c.Serials.Contains(serial, StringComparer.OrdinalIgnoreCase));

    /// <summary>Changes one record under the file lock (read, change, save).</summary>
    public static T Update<T>(AuthPaths paths, Func<ComputerStore, T> change)
    {
        lock (FileLock)
        {
            var store = Load(paths);
            var result = change(store);
            store.Save();
            return result;
        }
    }
}

public static class AuthData
{
    /// <summary>First start: organization CA, the auth server's TLS certificate and a join key.</summary>
    public static void Initialize(AuthPaths paths, Action<string> log)
    {
        ServerPaths.SecureDirectory(paths.DataDir);
        if (!File.Exists(paths.ConfigFile)) new AuthConfig().Save(paths);
        if (!File.Exists(paths.CaKeyFile))
        {
            using var ca = CertificateManager.CreateCa($"SecureVNC Organization CA ({Environment.MachineName})");
            CertificateManager.SaveProtected(ca, paths.CaKeyFile);
            File.WriteAllBytes(paths.CaCertFile, ca.Export(X509ContentType.Cert));
            log($"Organization CA created: {CertificateManager.Fingerprint(ca)}");
        }
        if (!File.Exists(paths.JoinKeyFile)) SetJoinKey(paths, CentralProtocol.NewJoinKey());
        CertificateManager.EnsureLeaf(paths.CaKeyFile, paths.TlsCertFile, log).ServerCertificate.Dispose();
    }

    public static string ReadJoinKey(AuthPaths paths) =>
        Encoding.UTF8.GetString(Dpapi.Unprotect(File.ReadAllBytes(paths.JoinKeyFile)));

    public static void SetJoinKey(AuthPaths paths, string key) =>
        File.WriteAllBytes(paths.JoinKeyFile, Dpapi.Protect(Encoding.UTF8.GetBytes(key)));

    public static string CaFingerprint(AuthPaths paths)
    {
        using var ca = new X509Certificate2(File.ReadAllBytes(paths.CaCertFile));
        return CertificateManager.Fingerprint(ca);
    }

    public static string AuditFile(AuthPaths paths, DateTime when) => Path.Combine(paths.LogDir, $"audit-{when:yyyyMM}.log");

    private static readonly object AuditLock = new();

    public static void Audit(AuthPaths paths, string line)
    {
        lock (AuditLock)
        {
            try
            {
                Directory.CreateDirectory(paths.LogDir);
                File.AppendAllText(AuditFile(paths, DateTime.Now), $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {line}{Environment.NewLine}");
            }
            catch
            {
                // auditing must not take the server down
            }
        }
    }

    /// <summary>Newest audit lines (this month and the previous one).</summary>
    public static IReadOnlyList<string> RecentAudit(AuthPaths paths, int count)
    {
        var lines = new List<string>();
        foreach (var month in new[] { DateTime.Now.AddMonths(-1), DateTime.Now })
        {
            var f = AuditFile(paths, month);
            if (File.Exists(f)) lines.AddRange(File.ReadAllLines(f));
        }
        return lines.TakeLast(count).Reverse().ToList();
    }

    public static string Display(IPAddress a) => NetworkInfo.Display(a);
}
