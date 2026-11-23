using System.Security.Cryptography;
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
    /// <summary>Organization CA with its private key, sealed to the vault (master password).</summary>
    public string CaKeyFile => Path.Combine(dataDir, "ca.pfx.sealed");
    public string CaCertFile => Path.Combine(dataDir, "ca.cer");
    public string ConfigFile => Path.Combine(dataDir, "auth-config.json");
    public string ComputersFile => Path.Combine(dataDir, "computers.json");
    public string JoinKeyFile => Path.Combine(dataDir, "join.key.sealed");
    public string LogDir => Path.Combine(dataDir, "logs");

    // Before the master password (1.3.x): Windows DPAPI only. Converted, then deleted, when the master password is set.
    public string LegacyCaKeyFile => Path.Combine(dataDir, "ca.pfx.protected");
    public string LegacyJoinKeyFile => Path.Combine(dataDir, "join.key.protected");
    public string LegacyTlsCertFile => Path.Combine(dataDir, "server.pfx.protected");

    /// <summary>Master password set and the organization CA sealed with it.</summary>
    public bool IsInitialized => Vault.Exists(this) && File.Exists(CaKeyFile) && File.Exists(CaCertFile);

    /// <summary>Data from before the master password exists and waits to be sealed.</summary>
    public bool HasLegacyData => File.Exists(LegacyCaKeyFile);
}

public sealed class AuthConfig
{
    public int Port { get; set; } = CentralProtocol.DefaultPort;
    public string ListenAddress { get; set; } = "::";
    /// <summary>Computers allowed to ask (private networks by default).</summary>
    public List<string> AllowedNetworks { get; set; } = new ServerConfig().AllowedNetworks;
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 5;
    /// <summary>New computers may log no one in until an administrator approves them in the Auth Console.</summary>
    public bool RequireApproval { get; set; }

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
    /// <summary>The address in this computer's current certificate ("" = name only).</summary>
    public string CertificateAddress { get; set; } = "";
    /// <summary>Blocked in the Auth Console: cannot log anyone in, renew its certificate or join again.</summary>
    public bool Revoked { get; set; }
    /// <summary>Joined while approval is required: waits for an administrator.</summary>
    public bool Pending { get; set; }

    public bool Same(string name, string machineGuid) =>
        string.Equals(Name, name, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(MachineGuid, machineGuid, StringComparison.OrdinalIgnoreCase);
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
    /// <summary>Folder and settings only; nothing secret (the installer runs this, the master password comes later).</summary>
    public static void Prepare(AuthPaths paths)
    {
        ServerPaths.SecureDirectory(paths.DataDir);
        if (!File.Exists(paths.ConfigFile)) new AuthConfig().Save(paths);
    }

    /// <summary>
    /// Sets the master password: creates the vault, then the organization CA and the join key, all sealed with it.
    /// Data from an older version (DPAPI only) is sealed instead and the old files deleted.
    /// </summary>
    public static void Initialize(AuthPaths paths, string masterPassword, Action<string> log)
    {
        Prepare(paths);
        if (Vault.Exists(paths)) throw new InvalidOperationException("The master password is already set.");
        Vault.Create(paths, masterPassword);

        if (paths.HasLegacyData)
        {
            using (var ca = CertificateManager.LoadProtected(paths.LegacyCaKeyFile))
                File.WriteAllBytes(paths.CaKeyFile, Vault.Seal(paths, ca.Export(X509ContentType.Pkcs12)));
            if (File.Exists(paths.LegacyJoinKeyFile))
                SetJoinKey(paths, Encoding.UTF8.GetString(Dpapi.Unprotect(File.ReadAllBytes(paths.LegacyJoinKeyFile))));
            var admins = UserStore.Load(paths.UsersFile);
            foreach (var u in admins.Users.Where(u => !Vault.IsSealedText(u.TotpSecret)))
            {
                var secret = Dpapi.Unprotect(Convert.FromBase64String(u.TotpSecret));
                u.TotpSecret = Vault.SealToText(paths, secret);
                CryptographicOperations.ZeroMemory(secret);
            }
            admins.Save();
            foreach (var old in new[] { paths.LegacyCaKeyFile, paths.LegacyJoinKeyFile, paths.LegacyTlsCertFile })
                if (File.Exists(old)) File.Delete(old);
            log("Existing keys and authenticator secrets sealed with the master password");
        }
        else
        {
            using var ca = CertificateManager.CreateCa($"SecureVNC Organization CA ({Environment.MachineName})");
            File.WriteAllBytes(paths.CaKeyFile, Vault.Seal(paths, ca.Export(X509ContentType.Pkcs12)));
            File.WriteAllBytes(paths.CaCertFile, ca.Export(X509ContentType.Cert));
            log($"Organization CA created: {CertificateManager.Fingerprint(ca)}");
        }
        if (!File.Exists(paths.JoinKeyFile)) SetJoinKey(paths, CentralProtocol.NewJoinKey());
    }

    /// <summary>The organization CA with its private key; needs the unlocked vault (auth service).</summary>
    public static X509Certificate2 OpenCa(AuthPaths paths) =>
        new(Vault.Unseal(File.ReadAllBytes(paths.CaKeyFile)), (string?)null, X509KeyStorageFlags.Exportable);

    /// <summary>Needs the unlocked vault (auth service).</summary>
    public static string ReadJoinKey(AuthPaths paths) =>
        Encoding.UTF8.GetString(Vault.Unseal(File.ReadAllBytes(paths.JoinKeyFile)));

    /// <summary>Works while locked: sealing needs only the public key.</summary>
    public static void SetJoinKey(AuthPaths paths, string key) =>
        File.WriteAllBytes(paths.JoinKeyFile, Vault.Seal(paths, Encoding.UTF8.GetBytes(key)));

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
                File.AppendAllText(AuditFile(paths, DateTime.Now), $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {Log.OneLine(line)}{Environment.NewLine}");
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
