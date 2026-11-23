using System.Security.AccessControl;
using System.Security.Principal;

namespace SecureVNC.Shared.Hosting;

/// <summary>Server data lives in %ProgramData%\SecureVNC, readable only by Administrators and SYSTEM.</summary>
public static class ServerPaths
{
    public static string DataDir { get; private set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureVNC");

    /// <summary>Keeps all data in another folder: the Auth Console (auth server data) and the self-test.</summary>
    public static void UseDataDir(string dir)
    {
        DataDir = dir;
        Directory.CreateDirectory(LogDir);
    }

    public static void UseDataDirForTesting(string dir) => UseDataDir(dir);

    public static string ConfigFile => Path.Combine(DataDir, "config.json");
    public static string UsersFile => Path.Combine(DataDir, "users.json");
    public static string CaKeyFile => Path.Combine(DataDir, "ca.pfx.protected");
    public static string CaCertFile => Path.Combine(DataDir, "ca.cer");
    public static string ServerCertFile => Path.Combine(DataDir, "server.pfx.protected");
    public static string LogDir => Path.Combine(DataDir, "logs");
    /// <summary>Machine GUID + name the keys were made for: a clone or rename gets new keys.</summary>
    public static string IdentityFile => Path.Combine(DataDir, "identity.json");
    /// <summary>Central mode: the join key, DPAPI-protected, to re-join automatically after cloning.</summary>
    public static string JoinKeyFile => Path.Combine(DataDir, "join.key.protected");

    /// <summary>Local mode: own CA key. Central mode: certificate from the auth server.</summary>
    public static bool IsInitialized => File.Exists(CaCertFile) && (File.Exists(CaKeyFile) || File.Exists(ServerCertFile));

    public static void EnsureDataDir() => SecureDirectory(DataDir);

    /// <summary>Creates the folder (and logs below it), readable only by Administrators and SYSTEM.</summary>
    public static void SecureDirectory(string path)
    {
        var dir = Directory.CreateDirectory(path);
        Directory.CreateDirectory(Path.Combine(path, "logs"));
        if (!IsAdministrator()) return;   // only the self-test runs unelevated; real installs always lock the folder
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
        {
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        dir.SetAccessControl(sec);
    }

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
