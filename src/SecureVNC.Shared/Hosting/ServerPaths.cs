using System.Security.AccessControl;
using System.Security.Principal;

namespace SecureVNC.Shared.Hosting;

/// <summary>Server data lives in %ProgramData%\SecureVNC, readable only by Administrators and SYSTEM.</summary>
public static class ServerPaths
{
    public static string DataDir { get; private set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureVNC");

    /// <summary>For the self-test only: keep all server data in another (temporary) folder.</summary>
    public static void UseDataDirForTesting(string dir)
    {
        DataDir = dir;
        Directory.CreateDirectory(LogDir);
    }

    public static string ConfigFile => Path.Combine(DataDir, "config.json");
    public static string UsersFile => Path.Combine(DataDir, "users.json");
    public static string CaKeyFile => Path.Combine(DataDir, "ca.pfx.protected");
    public static string CaCertFile => Path.Combine(DataDir, "ca.cer");
    public static string ServerCertFile => Path.Combine(DataDir, "server.pfx.protected");
    public static string LogDir => Path.Combine(DataDir, "logs");

    public static bool IsInitialized => File.Exists(CaKeyFile);

    public static void EnsureDataDir()
    {
        var dir = Directory.CreateDirectory(DataDir);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
        {
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        dir.SetAccessControl(sec);
        Directory.CreateDirectory(LogDir);
    }

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
