using System.Security.AccessControl;
using System.Security.Principal;

namespace SecureVNC.Shared.Hosting;

/// <summary>Server data lives in %ProgramData%\SecureVNC, readable only by Administrators and SYSTEM.</summary>
public static class ServerPaths
{
    public static string DataDir { get; private set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureVNC");

    /// <summary>Keeps all data in another folder: the Auth Console (auth server data) and the self-test.</summary>
    public static void UseDataDir(string dir) => DataDir = dir;

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
    /// <summary>Machine GUID + name the keys were made for: a clone or rename gets new keys.</summary>
    public static string IdentityFile => Path.Combine(DataDir, "identity.json");
    /// <summary>Central mode: the join key, DPAPI-protected, to re-join automatically after cloning.</summary>
    public static string JoinKeyFile => Path.Combine(DataDir, "join.key.protected");

    /// <summary>Local mode: own CA key. Central mode: certificate from the auth server.</summary>
    public static bool IsInitialized => File.Exists(CaCertFile) && (File.Exists(CaKeyFile) || File.Exists(ServerCertFile));

    public static void EnsureDataDir() => SecureDirectory(DataDir, fresh: !IsInitialized);

    /// <summary>
    /// Creates (or re-secures) a data folder: owner Administrators, access only for Administrators and SYSTEM.
    /// Any user may create folders in %ProgramData%, so a folder that is already there before SecureVNC set it up
    /// (<paramref name="fresh"/>) may hold planted users, settings or links: it is moved aside, never used.
    /// </summary>
    public static void SecureDirectory(string path, bool fresh)
    {
        if (!IsAdministrator())
        {
            // Only the self-test runs unelevated; real installs always lock the folder.
            Directory.CreateDirectory(Path.Combine(path, "logs"));
            return;
        }

        if (fresh && Directory.Exists(path))
        {
            var aside = $"{path}.untrusted-{DateTime.Now:yyyyMMdd-HHmmss}";
            try
            {
                Directory.Move(path, aside);
            }
            catch (Exception ex)
            {
                throw new UnauthorizedAccessException(
                    $"The folder {path} already existed before SecureVNC was set up and cannot be moved aside ({ex.Message}). " +
                    "Delete it as administrator and try again.", ex);
            }
        }

        var dir = new DirectoryInfo(path);
        if (!dir.Exists)
        {
            dir.Create(LockedDirectorySecurity());
            dir.Refresh();
            if (dir.EnumerateFileSystemInfos().Any())
                throw new UnauthorizedAccessException($"Someone created files in {path} while it was being set up. Delete it and try again.");
        }
        Harden(path);
        Directory.CreateDirectory(Path.Combine(path, "logs"));
    }

    /// <summary>
    /// Resets ownership and permissions of the folder and everything in it (owner Administrators, only inherited
    /// access), and removes links (junctions, symbolic links) that could redirect SYSTEM's writes elsewhere.
    /// Throws when that is not possible: then something in the folder is not ours.
    /// </summary>
    public static void Harden(string path)
    {
        if (!IsAdministrator() || !Directory.Exists(path)) return;
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        var root = new DirectoryInfo(path);
        if (root.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new UnauthorizedAccessException($"{path} is a link, not a folder. Delete it and reinstall.");
        root.SetAccessControl(LockedDirectorySecurity());

        HardenChildren(root, admins);
    }

    /// <summary>Walks the folder without ever following a link (a junction to C:\Windows must not be touched).</summary>
    private static void HardenChildren(DirectoryInfo dir, SecurityIdentifier admins)
    {
        foreach (var entry in dir.EnumerateFileSystemInfos("*", new EnumerationOptions { AttributesToSkip = 0, IgnoreInaccessible = false }))
        {
            if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                entry.Delete();   // removes the link itself, not its target
                continue;
            }
            if (entry is DirectoryInfo sub)
            {
                var s = new DirectorySecurity();
                s.SetOwner(admins);
                s.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
                sub.SetAccessControl(s);
                HardenChildren(sub, admins);
            }
            else if (entry is FileInfo file)
            {
                var s = new FileSecurity();
                s.SetOwner(admins);
                s.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
                file.SetAccessControl(s);
            }
        }
    }

    private static DirectorySecurity LockedDirectorySecurity()
    {
        var sec = new DirectorySecurity();
        sec.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
        {
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        return sec;
    }

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator) || id.IsSystem;
    }
}
