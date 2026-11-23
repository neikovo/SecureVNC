using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SecureVNC.Shared.Hosting;

/// <summary>
/// Who may own SecureVNC data. Ownership is the one thing an ordinary user cannot fake: Windows does not let a
/// user make Administrators or SYSTEM the owner of a folder. A folder or file owned by anyone else was not
/// created by SecureVNC's setup or services, so its contents are not trusted.
/// </summary>
public static class LocalAdmins
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static bool IsTrustedOwner(SecurityIdentifier? owner) =>
        owner is not null && (owner == Administrators || owner == System || owner == TrustedInstaller || IsMember(owner));

    public static SecurityIdentifier? OwnerOf(FileSystemInfo entry)
    {
        FileSystemSecurity security = entry is DirectoryInfo d
            ? d.GetAccessControl(AccessControlSections.Owner)
            : ((FileInfo)entry).GetAccessControl(AccessControlSections.Owner);
        return security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
    }

    /// <summary>Direct member of the local Administrators group (files created by an elevated administrator may carry that administrator's own account).</summary>
    public static bool IsMember(SecurityIdentifier sid)
    {
        try
        {
            var groupName = ((NTAccount)Administrators.Translate(typeof(NTAccount))).Value.Split('\\')[^1];
            IntPtr resume = IntPtr.Zero;
            int status = NetLocalGroupGetMembers(null, groupName, 0, out var buffer, -1, out int read, out _, ref resume);
            if (status != 0) return false;
            try
            {
                for (int i = 0; i < read; i++)
                {
                    var memberSid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    if (new SecurityIdentifier(memberSid) == sid) return true;
                }
                return false;
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }
        catch
        {
            return false;
        }
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? server, string group, int level, out IntPtr buffer,
        int maxLength, out int entriesRead, out int totalEntries, ref IntPtr resume);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
