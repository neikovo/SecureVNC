using System.Runtime.InteropServices;

namespace SecureVNC.Server;

/// <summary>
/// Keeps the calling thread on the desktop that currently receives input: "Default" for the user's
/// desktop, "Winlogon" for the login screen, lock screen, Ctrl+Alt+Del screen and UAC prompts.
/// Only a SYSTEM process (agent mode) may open Winlogon; in standalone mode this quietly stays on Default.
/// The thread must not own windows or hooks, so only the session worker threads call this.
/// </summary>
internal static partial class DesktopSwitcher
{
    private const uint GENERIC_ALL = 0x10000000;
    private const int UOI_NAME = 2;

    [ThreadStatic] private static nint _desktop;
    [ThreadStatic] private static string? _name;

    [LibraryImport("user32.dll", SetLastError = true)]
    private static partial nint OpenInputDesktop(uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetThreadDesktop(nint desktop);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseDesktop(nint desktop);

    [LibraryImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetUserObjectInformation(nint obj, int index, void* info, int length, out int needed);

    public static string? CurrentName => _name;

    /// <summary>Returns true when the thread moved to another desktop (screen DCs must be re-created).</summary>
    public static bool SyncThreadToInputDesktop()
    {
        nint input = OpenInputDesktop(0, false, GENERIC_ALL);
        if (input == 0) return false;   // not allowed (standalone mode on the secure desktop)

        string? name = GetName(input);
        if (name is not null && name == _name)
        {
            CloseDesktop(input);
            return false;
        }
        if (!SetThreadDesktop(input))
        {
            CloseDesktop(input);
            return false;
        }
        if (_desktop != 0) CloseDesktop(_desktop);
        _desktop = input;
        _name = name;
        return true;
    }

    private static unsafe string? GetName(nint desktop)
    {
        char* buffer = stackalloc char[128];
        return GetUserObjectInformation(desktop, UOI_NAME, buffer, 128 * sizeof(char), out _)
            ? new string(buffer)
            : null;
    }
}
