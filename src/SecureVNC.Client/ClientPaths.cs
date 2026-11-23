namespace SecureVNC.Client;

/// <summary>
/// Where the client keeps trusted servers (trust.json) and last-used settings (client.json).
/// Portable mode: a folder named "SecureVNC-data" next to SecureVNC.Client.exe (e.g. on a USB stick) -
/// then everything stays there and nothing is written to the PC. Otherwise: %AppData%\SecureVNC.
/// </summary>
internal static class ClientPaths
{
    public const string PortableFolderName = "SecureVNC-data";

    private static readonly string PortableDir = Path.Combine(AppContext.BaseDirectory, PortableFolderName);

    public static bool IsPortable { get; } = Directory.Exists(PortableDir);

    public static string DataDir { get; } = IsPortable
        ? PortableDir
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SecureVNC");
}
