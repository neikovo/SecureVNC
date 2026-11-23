using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

/// <summary>
/// Graphical server administration: users with Google Authenticator enrollment, CA fingerprint and export,
/// service status. The installer starts it with --first-run so the first user can be created right away.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Log.Source = "manager";

        if (!ServerPaths.IsAdministrator())
        {
            MessageBox.Show("SecureVNC Manager must run as administrator.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        try
        {
            if (!ServerPaths.IsInitialized)
            {
                ServerPaths.EnsureDataDir();
                if (!File.Exists(ServerPaths.ConfigFile)) new ServerConfig().Save();
                CertificateManager.InitializePki(force: true).Dispose();
                Log.Info("Local CA created by SecureVNC Manager");
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not create the local certificate:\n{ex.Message}", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Application.Run(new MainForm(firstRun: args.Contains("--first-run")));
    }
}
