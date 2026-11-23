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

        // Once a user exists, the Manager opens only with a SecureVNC login (password + authenticator code).
        string? user = null;
        if (UserStore.Load().Users.Count > 0)
        {
            using var login = new LoginDialog("Unlock SecureVNC Manager with a SecureVNC user: password and the code from Google Authenticator.");
            if (login.ShowDialog() != DialogResult.OK) return;
            user = login.UserName;
        }

        Application.Run(new MainForm(firstRun: args.Contains("--first-run"), user));
    }
}
