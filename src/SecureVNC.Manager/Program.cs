using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

/// <summary>
/// SecureVNC Manager (computers that can be controlled) and, with --auth, the SecureVNC Auth Console (auth server).
/// Once a user / administrator exists, both open only after a SecureVNC login (password + authenticator code).
/// The installer starts it with --first-run so the first user can be created right away.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        bool firstRun = args.Contains("--first-run");

        if (!ServerPaths.IsAdministrator())
        {
            MessageBox.Show("SecureVNC Manager must run as administrator.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        if (args.Contains("--auth"))
        {
            RunAuthConsole(firstRun);
            return;
        }

        Log.Source = "manager";
        try
        {
            if (!ServerPaths.IsInitialized)
            {
                ServerPaths.EnsureDataDir();
                if (!File.Exists(ServerPaths.ConfigFile)) new ServerConfig().Save();
                CertificateManager.InitializePki(force: true).Dispose();
                Log.Info("Local CA created by SecureVNC Manager");
            }
            MachineIdentity.Guard(Log.Info);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not prepare the certificate:\n{ex.Message}", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var config = ServerConfig.Load();
        string? user = null;
        if (config.IsCentral || UserStore.Load().Users.Count > 0)
        {
            string reason = config.IsCentral
                ? "Unlock SecureVNC Manager with an administrator of the auth server: password and the code from Google Authenticator."
                : "Unlock SecureVNC Manager with a SecureVNC user: password and the code from Google Authenticator.";
            using var login = new LoginDialog(reason, (name, password, code) =>
                LoginVerifier.Verify(name, password, code, $"Manager on {Environment.MachineName}") switch
                {
                    LoginResult.Ok => null,
                    LoginResult.Unavailable => "The auth server cannot be reached. (An administrator can leave it with: SecureVNC.Admin leave)",
                    _ => "Wrong user name, password or code. A code can be used only once: wait for the next one.",
                });
            if (login.ShowDialog() != DialogResult.OK) return;
            user = login.UserName;
        }

        Application.Run(new MainForm(firstRun, user));
    }

    private static void RunAuthConsole(bool firstRun)
    {
        var paths = new AuthPaths(AuthPaths.DefaultDir);
        ServerPaths.UseDataDir(paths.DataDir);   // users = the auth server's administrators
        Log.Source = "auth-console";
        try
        {
            if (!paths.IsInitialized) AuthData.Initialize(paths, Log.Info);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not prepare the auth server data:\n{ex.Message}", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        string? user = null;
        if (UserStore.Load().Users.Count > 0)
        {
            using var login = new LoginDialog("Unlock the SecureVNC Auth Console with an administrator: password and the code from Google Authenticator.",
                (name, password, code) => UserStore.Authenticate(name, password, code)
                    ? null
                    : "Wrong user name, password or code. A code can be used only once: wait for the next one.");
            if (login.ShowDialog() != DialogResult.OK) return;
            user = login.UserName;
        }
        Application.Run(new AuthMainForm(paths, firstRun, user));
    }
}
