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

    /// <summary>Sends the master password to the local auth service; null when it is unlocked, otherwise the reason.</summary>
    internal static string? Unlock(string masterPassword)
    {
        var r = AuthPipe.Send(new AuthPipeRequest { Op = "unlock", Password = masterPassword }, 30_000);
        return r.Ok ? null : r.Error ?? "Could not unlock.";
    }

    private static void RunAuthConsole(bool firstRun)
    {
        var paths = new AuthPaths(AuthPaths.DefaultDir);
        ServerPaths.UseDataDir(paths.DataDir);   // users = the auth server's administrators
        Log.Source = "auth-console";
        try
        {
            AuthData.Prepare(paths);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not prepare the auth server data:\n{ex.Message}", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // 1. Master password: set it the first time (sealing older data), or unlock the service after a restart.
        if (!paths.IsInitialized)
        {
            using var create = new MasterPasswordDialog(MasterPasswordMode.Create, (_, newPassword) =>
            {
                AuthData.Initialize(paths, newPassword, Log.Info);
                if (AuthPipe.State() is not null) Unlock(newPassword);
                return null;
            }, migrating: paths.HasLegacyData);
            if (create.ShowDialog() != DialogResult.OK) return;
        }
        var state = AuthPipe.State();
        if (state == "locked")
        {
            using var unlock = new MasterPasswordDialog(MasterPasswordMode.Unlock, (password, _) => Unlock(password));
            if (unlock.ShowDialog() != DialogResult.OK) return;
            state = AuthPipe.State();
        }
        if (state is null)
        {
            MessageBox.Show("The SecureVNC Auth Server service is not running. Start it (Services > SecureVNC Auth Server), then open the Auth Console again.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        // 2. New authenticator secrets are sealed to the vault (works while locked: public key only).
        UserStore.SealSecret = secret => Vault.SealToText(paths, secret);

        // 3. Administrator login, checked by the unlocked service (the console itself never holds the vault key).
        string? user = null;
        if (UserStore.Load().Users.Count > 0)
        {
            if (state != "unlocked")
            {
                MessageBox.Show("The auth server must be running and unlocked to check your login.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            using var login = new LoginDialog("Unlock the SecureVNC Auth Console with an administrator: password and the code from Google Authenticator.",
                (name, password, code) =>
                {
                    var r = AuthPipe.Send(new AuthPipeRequest { Op = "verify", User = name, Password = password, Code = code }, 10_000);
                    return r.Ok ? null : (r.Error ?? "Wrong user name, password or code.") + " A code can be used only once: wait for the next one.";
                });
            if (login.ShowDialog() != DialogResult.OK) return;
            user = login.UserName;
        }
        Application.Run(new AuthMainForm(paths, firstRun, user));
    }
}
