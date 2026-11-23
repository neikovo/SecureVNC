using System.Diagnostics;
using System.Text;
using QRCoder;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

namespace SecureVNC.Admin;

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (!ServerPaths.IsAdministrator())
        {
            Console.Error.WriteLine("SecureVNC.Admin must run as administrator.");
            return 1;
        }

        try
        {
            return (args.Select(a => a.ToLowerInvariant()).ToArray()) switch
            {
                ["init", ..] => Init(force: args.Contains("--force"), askForUser: !args.Contains("--no-user")),
                ["user", "add", _] => UserAdd(args[2]),
                ["user", "list"] => UserList(),
                ["user", "remove", _] => UserRemove(args[2]),
                ["user", "reset-mfa", _] => UserResetMfa(args[2]),
                ["user", "passwd", _] => UserPasswd(args[2]),
                ["cert", "show"] => CertShow(),
                ["cert", "renew"] => CertRenew(),
                ["export-ca", _] => ExportCa(args[1]),
                ["join", _, _, _] => Join(args[1], args[2], args[3]),
                ["leave"] => Leave(),
                ["status"] => Status(),
                _ => Usage(),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    private static int Usage()
    {
        Console.WriteLine("""
            SecureVNC.Admin - server administration

              init [--force] [--no-user]  create data folder, local CA and server certificate
              user add <name>          add a user (password + Google Authenticator)
              user list                list users
              user remove <name>       delete a user
              user reset-mfa <name>    enroll a new Google Authenticator secret
              user passwd <name>       change a user's password
              cert show                show CA fingerprint and server certificate
              cert renew               re-issue the server certificate now
              export-ca <file.cer>     export the CA certificate for clients
              join <server> <ca-fingerprint> <join-key>
                                       use a SecureVNC Auth Server for logins (central mode)
              leave                    back to local users (new local CA)
              status                   local or central mode, auth server reachable?
            """);
        return 2;
    }

    private static void RequireInit()
    {
        if (!ServerPaths.IsInitialized) throw new InvalidOperationException("Not initialized. Run: SecureVNC.Admin init");
    }

    private static int Init(bool force, bool askForUser)
    {
        if (ServerPaths.IsInitialized && !force)
        {
            try { MachineIdentity.Guard(Console.WriteLine); }
            catch (Exception ex) { Console.WriteLine($"Warning: {ex.Message}"); }
            Console.WriteLine($"Already initialized ({ServerPaths.DataDir}). Use --force to create a new CA.");
            Console.WriteLine("Warning: a new CA makes every client ask to trust the server again.");
            return CertShow();
        }

        ServerPaths.EnsureDataDir();
        if (!File.Exists(ServerPaths.ConfigFile)) new ServerConfig().Save();
        if (ServerConfig.Load().IsCentral)
        {
            Console.WriteLine("This computer uses an auth server (central mode). Use 'leave' first to go back to a local CA.");
            return 1;
        }
        using var ca = CertificateManager.InitializePki(force: true);
        Console.WriteLine($"Data folder:   {ServerPaths.DataDir}");
        Console.WriteLine($"CA:            {ca.Subject}");
        Console.WriteLine($"CA SHA-256:    {CertificateManager.Fingerprint(ca)}");
        Console.WriteLine("Clients show this fingerprint on first connect - compare it before trusting.");

        if (askForUser && UserStore.Load().Users.Count == 0)
        {
            Console.Write("\nCreate the first user now? [Y/n] ");
            if (Console.ReadLine()?.Trim().ToLowerInvariant() is "" or "y" or "yes")
            {
                Console.Write("User name: ");
                var name = Console.ReadLine()?.Trim() ?? "";
                return UserAdd(name);
            }
        }
        return 0;
    }

    private static int UserAdd(string name)
    {
        RequireInit();
        if (!UserStore.IsValidName(name)) throw new ArgumentException("User name: " + UserStore.NameRules);
        var store = UserStore.Load();
        if (store.Find(name) is not null) throw new InvalidOperationException($"User '{name}' already exists.");

        var password = ReadNewPassword();
        var (secret, step) = EnrollTotp(name);
        store.Users.Add(UserStore.CreateRecord(name, password, secret, step));
        store.Save();
        Console.WriteLine($"User '{name}' created.");
        return 0;
    }

    private static int UserList()
    {
        RequireInit();
        var users = UserStore.Load().Users;
        if (users.Count == 0) Console.WriteLine("No users.");
        foreach (var u in users) Console.WriteLine($"{u.Name,-32} created {u.CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm}");
        return 0;
    }

    private static int UserRemove(string name)
    {
        RequireInit();
        var store = UserStore.Load();
        var u = store.Find(name) ?? throw new InvalidOperationException($"No user '{name}'.");
        store.Users.Remove(u);
        store.Save();
        Console.WriteLine($"User '{u.Name}' removed.");
        return 0;
    }

    private static int UserResetMfa(string name)
    {
        RequireInit();
        var store = UserStore.Load();
        var u = store.Find(name) ?? throw new InvalidOperationException($"No user '{name}'.");
        var (secret, step) = EnrollTotp(u.Name);
        var fresh = UserStore.CreateRecord(u.Name, "unused", secret, step);
        u.TotpSecret = fresh.TotpSecret;
        u.LastTotpStep = step;
        store.Save();
        Console.WriteLine($"New authenticator secret saved for '{u.Name}'. The old one no longer works.");
        return 0;
    }

    private static int UserPasswd(string name)
    {
        RequireInit();
        var store = UserStore.Load();
        var u = store.Find(name) ?? throw new InvalidOperationException($"No user '{name}'.");
        u.PasswordHash = PasswordHasher.Hash(ReadNewPassword());
        store.Save();
        Console.WriteLine("Password changed.");
        return 0;
    }

    private static int CertShow()
    {
        RequireInit();
        using var ca = CertificateManager.LoadPublicCa();
        Console.WriteLine($"CA:          {ca.Subject}  (valid until {ca.NotAfter:yyyy-MM-dd})");
        Console.WriteLine($"CA SHA-256:  {CertificateManager.Fingerprint(ca)}");
        if (File.Exists(ServerPaths.ServerCertFile))
        {
            using var s = CertificateManager.LoadProtected(ServerPaths.ServerCertFile);
            Console.WriteLine($"Server:      {s.Subject}  (valid until {s.NotAfter:yyyy-MM-dd})");
            Console.WriteLine($"             {s.Extensions["2.5.29.17"]?.Format(false)}");
        }
        return 0;
    }

    private static int CertRenew()
    {
        RequireInit();
        CertificateManager.EnsureServerCredentials(Console.WriteLine, forceReissue: true).ServerCertificate.Dispose();
        return CertShow();
    }

    private static int ExportCa(string path)
    {
        RequireInit();
        File.Copy(ServerPaths.CaCertFile, path, overwrite: true);
        Console.WriteLine($"CA certificate written to {Path.GetFullPath(path)} (public, safe to copy to clients).");
        return 0;
    }

    private static int Join(string server, string fingerprint, string joinKey)
    {
        RequireInit();
        CentralClient.Join(server, fingerprint, joinKey, Console.WriteLine);
        Console.WriteLine("Restart the SecureVNC service to use it now: Restart-Service SecureVNC");
        return 0;
    }

    private static int Leave()
    {
        RequireInit();
        CentralClient.Leave();
        Console.WriteLine("Local mode: only local users can log in. Add one with: SecureVNC.Admin user add <name>");
        Console.WriteLine("Restart the SecureVNC service: Restart-Service SecureVNC");
        return 0;
    }

    private static int Status()
    {
        RequireInit();
        var config = ServerConfig.Load();
        if (!config.IsCentral)
        {
            Console.WriteLine($"Local mode: {UserStore.Load().Users.Count} local user(s).");
            return 0;
        }
        Console.WriteLine($"Central mode: auth server {config.AuthServer}");
        try
        {
            var r = CentralClient.Ping(config);
            Console.WriteLine(r.Ok ? $"Reachable, registered as {r.MachineName}." : $"Auth server says: {r.Error}");
            return r.Ok ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"NOT reachable: {ex.Message}");
            return 1;
        }
    }

    // ---- helpers ----

    private static (byte[] Secret, long Step) EnrollTotp(string name)
    {
        var secret = Totp.NewSecret();
        var uri = Totp.BuildUri("SecureVNC", $"{name}@{Environment.MachineName}", secret);

        using var qr = new QRCodeGenerator().CreateQrCode(uri, QRCodeGenerator.ECCLevel.M);
        Console.WriteLine("\nScan this QR code with Google Authenticator:\n");
        Console.WriteLine(new AsciiQRCode(qr).GetGraphicSmall());

        // Console fonts sometimes break the QR, so also open it as an image; deleted right after enrollment.
        var png = Path.Combine(Path.GetTempPath(), $"securevnc-{Guid.NewGuid():N}.png");
        File.WriteAllBytes(png, new PngByteQRCode(qr).GetGraphic(8));
        try { Process.Start(new ProcessStartInfo(png) { UseShellExecute = true }); } catch { /* no viewer */ }

        var key = Base32.Encode(secret);
        Console.WriteLine($"Or enter the key manually: {string.Join(" ", key.Chunk(4).Select(c => new string(c)))}");
        Console.WriteLine("(type: time based, 6 digits)\n");

        try
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                Console.Write("Enter the 6-digit code shown in the app: ");
                var code = (Console.ReadLine() ?? "").Replace(" ", "");
                long step = Totp.Verify(secret, code, DateTimeOffset.UtcNow);
                if (step >= 0)
                {
                    Console.WriteLine("Code accepted.");
                    return (secret, step);
                }
                Console.WriteLine("Wrong code. Check that the phone's clock is set automatically.");
            }
            throw new InvalidOperationException("Enrollment failed: three wrong codes.");
        }
        finally
        {
            try { File.Delete(png); } catch { Console.WriteLine($"Delete the QR image manually: {png}"); }
        }
    }

    private static string ReadNewPassword()
    {
        while (true)
        {
            var p1 = ReadHidden("Password (min 10 characters): ");
            if (UserStore.CheckPassword(p1) is { } problem) { Console.WriteLine(problem); continue; }
            var p2 = ReadHidden("Repeat password: ");
            if (p1 == p2) return p1;
            Console.WriteLine("Passwords do not match.");
        }
    }

    private static string ReadHidden(string prompt)
    {
        Console.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
            if (!char.IsControl(k.KeyChar)) sb.Append(k.KeyChar);
        }
        Console.WriteLine();
        return sb.ToString();
    }
}
