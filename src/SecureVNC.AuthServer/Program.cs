using System.ServiceProcess;
using SecureVNC.AuthServer;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;

// SecureVNC Auth Server: Windows service "SecureVNCAuth".
//   --init      create the (locked) data folder and settings; the master password is set in the Auth Console
//   --console   run in this window (testing)
var paths = new AuthPaths(AuthPaths.DefaultDir);
ServerPaths.UseDataDir(paths.DataDir);   // logs go to %ProgramData%\SecureVNC-Auth\logs
Log.Source = "auth";

if (args.Contains("--init"))
{
    if (!ServerPaths.IsAdministrator())
    {
        Console.Error.WriteLine("Run as administrator.");
        return 1;
    }
    AuthData.Prepare(paths);
    Console.WriteLine(paths.IsInitialized
        ? $"Ready. CA fingerprint: {AuthData.CaFingerprint(paths)}"
        : "Ready. Open the SecureVNC Auth Console to set the master password.");
    return 0;
}

if (args.Contains("--console"))
{
    var service = new CentralAuthService(paths);
    service.Start();
    Console.Write("Master password: ");
    service.Unlock(Console.ReadLine() ?? "");
    Console.WriteLine($"SecureVNC Auth Server on port {service.Port}. Press Enter to stop.");
    Console.ReadLine();
    service.Stop();
    return 0;
}

ServiceBase.Run(new AuthWindowsService(paths));
return 0;

internal sealed class AuthWindowsService : ServiceBase
{
    private readonly CentralAuthService _service;

    public AuthWindowsService(AuthPaths paths)
    {
        ServiceName = "SecureVNCAuth";
        _service = new CentralAuthService(paths);
    }

    protected override void OnStart(string[] args)
    {
        try
        {
            _service.Start();
        }
        catch (Exception ex)
        {
            Log.Info($"Auth server could not start: {ex}");
            throw;
        }
    }

    protected override void OnStop() => _service.Stop();
}
