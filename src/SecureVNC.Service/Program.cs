using System.ServiceProcess;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Service;

internal static class Program
{
    private static void Main()
    {
        Log.Source = "service";
        ServiceBase.Run(new SecureVncService());
    }
}

/// <summary>
/// Windows service (LocalSystem, automatic start). It does not touch the network itself: it keeps the agent
/// running in the console session and performs Ctrl+Alt+Del on request.
/// </summary>
internal sealed class SecureVncService : ServiceBase
{
    private AgentSupervisor? _supervisor;
    private SasPipeServer? _sas;

    public SecureVncService()
    {
        ServiceName = ServiceIpc.ServiceName;
        CanStop = true;
        CanShutdown = true;
        CanHandleSessionChangeEvent = true;
    }

    protected override void OnStart(string[] args)
    {
        Log.Info("Service starting");
        _sas = new SasPipeServer();
        _sas.Start();
        _supervisor = new AgentSupervisor();
        _supervisor.Start();
    }

    protected override void OnSessionChange(SessionChangeDescription change)
    {
        Log.Info($"Session change: {change.Reason} (session {change.SessionId})");
        _supervisor?.Poke();
    }

    protected override void OnStop() => Shutdown();

    protected override void OnShutdown() => Shutdown();

    private void Shutdown()
    {
        _supervisor?.Dispose();
        _supervisor = null;
        _sas?.Dispose();
        _sas = null;
        Log.Info("Service stopped");
    }
}
