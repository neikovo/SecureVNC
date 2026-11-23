namespace SecureVNC.Shared.Hosting;

/// <summary>Daily log files in %ProgramData%\SecureVNC\logs, one per component (service / agent / server).</summary>
public static class Log
{
    private static readonly object Gate = new();

    public static string Source { get; set; } = "server";

    public static void Info(string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{Environment.ProcessId}] {message}";
        lock (Gate)
        {
            try
            {
                Directory.CreateDirectory(ServerPaths.LogDir);
                File.AppendAllText(Path.Combine(ServerPaths.LogDir, $"{Source}-{DateTime.Now:yyyyMMdd}.log"), line + Environment.NewLine);
            }
            catch
            {
                // Logging must never take the process down.
            }
        }
    }
}

/// <summary>Names shared by the service and the agent.</summary>
public static class ServiceIpc
{
    public const string ServiceName = "SecureVNC";
    public const string PipeName = "SecureVNC.Service";
    public const string AgentArg = "--agent";
    public const string StopEventArg = "--stop-event";
}
