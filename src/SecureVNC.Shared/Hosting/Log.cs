namespace SecureVNC.Shared.Hosting;

/// <summary>Daily log files in %ProgramData%\SecureVNC\logs, one per component (service / agent / server).</summary>
public static partial class Log
{
    private static readonly object Gate = new();

    public static string Source { get; set; } = "server";

    public static void Info(string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{Environment.ProcessId}] {OneLine(message)}";
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

public static partial class Log
{
    /// <summary>
    /// One log line, no control characters: user names and computer names come from the network and must not be
    /// able to start a new, forged line in a log or the audit.
    /// </summary>
    public static string OneLine(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var chars = text.Select(c => char.IsControl(c) || c == '\u2028' || c == '\u2029' ? ' ' : c).ToArray();
        var s = new string(chars);
        return s.Length <= 4000 ? s : s[..4000] + "...";
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
