using System.IO.Pipes;

namespace SecureVNC.Shared.Central;

public sealed class AuthPipeRequest
{
    /// <summary>status, unlock, lock, verify (an administrator's login for the Auth Console), joinkey.</summary>
    public string Op { get; set; } = "";
    public string? Password { get; set; }
    public string? User { get; set; }
    public string? Code { get; set; }
}

public sealed class AuthPipeResponse
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    /// <summary>status: "not-set-up", "locked" or "unlocked".</summary>
    public string? State { get; set; }
    public string? JoinKey { get; set; }
}

/// <summary>
/// Auth Console -> auth service on the same machine (named pipe, Administrators and SYSTEM only). The master password
/// travels only over this local pipe, never over the network.
/// </summary>
public static class AuthPipe
{
    public const string Name = "SecureVNC.Auth";

    public static AuthPipeResponse Send(AuthPipeRequest request, int timeoutMs = 3000)
    {
        using var pipe = new NamedPipeClientStream(".", Name, PipeDirection.InOut);
        pipe.Connect(timeoutMs);
        CentralProtocol.Write(pipe, request);
        return CentralProtocol.Read<AuthPipeResponse>(pipe);
    }

    /// <summary>Null when the service is not running (or not reachable).</summary>
    public static string? State()
    {
        try { return Send(new AuthPipeRequest { Op = "status" }).State; }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException) { return null; }
    }
}
