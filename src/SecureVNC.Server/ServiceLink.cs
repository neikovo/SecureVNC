using System.IO.Pipes;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Server;

/// <summary>Asks the SecureVNC service for things only a real service may do (Ctrl+Alt+Del).</summary>
internal static class ServiceLink
{
    public static bool RequestCtrlAltDel()
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", ServiceIpc.PipeName, PipeDirection.InOut);
            pipe.Connect(2000);
            pipe.Write("SAS"u8);
            pipe.Flush();
            var reply = new byte[2];
            pipe.ReadExactly(reply);
            return reply[0] == (byte)'O' && reply[1] == (byte)'K';
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException)
        {
            Log.Info($"Ctrl+Alt+Del: service not reachable ({ex.Message}); it works only in service mode");
            return false;
        }
    }
}
