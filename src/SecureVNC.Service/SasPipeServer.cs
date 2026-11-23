using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Service;

/// <summary>
/// Named pipe that lets the agent ask for Ctrl+Alt+Del. Only SYSTEM may connect (the agent runs as SYSTEM).
/// Windows allows SendSAS only from a service, which is why the agent cannot do it itself.
/// </summary>
internal sealed class SasPipeServer : IDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private DateTime _lastSasUtc;

    public void Start() => _ = Task.Run(LoopAsync);

    private async Task LoopAsync()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = NamedPipeServerStreamAcl.Create(ServiceIpc.PipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
                await pipe.WaitForConnectionAsync(_cts.Token);

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                var request = new byte[3];
                await pipe.ReadExactlyAsync(request, timeout.Token);

                bool ok = false;
                if (request is [(byte)'S', (byte)'A', (byte)'S'] && DateTime.UtcNow - _lastSasUtc > TimeSpan.FromSeconds(2))
                {
                    _lastSasUtc = DateTime.UtcNow;
                    Native.SendSAS(false);
                    ok = true;
                    Log.Info("Ctrl+Alt+Del sent");
                }
                await pipe.WriteAsync(ok ? "OK"u8.ToArray() : "NO"u8.ToArray(), timeout.Token);
            }
            catch (OperationCanceledException) when (_cts.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.Info($"SAS pipe: {ex.Message}");
                await Task.Delay(500);
            }
        }
    }

    public void Dispose() => _cts.Cancel();
}
