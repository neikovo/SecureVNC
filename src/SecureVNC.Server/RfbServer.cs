using System.Net;
using System.Net.Sockets;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

namespace SecureVNC.Server;

/// <summary>Accepts TCP connections from allowed (local) networks and runs a session for each.</summary>
internal sealed class RfbServer(ServerConfig config)
{
    private readonly IReadOnlyList<IPNetwork> _allowed = config.ParseAllowedNetworks();
    private readonly AuthThrottle _throttle = new(config.MaxFailedAttempts, TimeSpan.FromMinutes(config.LockoutMinutes));
    private readonly List<ClientSession> _sessions = [];
    private readonly CancellationTokenSource _cts = new();
    private readonly object _credsLock = new();
    private TcpListener? _listener;
    private ServerCredentials? _creds;
    private DateTime _credsCheckedUtc;

    public event Action<ClientSession>? SessionStarted;
    public event Action<ClientSession>? SessionEnded;

    public int Port => config.Port;

    public IReadOnlyList<ClientSession> Sessions
    {
        get { lock (_sessions) return _sessions.ToList(); }
    }

    public void Start()
    {
        GetCredentials();
        var address = IPAddress.Parse(config.ListenAddress);
        _listener = new TcpListener(address, config.Port);
        if (address.Equals(IPAddress.IPv6Any)) _listener.Server.DualMode = true;
        _listener.Start();
        Log.Info($"Listening on port {config.Port}; allowed networks: {string.Join(", ", config.AllowedNetworks)}");
        _ = AcceptLoop();
    }

    public void Stop()
    {
        _cts.Cancel();
        _listener?.Stop();
        DisconnectAll();
        Log.Info("Server stopped");
    }

    public void DisconnectAll()
    {
        foreach (var s in Sessions) s.Close();
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient tcp;
            try
            {
                tcp = await _listener!.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception) when (_cts.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException ex)
            {
                Log.Info($"Accept failed: {ex.Message}");
                continue;
            }

            var ep = (IPEndPoint)tcp.Client.RemoteEndPoint!;
            var ip = ep.Address.IsIPv4MappedToIPv6 ? ep.Address.MapToIPv4() : ep.Address;
            if (!_allowed.Any(n => n.Contains(ip)))
            {
                Log.Info($"{ip}: rejected, not in allowed networks");
                tcp.Dispose();
                continue;
            }

            ServerCredentials creds;
            try
            {
                creds = GetCredentials();
            }
            catch (Exception ex)
            {
                Log.Info($"Cannot load certificates: {ex.Message}");
                tcp.Dispose();
                continue;
            }

            var session = new ClientSession(tcp, ip, config, creds, _throttle);
            session.Authenticated += s =>
            {
                lock (_sessions) _sessions.Add(s);
                SessionStarted?.Invoke(s);
            };
            // A dedicated thread (not the thread pool): it switches desktops with SetThreadDesktop.
            new Thread(() =>
            {
                session.Run();
                bool wasActive;
                lock (_sessions) wasActive = _sessions.Remove(session);
                if (wasActive) SessionEnded?.Invoke(session);
            }) { IsBackground = true, Name = $"session {ip}" }.Start();
        }
    }

    /// <summary>Re-checks at most once a minute that the certificate still matches the machine's addresses.</summary>
    private ServerCredentials GetCredentials()
    {
        lock (_credsLock)
        {
            if (_creds is null || DateTime.UtcNow - _credsCheckedUtc > TimeSpan.FromMinutes(1))
            {
                _creds = CertificateManager.EnsureServerCredentials(Log.Info);
                _credsCheckedUtc = DateTime.UtcNow;
            }
            return _creds;
        }
    }
}
