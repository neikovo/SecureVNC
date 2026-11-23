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
    private readonly ConnectionLimiter _limiter = new(maxTotal: 32, maxPerAddress: 4);
    private System.Threading.Timer? _renewTimer;
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

        // Keep the certificate fresh even when nobody connects (central mode: 7-day certificates).
        _renewTimer = new System.Threading.Timer(_ =>
        {
            try { GetCredentials(); }
            catch (Exception ex) { Log.Info($"Certificate check failed: {ex.Message}"); }
        }, null, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30));
    }

    public void Stop()
    {
        _cts.Cancel();
        _renewTimer?.Dispose();
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

            if (!_limiter.TryEnter(ip, Log.Info))
            {
                tcp.Dispose();
                continue;
            }
            int counted = 1;
            void Release()
            {
                if (Interlocked.Exchange(ref counted, 0) == 1) _limiter.Leave(ip);
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
                Release();
                continue;
            }

            var session = new ClientSession(tcp, ip, config, creds, _throttle);
            session.Authenticated += s =>
            {
                Release();   // logged in: no longer counts against the limit for half-open connections
                lock (_sessions) _sessions.Add(s);
                SessionStarted?.Invoke(s);
            };
            // A dedicated thread (not the thread pool): it switches desktops with SetThreadDesktop.
            new Thread(() =>
            {
                try { session.Run(); }
                finally { Release(); }
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
