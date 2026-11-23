using System.Diagnostics;
using System.Net.NetworkInformation;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Server;

internal static class Program
{
    /// <summary>
    /// Two modes:
    ///   (no args)  standalone: started by the user, runs in the user's desktop only.
    ///   --agent    started by SecureVNC.Service as SYSTEM in the console session: also sees and controls
    ///              the login screen, lock screen and UAC prompts.
    /// </summary>
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();   // per-monitor DPI aware: capture real pixels

        bool agent = args.Contains(ServiceIpc.AgentArg);
        int stopIndex = Array.IndexOf(args, ServiceIpc.StopEventArg);
        string? stopEventName = stopIndex >= 0 && stopIndex + 1 < args.Length ? args[stopIndex + 1] : null;
        Log.Source = agent ? "agent" : "server";

        // In agent mode nothing may pop up: the process runs as SYSTEM on the user's (or login) desktop.
        void Fail(string message)
        {
            Log.Info(message);
            if (!agent) MessageBox.Show(message, "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        using var mutex = new Mutex(true, @"Global\SecureVNC.Server", out bool first);
        if (!first)
        {
            Log.Info("Another SecureVNC server is already running; exiting");
            return;
        }
        if (!ServerPaths.IsAdministrator())
        {
            Fail("SecureVNC Server must run as administrator.");
            return;
        }
        if (!ServerPaths.IsInitialized)
        {
            Fail("SecureVNC is not set up yet.\n\nRun as administrator:\n  SecureVNC.Admin init");
            return;
        }

        try
        {
            MachineIdentity.Guard(Log.Info);   // cloned or renamed computer: make its own keys first
        }
        catch (Exception ex)
        {
            Fail($"SecureVNC could not create keys for this computer:\n{ex.Message}");
            return;
        }

        EventWaitHandle? stopEvent = null;
        if (stopEventName is not null)
        {
            try
            {
                stopEvent = EventWaitHandle.OpenExisting(stopEventName);
            }
            catch (Exception ex)
            {
                Log.Info($"Cannot open stop event: {ex.Message}");
                return;
            }
        }

        var server = new RfbServer(ServerConfig.Load());
        try
        {
            server.Start();
        }
        catch (Exception ex)
        {
            Fail($"SecureVNC Server could not start:\n{ex.Message}");
            return;
        }
        Log.Info(agent ? $"Agent started in session {Process.GetCurrentProcess().SessionId}" : "Server started");

        Application.Run(new TrayContext(server, agent, stopEvent));
        server.Stop();
        stopEvent?.Dispose();
    }
}

/// <summary>Tray icon: shows who is connected, so the person at the PC always knows.</summary>
internal sealed class TrayContext : ApplicationContext
{
    private static readonly Color Idle = Color.FromArgb(0x1E, 0x9E, 0x4A);        // green: running, nobody connected
    private static readonly Color Connected = Color.FromArgb(0xD3, 0x2F, 0x2F);   // red: someone is connected

    private readonly RfbServer _server;
    private readonly NotifyIcon _icon;
    private readonly Icon _idleIcon = TrayIcons.Create(Idle);
    private readonly Icon _connectedIcon = TrayIcons.Create(Connected);
    private readonly ToolStripMenuItem _addressItem;
    private readonly ToolStripMenuItem _sessionsItem;
    private readonly Control _ui = new();
    private readonly RegisteredWaitHandle? _stopWait;
    private IReadOnlyList<string> _addresses = [];

    public TrayContext(RfbServer server, bool agent, EventWaitHandle? stopEvent)
    {
        _server = server;
        _ui.CreateControl();

        _addressItem = new ToolStripMenuItem("") { Enabled = false };
        _sessionsItem = new ToolStripMenuItem("No active sessions") { Enabled = false };
        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripMenuItem($"SecureVNC - port {server.Port}{(agent ? " (service)" : "")}") { Enabled = false });
        menu.Items.Add(_addressItem);
        menu.Items.Add(_sessionsItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Disconnect all", null, (_, _) => _server.DisconnectAll());
        if (!agent)
        {
            // Never in agent mode: anything started from here would run as SYSTEM on the user's desktop.
            menu.Items.Add("Open log folder", null, (_, _) =>
                Process.Start(new ProcessStartInfo(ServerPaths.LogDir) { UseShellExecute = true }));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Stop server", null, (_, _) => ExitThread());
        }

        _icon = new NotifyIcon
        {
            Icon = _idleIcon,
            Text = "SecureVNC Server",
            ContextMenuStrip = menu,
            Visible = true,
        };

        server.SessionStarted += s => OnUi(() =>
        {
            _icon.ShowBalloonTip(5000, "SecureVNC", $"{s.UserName} connected from {NetworkInfo.Display(s.Remote)}", ToolTipIcon.Warning);
            Refresh();
        });
        server.SessionEnded += s => OnUi(() =>
        {
            _icon.ShowBalloonTip(3000, "SecureVNC", $"{s.UserName} disconnected", ToolTipIcon.Info);
            Refresh();
        });
        NetworkChange.NetworkAddressChanged += OnAddressChanged;

        if (stopEvent is not null)
        {
            _stopWait = ThreadPool.RegisterWaitForSingleObject(stopEvent, (_, _) =>
            {
                Log.Info("Stop requested by the service");
                OnUi(ExitThread);
            }, null, Timeout.Infinite, executeOnlyOnce: true);
        }

        UpdateAddresses();
        Refresh();
    }

    private void OnAddressChanged(object? sender, EventArgs e) => OnUi(() =>
    {
        UpdateAddresses();
        Refresh();
    });

    private void UpdateAddresses()
    {
        try { _addresses = NetworkInfo.LanAddresses(); }
        catch (Exception ex) { Log.Info($"Cannot list addresses: {ex.Message}"); }
        _addressItem.Text = $"{Environment.MachineName}  {string.Join(", ", _addresses)}";
    }

    private void OnUi(Action a)
    {
        if (!_ui.IsDisposed) _ui.BeginInvoke(a);
    }

    private void Refresh()
    {
        var sessions = _server.Sessions;
        _sessionsItem.Text = sessions.Count == 0
            ? "No active sessions"
            : string.Join("\n", sessions.Select(s => $"{s.UserName} from {NetworkInfo.Display(s.Remote)} since {s.StartedAt:HH:mm}"));
        _icon.Icon = sessions.Count == 0 ? _idleIcon : _connectedIcon;

        // Hover text (Windows allows at most 127 characters).
        var status = sessions.Count switch
        {
            0 => "SecureVNC - ready, no connection",
            1 => $"SecureVNC - CONNECTED: {sessions[0].UserName} ({NetworkInfo.Display(sessions[0].Remote)})",
            _ => $"SecureVNC - CONNECTED: {sessions.Count} sessions",
        };
        var text = $"{status}\nIP: {(_addresses.Count == 0 ? "no network" : string.Join(", ", _addresses))}\nPort {_server.Port}";
        _icon.Text = text.Length <= 127 ? text : text[..124] + "...";
    }

    protected override void ExitThreadCore()
    {
        NetworkChange.NetworkAddressChanged -= OnAddressChanged;
        _stopWait?.Unregister(null);
        _icon.Visible = false;
        _icon.Dispose();
        _idleIcon.Dispose();
        _connectedIcon.Dispose();
        _ui.Dispose();
        base.ExitThreadCore();
    }
}
