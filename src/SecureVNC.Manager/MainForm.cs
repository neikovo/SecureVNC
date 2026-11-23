using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.ServiceProcess;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

internal sealed class MainForm : Form
{
    private readonly bool _firstRun;
    private readonly Label _service = new() { AutoSize = true };
    private readonly Label _connect = new() { AutoSize = true, MaximumSize = new Size(620, 0) };
    private readonly TextBox _fingerprint = new() { ReadOnly = true, Multiline = true, WordWrap = true, Width = 620, Height = 56, Font = new Font("Consolas", 9.5f), TabStop = false };
    private readonly List<GroupBox> _groups = [];
    private readonly ListView _users = new() { View = View.Details, FullRowSelect = true, MultiSelect = false, Width = 620, Height = 200, HideSelection = false };
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 3000 };

    /// <summary>Closes itself after this much inactivity; reopening asks for the login again.</summary>
    private static readonly TimeSpan IdleClose = TimeSpan.FromMinutes(10);
    private DateTime _lastActivity = DateTime.UtcNow;

    public MainForm(bool firstRun, string? user)
    {
        _firstRun = firstRun;
        Text = user is null ? "SecureVNC Manager" : $"SecureVNC Manager - {user}";
        Application.AddMessageFilter(new ActivityFilter(() => _lastActivity = DateTime.UtcNow));
        Icon = SystemIcons.Shield;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        var root = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Padding = new Padding(12), WrapContents = false };

        // ---- server ----
        var server = Group("This server");
        server.Controls.Add(_service);
        server.Controls.Add(_connect);
        server.Controls.Add(new Label { Text = "Certificate fingerprint (clients show it on the first connection - it must match):", AutoSize = true, Margin = new Padding(3, 10, 3, 2) });
        server.Controls.Add(_fingerprint);
        server.Controls.Add(Buttons(
            ("Copy fingerprint", () => Clipboard.SetText(_fingerprint.Text)),
            ("Export CA for clients...", ExportCa),
            ("Restart service", RestartService),
            ("Open logs", () => Process.Start(new ProcessStartInfo(ServerPaths.LogDir) { UseShellExecute = true }))));
        root.Controls.Add(server.Parent!);

        // ---- users ----
        var users = Group("Users (password + Google Authenticator)");
        _users.Columns.Add("Name", 300);
        _users.Columns.Add("Created", 200);
        _users.DoubleClick += (_, _) => Selected(name => Dialog(UserDialogMode.Password, name));
        users.Controls.Add(_users);
        users.Controls.Add(Buttons(
            ("Add user...", () => Dialog(UserDialogMode.Add, null)),
            ("Change password...", () => Selected(name => Dialog(UserDialogMode.Password, name))),
            ("New authenticator...", () => Selected(name => Dialog(UserDialogMode.NewAuthenticator, name))),
            ("Remove", () => Selected(RemoveUser))));
        root.Controls.Add(users.Parent!);

        Controls.Add(root);
        _timer.Tick += (_, _) =>
        {
            RefreshService();
            if (DateTime.UtcNow - _lastActivity > IdleClose)
            {
                Log.Info("Manager closed after inactivity");
                _timer.Stop();
                Application.Exit();   // also closes open dialogs
            }
        };
        _timer.Start();
        RefreshAll();
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        int width = _groups.Max(g => g.Width);
        foreach (var g in _groups) g.MinimumSize = new Size(width, 0);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        ActiveControl = _users;
        _fingerprint.SelectionLength = 0;
        if (_firstRun && UserStore.Load().Users.Count == 0)
        {
            Dialog(UserDialogMode.Add, null,
                "SecureVNC is installed. Create the first user now: this is the name, password and phone (Google Authenticator) " +
                "you will use to connect to this computer.");
        }
    }

    private FlowLayoutPanel Group(string title)
    {
        var box = new GroupBox { Text = title, AutoSize = true, Padding = new Padding(10, 6, 10, 10), Margin = new Padding(0, 0, 0, 10) };
        var inner = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Dock = DockStyle.Fill };
        box.Controls.Add(inner);
        _groups.Add(box);
        return inner;
    }

    private static FlowLayoutPanel Buttons(params (string Text, Action Click)[] buttons)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 8, 0, 0) };
        foreach (var (text, click) in buttons)
        {
            var b = new Button { Text = text, AutoSize = true, Padding = new Padding(4, 1, 4, 1) };
            b.Click += (_, _) =>
            {
                try { click(); }
                catch (Exception ex) { MessageBox.Show(ex.Message, "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            };
            row.Controls.Add(b);
        }
        return row;
    }

    private void RefreshAll()
    {
        using (var ca = CertificateManager.LoadPublicCa()) _fingerprint.Text = CertificateManager.Fingerprint(ca);

        var config = ServerConfig.Load();
        var addresses = NetworkInfo.LanAddresses();
        _connect.Text = $"Clients connect to: {Environment.MachineName} or {string.Join(", ", addresses)}   port {config.Port}";

        _users.Items.Clear();
        foreach (var u in UserStore.Load().Users.OrderBy(u => u.Name, StringComparer.OrdinalIgnoreCase))
            _users.Items.Add(new ListViewItem([u.Name, u.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm")]));
        RefreshService();
    }

    private void RefreshService()
    {
        try
        {
            using var sc = new ServiceController(ServiceIpc.ServiceName);
            var status = sc.Status;
            _service.Text = $"Service: {status}";
            _service.ForeColor = status == ServiceControllerStatus.Running ? Color.DarkGreen : Color.Firebrick;
        }
        catch (InvalidOperationException)
        {
            _service.Text = "Service: not installed";
            _service.ForeColor = Color.Firebrick;
        }
    }

    private void Selected(Action<string> action)
    {
        if (_users.SelectedItems.Count == 0)
        {
            MessageBox.Show("Select a user first.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        action(_users.SelectedItems[0].Text);
    }

    private void Dialog(UserDialogMode mode, string? name, string? intro = null)
    {
        using var dlg = new UserDialog(mode, name, intro);
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        RefreshAll();
        var done = mode switch
        {
            UserDialogMode.Add => $"User '{dlg.CreatedName}' created. Connect with SecureVNC Client using this name, the password and the code from the phone.",
            UserDialogMode.NewAuthenticator => $"New authenticator saved for '{name}'. The old one no longer works.",
            _ => $"Password changed for '{name}'.",
        };
        MessageBox.Show(this, done, "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RemoveUser(string name)
    {
        if (MessageBox.Show(this, $"Remove user '{name}'? Active connections of this user stay open until they disconnect.",
                "SecureVNC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        var store = UserStore.Load();
        if (store.Find(name) is { } u)
        {
            store.Users.Remove(u);
            store.Save();
            Log.Info($"Manager: removed user '{name}'");
        }
        RefreshAll();
    }

    private void ExportCa()
    {
        using var dlg = new SaveFileDialog
        {
            FileName = $"SecureVNC-CA-{Environment.MachineName}.cer",
            Filter = "Certificate (*.cer)|*.cer",
            Title = "Export CA certificate (public, safe to copy to clients)",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.Copy(ServerPaths.CaCertFile, dlg.FileName, overwrite: true);
        MessageBox.Show(this, "Copy this file to the client computers (USB stick is safest) and use \"Import CA...\" in SecureVNC Client.",
            "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RestartService()
    {
        UseWaitCursor = true;
        try
        {
            using var sc = new ServiceController(ServiceIpc.ServiceName);
            if (sc.Status != ServiceControllerStatus.Stopped)
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
            }
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
        }
        finally
        {
            UseWaitCursor = false;
            RefreshService();
        }
    }

    /// <summary>Any key or mouse use in the Manager counts as activity.</summary>
    private sealed class ActivityFilter(Action touch) : IMessageFilter
    {
        public bool PreFilterMessage(ref Message m)
        {
            if (m.Msg is 0x0100 or 0x0104 or 0x0200 or 0x0201 or 0x0204 or 0x020A) touch();   // key, mouse move/click/wheel
            return false;
        }
    }
}
