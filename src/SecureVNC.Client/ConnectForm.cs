using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureVNC.Shared.Help;
using SecureVNC.Shared.Protocol;

namespace SecureVNC.Client;

internal sealed class ConnectForm : Form
{
    private static readonly string SettingsFile = Path.Combine(ClientPaths.DataDir, "client.json");

    private readonly TextBox _host = new() { Width = 240 };
    private readonly NumericUpDown _port = new() { Minimum = 1, Maximum = 65535, Value = Rfb.DefaultPort, Width = 90 };
    private readonly TextBox _user = new() { Width = 240 };
    private readonly TextBox _password = new() { Width = 240, UseSystemPasswordChar = true };
    private readonly TextBox _code = new() { Width = 120, MaxLength = 6, Font = new Font(FontFamily.GenericMonospace, 14f) };
    private readonly Button _connect = new() { Text = "Connect", AutoSize = true };
    private readonly Button _import = new() { Text = "Import CA...", AutoSize = true };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Color.DimGray };
    private readonly CheckBox _emergency = new() { Text = "Emergency login (local account on that computer, not the auth server)", AutoSize = true };

    private sealed record Settings(string Host, int Port, string User, bool StayInTray = true);

    // ----- help requests from colleagues (signed UDP broadcast, see HelpRequests) -----
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private readonly ListView _requests = new() { View = View.Details, FullRowSelect = true, MultiSelect = false, Width = 520, Height = 110, HideSelection = false };
    private readonly CheckBox _stayInTray = new() { Text = "Keep running in the tray to receive help requests", AutoSize = true, Checked = true };
    private readonly CheckBox _startWithWindows = new() { Text = "Start with Windows", AutoSize = true };
    private readonly NotifyIcon _tray = new() { Icon = SystemIcons.Shield, Text = "SecureVNC Client", Visible = true };
    private readonly Label _helpStatus = new() { AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(520, 0) };
    private HelpListener? _listener;
    private VerifiedHelpRequest? _balloonRequest;
    private bool _exiting;

    public ConnectForm() : this(false, true) { }

    public ConnectForm(bool startHidden, bool listenForHelp)
    {
        Text = ClientPaths.IsPortable ? "SecureVNC (portable)" : "SecureVNC";
        Icon = SystemIcons.Shield;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(12);

        var grid = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill };
        void Row(string label, Control c)
        {
            grid.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 8, 12, 3) });
            grid.Controls.Add(c);
        }
        Row("Computer (name or IP):", _host);
        Row("Port:", _port);
        Row("User:", _user);
        Row("Password:", _password);
        Row("Google Authenticator code:", _code);
        grid.Controls.Add(_emergency);
        grid.SetColumnSpan(_emergency, 2);

        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
        buttons.Controls.Add(_connect);
        buttons.Controls.Add(_import);
        grid.Controls.Add(buttons);
        grid.SetColumnSpan(buttons, 2);
        grid.Controls.Add(_status);
        grid.SetColumnSpan(_status, 2);

        var helpBox = new GroupBox { Text = "Help requests from colleagues", AutoSize = true, Padding = new Padding(8, 4, 8, 8), Margin = new Padding(3, 10, 3, 3) };
        var helpFlow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Dock = DockStyle.Fill };
        _requests.Columns.Add("Time", 60);
        _requests.Columns.Add("Computer", 120);
        _requests.Columns.Add("User", 110);
        _requests.Columns.Add("Problem", 210);
        _requests.DoubleClick += (_, _) => UseSelectedRequest();
        var useRequest = new Button { Text = "Connect to selected", AutoSize = true };
        useRequest.Click += (_, _) => UseSelectedRequest();
        helpFlow.Controls.Add(_requests);
        helpFlow.Controls.Add(useRequest);
        helpFlow.Controls.Add(_stayInTray);
        helpFlow.Controls.Add(_startWithWindows);
        helpFlow.Controls.Add(_helpStatus);
        helpBox.Controls.Add(helpFlow);
        grid.Controls.Add(helpBox);
        grid.SetColumnSpan(helpBox, 2);
        Controls.Add(grid);

        AcceptButton = _connect;
        _connect.Click += async (_, _) => await ConnectAsync();
        _import.Click += (_, _) => ImportCa();
        _code.KeyPress += (_, e) => e.Handled = !char.IsDigit(e.KeyChar) && !char.IsControl(e.KeyChar);

        LoadSettings();
        Shown += (_, _) => (_host.Text.Length == 0 ? _host : _password).Focus();

        _startWithWindows.Checked = IsStartWithWindows();
        _startWithWindows.CheckedChanged += (_, _) => SetStartWithWindows(_startWithWindows.Checked);
        _stayInTray.CheckedChanged += (_, _) => SaveTrayChoice();
        var trayMenu = new ContextMenuStrip();
        trayMenu.Items.Add("Open SecureVNC", null, (_, _) => ShowFromTray());
        trayMenu.Items.Add(new ToolStripSeparator());
        trayMenu.Items.Add("Exit", null, (_, _) => ExitApp());
        _tray.ContextMenuStrip = trayMenu;
        _tray.DoubleClick += (_, _) => ShowFromTray();
        _tray.BalloonTipClicked += (_, _) =>
        {
            ShowFromTray();
            if (_balloonRequest is { } r) FillFromRequest(r);
        };

        if (listenForHelp) StartHelpListener();
        else _helpStatus.Text = "Another SecureVNC Client window already receives help requests.";
        if (startHidden) CreateHandle();
    }

    private void StartHelpListener()
    {
        try
        {
            _listener = new HelpListener(() => TrustStore.Load().AllTrusted());
            _listener.Received += r => BeginInvoke(() => OnHelpRequest(r));
            _helpStatus.Text = "Listening for help requests on the local network (UDP 5904). Only computers with a certificate you trust are shown.";
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            _helpStatus.Text = $"Cannot receive help requests: {ex.Message}";
        }
    }

    private void OnHelpRequest(VerifiedHelpRequest r)
    {
        var item = new ListViewItem([r.ReceivedLocal.ToString("HH:mm"), r.Request.Computer, r.Request.User, r.Request.Text]) { Tag = r };
        _requests.Items.Insert(0, item);
        while (_requests.Items.Count > 50) _requests.Items.RemoveAt(_requests.Items.Count - 1);
        _balloonRequest = r;
        var problem = r.Request.Text.Length > 0 ? $": {r.Request.Text}" : "";
        _tray.ShowBalloonTip(15000, "SecureVNC - help requested",
            $"{r.Request.Computer} ({r.Request.User}) asks for help{problem}\nClick to connect.", ToolTipIcon.Info);
    }

    private void UseSelectedRequest()
    {
        if (_requests.SelectedItems.Count == 0) return;
        FillFromRequest((VerifiedHelpRequest)_requests.SelectedItems[0].Tag!);
    }

    /// <summary>Fills in the computer from the request's certificate; logging in stays password + code.</summary>
    private void FillFromRequest(VerifiedHelpRequest r)
    {
        _host.Text = r.ConnectTo;
        _port.Value = Rfb.DefaultPort;
        _status.Text = $"Help request from {r.Request.Computer} ({r.Request.User}). Enter your password and code, then Connect.";
        (_user.Text.Length == 0 ? _user : _password).Focus();
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }

    private void ExitApp()
    {
        _exiting = true;
        _listener?.Dispose();
        _tray.Visible = false;
        _tray.Dispose();
        Application.Exit();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_exiting && _stayInTray.Checked && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        _listener?.Dispose();
        _tray.Visible = false;
        base.OnFormClosing(e);
    }

    private static bool IsStartWithWindows()
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue("SecureVNC Client") is string;
    }

    private static void SetStartWithWindows(bool on)
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunKey);
        if (on) key.SetValue("SecureVNC Client", $"\"{Environment.ProcessPath}\" --tray");
        else key.DeleteValue("SecureVNC Client", throwOnMissingValue: false);
    }

    private async Task ConnectAsync()
    {
        var options = new ConnectOptions(_host.Text.Trim(), (int)_port.Value, _user.Text.Trim(), _password.Text, _code.Text.Trim(), _emergency.Checked);
        if (options.Host.Length == 0 || options.User.Length == 0)
        {
            _status.Text = "Enter the computer and the user name.";
            return;
        }
        if (options.Code.Length != 6)
        {
            _status.Text = "Enter the 6-digit code from Google Authenticator.";
            _code.Focus();
            return;
        }

        SetBusy(true, $"Connecting to {options.Host}...");
        try
        {
            var trust = TrustStore.Load();
            var client = await Task.Run(() => RfbClient.Connect(options, trust, AskTrust));
            SaveSettings(options, _stayInTray.Checked);
            _password.Clear();
            _code.Clear();
            _status.Text = "";
            var viewer = new ViewerForm(client, options.User, options.Host);
            viewer.FormClosed += (_, _) =>
            {
                Show();
                _code.Focus();
            };
            Hide();
            viewer.Show();
        }
        catch (OperationCanceledException ex)
        {
            _status.Text = ex.Message;
        }
        catch (Exception ex)
        {
            var inner = ex is AggregateException { InnerException: { } i } ? i : ex;
            _code.Clear();
            _status.Text = "";
            MessageBox.Show(this, inner is AuthenticationException
                    ? $"Login failed:\n{inner.Message}"
                    : $"Cannot connect:\n{inner.Message}",
                "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            _code.Focus();
        }
        finally
        {
            SetBusy(false, null);
        }
    }

    /// <summary>Runs on the connect thread; asks the user on the UI thread.</summary>
    private bool AskTrust(X509Certificate2 ca, bool caChanged)
    {
        string fp = TrustStore.Fingerprint(ca);
        string text = caChanged
            ? $"WARNING: the certificate authority of this server has CHANGED.\n\n" +
              $"This happens if SecureVNC was re-initialized on that computer - or if someone is impersonating it.\n\n" +
              $"New CA: {ca.Subject}\nSHA-256:\n{fp}\n\n" +
              "Trust the new certificate only if you re-initialized the server and the fingerprint matches " +
              "'SecureVNC.Admin cert show' on it."
            : $"First connection to this server.\n\nCA: {ca.Subject}\nSHA-256:\n{fp}\n\n" +
              "Compare the fingerprint with 'SecureVNC.Admin cert show' on the server.\nTrust this server?";
        return (bool)Invoke(() => MessageBox.Show(this, text, "SecureVNC - server certificate",
            MessageBoxButtons.YesNo, caChanged ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2) == DialogResult.Yes);
    }

    private void ImportCa()
    {
        using var dlg = new OpenFileDialog { Filter = "Certificate (*.cer;*.crt)|*.cer;*.crt|All files|*.*", Title = "Import server CA" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var trust = TrustStore.Load();
            trust.Import(dlg.FileName);
            using var ca = new X509Certificate2(dlg.FileName);
            _status.Text = $"Trusted: {ca.Subject}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SetBusy(bool busy, string? status)
    {
        foreach (Control c in new Control[] { _host, _port, _user, _password, _code, _emergency, _connect, _import }) c.Enabled = !busy;
        if (status is not null) _status.Text = status;
        UseWaitCursor = busy;
    }

    private void LoadSettings()
    {
        try
        {
            if (!File.Exists(SettingsFile)) return;
            var s = JsonSerializer.Deserialize<Settings>(File.ReadAllText(SettingsFile));
            if (s is null) return;
            _host.Text = s.Host;
            _port.Value = Math.Clamp(s.Port, 1, 65535);
            _user.Text = s.User;
            _stayInTray.Checked = s.StayInTray;
        }
        catch { /* ignore broken settings */ }
    }

    private static void SaveSettings(ConnectOptions o, bool stayInTray)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
        File.WriteAllText(SettingsFile, JsonSerializer.Serialize(new Settings(o.Host, o.Port, o.User, stayInTray)));
    }

    private void SaveTrayChoice()
    {
        try { SaveSettings(new ConnectOptions(_host.Text.Trim(), (int)_port.Value, _user.Text.Trim(), "", ""), _stayInTray.Checked); }
        catch { /* settings are a convenience */ }
    }
}
