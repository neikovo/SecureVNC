using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
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

    private sealed record Settings(string Host, int Port, string User);

    public ConnectForm()
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

        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
        buttons.Controls.Add(_connect);
        buttons.Controls.Add(_import);
        grid.Controls.Add(buttons);
        grid.SetColumnSpan(buttons, 2);
        grid.Controls.Add(_status);
        grid.SetColumnSpan(_status, 2);
        Controls.Add(grid);

        AcceptButton = _connect;
        _connect.Click += async (_, _) => await ConnectAsync();
        _import.Click += (_, _) => ImportCa();
        _code.KeyPress += (_, e) => e.Handled = !char.IsDigit(e.KeyChar) && !char.IsControl(e.KeyChar);

        LoadSettings();
        Shown += (_, _) => (_host.Text.Length == 0 ? _host : _password).Focus();
    }

    private async Task ConnectAsync()
    {
        var options = new ConnectOptions(_host.Text.Trim(), (int)_port.Value, _user.Text.Trim(), _password.Text, _code.Text.Trim());
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
            SaveSettings(options);
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
        foreach (Control c in new Control[] { _host, _port, _user, _password, _code, _connect, _import }) c.Enabled = !busy;
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
        }
        catch { /* ignore broken settings */ }
    }

    private static void SaveSettings(ConnectOptions o)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
        File.WriteAllText(SettingsFile, JsonSerializer.Serialize(new Settings(o.Host, o.Port, o.User)));
    }
}
