using System.Diagnostics;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

/// <summary>SecureVNC Manager on a computer that can be controlled: certificate, auth server, users.</summary>
internal sealed class MainForm : ManagerForm
{
    private readonly bool _firstRun;
    private readonly Label _connect = new() { AutoSize = true, MaximumSize = new Size(ContentWidth, 0) };
    private readonly TextBox _fingerprint = ReadOnlyBox(2);
    private readonly Label _central = new() { AutoSize = true, MaximumSize = new Size(ContentWidth, 0) };
    private readonly Button _join = new() { Text = "Join auth server...", AutoSize = true, Padding = new Padding(4, 1, 4, 1) };
    private readonly Button _leave = new() { Text = "Leave auth server", AutoSize = true, Padding = new Padding(4, 1, 4, 1) };
    private readonly UsersPanel _users = new();
    private readonly FlowLayoutPanel _usersGroup;

    public MainForm(bool firstRun, string? user)
        : base(user is null ? "SecureVNC Manager" : $"SecureVNC Manager - {user}", ServiceIpc.ServiceName)
    {
        _firstRun = firstRun;

        var server = Group("This computer");
        server.Controls.Add(ServiceLabel);
        server.Controls.Add(_connect);
        server.Controls.Add(new Label { Text = "Certificate fingerprint (clients show it on the first connection - it must match):", AutoSize = true, Margin = new Padding(3, 10, 3, 2) });
        server.Controls.Add(_fingerprint);
        server.Controls.Add(Buttons(
            ("Copy fingerprint", () => Clipboard.SetText(_fingerprint.Text)),
            ("Export CA for clients...", () => ExportCa(ServerPaths.CaCertFile, $"SecureVNC-CA-{Environment.MachineName}.cer",
                "Copy this file to the client computers (USB stick is safest) and use \"Import CA...\" in SecureVNC Client.")),
            ("Restart service", RestartService),
            ("Open logs", () => Process.Start(new ProcessStartInfo(ServerPaths.LogDir) { UseShellExecute = true }))));

        var central = Group("Central authentication (SecureVNC Auth Server)");
        central.Controls.Add(_central);
        var row = Buttons();
        _join.Click += (_, _) => JoinAuthServer();
        _leave.Click += (_, _) => LeaveAuthServer();
        row.Controls.Add(_join);
        row.Controls.Add(_leave);
        central.Controls.Add(row);

        _usersGroup = Group("Users");
        _usersGroup.Controls.Add(_users);

        RefreshAll();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        ActiveControl = null;
        _fingerprint.SelectionLength = 0;
        if (_firstRun && !ServerConfig.Load().IsCentral && _users.Count == 0)
        {
            _users.Dialog(UserDialogMode.Add, null,
                "SecureVNC is installed. Create the first user now: this is the name, password and phone (Google Authenticator) " +
                "you will use to connect to this computer.");
        }
    }

    private void RefreshAll()
    {
        using (var ca = CertificateManager.LoadPublicCa()) _fingerprint.Text = CertificateManager.Fingerprint(ca);
        var config = ServerConfig.Load();
        _connect.Text = $"Clients connect to: {Environment.MachineName} or {string.Join(", ", NetworkInfo.LanAddresses())}   port {config.Port}";
        _users.Reload();

        _join.Visible = !config.IsCentral;
        _leave.Visible = config.IsCentral;
        BoxOf(_usersGroup).Text = config.IsCentral
            ? "Local emergency users - only with \"Emergency login\" in the client (normally none)"
            : "Users (password + Google Authenticator)";

        if (!config.IsCentral)
        {
            _central.Text = "Not used: the users below are checked on this computer.";
            _central.ForeColor = SystemColors.ControlText;
            return;
        }
        _central.Text = $"Auth server {config.AuthServer}: checking...";
        _central.ForeColor = SystemColors.ControlText;
        int localUsers = _users.Count;
        Task.Run(() =>
        {
            string text;
            bool ok = false;
            try
            {
                var r = CentralClient.Ping(config);
                ok = r.Ok;
                text = r.Ok ? $"Auth server {config.AuthServer}: reachable. This computer is registered as {r.MachineName}. Logins are checked there."
                            : $"Auth server {config.AuthServer}: {r.Error}";
            }
            catch (Exception ex)
            {
                text = $"Auth server {config.AuthServer}: NOT reachable ({ex.Message}). Nobody can log in until it is back" +
                       (localUsers > 0 ? ", except the local emergency users." : ".");
            }
            if (IsHandleCreated) BeginInvoke(() =>
            {
                _central.Text = text;
                _central.ForeColor = ok ? Color.DarkGreen : Color.Firebrick;
            });
        });
    }

    private void JoinAuthServer()
    {
        using var dlg = new JoinDialog();
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        RestartIfInstalled();
        RefreshAll();
        MessageBox.Show(this, "This computer now uses the auth server: administrators log in with the accounts kept there.",
            "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void LeaveAuthServer()
    {
        if (MessageBox.Show(this,
                "Stop using the auth server? This computer gets its own certificate again (clients will ask to trust it) " +
                "and only the local users below can log in.", "SecureVNC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        CentralClient.Leave();
        Log.Info("Left the auth server");
        RestartIfInstalled();
        RefreshAll();
        if (_users.Count == 0)
            _users.Dialog(UserDialogMode.Add, null, "There are no local users yet. Create one, otherwise nobody can connect.");
    }

    private void RestartIfInstalled()
    {
        try { RestartService(); }
        catch (InvalidOperationException) { /* service not installed (manual tests) */ }
    }
}
