using System.Diagnostics;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

/// <summary>SecureVNC Auth Console (Manager --auth): administrators, joined computers, audit, join key.</summary>
internal sealed class AuthMainForm : ManagerForm
{
    private readonly AuthPaths _paths;
    private readonly Label _connect = new() { AutoSize = true, MaximumSize = new Size(ContentWidth, 0) };
    private readonly TextBox _fingerprint = ReadOnlyBox(2);
    private readonly TextBox _joinKey = ReadOnlyBox(1);
    private readonly UsersPanel _admins = new();
    private readonly ListView _computers = new() { View = View.Details, FullRowSelect = true, MultiSelect = false, Width = 615, Height = 200, HideSelection = false };
    private readonly ListBox _audit = new() { Width = 615, Height = 220, Font = new Font("Consolas", 8.5f), HorizontalScrollbar = true };
    private bool _keyShown;

    public AuthMainForm(AuthPaths paths, bool firstRun, string? user)
        : base(user is null ? "SecureVNC Auth Console" : $"SecureVNC Auth Console - {user}", "SecureVNCAuth")
    {
        _paths = paths;

        var server = Group("Auth server");
        server.Controls.Add(ServiceLabel);
        server.Controls.Add(_connect);
        server.Controls.Add(new Label
        {
            Text = "To join a computer: SecureVNC Manager on it > Join auth server... and enter this server's address, the CA fingerprint and the join key.",
            AutoSize = true, MaximumSize = new Size(ContentWidth, 0), Margin = new Padding(3, 8, 3, 2),
        });
        server.Controls.Add(new Label { Text = "CA fingerprint:", AutoSize = true, Margin = new Padding(3, 6, 3, 2) });
        server.Controls.Add(_fingerprint);
        server.Controls.Add(new Label { Text = "Join key (secret - anyone with it can join a computer):", AutoSize = true, Margin = new Padding(3, 6, 3, 2) });
        server.Controls.Add(_joinKey);
        server.Controls.Add(Buttons(
            ("Copy fingerprint", () => Clipboard.SetText(_fingerprint.Text)),
            ("Show / hide join key", ToggleKey),
            ("Copy join key", () => Clipboard.SetText(AuthData.ReadJoinKey(_paths))),
            ("New join key...", NewJoinKey)));
        server.Controls.Add(Buttons(
            ("Export CA for clients...", () => ExportCa(_paths.CaCertFile, "SecureVNC-Organization-CA.cer",
                "Import this file once in SecureVNC Client (\"Import CA...\"): it then trusts every computer joined to this auth server.")),
            ("Restart service", RestartService),
            ("Open logs", () => Process.Start(new ProcessStartInfo(_paths.LogDir) { UseShellExecute = true }))));

        var tabs = new TabControl { Width = ContentWidth + 10, Height = 345 };
        TabPage Page(string title, params Control[] content)
        {
            var page = new TabPage(title) { Padding = new Padding(8) };
            var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, Dock = DockStyle.Fill, WrapContents = false };
            flow.Controls.AddRange(content);
            page.Controls.Add(flow);
            tabs.TabPages.Add(page);
            return page;
        }
        Page("Administrators", new Label
        {
            Text = "Password + Google Authenticator. Administrators can log in to every joined computer.",
            AutoSize = true, MaximumSize = new Size(ContentWidth, 0),
        }, _admins);

        _computers.Columns.Add("Name", 160);
        _computers.Columns.Add("Address", 115);
        _computers.Columns.Add("Last seen", 130);
        _computers.Columns.Add("Joined", 100);
        _computers.Columns.Add("Status", 95);
        Page("Computers", _computers, Buttons(
            ("Block", () => SetBlocked(true)),
            ("Allow again", () => SetBlocked(false)),
            ("Delete entry", DeleteComputer),
            ("Refresh", RefreshAll)));

        Page("Audit", _audit, Buttons(("Refresh", RefreshAll)));
        Group("Manage").Controls.Add(tabs);

        RefreshAll();
        if (firstRun && _admins.Count == 0)
            Shown += (_, _) => _admins.Dialog(UserDialogMode.Add, null,
                "SecureVNC Auth Server is installed. Add the first administrator: name, password and phone (Google Authenticator). " +
                "Administrators can log in to every computer joined to this server.");
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        ActiveControl = null;
        _fingerprint.SelectionLength = 0;
    }

    private void RefreshAll()
    {
        var config = AuthConfig.Load(_paths);
        _connect.Text = $"Computers connect to: {Environment.MachineName} or {string.Join(", ", NetworkInfo.LanAddresses())}   port {config.Port}";
        _fingerprint.Text = AuthData.CaFingerprint(_paths);
        _joinKey.Text = _keyShown ? AuthData.ReadJoinKey(_paths) : "•••• - •••• - •••• - •••• - •••• - ••••";
        _admins.Reload();

        _computers.Items.Clear();
        foreach (var c in ComputerStore.Load(_paths).Computers.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase))
        {
            _computers.Items.Add(new ListViewItem([
                c.Name, c.LastAddress, c.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
                c.JoinedUtc.ToLocalTime().ToString("yyyy-MM-dd"), c.Revoked ? "BLOCKED" : "allowed",
            ]) { Tag = c, ForeColor = c.Revoked ? Color.Firebrick : SystemColors.WindowText });
        }

        _audit.Items.Clear();
        foreach (var line in AuthData.RecentAudit(_paths, 300)) _audit.Items.Add(line);
    }

    private void ToggleKey()
    {
        _keyShown = !_keyShown;
        RefreshAll();
    }

    private void NewJoinKey()
    {
        if (MessageBox.Show(this,
                "Create a new join key? The old one stops working at once: computers already joined keep working, but new " +
                "computers and clones made from an image with the old key cannot join until they get the new one.",
                "SecureVNC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        AuthData.SetJoinKey(_paths, CentralProtocol.NewJoinKey());
        AuthData.Audit(_paths, "JOIN-KEY changed in the Auth Console");
        _keyShown = true;
        RefreshAll();
    }

    private ComputerRecord? SelectedComputer()
    {
        if (_computers.SelectedItems.Count == 0)
        {
            MessageBox.Show(this, "Select a computer first.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return null;
        }
        return (ComputerRecord)_computers.SelectedItems[0].Tag!;
    }

    private static bool Same(ComputerRecord a, ComputerRecord b) =>
        string.Equals(a.Name, b.Name, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.MachineGuid, b.MachineGuid, StringComparison.OrdinalIgnoreCase);

    private void SetBlocked(bool blocked)
    {
        if (SelectedComputer() is not { } c) return;
        ComputerStore.Update(_paths, s =>
        {
            foreach (var r in s.Computers.Where(r => Same(r, c))) r.Revoked = blocked;
            return 0;
        });
        AuthData.Audit(_paths, $"{(blocked ? "BLOCKED" : "ALLOWED")}  computer {c.Name} in the Auth Console");
        RefreshAll();
    }

    private void DeleteComputer()
    {
        if (SelectedComputer() is not { } c) return;
        if (MessageBox.Show(this,
                $"Delete {c.Name}? It can no longer log anyone in. If it still has the join key (or is cloned again), it can join again; " +
                "use Block to keep it out.", "SecureVNC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        ComputerStore.Update(_paths, s => s.Computers.RemoveAll(r => Same(r, c)));
        AuthData.Audit(_paths, $"DELETED  computer {c.Name} in the Auth Console");
        RefreshAll();
    }
}
