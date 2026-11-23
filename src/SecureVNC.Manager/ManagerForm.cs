using System.ServiceProcess;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

/// <summary>
/// Common parts of SecureVNC Manager and the Auth Console: layout helpers, service status,
/// and closing after 10 minutes without activity (reopening asks for the login again).
/// </summary>
internal abstract class ManagerForm : Form
{
    private static readonly TimeSpan IdleClose = TimeSpan.FromMinutes(10);
    protected const int ContentWidth = 640;
    private readonly List<GroupBox> _groups = [];
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 3000 };
    private readonly string _serviceName;
    private DateTime _lastActivity = DateTime.UtcNow;

    protected readonly Label ServiceLabel = new() { AutoSize = true };
    protected readonly FlowLayoutPanel Root = new() { FlowDirection = FlowDirection.TopDown, AutoSize = true, Padding = new Padding(12), WrapContents = false };

    protected ManagerForm(string title, string serviceName)
    {
        _serviceName = serviceName;
        Text = title;
        Icon = SystemIcons.Shield;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);
        Controls.Add(Root);

        Application.AddMessageFilter(new ActivityFilter(() => _lastActivity = DateTime.UtcNow));
        _timer.Tick += (_, _) =>
        {
            RefreshService();
            if (DateTime.UtcNow - _lastActivity > IdleClose)
            {
                Log.Info("Closed after inactivity");
                _timer.Stop();
                Application.Exit();   // also closes open dialogs
            }
        };
        _timer.Start();
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        int width = _groups.Max(g => g.Width);
        foreach (var g in _groups) g.MinimumSize = new Size(width, 0);
        RefreshService();
    }

    protected FlowLayoutPanel Group(string title)
    {
        var box = new GroupBox { Text = title, AutoSize = true, Padding = new Padding(10, 6, 10, 10), Margin = new Padding(0, 0, 0, 10) };
        var inner = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Dock = DockStyle.Fill };
        box.Controls.Add(inner);
        _groups.Add(box);
        Root.Controls.Add(box);
        return inner;
    }

    protected static GroupBox BoxOf(Control inner) => (GroupBox)inner.Parent!;

    public static FlowLayoutPanel Buttons(params (string Text, Action Click)[] buttons)
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

    protected static TextBox ReadOnlyBox(int lines) => new()
    {
        ReadOnly = true, Multiline = lines > 1, WordWrap = true, Width = ContentWidth,
        Height = lines > 1 ? 18 + 19 * lines : 0, Font = new Font("Consolas", 9.5f), TabStop = false,
    };

    protected void RefreshService()
    {
        try
        {
            using var sc = new ServiceController(_serviceName);
            var status = sc.Status;
            ServiceLabel.Text = $"Service: {status}";
            ServiceLabel.ForeColor = status == ServiceControllerStatus.Running ? Color.DarkGreen : Color.Firebrick;
        }
        catch (InvalidOperationException)
        {
            ServiceLabel.Text = "Service: not installed";
            ServiceLabel.ForeColor = Color.Firebrick;
        }
    }

    protected void RestartService()
    {
        UseWaitCursor = true;
        try
        {
            using var sc = new ServiceController(_serviceName);
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

    protected void ExportCa(string caFile, string fileName, string hint)
    {
        using var dlg = new SaveFileDialog
        {
            FileName = fileName,
            Filter = "Certificate (*.cer)|*.cer",
            Title = "Export CA certificate (public, safe to copy)",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.Copy(caFile, dlg.FileName, overwrite: true);
        MessageBox.Show(this, hint, "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    /// <summary>Any key or mouse use counts as activity.</summary>
    private sealed class ActivityFilter(Action touch) : IMessageFilter
    {
        public bool PreFilterMessage(ref Message m)
        {
            if (m.Msg is 0x0100 or 0x0104 or 0x0200 or 0x0201 or 0x0204 or 0x020A) touch();   // key, mouse move/click/wheel
            return false;
        }
    }
}

/// <summary>User list with add / password / new authenticator / remove (local users, or the auth server's administrators).</summary>
internal sealed class UsersPanel : FlowLayoutPanel
{
    private readonly ListView _list = new() { View = View.Details, FullRowSelect = true, MultiSelect = false, Width = 615, Height = 170, HideSelection = false };

    public UsersPanel()
    {
        FlowDirection = FlowDirection.TopDown;
        AutoSize = true;
        WrapContents = false;
        Margin = Padding.Empty;
        _list.Columns.Add("Name", 320);
        _list.Columns.Add("Created", 200);
        _list.DoubleClick += (_, _) => Selected(name => Dialog(UserDialogMode.Password, name));
        Controls.Add(_list);
        Controls.Add(ManagerForm.Buttons(
            ("Add...", () => Dialog(UserDialogMode.Add, null)),
            ("Change password...", () => Selected(name => Dialog(UserDialogMode.Password, name))),
            ("New authenticator...", () => Selected(name => Dialog(UserDialogMode.NewAuthenticator, name))),
            ("Remove", () => Selected(Remove))));
        Reload();
    }

    public int Count => _list.Items.Count;

    public void Reload()
    {
        _list.Items.Clear();
        foreach (var u in UserStore.Load().Users.OrderBy(u => u.Name, StringComparer.OrdinalIgnoreCase))
            _list.Items.Add(new ListViewItem([u.Name, u.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm")]));
    }

    public void Dialog(UserDialogMode mode, string? name, string? intro = null)
    {
        using var dlg = new UserDialog(mode, name, intro);
        if (dlg.ShowDialog(FindForm()) != DialogResult.OK) return;
        Reload();
        var done = mode switch
        {
            UserDialogMode.Add => $"'{dlg.CreatedName}' created. Connect with SecureVNC Client using this name, the password and the code from the phone.",
            UserDialogMode.NewAuthenticator => $"New authenticator saved for '{name}'. The old one no longer works.",
            _ => $"Password changed for '{name}'.",
        };
        MessageBox.Show(FindForm(), done, "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void Selected(Action<string> action)
    {
        if (_list.SelectedItems.Count == 0)
        {
            MessageBox.Show(FindForm(), "Select a user first.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        action(_list.SelectedItems[0].Text);
    }

    private void Remove(string name)
    {
        if (MessageBox.Show(FindForm(), $"Remove '{name}'? Open connections of this user stay open until they disconnect.",
                "SecureVNC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        var store = UserStore.Load();
        if (store.Find(name) is { } u)
        {
            store.Users.Remove(u);
            store.Save();
            Log.Info($"Removed user '{name}'");
        }
        Reload();
    }
}
