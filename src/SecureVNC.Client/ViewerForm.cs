using SecureVNC.Shared.Protocol;

namespace SecureVNC.Client;

internal sealed class ViewerForm : Form
{
    private static readonly (ushort, ushort, bool) Ctrl = (0x11, 0x1D, false), Shift = (0x10, 0x2A, false),
        Alt = (0x12, 0x38, false), Esc = (0x1B, 0x01, false), Tab = (0x09, 0x0F, false), Win = (0x5B, 0x5B, true);

    private readonly RfbClient _client;
    private readonly RemoteView _view;
    private readonly Panel _scroller;
    private readonly ToolStripComboBox _monitor = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = false, Width = 190, ToolTipText = "Monitor" };
    private readonly ToolStripComboBox _quality = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = false, Width = 185, ToolTipText = "Picture quality" };
    private readonly ToolStripComboBox _fps = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = false, Width = 70, ToolTipText = "Frames per second" };
    private bool _updatingMenus;

    public ViewerForm(RfbClient client, string user, string host)
    {
        _client = client;
        Text = $"{client.DesktopName} - SecureVNC";
        Icon = SystemIcons.Shield;
        KeyPreview = false;
        StartPosition = FormStartPosition.CenterScreen;
        var work = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 800);
        Size = new Size(work.Width * 4 / 5, work.Height * 4 / 5);

        _view = new RemoteView(client) { Dock = DockStyle.Fill };
        _scroller = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = Color.Black };
        _scroller.Controls.Add(_view);

        var fit = new ToolStripButton("Fit to window") { CheckOnClick = true, Checked = true };
        fit.CheckedChanged += (_, _) => SetFit(fit.Checked);

        var bar = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, TabStop = false };
        bar.Items.Add(fit);
        bar.Items.Add(new ToolStripSeparator());
        bar.Items.Add("Ctrl+Alt+Del", null, (_, _) =>
        {
            client.SendCtrlAltDel();
            _view.Focus();
        });
        bar.Items.Add("Win", null, (_, _) => _view.SendCombo(Win));
        bar.Items.Add("Alt+Tab", null, (_, _) => _view.SendCombo(Alt, Tab));
        bar.Items.Add("Ctrl+Shift+Esc", null, (_, _) => _view.SendCombo(Ctrl, Shift, Esc));
        bar.Items.Add(new ToolStripSeparator());

        // Monitor: filled from the server's monitor list.
        _monitor.Items.Add("All monitors");
        _monitor.SelectedIndex = 0;
        _monitor.SelectedIndexChanged += (_, _) =>
        {
            if (_updatingMenus || _monitor.SelectedIndex < 0) return;
            client.SetVideo(client.Video with { Monitor = _monitor.SelectedIndex });
            _view.Focus();
        };
        bar.Items.Add(_monitor);

        _quality.Items.AddRange(["Best quality (lossless)", "Balanced (JPEG 80)", "Low bandwidth (JPEG 50)", "16-bit colour (lossless)"]);
        _quality.SelectedIndex = (int)client.Video.Quality;
        _quality.SelectedIndexChanged += (_, _) =>
        {
            client.SetVideo(client.Video with { Quality = (PictureQuality)_quality.SelectedIndex });
            _view.Focus();
        };
        bar.Items.Add(_quality);

        _fps.Items.AddRange(["30 fps", "15 fps", "5 fps"]);
        _fps.SelectedIndex = 0;
        _fps.SelectedIndexChanged += (_, _) =>
        {
            client.SetVideo(client.Video with { MaxFps = _fps.SelectedIndex switch { 1 => 15, 2 => 5, _ => 30 } });
            _view.Focus();
        };
        bar.Items.Add(_fps);
        bar.Items.Add(new ToolStripSeparator());
        bar.Items.Add("Disconnect", null, (_, _) => Close());
        bar.Items.Add(new ToolStripLabel($"{user}@{host}  ·  {client.TlsInfo}  ·  MFA, {client.LoginMethod}")
        {
            Alignment = ToolStripItemAlignment.Right,
            ForeColor = Color.DarkGreen,
        });

        Controls.Add(_scroller);
        Controls.Add(bar);

        client.RegionUpdated += r => UiAsync(() => _view.InvalidateRemote(r));
        client.MonitorsChanged += () => UiAsync(UpdateMonitorMenu);
        client.Resized += () => UiAsync(() =>
        {
            SetFit(_view.FitToWindow);
            _view.Invalidate();
        });
        client.Disconnected += err => UiAsync(() =>
        {
            if (err is not null)
                MessageBox.Show(this, $"Connection lost:\n{err.Message}", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            Close();
        });

        Shown += (_, _) =>
        {
            _view.UpdateLayoutRect();
            _view.Focus();
            client.Start();
        };
    }

    private void UpdateMonitorMenu()
    {
        _updatingMenus = true;
        try
        {
            _monitor.Items.Clear();
            _monitor.Items.Add(_client.Monitors.Count > 1 ? $"All monitors ({_client.Monitors.Count})" : "All monitors");
            for (int i = 0; i < _client.Monitors.Count; i++)
            {
                var m = _client.Monitors[i];
                _monitor.Items.Add($"Monitor {i + 1}: {m.Width}x{m.Height}{(m.Primary ? " (main)" : "")}");
            }
            _monitor.SelectedIndex = Math.Min(_client.SelectedMonitor, _monitor.Items.Count - 1);
        }
        finally
        {
            _updatingMenus = false;
        }
    }

    private void SetFit(bool fit)
    {
        if (fit)
        {
            _view.Dock = DockStyle.Fill;
        }
        else
        {
            _view.Dock = DockStyle.None;
            _view.Location = Point.Empty;
            _view.Size = new Size(_client.Width, _client.Height);
        }
        _view.FitToWindow = fit;
        _view.Focus();
    }

    private void UiAsync(Action a)
    {
        if (IsHandleCreated && !IsDisposed) BeginInvoke(a);
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _client.Dispose();
        base.OnFormClosed(e);
    }
}
