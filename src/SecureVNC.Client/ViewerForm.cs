namespace SecureVNC.Client;

internal sealed class ViewerForm : Form
{
    private static readonly (ushort, ushort, bool) Ctrl = (0x11, 0x1D, false), Shift = (0x10, 0x2A, false),
        Alt = (0x12, 0x38, false), Esc = (0x1B, 0x01, false), Tab = (0x09, 0x0F, false), Win = (0x5B, 0x5B, true);

    private readonly RfbClient _client;
    private readonly RemoteView _view;
    private readonly Panel _scroller;

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
        bar.Items.Add("Disconnect", null, (_, _) => Close());
        bar.Items.Add(new ToolStripLabel($"{user}@{host}  ·  {client.TlsInfo}  ·  MFA")
        {
            Alignment = ToolStripItemAlignment.Right,
            ForeColor = Color.DarkGreen,
        });

        Controls.Add(_scroller);
        Controls.Add(bar);

        client.RegionUpdated += r => UiAsync(() => _view.InvalidateRemote(r));
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
