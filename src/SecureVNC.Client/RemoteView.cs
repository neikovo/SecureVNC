using System.Drawing.Drawing2D;

namespace SecureVNC.Client;

/// <summary>Draws the remote screen and forwards mouse and keyboard (as Windows scan codes).</summary>
internal sealed class RemoteView : Control
{
    private const int WM_KEYDOWN = 0x100, WM_KEYUP = 0x101, WM_CHAR = 0x102, WM_DEADCHAR = 0x103,
        WM_SYSKEYDOWN = 0x104, WM_SYSKEYUP = 0x105, WM_SYSCHAR = 0x106, WM_SYSDEADCHAR = 0x107;

    private readonly RfbClient _client;
    private readonly HashSet<(ushort Vk, ushort Scan, bool Ext)> _pressed = [];
    private byte _buttons;
    private Rectangle _dest;
    private float _scale = 1f;
    private bool _fit = true;

    public RemoteView(RfbClient client)
    {
        _client = client;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.Selectable | ControlStyles.ResizeRedraw, true);
        TabStop = true;
        BackColor = Color.Black;
        Cursor = Cursors.Cross;
    }

    public bool FitToWindow
    {
        get => _fit;
        set
        {
            _fit = value;
            UpdateLayoutRect();
            Invalidate();
        }
    }

    public void UpdateLayoutRect()
    {
        int w = _client.Width, h = _client.Height;
        if (w == 0 || h == 0) return;
        if (_fit)
        {
            _scale = Math.Min((float)ClientSize.Width / w, (float)ClientSize.Height / h);
            if (_scale <= 0) _scale = 1;
            int dw = (int)(w * _scale), dh = (int)(h * _scale);
            _dest = new Rectangle((ClientSize.Width - dw) / 2, (ClientSize.Height - dh) / 2, dw, dh);
        }
        else
        {
            _scale = 1;
            _dest = new Rectangle(0, 0, w, h);
        }
    }

    /// <summary>Invalidates the window area showing the given remote rectangle.</summary>
    public void InvalidateRemote(Rectangle r)
    {
        Invalidate(new Rectangle(
            _dest.X + (int)(r.X * _scale) - 1, _dest.Y + (int)(r.Y * _scale) - 1,
            (int)Math.Ceiling(r.Width * _scale) + 2, (int)Math.Ceiling(r.Height * _scale) + 2));
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        UpdateLayoutRect();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Color.Black);
        lock (_client.FrameLock)
        {
            if (_client.Frame is null) return;
            g.CompositingMode = CompositingMode.SourceCopy;
            g.InterpolationMode = Math.Abs(_scale - 1f) < 0.001f ? InterpolationMode.NearestNeighbor : InterpolationMode.Bilinear;
            g.PixelOffsetMode = PixelOffsetMode.Half;
            g.DrawImage(_client.Frame, _dest);
        }
    }

    // ---- mouse ----

    private (int X, int Y) ToRemote(Point p) =>
        (Math.Clamp((int)((p.X - _dest.X) / _scale), 0, Math.Max(0, _client.Width - 1)),
         Math.Clamp((int)((p.Y - _dest.Y) / _scale), 0, Math.Max(0, _client.Height - 1)));

    private static byte ButtonBit(MouseButtons b) => b switch
    {
        MouseButtons.Left => 1,
        MouseButtons.Middle => 2,
        MouseButtons.Right => 4,
        _ => 0,
    };

    protected override void OnMouseMove(MouseEventArgs e)
    {
        var (x, y) = ToRemote(e.Location);
        _client.SendPointer(_buttons, x, y);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        Focus();
        _buttons |= ButtonBit(e.Button);
        var (x, y) = ToRemote(e.Location);
        _client.SendPointer(_buttons, x, y);
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        _buttons &= (byte)~ButtonBit(e.Button);
        var (x, y) = ToRemote(e.Location);
        _client.SendPointer(_buttons, x, y);
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        var (x, y) = ToRemote(e.Location);
        byte bit = e.Delta > 0 ? (byte)8 : (byte)16;
        int notches = Math.Max(1, Math.Abs(e.Delta) / 120);
        for (int i = 0; i < notches; i++)
        {
            _client.SendPointer((byte)(_buttons | bit), x, y);
            _client.SendPointer(_buttons, x, y);
        }
    }

    // ---- keyboard ----

    protected override bool IsInputKey(Keys keyData) => true;

    protected override void WndProc(ref Message m)
    {
        switch (m.Msg)
        {
            case WM_KEYDOWN or WM_SYSKEYDOWN or WM_KEYUP or WM_SYSKEYUP:
            {
                bool down = m.Msg is WM_KEYDOWN or WM_SYSKEYDOWN;
                ushort vk = (ushort)m.WParam;
                long lp = m.LParam;
                ushort scan = (ushort)((lp >> 16) & 0xFF);
                bool ext = ((lp >> 24) & 1) != 0;
                SendKey(down, vk, scan, ext);
                return;   // not passed on: Alt, F10, Alt+F4 ... go to the remote PC
            }
            case WM_CHAR or WM_DEADCHAR or WM_SYSCHAR or WM_SYSDEADCHAR:
                return;
        }
        base.WndProc(ref m);
    }

    public void SendKey(bool down, ushort vk, ushort scan, bool ext)
    {
        _client.SendKey(down, vk, scan, ext);
        if (down) _pressed.Add((vk, scan, ext));
        else _pressed.Remove((vk, scan, ext));
    }

    /// <summary>Sends a key combination, e.g. Ctrl+Shift+Esc or the Windows key.</summary>
    public void SendCombo(params (ushort Vk, ushort Scan, bool Ext)[] keys)
    {
        foreach (var k in keys) _client.SendKey(true, k.Vk, k.Scan, k.Ext);
        foreach (var k in keys.Reverse()) _client.SendKey(false, k.Vk, k.Scan, k.Ext);
        Focus();
    }

    /// <summary>Releases everything when focus leaves, so no key or button stays stuck on the remote PC.</summary>
    protected override void OnLostFocus(EventArgs e)
    {
        base.OnLostFocus(e);
        foreach (var k in _pressed.ToList()) _client.SendKey(false, k.Vk, k.Scan, k.Ext);
        _pressed.Clear();
        if (_buttons != 0)
        {
            _buttons = 0;
            var (x, y) = ToRemote(PointToClient(MousePosition));
            _client.SendPointer(0, x, y);
        }
    }
}
