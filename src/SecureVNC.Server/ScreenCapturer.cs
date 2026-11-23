using System.Runtime.InteropServices;
using static SecureVNC.Server.Native;

namespace SecureVNC.Server;

/// <summary>
/// Captures the whole virtual desktop (all monitors), or one monitor (<see cref="Region"/>), into a top-down
/// 32bpp BGRX DIB with GDI, including the mouse cursor.
/// </summary>
internal sealed unsafe class ScreenCapturer : IDisposable
{
    private nint _screenDc, _memDc, _dib, _oldBitmap;
    private byte* _bits;

    public int Left { get; private set; }
    public int Top { get; private set; }
    public int Width { get; private set; }
    public int Height { get; private set; }
    public int Stride => Width * 4;
    /// <summary>Top-left of the whole virtual desktop at the last capture.</summary>
    public int VirtualLeft { get; private set; }
    public int VirtualTop { get; private set; }

    /// <summary>Part of the desktop to capture, in screen coordinates (one monitor); null = everything.</summary>
    public Rectangle? Region { get; set; }

    public ReadOnlySpan<byte> Pixels => new(_bits, Width * Height * 4);

    /// <summary>Grabs a new frame. Returns false if the desktop could not be read (e.g. secure desktop).</summary>
    public bool Capture()
    {
        int l = GetSystemMetrics(SM_XVIRTUALSCREEN), t = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int w = GetSystemMetrics(SM_CXVIRTUALSCREEN), h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (w <= 0 || h <= 0) return false;
        VirtualLeft = l;
        VirtualTop = t;
        if (Region is { } region)
        {
            var part = Rectangle.Intersect(region, new Rectangle(l, t, w, h));
            if (part.Width > 0 && part.Height > 0) (l, t, w, h) = (part.X, part.Y, part.Width, part.Height);
        }
        if (_screenDc == 0) _screenDc = GetDC(0);
        if (w != Width || h != Height || _dib == 0) Recreate(w, h);
        Left = l;
        Top = t;

        bool ok = BitBlt(_memDc, 0, 0, w, h, _screenDc, l, t, SRCCOPY);
        if (!ok)
        {
            // The DC goes stale when the input desktop changes; get a new one next time.
            ReleaseDC(0, _screenDc);
            _screenDc = 0;
            return false;
        }
        DrawCursor();
        GdiFlush();
        return true;
    }

    private void Recreate(int w, int h)
    {
        FreeBitmap();
        _memDc = CreateCompatibleDC(_screenDc);
        var bmi = new BITMAPINFOHEADER
        {
            biSize = Marshal.SizeOf<BITMAPINFOHEADER>(),
            biWidth = w,
            biHeight = -h,   // top-down
            biPlanes = 1,
            biBitCount = 32,
        };
        _dib = CreateDIBSection(_screenDc, ref bmi, 0, out var bits, 0, 0);
        if (_dib == 0) throw new InvalidOperationException("CreateDIBSection failed.");
        _bits = (byte*)bits;
        _oldBitmap = SelectObject(_memDc, _dib);
        Width = w;
        Height = h;
    }

    private void DrawCursor()
    {
        var ci = new CURSORINFO { cbSize = Marshal.SizeOf<CURSORINFO>() };
        if (!GetCursorInfo(ref ci) || (ci.flags & CURSOR_SHOWING) == 0 || ci.hCursor == 0) return;
        if (!GetIconInfo(ci.hCursor, out var ii)) return;
        try
        {
            DrawIconEx(_memDc, ci.ptScreenPos.X - ii.xHotspot - Left, ci.ptScreenPos.Y - ii.yHotspot - Top,
                ci.hCursor, 0, 0, 0, 0, DI_NORMAL);
        }
        finally
        {
            if (ii.hbmMask != 0) DeleteObject(ii.hbmMask);
            if (ii.hbmColor != 0) DeleteObject(ii.hbmColor);
        }
    }

    private void FreeBitmap()
    {
        if (_memDc != 0)
        {
            SelectObject(_memDc, _oldBitmap);
            DeleteDC(_memDc);
            _memDc = 0;
        }
        if (_dib != 0)
        {
            DeleteObject(_dib);
            _dib = 0;
        }
        _bits = null;
        Width = Height = 0;
    }

    public void Dispose() => ResetDesktop();

    /// <summary>Drops all GDI objects; call after the thread switched desktops. The next Capture re-creates them.</summary>
    public void ResetDesktop()
    {
        FreeBitmap();
        if (_screenDc != 0)
        {
            ReleaseDC(0, _screenDc);
            _screenDc = 0;
        }
    }
}
