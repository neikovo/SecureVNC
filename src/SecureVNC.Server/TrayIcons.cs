using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace SecureVNC.Server;

/// <summary>Tray icons drawn at run time: green = waiting (nobody connected), red = someone is connected.</summary>
internal static partial class TrayIcons
{
    public static Icon Create(Color fill)
    {
        int size = Math.Max(16, SystemInformation.SmallIconSize.Width);
        using var bmp = new Bitmap(size, size);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            float s = size;

            // round badge
            using (var brush = new SolidBrush(fill))
                g.FillEllipse(brush, 0.5f, 0.5f, s - 1.5f, s - 1.5f);
            using (var border = new Pen(ControlPaint.Dark(fill, 0.25f), Math.Max(1f, s / 16f)))
                g.DrawEllipse(border, 0.5f, 0.5f, s - 1.5f, s - 1.5f);

            // white monitor: screen + stand
            using var white = new SolidBrush(Color.White);
            using var pen = new Pen(Color.White, Math.Max(1f, s / 14f));
            var screen = new RectangleF(s * 0.24f, s * 0.27f, s * 0.52f, s * 0.36f);
            g.DrawRectangle(pen, screen.X, screen.Y, screen.Width, screen.Height);
            g.FillRectangle(white, s * 0.46f, screen.Bottom, s * 0.08f, s * 0.09f);
            g.FillRectangle(white, s * 0.34f, screen.Bottom + s * 0.08f, s * 0.32f, Math.Max(1f, s / 14f));
        }

        // Icon.FromHandle does not own the handle: clone it into a managed icon and free the original.
        IntPtr h = bmp.GetHicon();
        try { return (Icon)Icon.FromHandle(h).Clone(); }
        finally { DestroyIcon(h); }
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyIcon(IntPtr hIcon);
}
