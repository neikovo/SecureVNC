using SecureVNC.Shared.Protocol;

namespace SecureVNC.Server;

internal static class Monitors
{
    /// <summary>Monitors in screen coordinates (physical pixels: the server is per-monitor DPI aware); primary first.</summary>
    public static List<Rectangle> Bounds() =>
        Screen.AllScreens.OrderByDescending(s => s.Primary).ThenBy(s => s.Bounds.X).ThenBy(s => s.Bounds.Y)
            .Select(s => s.Bounds).Take(Rfb.MaxMonitors).ToList();

    public static List<MonitorInfo> Describe(List<Rectangle> bounds, int virtualLeft, int virtualTop) =>
        bounds.Select((b, i) => new MonitorInfo(b.X - virtualLeft, b.Y - virtualTop, b.Width, b.Height, i == 0)).ToList();
}
