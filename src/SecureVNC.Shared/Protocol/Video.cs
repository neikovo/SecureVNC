namespace SecureVNC.Shared.Protocol;

public enum PictureQuality
{
    /// <summary>zlib, exact pixels (best for text, LAN).</summary>
    Lossless,
    /// <summary>JPEG quality 80: far less data, slight blur.</summary>
    Balanced,
    /// <summary>JPEG quality 50: least data, for slow links.</summary>
    LowBandwidth,
    /// <summary>zlib of 16-bit colour: lossless shapes, fewer colours, about half the data.</summary>
    Colors16,
}

/// <summary>One monitor of the remote computer, relative to the top-left of its whole desktop.</summary>
public sealed record MonitorInfo(int X, int Y, int Width, int Height, bool Primary);

/// <summary>
/// What the viewer wants. Sent in the standard RFB SetEncodings message (preferred encodings first, then SecureVNC
/// pseudo-encodings for monitor, JPEG quality and frame rate), so a server that does not know them simply ignores
/// them - viewers and computers can be updated in any order.
/// </summary>
public sealed record VideoPreferences(PictureQuality Quality = PictureQuality.Lossless, int MaxFps = 30, int Monitor = 0)
{
    public int JpegQuality => Quality == PictureQuality.LowBandwidth ? 50 : 80;

    public int[] ToEncodings()
    {
        var list = new List<int>();
        if (Quality is PictureQuality.Balanced or PictureQuality.LowBandwidth) list.Add(Rfb.EncodingJpegRect);
        if (Quality == PictureQuality.Colors16) list.Add(Rfb.EncodingZlib16Rect);
        list.Add(Rfb.EncodingZlibRect);
        list.Add(Rfb.EncodingRaw);
        list.Add(Rfb.PseudoEncodingDesktopSize);
        list.Add(Rfb.PseudoMonitorList);
        list.Add(Rfb.PseudoMonitorSelectBase - Math.Clamp(Monitor, 0, 16));
        list.Add(Rfb.PseudoJpegQualityBase - Math.Clamp(JpegQuality, 10, 95));
        list.Add(Rfb.PseudoMaxFpsBase - Math.Clamp(MaxFps, 1, 60));
        return [.. list];
    }
}

public enum RectMode { Zlib, Jpeg, Zlib16 }

/// <summary>The server's reading of a SetEncodings message.</summary>
public sealed record VideoChoice(RectMode Mode, int JpegQuality, int MaxFps, int Monitor, bool WantsMonitorList)
{
    public static readonly VideoChoice Default = new(RectMode.Zlib, 80, 60, 0, false);

    public static VideoChoice Parse(IReadOnlyList<int> encodings)
    {
        var mode = RectMode.Zlib;
        // The first encoding we know decides the rectangle format (RFB: the client lists them in order of preference).
        foreach (var e in encodings)
        {
            if (e == Rfb.EncodingJpegRect) { mode = RectMode.Jpeg; break; }
            if (e == Rfb.EncodingZlib16Rect) { mode = RectMode.Zlib16; break; }
            if (e is Rfb.EncodingZlibRect or Rfb.EncodingRaw) break;
        }
        int quality = 80, fps = 60, monitor = 0;
        foreach (var e in encodings)
        {
            if (e <= Rfb.PseudoMonitorSelectBase && e >= Rfb.PseudoMonitorSelectBase - 16) monitor = Rfb.PseudoMonitorSelectBase - e;
            else if (e <= Rfb.PseudoJpegQualityBase - 10 && e >= Rfb.PseudoJpegQualityBase - 95) quality = Rfb.PseudoJpegQualityBase - e;
            else if (e <= Rfb.PseudoMaxFpsBase - 1 && e >= Rfb.PseudoMaxFpsBase - 60) fps = Rfb.PseudoMaxFpsBase - e;
        }
        return new VideoChoice(mode, quality, fps, monitor, encodings.Contains(Rfb.PseudoMonitorList));
    }
}
