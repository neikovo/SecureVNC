using System.Drawing;
using System.Drawing.Imaging;
using System.IO.Compression;
using SecureVNC.Shared.Protocol;

namespace SecureVNC.Server;

/// <summary>
/// Finds changed 64x64 tiles against the previous frame and encodes them as the viewer prefers:
/// zlib (lossless), JPEG (lossy, small) or zlib of 16-bit colour.
/// </summary>
internal sealed class FrameEncoder
{
    private const int Tile = 64;
    private byte[] _prev = [];
    private int _w, _h;
    private byte[] _scratch = [];
    private readonly MemoryStream _zbuf = new();

    public void Reset() => _w = _h = 0;

    /// <summary>Returns the changed regions; all of the frame if the size changed or a full update was asked for.</summary>
    public List<Rectangle> Diff(ReadOnlySpan<byte> cur, int w, int h, bool full)
    {
        if (w != _w || h != _h)
        {
            _prev = new byte[w * h * 4];
            _w = w;
            _h = h;
            full = true;
        }
        var rects = new List<Rectangle>();
        if (full)
        {
            rects.Add(new Rectangle(0, 0, w, h));
        }
        else
        {
            int stride = w * 4, tilesX = (w + Tile - 1) / Tile;
            var dirty = new bool[tilesX];
            for (int ty = 0; ty < h; ty += Tile)
            {
                int th = Math.Min(Tile, h - ty);
                Array.Clear(dirty);
                for (int tx = 0; tx < tilesX; tx++)
                {
                    int x0 = tx * Tile, bytes = Math.Min(Tile, w - x0) * 4;
                    for (int row = 0; row < th; row++)
                    {
                        int off = (ty + row) * stride + x0 * 4;
                        if (!cur.Slice(off, bytes).SequenceEqual(_prev.AsSpan(off, bytes)))
                        {
                            dirty[tx] = true;
                            break;
                        }
                    }
                }
                for (int tx = 0; tx < tilesX;)
                {
                    if (!dirty[tx]) { tx++; continue; }
                    int start = tx;
                    while (tx < tilesX && dirty[tx]) tx++;
                    int x0 = start * Tile, x1 = Math.Min(tx * Tile, w);
                    AddMerged(rects, new Rectangle(x0, ty, x1 - x0, th));
                }
            }
        }
        cur.CopyTo(_prev);
        return rects;
    }

    // Merge with a rectangle directly above that has the same horizontal span.
    private static void AddMerged(List<Rectangle> rects, Rectangle r)
    {
        for (int i = rects.Count - 1; i >= 0; i--)
        {
            var p = rects[i];
            if (p.Bottom < r.Top) break;
            if (p.X == r.X && p.Width == r.Width && p.Bottom == r.Top)
            {
                rects[i] = new Rectangle(p.X, p.Y, p.Width, p.Height + r.Height);
                return;
            }
        }
        rects.Add(r);
    }

    private static readonly ImageCodecInfo JpegCodec = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
    private readonly MemoryStream _jpeg = new();

    /// <summary>Appends one rectangle (header + payload) of the current frame to the update message.</summary>
    public void EncodeRect(RfbWriter w, ReadOnlySpan<byte> frame, int frameWidth, Rectangle r, VideoChoice? video = null)
    {
        int rowBytes = r.Width * 4, len = rowBytes * r.Height;
        if (_scratch.Length < len) _scratch = new byte[len];
        for (int row = 0; row < r.Height; row++)
            frame.Slice(((r.Y + row) * frameWidth + r.X) * 4, rowBytes).CopyTo(_scratch.AsSpan(row * rowBytes));

        switch (video?.Mode)
        {
            case RectMode.Jpeg:
                EncodeJpeg(w, r, video.JpegQuality);
                return;
            case RectMode.Zlib16:
                EncodeZlib16(w, r);
                return;
        }

        _zbuf.SetLength(0);
        using (var z = new ZLibStream(_zbuf, CompressionLevel.Fastest, leaveOpen: true))
            z.Write(_scratch, 0, len);

        w.U16((ushort)r.X).U16((ushort)r.Y).U16((ushort)r.Width).U16((ushort)r.Height);
        if (_zbuf.Length < len)
        {
            w.S32(Rfb.EncodingZlibRect).U32((uint)_zbuf.Length).Bytes(_zbuf.GetBuffer().AsSpan(0, (int)_zbuf.Length));
        }
        else
        {
            w.S32(Rfb.EncodingRaw).Bytes(_scratch.AsSpan(0, len));
        }
    }

    private void EncodeJpeg(RfbWriter w, Rectangle r, int quality)
    {
        using (var bmp = new Bitmap(r.Width, r.Height, PixelFormat.Format32bppRgb))
        {
            var data = bmp.LockBits(new Rectangle(0, 0, r.Width, r.Height), ImageLockMode.WriteOnly, PixelFormat.Format32bppRgb);
            try
            {
                for (int row = 0; row < r.Height; row++)
                    System.Runtime.InteropServices.Marshal.Copy(_scratch, row * r.Width * 4, data.Scan0 + row * data.Stride, r.Width * 4);
            }
            finally
            {
                bmp.UnlockBits(data);
            }
            using var parameters = new EncoderParameters(1);
            parameters.Param[0] = new EncoderParameter(Encoder.Quality, (long)quality);
            _jpeg.SetLength(0);
            bmp.Save(_jpeg, JpegCodec, parameters);
        }
        w.U16((ushort)r.X).U16((ushort)r.Y).U16((ushort)r.Width).U16((ushort)r.Height)
            .S32(Rfb.EncodingJpegRect).U32((uint)_jpeg.Length).Bytes(_jpeg.GetBuffer().AsSpan(0, (int)_jpeg.Length));
    }

    private byte[] _rgb565 = [];

    private void EncodeZlib16(RfbWriter w, Rectangle r)
    {
        int pixels = r.Width * r.Height;
        if (_rgb565.Length < pixels * 2) _rgb565 = new byte[pixels * 2];
        for (int i = 0; i < pixels; i++)
        {
            int b = _scratch[i * 4], g = _scratch[i * 4 + 1], red = _scratch[i * 4 + 2];
            int v = ((red >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
            _rgb565[i * 2] = (byte)v;
            _rgb565[i * 2 + 1] = (byte)(v >> 8);
        }
        _zbuf.SetLength(0);
        using (var z = new ZLibStream(_zbuf, CompressionLevel.Fastest, leaveOpen: true))
            z.Write(_rgb565, 0, pixels * 2);
        w.U16((ushort)r.X).U16((ushort)r.Y).U16((ushort)r.Width).U16((ushort)r.Height)
            .S32(Rfb.EncodingZlib16Rect).U32((uint)_zbuf.Length).Bytes(_zbuf.GetBuffer().AsSpan(0, (int)_zbuf.Length));
    }
}
