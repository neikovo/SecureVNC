using System.Drawing;
using System.Drawing.Imaging;
using System.IO.Compression;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureVNC.Shared.Protocol;

namespace SecureVNC.Client;

public sealed record ConnectOptions(string Host, int Port, string User, string Password, string Code);

/// <summary>How the user answered a certificate question.</summary>
public delegate bool TrustPrompt(X509Certificate2 ca, bool caChanged);

/// <summary>SecureVNC viewer side of the protocol. The frame buffer is a Bitmap guarded by FrameLock.</summary>
public sealed class RfbClient : IDisposable
{
    private readonly object _writeLock = new();
    private readonly RfbWriter _w = new();
    private TcpClient? _tcp;
    private SslStream? _ssl;
    private RfbReader? _r;
    private volatile bool _closing;
    private byte[] _pixels = [];
    private byte[] _compressed = [];

    public object FrameLock { get; } = new();
    public Bitmap? Frame { get; private set; }
    public int Width { get; private set; }
    public int Height { get; private set; }
    public string DesktopName { get; private set; } = "";
    public string TlsInfo { get; private set; } = "";

    public event Action<Rectangle>? RegionUpdated;
    public event Action? Resized;
    public event Action<Exception?>? Disconnected;

    public static RfbClient Connect(ConnectOptions o, TrustStore trust, TrustPrompt prompt)
    {
        var c = new RfbClient();
        try
        {
            c.DoConnect(o, trust, prompt);
            return c;
        }
        catch
        {
            c.Dispose();
            throw;
        }
    }

    private void DoConnect(ConnectOptions o, TrustStore trust, TrustPrompt prompt)
    {
        _tcp = new TcpClient();
        var connect = _tcp.ConnectAsync(o.Host, o.Port);
        if (!connect.Wait(TimeSpan.FromSeconds(8))) throw new TimeoutException($"No answer from {o.Host}:{o.Port}.");
        connect.GetAwaiter().GetResult();
        _tcp.NoDelay = true;
        var ns = _tcp.GetStream();
        ns.ReadTimeout = 30_000;

        // The certificate is checked after the handshake (below), before any secret is sent.
        X509Certificate2? leaf = null;
        _ssl = new SslStream(ns, false, (_, cert, _, _) =>
        {
            if (cert is not null) leaf = new X509Certificate2(cert);
            return cert is not null;
        });
        _ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = o.Host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        });
        TlsInfo = $"{_ssl.SslProtocol}, {_ssl.NegotiatedCipherSuite}";
        _r = new RfbReader(_ssl);

        var version = Encoding.ASCII.GetString(_r.ReadBytes(12));
        if (!version.StartsWith("RFB ")) throw new ProtocolException("Not a SecureVNC server.");
        Send(w => w.Bytes(Encoding.ASCII.GetBytes(Rfb.ProtocolVersion)));

        int count = _r.U8();
        if (count == 0) throw new AuthenticationException(_r.LengthPrefixedString(4096));
        if (!_r.ReadBytes(count).Contains(Rfb.SecurityTypeSecureVnc))
            throw new ProtocolException("The server does not offer SecureVNC authentication.");
        Send(w => w.U8(Rfb.SecurityTypeSecureVnc));

        uint caLen = _r.U32();
        if (caLen is 0 or > 65536) throw new ProtocolException("Bad CA certificate from server.");
        using var presentedCa = new X509Certificate2(_r.ReadBytes((int)caLen));
        VerifyServer(o.Host, leaf ?? throw new AuthenticationException("No server certificate."), presentedCa, trust, prompt);

        var user = Encoding.UTF8.GetBytes(o.User);
        var pass = Encoding.UTF8.GetBytes(o.Password);
        if (user.Length is 0 or > Rfb.MaxUserNameBytes) throw new ArgumentException("User name is empty or too long.");
        if (pass.Length > Rfb.MaxPasswordBytes) throw new ArgumentException("Password is too long.");
        if (o.Code.Length != Rfb.TotpCodeLength || !o.Code.All(char.IsAsciiDigit))
            throw new ArgumentException("The authenticator code must be 6 digits.");
        Send(w => w.U8((byte)user.Length).Bytes(user).U8((byte)pass.Length).Bytes(pass).Bytes(Encoding.ASCII.GetBytes(o.Code)));

        if (_r.U32() != Rfb.SecurityResultOk) throw new AuthenticationException(_r.LengthPrefixedString(4096));

        Send(w => w.U8(1));   // ClientInit: shared
        Width = _r.U16();
        Height = _r.U16();
        CheckScreenSize(Width, Height);
        var pf = _r.ReadBytes(16);
        if (pf[0] != 32) throw new ProtocolException("Unsupported pixel format.");
        DesktopName = _r.LengthPrefixedString(1024);
        Frame = new Bitmap(Math.Max(1, Width), Math.Max(1, Height), PixelFormat.Format32bppRgb);
        ns.ReadTimeout = Timeout.Infinite;

        Send(w => w.U8(Rfb.ClientSetEncodings).U8(0).U16(3)
            .S32(Rfb.EncodingZlibRect).S32(Rfb.EncodingRaw).S32(Rfb.PseudoEncodingDesktopSize));
    }

    /// <summary>
    /// Accepts the server only if its certificate is valid for the typed host name and chains to a CA
    /// this user trusts. A new CA needs the user's OK (fingerprint shown); a changed CA gets a warning.
    /// </summary>
    private static void VerifyServer(string host, X509Certificate2 leaf, X509Certificate2 presentedCa, TrustStore trust, TrustPrompt prompt)
    {
        if (!leaf.MatchesHostname(host, allowWildcards: false, allowCommonName: false))
            throw new AuthenticationException($"The server certificate is not valid for '{host}'. Use the computer name or its current IP address.");

        var known = trust.CaForHost(host);
        if (known is not null && TrustStore.ChainsTo(leaf, [known])) return;
        if (known is null && TrustStore.ChainsTo(leaf, trust.Imported()))
        {
            trust.TrustHost(host, presentedCa);
            return;
        }

        if (!TrustStore.IsCa(presentedCa) || !TrustStore.ChainsTo(leaf, [presentedCa]))
            throw new AuthenticationException("The server's certificate chain is invalid.");
        if (!prompt(presentedCa, caChanged: known is not null))
            throw new OperationCanceledException("Connection cancelled: the server certificate was not trusted.");
        trust.TrustHost(host, presentedCa);
    }

    public void Start()
    {
        new Thread(ReadLoop) { IsBackground = true, Name = "rfb reader" }.Start();
        RequestUpdate(incremental: false);
    }

    public void RequestUpdate(bool incremental) =>
        Send(w => w.U8(Rfb.ClientFramebufferUpdateRequest).U8((byte)(incremental ? 1 : 0))
            .U16(0).U16(0).U16((ushort)Width).U16((ushort)Height));

    public void SendPointer(byte mask, int x, int y) =>
        Send(w => w.U8(Rfb.ClientPointerEvent).U8(mask).U16((ushort)Math.Max(0, x)).U16((ushort)Math.Max(0, y)));

    public void SendKey(bool down, ushort vk, ushort scan, bool extended) =>
        Send(w => w.U8(Rfb.ClientWinKeyEvent).U8((byte)(down ? 1 : 0)).U16(vk).U16(scan).U16((ushort)(extended ? 1 : 0)));

    /// <summary>Works when the server runs as a service (login, lock screen, task manager menu).</summary>
    public void SendCtrlAltDel() => Send(w => w.U8(Rfb.ClientCtrlAltDel));

    private void Send(Action<RfbWriter> build)
    {
        lock (_writeLock)
        {
            if (_ssl is null) return;
            build(_w.Reset());
            try { _w.WriteTo(_ssl); }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                // A broken connection is reported once, by the reader thread.
            }
        }
    }

    private void ReadLoop()
    {
        Exception? error = null;
        try
        {
            while (true)
            {
                byte type = _r!.U8();
                switch (type)
                {
                    case Rfb.ServerFramebufferUpdate:
                        ReadUpdate();
                        RequestUpdate(incremental: true);
                        break;
                    case Rfb.ServerBell:
                        break;
                    case Rfb.ServerCutText:
                        _r.Skip(3);
                        uint len = _r.U32();
                        if (len > 8_000_000) throw new ProtocolException("Clipboard text too large.");
                        _r.Skip(len);
                        break;
                    default:
                        throw new ProtocolException($"Unknown server message {type}.");
                }
            }
        }
        catch (Exception ex)
        {
            if (!_closing) error = ex;
        }
        Disconnected?.Invoke(error);
    }

    private void ReadUpdate()
    {
        var r = _r!;
        r.Skip(1);
        int count = r.U16();
        Rectangle dirty = Rectangle.Empty;
        for (int i = 0; i < count; i++)
        {
            int x = r.U16(), y = r.U16(), w = r.U16(), h = r.U16();
            int encoding = r.S32();
            if (encoding != Rfb.PseudoEncodingDesktopSize && (x + w > Width || y + h > Height))
                throw new ProtocolException("Rectangle outside the screen.");
            switch (encoding)
            {
                case Rfb.PseudoEncodingDesktopSize:
                    CheckScreenSize(w, h);
                    lock (FrameLock)
                    {
                        Frame?.Dispose();
                        Frame = new Bitmap(Math.Max(1, w), Math.Max(1, h), PixelFormat.Format32bppRgb);
                        Width = w;
                        Height = h;
                    }
                    Resized?.Invoke();
                    continue;
                case Rfb.EncodingRaw:
                {
                    int len = w * h * 4;
                    EnsureCapacity(ref _pixels, len);
                    r.ReadExactly(_pixels.AsSpan(0, len));
                    break;
                }
                case Rfb.EncodingZlibRect:
                {
                    int clen = (int)r.U32();
                    if (clen > 64 * 1024 * 1024) throw new ProtocolException("Rectangle too large.");
                    EnsureCapacity(ref _compressed, clen);
                    r.ReadExactly(_compressed.AsSpan(0, clen));
                    int len = w * h * 4;
                    EnsureCapacity(ref _pixels, len);
                    using var z = new ZLibStream(new MemoryStream(_compressed, 0, clen), CompressionMode.Decompress);
                    z.ReadExactly(_pixels, 0, len);
                    break;
                }
                default:
                    throw new ProtocolException($"Unsupported encoding {encoding}.");
            }
            Blit(x, y, w, h);
            var rect = new Rectangle(x, y, w, h);
            dirty = dirty.IsEmpty ? rect : Rectangle.Union(dirty, rect);
        }
        if (!dirty.IsEmpty) RegionUpdated?.Invoke(dirty);
    }

    private unsafe void Blit(int x, int y, int w, int h)
    {
        if (w == 0 || h == 0) return;
        lock (FrameLock)
        {
            if (Frame is null || x + w > Frame.Width || y + h > Frame.Height || (long)w * h * 4 > _pixels.Length)
                throw new ProtocolException("Rectangle outside the screen.");
            var data = Frame.LockBits(new Rectangle(x, y, w, h), ImageLockMode.WriteOnly, PixelFormat.Format32bppRgb);
            try
            {
                int rowBytes = w * 4;
                fixed (byte* src = _pixels)
                {
                    for (int row = 0; row < h; row++)
                        Buffer.MemoryCopy(src + row * rowBytes, (byte*)data.Scan0 + row * data.Stride, rowBytes, rowBytes);
                }
            }
            finally
            {
                Frame.UnlockBits(data);
            }
        }
    }

    /// <summary>A malicious server must not make the client allocate gigabytes or overflow size calculations.</summary>
    private static void CheckScreenSize(int width, int height)
    {
        if (width > MaxScreenSide || height > MaxScreenSide)
            throw new ProtocolException($"Screen size {width}x{height} is not supported.");
    }

    private const int MaxScreenSide = 16384;   // 16384 x 16384 x 4 bytes = 1 GiB at most; real screens are far smaller

    private static void EnsureCapacity(ref byte[] buffer, int size)
    {
        if (buffer.Length < size) buffer = new byte[size];
    }

    public void Dispose()
    {
        _closing = true;
        try { _ssl?.Dispose(); } catch { /* ignore */ }
        _tcp?.Dispose();
    }
}
