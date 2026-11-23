using System.Diagnostics;
using System.Drawing;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Protocol;
using SecureVNC.Shared.Security;

namespace SecureVNC.Server;

/// <summary>
/// One connected viewer: TLS handshake, RFB handshake with password + TOTP,
/// then a reader thread (input) and an update thread (screen).
/// </summary>
internal sealed class ClientSession(
    TcpClient tcp, IPAddress remote, ServerConfig config, ServerCredentials creds, AuthThrottle throttle)
{
    private readonly object _writeLock = new();
    private readonly object _requestLock = new();
    private readonly InputInjector _input = new();
    private volatile bool _closed;
    private bool _requestPending, _requestFull;
    private SslStream? _ssl;

    public IPAddress Remote => remote;
    public string? UserName { get; private set; }
    public DateTime StartedAt { get; } = DateTime.Now;

    public event Action<ClientSession>? Authenticated;

    public void Run()
    {
        try
        {
            DesktopSwitcher.SyncThreadToInputDesktop();
            tcp.NoDelay = true;
            var ns = tcp.GetStream();
            ns.ReadTimeout = 30_000;    // the whole login must finish in time
            ns.WriteTimeout = 30_000;
            _ssl = new SslStream(ns, leaveInnerStreamOpen: false);
            _ssl.AuthenticateAsServer(new SslServerAuthenticationOptions
            {
                ServerCertificateContext = creds.Context,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificateRequired = false,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            });
            var r = new RfbReader(_ssl);
            if (!Handshake(r)) return;

            ns.ReadTimeout = Timeout.Infinite;
            Authenticated?.Invoke(this);
            Log.Info($"{remote}: user '{UserName}' connected ({_ssl.SslProtocol}, {_ssl.NegotiatedCipherSuite})");

            var updater = new Thread(UpdateLoop) { IsBackground = true, Name = $"updates {remote}" };
            updater.Start();
            ReadLoop(r);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException or ProtocolException or ObjectDisposedException or SocketException)
        {
            if (!_closed) Log.Info($"{remote}: {(UserName is null ? "handshake" : "session")} ended: {ex.Message}");
        }
        catch (Exception ex)
        {
            Log.Info($"{remote}: error: {ex}");
        }
        finally
        {
            if (UserName is not null) Log.Info($"{remote}: user '{UserName}' disconnected");
            Close();
            try { if (!config.ViewOnly) _input.ReleaseAll(); } catch { /* ignore */ }
        }
    }

    public void Close()
    {
        _closed = true;
        lock (_requestLock) Monitor.PulseAll(_requestLock);
        try { _ssl?.Dispose(); } catch { /* ignore */ }
        tcp.Dispose();
    }

    private bool Handshake(RfbReader r)
    {
        var w = new RfbWriter();
        Send(w.Reset().Bytes(Encoding.ASCII.GetBytes(Rfb.ProtocolVersion)));
        var version = Encoding.ASCII.GetString(r.ReadBytes(12));
        if (version != Rfb.ProtocolVersion) throw new ProtocolException($"Unsupported client version '{version.Trim()}'");

        string ipKey = $"ip:{remote}";
        if (throttle.IsLocked(ipKey))
        {
            Send(w.Reset().U8(0).LengthPrefixedString("Too many failed attempts. Try again later."));
            Log.Info($"{remote}: rejected, address is locked out");
            return false;
        }

        Send(w.Reset().U8(1).U8(Rfb.SecurityTypeSecureVnc));
        if (r.U8() != Rfb.SecurityTypeSecureVnc) throw new ProtocolException("Client chose an unsupported security type");

        // Send our CA so a new client can show its fingerprint for first-time trust.
        var ca = creds.CaCertificate.RawData;
        Send(w.Reset().U32((uint)ca.Length).Bytes(ca));

        int userLen = r.U8();
        if (userLen is 0 or > Rfb.MaxUserNameBytes) throw new ProtocolException("Bad user name length");
        var user = Encoding.UTF8.GetString(r.ReadBytes(userLen));
        int passLen = r.U8();
        if (passLen > Rfb.MaxPasswordBytes) throw new ProtocolException("Bad password length");
        var password = Encoding.UTF8.GetString(r.ReadBytes(passLen));
        var code = Encoding.ASCII.GetString(r.ReadBytes(Rfb.TotpCodeLength));

        string userKey = $"user:{user.ToLowerInvariant()}";
        var result = throttle.IsLocked(userKey)
            ? LoginResult.Failed
            : LoginVerifier.Verify(user, password, code, NetworkInfo.Display(remote));
        if (result != LoginResult.Ok)
        {
            string message = "Authentication failed.";
            if (result == LoginResult.Unavailable)
            {
                message = "The SecureVNC authentication server is not reachable. Try again later.";
                Log.Info($"{remote}: login for '{user}' not possible: auth server unreachable");
            }
            else
            {
                throttle.Fail(ipKey);
                throttle.Fail(userKey);
                Log.Info($"{remote}: failed login for '{user}'");
                Thread.Sleep(1000);
            }
            Send(w.Reset().U32(Rfb.SecurityResultFailed).LengthPrefixedString(message));
            return false;
        }
        throttle.Success(ipKey);
        throttle.Success(userKey);
        UserName = user;
        Send(w.Reset().U32(Rfb.SecurityResultOk));

        r.U8(); // ClientInit shared flag: sessions are always shared

        using var probe = new ScreenCapturer();
        probe.Capture();
        w.Reset().U16((ushort)probe.Width).U16((ushort)probe.Height);
        Rfb.WritePixelFormat(w);
        w.LengthPrefixedString(Environment.MachineName);
        Send(w);
        return true;
    }

    private void ReadLoop(RfbReader r)
    {
        while (!_closed)
        {
            byte type = r.U8();
            switch (type)
            {
                case Rfb.ClientSetPixelFormat:
                    r.Skip(3 + 16);   // always 32bpp BGRX
                    break;
                case Rfb.ClientSetEncodings:
                    r.Skip(1);
                    r.Skip(r.U16() * 4L);   // our client always supports ZlibRect + Raw + DesktopSize
                    break;
                case Rfb.ClientFramebufferUpdateRequest:
                    bool incremental = r.U8() != 0;
                    r.Skip(8);   // region: we always consider the whole screen
                    lock (_requestLock)
                    {
                        _requestPending = true;
                        if (!incremental) _requestFull = true;
                        Monitor.Pulse(_requestLock);
                    }
                    break;
                case Rfb.ClientKeyEvent:
                    r.Skip(7);   // X11 keysyms are not supported; our client sends WinKeyEvent
                    break;
                case Rfb.ClientPointerEvent:
                {
                    byte mask = r.U8();
                    int x = r.U16(), y = r.U16();
                    if (!config.ViewOnly)
                    {
                        DesktopSwitcher.SyncThreadToInputDesktop();   // input must go to the visible desktop
                        _input.Pointer(mask, x, y);
                    }
                    break;
                }
                case Rfb.ClientCutText:
                {
                    r.Skip(3);
                    uint len = r.U32();
                    if (len > 1_000_000) throw new ProtocolException("Clipboard text too large");
                    r.Skip(len);
                    break;
                }
                case Rfb.ClientWinKeyEvent:
                {
                    bool down = r.U8() != 0;
                    ushort vk = r.U16(), scan = r.U16(), flags = r.U16();
                    if (!config.ViewOnly)
                    {
                        DesktopSwitcher.SyncThreadToInputDesktop();
                        _input.Key(down, vk, scan, (flags & 1) != 0);
                    }
                    break;
                }
                case Rfb.ClientCtrlAltDel:
                    if (!config.ViewOnly)
                    {
                        bool sent = ServiceLink.RequestCtrlAltDel();
                        Log.Info($"{remote}: '{UserName}' sent Ctrl+Alt+Del{(sent ? "" : " (failed)")}");
                    }
                    break;
                default:
                    throw new ProtocolException($"Unknown client message {type}");
            }
        }
    }

    private void UpdateLoop()
    {
        var frameInterval = TimeSpan.FromMilliseconds(1000.0 / Math.Clamp(config.MaxFramesPerSecond, 1, 60));
        var clock = Stopwatch.StartNew();
        var lastFrame = TimeSpan.Zero - frameInterval;
        var encoder = new FrameEncoder();
        var w = new RfbWriter();
        int sentW = 0, sentH = 0;
        bool captureBlocked = false;
        using var capturer = new ScreenCapturer();
        try
        {
            while (!_closed)
            {
                bool full;
                lock (_requestLock)
                {
                    while (!_requestPending && !_closed) Monitor.Wait(_requestLock, 500);
                    if (_closed) break;
                    full = _requestFull;
                }

                var wait = lastFrame + frameInterval - clock.Elapsed;
                if (wait > TimeSpan.Zero) Thread.Sleep(wait);
                lastFrame = clock.Elapsed;

                if (DesktopSwitcher.SyncThreadToInputDesktop())
                {
                    capturer.ResetDesktop();
                    Log.Info($"{remote}: now showing desktop '{DesktopSwitcher.CurrentName}'");
                }
                if (!capturer.Capture())
                {
                    // Lock screen / UAC secure desktop cannot be read from the user session.
                    if (!captureBlocked) Log.Info($"{remote}: screen not readable (locked or secure desktop), waiting");
                    captureBlocked = true;
                    Thread.Sleep(200);
                    continue;
                }
                if (captureBlocked) Log.Info($"{remote}: screen readable again");
                captureBlocked = false;
                int cw = capturer.Width, ch = capturer.Height;
                bool resized = sentW != 0 && (cw != sentW || ch != sentH);
                var pixels = capturer.Pixels;
                List<Rectangle> rects = encoder.Diff(pixels, cw, ch, full || resized);
                if (rects.Count == 0) continue;   // nothing changed; the request stays pending

                lock (_requestLock)
                {
                    _requestPending = false;
                    if (full) _requestFull = false;
                }

                w.Reset().U8(Rfb.ServerFramebufferUpdate).U8(0).U16((ushort)(rects.Count + (resized ? 1 : 0)));
                if (resized)
                    w.U16(0).U16(0).U16((ushort)cw).U16((ushort)ch).S32(Rfb.PseudoEncodingDesktopSize);
                foreach (var rect in rects) encoder.EncodeRect(w, pixels, cw, rect);
                Send(w);
                sentW = cw;
                sentH = ch;
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            if (!_closed) Log.Info($"{remote}: update stream ended: {ex.Message}");
        }
        catch (Exception ex)
        {
            Log.Info($"{remote}: update error: {ex}");
        }
        finally
        {
            Close();
        }
    }

    private void Send(RfbWriter w)
    {
        lock (_writeLock) w.WriteTo(_ssl!);
    }
}
