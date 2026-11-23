namespace SecureVNC.Shared.Protocol;

/// <summary>
/// RFB (VNC) protocol constants, RFC 6143, plus the SecureVNC extensions.
/// The whole RFB session runs inside TLS; the SecureVNC security type carries
/// username + password + TOTP code.
/// </summary>
public static class Rfb
{
    public const string ProtocolVersion = "RFB 003.008\n";
    public const int DefaultPort = 5901;

    // Security
    public const byte SecurityTypeSecureVnc = 0x80;   // SecureVNC: CA delivery + password + TOTP (checked on the computer)
    public const byte SecurityTypeTicket = 0x81;      // SecureVNC central mode: CA + name + auth server + nonce, then a signed ticket
    public const int MaxTicketBytes = 4096;
    public const int TicketNonceBytes = 32;
    public const uint SecurityResultOk = 0;
    public const uint SecurityResultFailed = 1;
    public const int MaxUserNameBytes = 64;
    public const int MaxPasswordBytes = 128;
    public const int TotpCodeLength = 6;

    // Client -> server messages
    public const byte ClientSetPixelFormat = 0;
    public const byte ClientSetEncodings = 2;
    public const byte ClientFramebufferUpdateRequest = 3;
    public const byte ClientKeyEvent = 4;                // X11 keysym (not used by our client)
    public const byte ClientPointerEvent = 5;
    public const byte ClientCutText = 6;
    public const byte ClientWinKeyEvent = 250;           // SecureVNC: Windows VK + scan code
    public const byte ClientCtrlAltDel = 251;            // SecureVNC: secure attention sequence (no payload)

    // Server -> client messages
    public const byte ServerFramebufferUpdate = 0;
    public const byte ServerBell = 2;
    public const byte ServerCutText = 3;

    // Encodings
    public const int EncodingRaw = 0;
    public const int EncodingZlibRect = -512;            // SecureVNC: independent zlib stream per rectangle
    public const int PseudoEncodingDesktopSize = -223;

    // Pointer button mask bits
    public const byte ButtonLeft = 1, ButtonMiddle = 2, ButtonRight = 4;
    public const byte WheelUp = 8, WheelDown = 16, WheelLeft = 32, WheelRight = 64;

    /// <summary>Writes the only pixel format SecureVNC uses: 32bpp BGRX little endian (Windows DIB layout).</summary>
    public static void WritePixelFormat(RfbWriter w)
    {
        w.U8(32)        // bits per pixel
         .U8(24)        // depth
         .U8(0)         // big endian
         .U8(1)         // true colour
         .U16(255).U16(255).U16(255)  // red/green/blue max
         .U8(16).U8(8).U8(0)          // red/green/blue shift
         .U8(0).U8(0).U8(0);          // padding
    }
}

public sealed class ProtocolException(string message) : Exception(message);
