using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SecureVNC.Shared.Security;

/// <summary>
/// RFC 6238 TOTP with the parameters Google Authenticator uses: HMAC-SHA1, 6 digits, 30 s.
/// </summary>
public static class Totp
{
    public const int Digits = 6;
    public const int StepSeconds = 30;

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    public static long CurrentStep(DateTimeOffset now) => now.ToUnixTimeSeconds() / StepSeconds;

    public static string Compute(ReadOnlySpan<byte> secret, long step)
    {
        Span<byte> msg = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(msg, step);
        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(secret, msg, hash);
        int off = hash[19] & 0x0F;
        int bin = ((hash[off] & 0x7F) << 24) | (hash[off + 1] << 16) | (hash[off + 2] << 8) | hash[off + 3];
        return (bin % 1_000_000).ToString("D6");
    }

    /// <summary>
    /// Checks the code against the current step ±window. Returns the matching step, or -1.
    /// The caller must reject steps it has already accepted (replay protection).
    /// </summary>
    public static long Verify(ReadOnlySpan<byte> secret, string code, DateTimeOffset now, int window = 1)
    {
        if (code is not { Length: Digits } || !code.All(char.IsAsciiDigit)) return -1;
        var given = Encoding.ASCII.GetBytes(code);
        long current = CurrentStep(now);
        long matched = -1;
        for (int i = -window; i <= window; i++)
        {
            var expected = Encoding.ASCII.GetBytes(Compute(secret, current + i));
            if (CryptographicOperations.FixedTimeEquals(expected, given)) matched = current + i;
        }
        return matched;
    }

    /// <summary>otpauth:// URI understood by Google Authenticator (and Microsoft Authenticator, Authy, ...).</summary>
    public static string BuildUri(string issuer, string account, ReadOnlySpan<byte> secret)
    {
        string i = Uri.EscapeDataString(issuer);
        return $"otpauth://totp/{i}:{Uri.EscapeDataString(account)}?secret={Base32.Encode(secret)}" +
               $"&issuer={i}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
    }
}

public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
            buffer &= (1 << bits) - 1;
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }
}
