using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

namespace SecureVNC.Shared.Central;

/// <summary>
/// Computer -> SecureVNC Auth Server, over TLS (port 5902). One request and one response per connection,
/// each a 4-byte big-endian length followed by UTF-8 JSON.
///   enroll  (no client certificate)  join key + public key            -> certificate from the organization CA
///   renew   (client certificate)     new public key                   -> new certificate (new IP address)
///   verify  (client certificate)     user + password + code + client  -> ok / failed
///   ping    (client certificate)                                      -> ok + computer name (status check)
///   ticket  (viewer, no certificate) user + password + code + computer + nonce -> signed ticket (see Tickets)
///   confirm (client certificate)     ticket number + nonce            -> ok + user, once per ticket
/// </summary>
public static class CentralProtocol
{
    public const int DefaultPort = 5902;

    /// <summary>
    /// Computer certificates live 7 days and are renewed after 3: a blocked computer cannot renew, so viewers stop
    /// trusting it within a week (viewers do not ask the auth server about blocked computers).
    /// </summary>
    public static readonly TimeSpan ComputerCertificateLifetime = TimeSpan.FromDays(7);
    public static readonly TimeSpan ComputerCertificateRenewBefore = TimeSpan.FromDays(4);
    private const int MaxMessageBytes = 64 * 1024;

    public static void Write<T>(Stream stream, T message)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, ServerConfig.Json);
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)body.Length);
        body.CopyTo(frame, 4);
        stream.Write(frame);
        stream.Flush();
    }

    public static T Read<T>(Stream stream)
    {
        Span<byte> header = stackalloc byte[4];
        stream.ReadExactly(header);
        uint length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length is 0 or > MaxMessageBytes) throw new InvalidDataException("Bad message length");
        var body = new byte[length];
        stream.ReadExactly(body);
        return JsonSerializer.Deserialize<T>(body, ServerConfig.Json) ?? throw new InvalidDataException("Empty message");
    }

    /// <summary>"AB:CD:..." or "abcd..." -> "ABCD...", for comparing fingerprints typed by people.</summary>
    public static string NormalizeFingerprint(string? text) =>
        new((text ?? "").Where(Uri.IsHexDigit).Select(char.ToUpperInvariant).ToArray());

    public static bool SameFingerprint(string? a, string? b)
    {
        var x = NormalizeFingerprint(a);
        return x.Length == 64 && x == NormalizeFingerprint(b);
    }

    /// <summary>New join key: 120 random bits, shown as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX.</summary>
    public static string NewJoinKey() =>
        string.Join("-", Base32.Encode(RandomNumberGenerator.GetBytes(15)).Chunk(4).Select(c => new string(c)));

    public static string NormalizeJoinKey(string? key) =>
        new((key ?? "").Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    public static (string Host, int Port) ParseAddress(string address)
    {
        address = address.Trim();
        int colon = address.LastIndexOf(':');
        if (colon > 0 && address.IndexOf(':') == colon && int.TryParse(address[(colon + 1)..], out int port))
            return (address[..colon], port);
        return (address, DefaultPort);
    }
}

public sealed class CentralRequest
{
    public string Op { get; set; } = "";
    public string? JoinKey { get; set; }
    public string? MachineName { get; set; }
    public string? MachineGuid { get; set; }
    /// <summary>SubjectPublicKeyInfo, base64.</summary>
    public string? PublicKey { get; set; }
    public string? User { get; set; }
    public string? Password { get; set; }
    public string? Code { get; set; }
    /// <summary>Address of the viewer that is logging in to the computer (for lockout and audit).</summary>
    public string? ClientAddress { get; set; }
    /// <summary>ticket: the computer the viewer wants; confirm: unused.</summary>
    public string? Computer { get; set; }
    /// <summary>ticket / confirm: the computer's nonce for this connection (base64).</summary>
    public string? Nonce { get; set; }
    /// <summary>confirm: the ticket number.</summary>
    public string? TicketId { get; set; }
}

public sealed class CentralResponse
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public string? MachineName { get; set; }
    /// <summary>Issued certificate (DER, base64).</summary>
    public string? Certificate { get; set; }
    /// <summary>Organization CA (DER, base64).</summary>
    public string? CaCertificate { get; set; }
    /// <summary>ticket: the signed ticket (JSON, base64) and its signature (base64).</summary>
    public string? Ticket { get; set; }
    public string? Signature { get; set; }
    /// <summary>confirm: the user the ticket was issued to.</summary>
    public string? User { get; set; }
}
