using System.Collections.Concurrent;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Shared.Central;

/// <summary>
/// What a ticket says. The auth server signs it with the organization CA key after checking password + code;
/// the password itself never reaches the computer.
/// </summary>
public sealed class TicketPayload
{
    public int V { get; set; } = 1;
    /// <summary>Random ticket number; the computer confirms it with the auth server, which accepts it once.</summary>
    public string Id { get; set; } = "";
    public string User { get; set; } = "";
    /// <summary>The only computer this ticket is for (its registered name).</summary>
    public string Computer { get; set; } = "";
    /// <summary>Address the auth server saw the viewer on: the computer accepts the ticket only from there.</summary>
    public string ClientAddress { get; set; } = "";
    /// <summary>Random value the computer chose for this one connection: the ticket is useless on any other.</summary>
    public string Nonce { get; set; } = "";
    public long IssuedUnix { get; set; }
}

/// <summary>
/// Ticket login (central mode):
///   1. computer -> viewer: its name, the auth server address and a fresh nonce (inside the TLS session)
///   2. viewer -> auth server: user + password + code + computer + nonce        (only the auth server sees the password)
///   3. auth server -> viewer: ticket signed by the organization CA (user, computer, viewer address, nonce)
///   4. viewer -> computer: the ticket; the computer checks signature, its own name, the nonce and the viewer's address
///   5. computer -> auth server (its own certificate): "confirm ticket N" - the auth server confirms that it issued
///      exactly this ticket for this computer and marks it used. Then the session starts.
/// </summary>
public static class Tickets
{
    /// <summary>Marks the auth server's own TLS certificate; computers never get it, so none can pose as the auth server.</summary>
    public const string AuthServerEkuOid = "2.25.91737413245203036390393277034487519368";
    private const string SigningContext = "SecureVNC-ticket-v1\n";
    private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(10);   // generous for clock differences; the nonce makes it one-shot

    public static (byte[] Ticket, byte[] Signature) Sign(TicketPayload payload, ECDsa caKey)
    {
        var ticket = JsonSerializer.SerializeToUtf8Bytes(payload, ServerConfig.Json);
        return (ticket, caKey.SignData(Signed(ticket), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    private static byte[] Signed(byte[] ticket) => [.. Encoding.ASCII.GetBytes(SigningContext), .. ticket];

    /// <summary>Computer side, step 4. Returns the payload, or throws with the reason.</summary>
    public static TicketPayload Check(byte[] ticket, byte[] signature, X509Certificate2 organizationCa,
        string myName, byte[] nonce, string viewerAddress)
    {
        using var key = organizationCa.GetECDsaPublicKey() ?? throw new AuthenticationException("The CA has no ECDSA key.");
        if (!key.VerifyData(Signed(ticket), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new AuthenticationException("The ticket is not signed by the auth server.");
        var payload = JsonSerializer.Deserialize<TicketPayload>(ticket, ServerConfig.Json) ?? throw new AuthenticationException("Empty ticket.");
        if (payload.V != 1) throw new AuthenticationException("Unknown ticket version.");
        if (!string.Equals(payload.Computer, myName, StringComparison.OrdinalIgnoreCase))
            throw new AuthenticationException($"The ticket is for {payload.Computer}, not for this computer.");
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(payload.Nonce), nonce))
            throw new AuthenticationException("The ticket belongs to another connection.");
        if (payload.ClientAddress != viewerAddress)
            throw new AuthenticationException($"The ticket was issued to {payload.ClientAddress}, but the viewer connects from {viewerAddress}.");
        var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(payload.IssuedUnix);
        if (age > MaxAge || age < -MaxAge) throw new AuthenticationException("The ticket has expired.");
        if (!UserStore.IsValidName(payload.User)) throw new AuthenticationException("Bad user name in the ticket.");
        return payload;
    }

    /// <summary>Registered name of this computer: the name in the certificate the auth server issued.</summary>
    public static string MyRegisteredName(X509Certificate2 myCertificate) =>
        myCertificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

    /// <summary>
    /// Viewer side, steps 2-3. The auth server must present a certificate from the same organization CA the computer
    /// chains to, carrying the auth-server mark, for the address used.
    /// </summary>
    public static CentralResponse RequestTicket(string authServer, X509Certificate2 organizationCa, string user, string password,
        string code, string computer, byte[] nonce)
    {
        var (host, port) = CentralProtocol.ParseAddress(authServer);
        using var tcp = new TcpClient();
        try
        {
            if (!tcp.ConnectAsync(host, port).Wait(TimeSpan.FromSeconds(5))) throw new IOException("no answer");
        }
        catch (Exception ex)
        {
            throw new IOException($"The SecureVNC authentication server ({host}:{port}) is not reachable. Try again later.", ex);
        }
        var ns = tcp.GetStream();
        ns.ReadTimeout = ns.WriteTimeout = 15_000;
        using var ssl = new SslStream(ns, false, (_, cert, _, _) => cert is not null && IsAuthServer(new X509Certificate2(cert), host, organizationCa));
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        });
        CentralProtocol.Write(ssl, new CentralRequest
        {
            Op = "ticket", User = user, Password = password, Code = code, Computer = computer, Nonce = Convert.ToBase64String(nonce),
        });
        return CentralProtocol.Read<CentralResponse>(ssl);
    }

    public static bool IsAuthServer(X509Certificate2 leaf, string host, X509Certificate2 organizationCa)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(organizationCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(AuthServerEkuOid));
        return chain.Build(leaf) && leaf.MatchesHostname(host, allowWildcards: false, allowCommonName: false);
    }
}

/// <summary>Auth server side: tickets issued in the last minutes, each confirmable once by its computer.</summary>
public sealed class TicketBook
{
    private sealed record Entry(TicketPayload Payload, DateTime ExpiresUtc);
    private static readonly TimeSpan Life = TimeSpan.FromMinutes(2);
    private readonly ConcurrentDictionary<string, Entry> _open = new();

    public void Add(TicketPayload payload)
    {
        foreach (var (id, e) in _open)
            if (e.ExpiresUtc < DateTime.UtcNow) _open.TryRemove(id, out _);
        _open[payload.Id] = new Entry(payload, DateTime.UtcNow + Life);
    }

    /// <summary>Removes and returns the ticket when it exists, has not expired and was issued for this computer.</summary>
    public TicketPayload? Confirm(string id, string computer, string nonce)
    {
        if (!_open.TryRemove(id, out var e)) return null;   // unknown, or already confirmed once
        if (e.ExpiresUtc < DateTime.UtcNow) return null;
        if (!string.Equals(e.Payload.Computer, computer, StringComparison.OrdinalIgnoreCase)) return null;
        if (e.Payload.Nonce != nonce) return null;
        return e.Payload;
    }
}
