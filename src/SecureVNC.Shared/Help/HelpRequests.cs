using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Shared.Help;

/// <summary>What a colleague's computer announces when they click "Request help" in the tray.</summary>
public sealed class HelpRequest
{
    public int V { get; set; } = 1;
    public string Id { get; set; } = "";
    /// <summary>Name in the computer's certificate.</summary>
    public string Computer { get; set; } = "";
    /// <summary>Windows user signed in on that computer.</summary>
    public string User { get; set; } = "";
    public string Text { get; set; } = "";
    public long IssuedUnix { get; set; }
}

/// <summary>A request that passed every check, plus where it came from.</summary>
public sealed record VerifiedHelpRequest(HelpRequest Request, IPAddress Source, string ConnectTo, DateTime ReceivedLocal);

/// <summary>
/// "Request help" (phase A): a signed UDP broadcast on the local network. The request is only a notice and never
/// grants access - logging in stays password + code (+ ticket). It is signed with the computer's certificate key,
/// so a viewer shows it only when the certificate chains to a CA it already trusts, the name matches and it is fresh;
/// "Connect" goes to the computer named in that certificate, never to an address someone merely claims.
///
/// Packet: "SVNCHELP1" | u16 payload length | payload (JSON) | u16 certificate length | certificate (DER) | u16 signature length | signature
/// </summary>
public static class HelpRequests
{
    public const int Port = 5904;
    public const int MaxTextLength = 200;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SVNCHELP1");
    private static readonly byte[] SigningContext = Encoding.ASCII.GetBytes("SecureVNC-help-v1\n");
    private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(2);

    /// <summary>Builds and signs a request with the computer's certificate (must hold its private key).</summary>
    public static byte[] Create(X509Certificate2 computerCertificate, string user, string text, DateTimeOffset? issued = null, string? computer = null)
    {
        var request = new HelpRequest
        {
            Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)),
            Computer = computer ?? Tickets.MyRegisteredName(computerCertificate),
            User = Clean(user, 64),
            Text = Clean(text, MaxTextLength),
            IssuedUnix = (issued ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
        };
        var payload = JsonSerializer.SerializeToUtf8Bytes(request, ServerConfig.Json);
        using var key = computerCertificate.GetECDsaPrivateKey() ?? throw new InvalidOperationException("The certificate has no ECDSA private key.");
        var signature = key.SignData((byte[])[.. SigningContext, .. payload], HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var cert = computerCertificate.RawData;

        var packet = new byte[Magic.Length + 2 + payload.Length + 2 + cert.Length + 2 + signature.Length];
        int at = 0;
        void Put(ReadOnlySpan<byte> data) { data.CopyTo(packet.AsSpan(at)); at += data.Length; }
        void PutLength(int n) { BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(at), (ushort)n); at += 2; }
        Put(Magic);
        PutLength(payload.Length); Put(payload);
        PutLength(cert.Length); Put(cert);
        PutLength(signature.Length); Put(signature);
        return packet;
    }

    /// <summary>All checks; throws with the reason when the packet must not be shown.</summary>
    public static VerifiedHelpRequest Verify(byte[] packet, IPAddress source, X509Certificate2Collection trustedCas)
    {
        if (packet.Length > 4000 || !packet.AsSpan().StartsWith(Magic)) throw new InvalidDataException("Not a SecureVNC help request.");
        int at = Magic.Length;
        byte[] Take()
        {
            if (at + 2 > packet.Length) throw new InvalidDataException("Truncated help request.");
            int n = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(at));
            at += 2;
            if (n == 0 || at + n > packet.Length) throw new InvalidDataException("Truncated help request.");
            var part = packet.AsSpan(at, n).ToArray();
            at += n;
            return part;
        }
        var payload = Take();
        using var cert = new X509Certificate2(Take());
        var signature = Take();

        if (trustedCas.Count == 0 || !Chains(cert, trustedCas))
            throw new CryptographicException("The computer's certificate is not from a CA this viewer trusts.");
        using (var key = cert.GetECDsaPublicKey() ?? throw new CryptographicException("No ECDSA key."))
        {
            if (!key.VerifyData((byte[])[.. SigningContext, .. payload], signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new CryptographicException("Bad signature.");
        }
        var request = JsonSerializer.Deserialize<HelpRequest>(payload, ServerConfig.Json) ?? throw new InvalidDataException("Empty request.");
        if (request.V != 1) throw new InvalidDataException("Unknown version.");
        var certName = Tickets.MyRegisteredName(cert);
        if (!string.Equals(request.Computer, certName, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException($"The request says {request.Computer}, the certificate is for {certName}.");
        var age = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(request.IssuedUnix);
        if (age > MaxAge || age < -MaxAge) throw new InvalidDataException("The request is too old (or the clocks differ a lot).");
        request.User = Clean(request.User, 64);
        request.Text = Clean(request.Text, MaxTextLength);

        // Connect to the address the request came from only if the certificate itself names it; otherwise to the name.
        var src = source.IsIPv4MappedToIPv6 ? source.MapToIPv4() : source;
        string connectTo = CertificateManager.SanAddresses(cert).Contains(src) ? src.ToString() : certName;
        return new VerifiedHelpRequest(request, src, connectTo, DateTime.Now);
    }

    private static bool Chains(X509Certificate2 leaf, X509Certificate2Collection roots)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        return chain.Build(leaf);
    }

    /// <summary>One line, no control characters, limited length.</summary>
    public static string Clean(string? text, int max)
    {
        var s = Log.OneLine(text).Trim();
        return s.Length <= max ? s : s[..max];
    }

    /// <summary>Sends the request to the broadcast address of every LAN interface (3 times: UDP may drop a packet).</summary>
    public static void Broadcast(byte[] packet, IEnumerable<IPEndPoint>? targets = null)
    {
        var endpoints = (targets ?? BroadcastTargets()).ToList();
        using var udp = new UdpClient(AddressFamily.InterNetwork) { EnableBroadcast = true };
        for (int round = 0; round < 3; round++)
        {
            foreach (var ep in endpoints)
            {
                try { udp.Send(packet, packet.Length, ep); }
                catch (SocketException ex) { Log.Info($"Help request to {ep} failed: {ex.Message}"); }
            }
            Thread.Sleep(300);
        }
    }

    private static IEnumerable<IPEndPoint> BroadcastTargets()
    {
        var targets = new HashSet<IPAddress> { IPAddress.Broadcast };
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask is null) continue;
                var ip = ua.Address.GetAddressBytes();
                var mask = ua.IPv4Mask.GetAddressBytes();
                var bcast = new byte[4];
                for (int i = 0; i < 4; i++) bcast[i] = (byte)(ip[i] | ~mask[i]);
                targets.Add(new IPAddress(bcast));
            }
        }
        return targets.Select(a => new IPEndPoint(a, Port));
    }
}

/// <summary>
/// Viewer side: listens on UDP 5904, verifies every packet, drops repeats (the same request arrives up to 3 times per
/// interface) and floods (one notice per computer per 30 seconds).
/// </summary>
public sealed class HelpListener : IDisposable
{
    private readonly UdpClient _udp;
    private readonly Func<X509Certificate2Collection> _trustedCas;
    private readonly ConcurrentDictionary<string, DateTime> _seenIds = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastPerComputer = new();
    private readonly CancellationTokenSource _cts = new();

    public event Action<VerifiedHelpRequest>? Received;
    public event Action<string>? Rejected;

    public HelpListener(Func<X509Certificate2Collection> trustedCas, int port = HelpRequests.Port, IPAddress? bind = null)
    {
        _trustedCas = trustedCas;
        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(bind ?? IPAddress.Any, port));
        _ = Task.Run(LoopAsync);
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            UdpReceiveResult packet;
            try
            {
                packet = await _udp.ReceiveAsync(_cts.Token);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { continue; }

            try
            {
                var verified = HelpRequests.Verify(packet.Buffer, packet.RemoteEndPoint.Address, _trustedCas());
                var now = DateTime.UtcNow;
                foreach (var (id, t) in _seenIds) if (now - t > TimeSpan.FromMinutes(10)) _seenIds.TryRemove(id, out _);
                if (!_seenIds.TryAdd(verified.Request.Id, now)) continue;   // repeat of a request already shown
                var computer = verified.Request.Computer.ToUpperInvariant();
                if (_lastPerComputer.TryGetValue(computer, out var last) && now - last < TimeSpan.FromSeconds(30)) continue;
                _lastPerComputer[computer] = now;
                Received?.Invoke(verified);
            }
            catch (Exception ex)
            {
                Rejected?.Invoke($"{packet.RemoteEndPoint.Address}: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _udp.Dispose();
    }
}
