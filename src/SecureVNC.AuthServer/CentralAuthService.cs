using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

namespace SecureVNC.AuthServer;

/// <summary>
/// SecureVNC Auth Server: administrators (password + Google Authenticator) are kept here, computers ask it
/// to check every login. Computers join with the join key and get a certificate from the organization CA,
/// which they then use to prove who they are. Every decision goes to the audit log.
/// </summary>
public sealed partial class CentralAuthService(AuthPaths paths)
{
    private readonly AuthConfig _config = AuthConfig.Load(paths);
    private readonly CancellationTokenSource _cts = new();
    private readonly object _credsLock = new();
    private AuthThrottle? _throttle;
    private TcpListener? _listener;
    private ServerCredentials? _creds;
    private DateTime _credsCheckedUtc;
    private X509Certificate2? _ca;
    private readonly ConnectionLimiter _limiter = new(maxTotal: 64, maxPerAddress: 8);

    public int Port => _config.Port;

    public void Start(string? listenAddress = null)
    {
        if (paths.IsInitialized) ServerPaths.Harden(paths.DataDir);   // ownership and links, see ServerPaths
        else AuthData.Initialize(paths, Log.Info);
        _ca = new X509Certificate2(File.ReadAllBytes(paths.CaCertFile));
        _throttle = new AuthThrottle(_config.MaxFailedAttempts, TimeSpan.FromMinutes(_config.LockoutMinutes));
        GetCredentials();

        var address = IPAddress.Parse(listenAddress ?? _config.ListenAddress);
        _listener = new TcpListener(address, _config.Port);
        if (address.Equals(IPAddress.IPv6Any)) _listener.Server.DualMode = true;
        _listener.Start();
        Log.Info($"Auth server listening on port {_config.Port}");
        _ = AcceptLoop();
    }

    public void Stop()
    {
        _cts.Cancel();
        _listener?.Stop();
        Log.Info("Auth server stopped");
    }

    private async Task AcceptLoop()
    {
        var allowed = _config.AllowedNetworks.Select(IPNetwork.Parse).ToList();
        while (!_cts.IsCancellationRequested)
        {
            TcpClient tcp;
            try
            {
                tcp = await _listener!.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception) when (_cts.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException ex)
            {
                Log.Info($"Accept failed: {ex.Message}");
                continue;
            }

            var ep = (IPEndPoint)tcp.Client.RemoteEndPoint!;
            var ip = ep.Address.IsIPv4MappedToIPv6 ? ep.Address.MapToIPv4() : ep.Address;
            if (!allowed.Any(n => n.Contains(ip)))
            {
                Log.Info($"{ip}: rejected, not in allowed networks");
                tcp.Dispose();
                continue;
            }
            if (!_limiter.TryEnter(ip, Log.Info))
            {
                tcp.Dispose();
                continue;
            }
            _ = Task.Run(() =>
            {
                try { Handle(tcp, ip); }
                finally { _limiter.Leave(ip); }
            });
        }
    }

    private void Handle(TcpClient tcp, IPAddress ip)
    {
        using var _ = tcp;
        try
        {
            var ns = tcp.GetStream();
            ns.ReadTimeout = ns.WriteTimeout = 15_000;
            using var ssl = new SslStream(ns, leaveInnerStreamOpen: false, ValidateComputerCertificate);
            ssl.AuthenticateAsServer(new SslServerAuthenticationOptions
            {
                ServerCertificateContext = GetCredentials().Context,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificateRequired = true,   // optional in practice: joining computers have none yet
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            });
            var computerCert = ssl.RemoteCertificate is null ? null : new X509Certificate2(ssl.RemoteCertificate);
            var request = CentralProtocol.Read<CentralRequest>(ssl);
            var response = request.Op switch
            {
                "enroll" => Enroll(request, ip),
                "renew" => WithComputer(computerCert, ip, c => Renew(request, c, ip), allowPending: true),
                "verify" => WithComputer(computerCert, ip, c => Verify(request, c, ip)),
                "ping" => WithComputer(computerCert, ip, c => new CentralResponse { Ok = true, MachineName = c.Name }),
                _ => new CentralResponse { Error = "Unknown request." },
            };
            CentralProtocol.Write(ssl, response);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException or InvalidDataException or System.Text.Json.JsonException)
        {
            Log.Info($"{ip}: {ex.Message}");
        }
        catch (Exception ex)
        {
            Log.Info($"{ip}: error: {ex}");
        }
    }

    /// <summary>A computer certificate, when sent, must come from the organization CA.</summary>
    private bool ValidateComputerCertificate(object sender, X509Certificate? cert, X509Chain? _, SslPolicyErrors errors)
    {
        if (cert is null) return true;   // joining computer; requests other than "enroll" are refused below
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_ca!);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));   // clientAuth
        return chain.Build(new X509Certificate2(cert));
    }

    private CentralResponse WithComputer(X509Certificate2? cert, IPAddress ip, Func<ComputerRecord, CentralResponse> action, bool allowPending = false)
    {
        if (cert is null) return new CentralResponse { Error = "This computer has not joined." };
        var computer = ComputerStore.Load(paths).BySerial(cert.SerialNumber);
        if (computer is null || computer.Revoked)
        {
            AuditLine($"REFUSED  computer certificate {cert.Subject} from {ip}: {(computer is null ? "unknown or deleted" : "blocked")} computer");
            return new CentralResponse { Error = computer is null ? "This computer is not registered. Join it again." : "This computer is blocked in the Auth Console." };
        }
        if (computer.Pending && !allowPending)
            return new CentralResponse { Error = "This computer waits for approval in the Auth Console." };
        return action(computer);
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")]
    private static partial Regex ComputerNamePattern();

    private CentralResponse Enroll(CentralRequest r, IPAddress ip)
    {
        string ipKey = $"enroll:{ip}";
        if (_throttle!.IsLocked(ipKey)) return new CentralResponse { Error = "Too many failed attempts. Try again later." };

        var expected = Encoding.ASCII.GetBytes(CentralProtocol.NormalizeJoinKey(AuthData.ReadJoinKey(paths)));
        var given = Encoding.ASCII.GetBytes(CentralProtocol.NormalizeJoinKey(r.JoinKey));
        if (!CryptographicOperations.FixedTimeEquals(expected, given))
        {
            _throttle.Fail(ipKey);
            AuditLine($"JOIN-REFUSED  {r.MachineName} from {ip}: wrong join key");
            Thread.Sleep(1000);
            return new CentralResponse { Error = "Wrong join key." };
        }
        _throttle.Success(ipKey);

        var name = r.MachineName ?? "";
        if (!ComputerNamePattern().IsMatch(name) || string.IsNullOrEmpty(r.PublicKey))
            return new CentralResponse { Error = "Bad request." };
        var guid = r.MachineGuid ?? "";

        // A name that belongs to another registered computer cannot be taken over (its certificate is what
        // viewers trust for that name). Remove the old entry in the Auth Console first.
        var computers = ComputerStore.Load(paths).Computers;
        if (computers.Any(c => c.Revoked && c.Same(name, guid)))
        {
            AuditLine($"JOIN-REFUSED  {name} from {ip}: the computer is blocked");
            return new CentralResponse { Error = "This computer is blocked in the Auth Console." };
        }
        var taken = computers.FirstOrDefault(c =>
            string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(c.MachineGuid, guid, StringComparison.OrdinalIgnoreCase));
        if (taken is not null)
        {
            AuditLine($"JOIN-REFUSED  {name} from {ip}: the name belongs to another registered computer");
            return new CentralResponse { Error = $"A computer named {name} is already registered. Remove it in the Auth Console first." };
        }

        var cert = Issue(name, guid, r.PublicKey, ip);
        bool pending = false;
        ComputerStore.Update(paths, store =>
        {
            var record = store.Computers.FirstOrDefault(c => c.Same(name, guid));
            if (record is null)
            {
                record = new ComputerRecord { Name = name, MachineGuid = guid, Pending = AuthConfig.Load(paths).RequireApproval };   // read now: changed in the Auth Console without restart
                store.Computers.Add(record);
            }
            pending = record.Pending;
            record.Serials = [cert.SerialNumber];   // joining again replaces the old certificates
            record.JoinedUtc = record.LastSeenUtc = DateTime.UtcNow;
            record.LastAddress = AuthData.Display(ip);
            return 0;
        });
        AuditLine($"JOINED  {name} from {ip}{(pending ? " - waits for approval" : "")}");
        return new CentralResponse
        {
            Ok = true, MachineName = name,
            Certificate = Convert.ToBase64String(cert.RawData),
            CaCertificate = Convert.ToBase64String(_ca!.RawData),
        };
    }

    private CentralResponse Renew(CentralRequest r, ComputerRecord computer, IPAddress ip)
    {
        if (string.IsNullOrEmpty(r.PublicKey)) return new CentralResponse { Error = "Bad request." };
        var cert = Issue(computer.Name, computer.MachineGuid, r.PublicKey, ip);
        ComputerStore.Update(paths, store =>
        {
            var record = store.BySerial(computer.Serials[0]);
            if (record is null) return 0;
            record.Serials.Add(cert.SerialNumber);
            if (record.Serials.Count > 3) record.Serials.RemoveAt(0);
            record.LastSeenUtc = DateTime.UtcNow;
            record.LastAddress = AuthData.Display(ip);
            return 0;
        });
        AuditLine($"RENEWED  {computer.Name} at {ip}");
        return new CentralResponse
        {
            Ok = true, MachineName = computer.Name,
            Certificate = Convert.ToBase64String(cert.RawData),
            CaCertificate = Convert.ToBase64String(_ca!.RawData),
        };
    }

    private CentralResponse Verify(CentralRequest r, ComputerRecord computer, IPAddress ip)
    {
        var user = r.User ?? "";
        var client = r.ClientAddress ?? "?";
        string userKey = $"user:{user.ToLowerInvariant()}", clientKey = $"client:{client}";

        bool ok = !_throttle!.IsLocked(userKey) && !_throttle.IsLocked(clientKey)
                  && UserStore.Authenticate(paths.UsersFile, user, r.Password ?? "", r.Code ?? "");

        ComputerStore.Update(paths, store =>
        {
            if (store.BySerial(computer.Serials[^1]) is { } record)
            {
                record.LastSeenUtc = DateTime.UtcNow;
                record.LastAddress = AuthData.Display(ip);
            }
            return 0;
        });

        if (!ok)
        {
            _throttle.Fail(userKey);
            _throttle.Fail(clientKey);
            AuditLine($"LOGIN-FAILED  user '{user}' from {client} to {computer.Name} ({ip})");
            Thread.Sleep(1000);
            return new CentralResponse { Error = $"Login failed for '{user}'." };
        }
        _throttle.Success(userKey);
        _throttle.Success(clientKey);
        AuditLine($"LOGIN  user '{user}' from {client} to {computer.Name} ({ip})");
        return new CentralResponse { Ok = true, MachineName = computer.Name };
    }

    /// <summary>
    /// The certificate names only this computer: its name and the address the auth server sees it on.
    /// Addresses the computer claims are not used, so it cannot obtain a certificate for someone else's address.
    /// </summary>
    private X509Certificate2 Issue(string name, string machineGuid, string publicKeyBase64, IPAddress ip)
    {
        var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);

        // An address another registered computer used recently stays out of the certificate (DHCP reuse, or
        // someone taking the address of a computer that is off): viewers must not trust a stranger at that address.
        string address = AuthData.Display(ip);
        var holder = ComputerStore.Load(paths).Computers.FirstOrDefault(c =>
            !c.Revoked && !c.Same(name, machineGuid) && c.LastAddress == address &&
            c.LastSeenUtc > DateTime.UtcNow - CentralProtocol.ComputerCertificateLifetime - TimeSpan.FromDays(1));
        IPAddress[] ips = holder is null ? [ip] : [];
        if (holder is not null)
            AuditLine($"ADDRESS-IN-USE  {name}: {address} was used by {holder.Name}; certificate issued for the name only");

        using var ca = CertificateManager.LoadProtected(paths.CaKeyFile);
        return CertificateManager.IssueCertificate(ca, publicKey, name, [name, name + ".local"], ips, clientAuth: true,
            CentralProtocol.ComputerCertificateLifetime);
    }

    private void AuditLine(string line)
    {
        AuthData.Audit(paths, line);
        Log.Info(line);
    }

    private ServerCredentials GetCredentials()
    {
        lock (_credsLock)
        {
            if (_creds is null || DateTime.UtcNow - _credsCheckedUtc > TimeSpan.FromMinutes(1))
            {
                _creds = CertificateManager.EnsureLeaf(paths.CaKeyFile, paths.TlsCertFile, Log.Info);
                _credsCheckedUtc = DateTime.UtcNow;
            }
            return _creds;
        }
    }
}
