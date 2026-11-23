using System.IO.Pipes;
using System.Net;
using System.Net.Security;
using System.Security.AccessControl;
using System.Security.Principal;
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
/// SecureVNC Auth Server: administrators (password + Google Authenticator) are kept here, viewers get tickets here,
/// computers join with the join key and get a certificate from the organization CA. Every decision goes to the audit.
/// All secrets are sealed with the master password (see <see cref="Vault"/>): after a restart the server is locked -
/// it does not even listen on the network - until an administrator unlocks it in the Auth Console (local pipe).
/// </summary>
public sealed partial class CentralAuthService(AuthPaths paths)
{
    private AuthConfig _config = AuthConfig.Load(paths);
    private readonly CancellationTokenSource _cts = new();
    private readonly object _credsLock = new();
    private readonly object _stateLock = new();
    private readonly AuthThrottle _unlockThrottle = new(5, TimeSpan.FromMinutes(5));
    private AuthThrottle _throttle = new(5, TimeSpan.FromMinutes(5));
    private CancellationTokenSource? _listenCts;
    private TcpListener? _listener;
    private ServerCredentials? _creds;
    private DateTime _credsCheckedUtc;
    private X509Certificate2? _ca;
    private X509Certificate2? _caKey;
    private string? _listenAddress;
    private readonly ConnectionLimiter _limiter = new(maxTotal: 64, maxPerAddress: 8);
    private readonly TicketBook _tickets = new();

    public int Port => _config.Port;

    /// <summary>"not-set-up" (no master password yet), "locked" or "unlocked".</summary>
    public string State
    {
        get
        {
            lock (_stateLock) return !paths.IsInitialized ? "not-set-up" : _caKey is null ? "locked" : "unlocked";
        }
    }

    /// <summary>Starts locked: only the local unlock pipe runs until <see cref="Unlock"/>.</summary>
    public void Start(string? listenAddress = null, bool unlockPipe = true)
    {
        if (Directory.Exists(paths.DataDir)) ServerPaths.Harden(paths.DataDir);   // ownership and links, see ServerPaths
        AuthData.Prepare(paths);
        _config = AuthConfig.Load(paths);
        _listenAddress = listenAddress;
        if (unlockPipe) _ = Task.Run(PipeLoopAsync);
        Log.Info(State == "not-set-up"
            ? "Auth server waits for a master password (open the SecureVNC Auth Console)"
            : "Auth server is locked: enter the master password in the SecureVNC Auth Console");
    }

    public void Stop()
    {
        Lock("service stopping");
        _cts.Cancel();
        Log.Info("Auth server stopped");
    }

    /// <summary>Opens the vault with the master password and starts serving the network.</summary>
    public void Unlock(string masterPassword)
    {
        lock (_stateLock)
        {
            if (!paths.IsInitialized) throw new InvalidOperationException("No master password has been set yet.");
            if (_caKey is not null) return;
            if (_unlockThrottle.IsLocked("unlock")) throw new InvalidOperationException("Too many wrong master passwords. Wait 5 minutes.");
            try
            {
                Vault.Unlock(paths, masterPassword);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                _unlockThrottle.Fail("unlock");
                AuditLine("UNLOCK-FAILED  wrong master password");
                Thread.Sleep(1000);
                throw new InvalidOperationException("Wrong master password.");
            }
            _unlockThrottle.Success("unlock");
            _caKey = AuthData.OpenCa(paths);
            _ca = new X509Certificate2(File.ReadAllBytes(paths.CaCertFile));
            _throttle = new AuthThrottle(_config.MaxFailedAttempts, TimeSpan.FromMinutes(_config.LockoutMinutes));
            _creds = null;
            GetCredentials();

            var address = IPAddress.Parse(_listenAddress ?? _config.ListenAddress);
            _listenCts = new CancellationTokenSource();
            _listener = new TcpListener(address, _config.Port);
            if (address.Equals(IPAddress.IPv6Any)) _listener.Server.DualMode = true;
            _listener.Start();
            _ = AcceptLoop(_listener, _listenCts.Token);
            AuditLine($"UNLOCKED  auth server listening on port {_config.Port}");
        }
    }

    /// <summary>Forgets the keys and stops serving the network until the master password is entered again.</summary>
    public void Lock(string reason)
    {
        lock (_stateLock)
        {
            if (_caKey is null) return;
            _listenCts?.Cancel();
            _listener?.Stop();
            _caKey.Dispose();
            _caKey = null;
            lock (_credsLock) _creds = null;
            Vault.Lock();
            AuditLine($"LOCKED  ({reason})");
        }
    }

    /// <summary>Local pipe for the Auth Console: status, unlock, lock, administrator login check, join key.</summary>
    private async Task PipeLoopAsync()
    {
        var security = new PipeSecurity();
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = NamedPipeServerStreamAcl.Create(AuthPipe.Name, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
                await pipe.WaitForConnectionAsync(_cts.Token);
                var request = CentralProtocol.Read<AuthPipeRequest>(pipe);
                CentralProtocol.Write(pipe, HandlePipe(request));
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.Info($"Unlock pipe: {ex.Message}");
                try { await Task.Delay(500, _cts.Token); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private AuthPipeResponse HandlePipe(AuthPipeRequest r)
    {
        try
        {
            switch (r.Op)
            {
                case "status":
                    return new AuthPipeResponse { Ok = true, State = State };
                case "unlock":
                    Unlock(r.Password ?? "");
                    return new AuthPipeResponse { Ok = true, State = State };
                case "lock":
                    Lock("Auth Console");
                    return new AuthPipeResponse { Ok = true, State = State };
                case "verify":
                {
                    if (State != "unlocked") return new AuthPipeResponse { Error = "The auth server is locked." };
                    string key = $"console:{(r.User ?? "").ToLowerInvariant()}";
                    bool ok = !_throttle.IsLocked(key) && UserStore.Authenticate(paths.UsersFile, r.User ?? "", r.Password ?? "", r.Code ?? "");
                    if (ok) _throttle.Success(key); else { _throttle.Fail(key); Thread.Sleep(1000); }
                    AuditLine($"{(ok ? "CONSOLE-LOGIN" : "CONSOLE-LOGIN-FAILED")}  user '{r.User}'");
                    return ok ? new AuthPipeResponse { Ok = true } : new AuthPipeResponse { Error = "Wrong user name, password or code." };
                }
                case "joinkey":
                    if (State != "unlocked") return new AuthPipeResponse { Error = "The auth server is locked." };
                    return new AuthPipeResponse { Ok = true, JoinKey = AuthData.ReadJoinKey(paths) };
                default:
                    return new AuthPipeResponse { Error = "Unknown request." };
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            return new AuthPipeResponse { Error = ex.Message, State = State };
        }
    }

    private async Task AcceptLoop(TcpListener listener, CancellationToken token)
    {
        var allowed = _config.AllowedNetworks.Select(IPNetwork.Parse).ToList();
        while (!token.IsCancellationRequested)
        {
            TcpClient tcp;
            try
            {
                tcp = await listener.AcceptTcpClientAsync(token);
            }
            catch (Exception) when (token.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
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
                "ticket" => IssueTicket(request, ip),
                "confirm" => WithComputer(computerCert, ip, c => ConfirmTicket(request, c, ip)),
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

        var (cert, certAddress) = Issue(name, guid, r.PublicKey, ip);
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
            record.CertificateAddress = certAddress;
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
        var (cert, certAddress) = Issue(computer.Name, computer.MachineGuid, r.PublicKey, ip);
        ComputerStore.Update(paths, store =>
        {
            var record = store.BySerial(computer.Serials[0]);
            if (record is null) return 0;
            record.Serials.Add(cert.SerialNumber);
            if (record.Serials.Count > 3) record.Serials.RemoveAt(0);
            record.CertificateAddress = certAddress;
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
    /// A viewer asks for a ticket to one computer. Password and code are checked here; the computer only ever sees
    /// the signed ticket, which is bound to it, to this viewer's address and to one connection.
    /// </summary>
    private CentralResponse IssueTicket(CentralRequest r, IPAddress ip)
    {
        var user = r.User ?? "";
        var computerName = r.Computer ?? "";
        string viewer = AuthData.Display(ip);
        string userKey = $"user:{user.ToLowerInvariant()}", clientKey = $"client:{viewer}";

        bool ok = !_throttle!.IsLocked(userKey) && !_throttle.IsLocked(clientKey)
                  && UserStore.Authenticate(paths.UsersFile, user, r.Password ?? "", r.Code ?? "");
        if (!ok)
        {
            _throttle.Fail(userKey);
            _throttle.Fail(clientKey);
            AuditLine($"LOGIN-FAILED  user '{user}' from {viewer} to {computerName}");
            Thread.Sleep(1000);
            return new CentralResponse { Error = "Authentication failed." };
        }
        _throttle.Success(userKey);
        _throttle.Success(clientKey);

        var computer = ComputerStore.Load(paths).Computers.FirstOrDefault(c =>
            string.Equals(c.Name, computerName, StringComparison.OrdinalIgnoreCase));
        if (computer is null || computer.Revoked || computer.Pending)
        {
            AuditLine($"TICKET-REFUSED  user '{user}' from {viewer} to {computerName}: computer {(computer is null ? "not registered" : computer.Revoked ? "blocked" : "waits for approval")}");
            return new CentralResponse { Error = $"{computerName} is not allowed by the auth server." };
        }
        byte[] nonce;
        try { nonce = Convert.FromBase64String(r.Nonce ?? ""); }
        catch (FormatException) { return new CentralResponse { Error = "Bad request." }; }
        if (nonce.Length != 32) return new CentralResponse { Error = "Bad request." };

        var payload = new TicketPayload
        {
            Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
            User = UserStore.Load(paths.UsersFile).Find(user)?.Name ?? user,
            Computer = computer.Name,
            ClientAddress = viewer,
            Nonce = Convert.ToBase64String(nonce),
            IssuedUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        using var key = (_caKey ?? throw new InvalidOperationException("locked")).GetECDsaPrivateKey()!;
        var (ticket, signature) = Tickets.Sign(payload, key);
        _tickets.Add(payload);
        AuditLine($"TICKET  user '{payload.User}' from {viewer} to {computer.Name}");
        return new CentralResponse { Ok = true, Ticket = Convert.ToBase64String(ticket), Signature = Convert.ToBase64String(signature) };
    }

    /// <summary>The computer asks: did you issue this ticket for me? Each ticket is confirmed once.</summary>
    private CentralResponse ConfirmTicket(CentralRequest r, ComputerRecord computer, IPAddress ip)
    {
        var payload = _tickets.Confirm(r.TicketId ?? "", computer.Name, r.Nonce ?? "");
        if (payload is null)
        {
            AuditLine($"CONFIRM-REFUSED  ticket {r.TicketId} on {computer.Name} ({ip}): unknown, used, expired or for another computer");
            return new CentralResponse { Error = "The auth server did not issue this ticket for this computer (or it was already used)." };
        }
        ComputerStore.Update(paths, store =>
        {
            if (store.Computers.FirstOrDefault(c => c.Same(computer.Name, computer.MachineGuid)) is { } record)
            {
                record.LastSeenUtc = DateTime.UtcNow;
                record.LastAddress = AuthData.Display(ip);
            }
            return 0;
        });
        AuditLine($"LOGIN  user '{payload.User}' from {payload.ClientAddress} to {computer.Name} ({ip})");
        return new CentralResponse { Ok = true, User = payload.User, MachineName = computer.Name };
    }

    /// <summary>
    /// The certificate names only this computer: its name and the address the auth server sees it on.
    /// Addresses the computer claims are not used, so it cannot obtain a certificate for someone else's address.
    /// </summary>
    private (X509Certificate2 Certificate, string Address) Issue(string name, string machineGuid, string publicKeyBase64, IPAddress ip)
    {
        var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);

        // An address another registered computer used recently stays out of the certificate (DHCP reuse, or
        // someone taking the address of a computer that is off): viewers must not trust a stranger at that address.
        string address = AuthData.Display(ip);
        var holder = ComputerStore.Load(paths).Computers.FirstOrDefault(c =>
            !c.Revoked && !c.Same(name, machineGuid) && c.CertificateAddress == address &&
            c.LastSeenUtc > DateTime.UtcNow - CentralProtocol.ComputerCertificateLifetime - TimeSpan.FromDays(1));
        IPAddress[] ips = holder is null ? [ip] : [];
        if (holder is not null)
            AuditLine($"ADDRESS-IN-USE  {name}: {address} was used by {holder.Name}; certificate issued for the name only");

        var ca = _caKey ?? throw new InvalidOperationException("locked");
        var cert = CertificateManager.IssueCertificate(ca, publicKey, name, [name, name + ".local"], ips, clientAuth: true,
            CentralProtocol.ComputerCertificateLifetime);
        return (cert, holder is null ? address : "");
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
                // The TLS certificate lives only in memory: issued from the unlocked CA, re-issued when addresses change.
                var ca = _caKey ?? throw new InvalidOperationException("The auth server is locked.");
                var (dns, ips) = CertificateManager.CurrentIdentity();
                if (_creds is null || _creds.ServerCertificate.NotAfter < DateTime.Now.AddDays(30) || !CertificateManager.Covers(_creds.ServerCertificate, dns, ips))
                {
                    using var fresh = CertificateManager.IssueServerCertificate(ca, dns, ips, Tickets.AuthServerEkuOid);
                    var leaf = new X509Certificate2(fresh.Export(X509ContentType.Pkcs12), (string?)null, X509KeyStorageFlags.Exportable);
                    _creds = new ServerCredentials(leaf, _ca!, SslStreamCertificateContext.Create(leaf, [_ca!], offline: true));
                }
                _credsCheckedUtc = DateTime.UtcNow;
            }
            return _creds;
        }
    }
}
