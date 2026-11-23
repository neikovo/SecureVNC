using System.Security.Authentication;
using System.Text;
using SecureVNC.Client;
using SecureVNC.AuthServer;
using SecureVNC.Server;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

// End-to-end self-test: real server + real client on loopback, temporary data folder.
// Does not inject any input, so it never touches the mouse or keyboard.

Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);   // same as the real server
int failures = 0;
void Check(bool ok, string what)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {what}");
    if (!ok) failures++;
}

// 1. TOTP against the RFC 6238 test vectors (SHA-1, last 6 of the 8 digits).
var rfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");
Check(Totp.Compute(rfcSecret, 59 / 30) == "287082", "TOTP RFC 6238 vector t=59");
Check(Totp.Compute(rfcSecret, 1111111109 / 30) == "081804", "TOTP RFC 6238 vector t=1111111109");
Check(Base32.Encode(Encoding.ASCII.GetBytes("foobar")) == "MZXW6YTBOI", "Base32 RFC 4648 vector");

if (!args.Contains("--cold"))
using (var cap = new ScreenCapturer())
{
    bool ok = cap.Capture();
    int nonBlack = 0;
    var px = ok ? cap.Pixels : default;
    for (int i = 0; i < px.Length; i += 4 * 97) if (px[i] != 0 || px[i + 1] != 0 || px[i + 2] != 0) nonBlack++;
    Check(ok && nonBlack > 0, $"screen capture {cap.Width}x{cap.Height}, ok={ok}, sampled non-black={nonBlack}, err={System.Runtime.InteropServices.Marshal.GetLastPInvokeError()}");
}

string? desktopName = null;
bool firstSync = false, secondSync = true;
var syncThread = new Thread(() =>
{
    firstSync = DesktopSwitcher.SyncThreadToInputDesktop();
    secondSync = DesktopSwitcher.SyncThreadToInputDesktop();
    desktopName = DesktopSwitcher.CurrentName;
});
syncThread.Start();
syncThread.Join();
Check(firstSync && !secondSync && desktopName == "Default", $"worker thread follows input desktop ('{desktopName}')");

// 2. PKI + user in a temporary data folder.
var temp = Path.Combine(Path.GetTempPath(), "securevnc-selftest-" + Guid.NewGuid().ToString("N"));
ServerPaths.UseDataDirForTesting(temp);
TrustStore.UseDirForTesting(Path.Combine(temp, "client"));
using (var ca = CertificateManager.InitializePki(force: true))
    Check(ca.Subject.Contains("SecureVNC CA"), $"local CA created ({CertificateManager.Fingerprint(ca)[..23]}...)");

var secret = Totp.NewSecret();
const string password = "correct horse battery";
var store = new UserStore();
store.Users.Add(UserStore.CreateRecord("tester", password, secret, acceptedStep: 0));
store.Save();

var config = new ServerConfig { Port = 15901, ListenAddress = "127.0.0.1" };
var server = new RfbServer(config);
server.Start();

int prompts = 0;
bool Trust(System.Security.Cryptography.X509Certificates.X509Certificate2 ca, bool changed)
{
    prompts++;
    return true;
}

string Code(int offset) => Totp.Compute(secret, Totp.CurrentStep(DateTimeOffset.UtcNow) + offset);

Exception? Try(Action a)
{
    try { a(); return null; }
    catch (Exception ex) { return ex; }
}

// 3. Good login, receive a frame.
var code0 = Code(0);
RfbClient? client = null;
var err = Try(() => client = RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "tester", password, code0), TrustStore.Load(), Trust));
Check(err is null && client is not null, $"login with password + TOTP {(err is null ? $"({client!.TlsInfo})" : err.Message)}");
Check(prompts == 1, "first connection asked to trust the CA");
if (client is not null)
{
    var frame = new ManualResetEventSlim();
    int pixelsSeen = 0;
    client.RegionUpdated += r =>
    {
        pixelsSeen += r.Width * r.Height;
        frame.Set();
    };
    client.Disconnected += e => Console.WriteLine($"      client disconnected: {e}");
    client.Start();
    bool got = frame.Wait(TimeSpan.FromSeconds(10));
    Check(got && client.Width > 0 && client.Height > 0, $"received screen {client.Width}x{client.Height} ({pixelsSeen} px)");
    Check(server.Sessions.Count == 1, "server lists 1 active session");

    // Without the service, Ctrl+Alt+Del cannot be done; the session must survive the request.
    client.SendCtrlAltDel();
    Thread.Sleep(3000);
    Check(server.Sessions.Count == 1, "Ctrl+Alt+Del without service: session stays up");
    client.Dispose();
}

// Attack test: malformed and hostile handshakes from the network must not crash or wedge the server.
var rnd = new Random(20261123);
// Own instance with a huge lockout limit, so that the garbage "logins" do not lock 127.0.0.1 for the tests below.
var fuzzServer = new RfbServer(new ServerConfig { Port = 15903, ListenAddress = "127.0.0.1", MaxFailedAttempts = 1_000_000 });
fuzzServer.Start();
int fuzzRuns = 90;
var fuzzOutcomes = new Dictionary<string, int>();
var fuzzWatch = System.Diagnostics.Stopwatch.StartNew();
for (int i = 0; i < fuzzRuns; i++)
{
    try
    {
        using var t = new System.Net.Sockets.TcpClient();
        t.Connect("127.0.0.1", 15903);
        var st = t.GetStream();
        st.ReadTimeout = st.WriteTimeout = 3000;
        var junk = new byte[rnd.Next(1, 6000)];
        rnd.NextBytes(junk);
        if (i % 3 == 0)
        {
            st.Write(junk);   // not even TLS
            try { st.ReadByte(); } catch (IOException) { }
        }
        else
        {
            using var ssl = new System.Net.Security.SslStream(st, false, (_, _, _, _) => true);
            ssl.AuthenticateAsClient("localhost");
            ssl.ReadExactly(new byte[12]);
            if (i % 3 == 1)
            {
                ssl.Write(junk);   // garbage instead of the version
                try { ssl.ReadByte(); } catch (IOException) { }
            }
            else
            {
                ssl.Write(Encoding.ASCII.GetBytes("RFB 003.008\n"));
                int n = ssl.ReadByte();
                ssl.ReadExactly(new byte[n]);
                ssl.WriteByte(0x80);
                var lenBytes = new byte[4];
                ssl.ReadExactly(lenBytes);
                ssl.ReadExactly(new byte[System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(lenBytes)]);
                junk[0] = (byte)(i % 2 == 0 ? 255 : rnd.Next(1, 64));   // oversized or random user name length
                ssl.Write(junk);
                try { while (ssl.ReadByte() >= 0) { } } catch (IOException) { }   // until the server hangs up
            }
        }
    }
    catch (Exception ex) { fuzzOutcomes[ex.GetType().Name] = fuzzOutcomes.GetValueOrDefault(ex.GetType().Name) + 1; continue; }
    fuzzOutcomes["closed by server"] = fuzzOutcomes.GetValueOrDefault("closed by server") + 1;
}
bool alive;
using (var probe = new System.Net.Sockets.TcpClient())
{
    probe.Connect("127.0.0.1", 15903);
    using var ssl = new System.Net.Security.SslStream(probe.GetStream(), false, (_, _, _, _) => true);
    ssl.AuthenticateAsClient("localhost");
    var v = new byte[12];
    ssl.ReadExactly(v);
    alive = Encoding.ASCII.GetString(v) == "RFB 003.008\n";
}
fuzzServer.Stop();
Check(alive && fuzzServer.Sessions.Count == 0,
    $"attack test: {fuzzRuns} malformed/hostile handshakes, server still answers ({fuzzWatch.Elapsed.TotalSeconds:F1} s; {string.Join(", ", fuzzOutcomes.Select(kv => $"{kv.Key} {kv.Value}"))})");

// 4. Replay of the same code must fail.
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "tester", password, code0), TrustStore.Load(), Trust).Dispose());
Check(err is AuthenticationException, $"reused TOTP code rejected ({err?.Message})");

// 5. Wrong password must fail.
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "tester", "wrong password!!", Code(1)), TrustStore.Load(), Trust).Dispose());
Check(err is AuthenticationException, $"wrong password rejected ({err?.Message})");

// 6. Unknown user must fail the same way.
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "nobody", password, Code(1)), TrustStore.Load(), Trust).Dispose());
Check(err is AuthenticationException, $"unknown user rejected ({err?.Message})");

// 7. The server certificate covers exactly this machine's names and addresses.
using (var leaf = CertificateManager.LoadProtected(ServerPaths.ServerCertFile))
{
    Check(leaf.MatchesHostname("127.0.0.1", false, false) && leaf.MatchesHostname(Environment.MachineName, false, false)
          && !leaf.MatchesHostname("127.0.0.2", false, false) && !leaf.MatchesHostname("evil.example", false, false),
        "certificate host name check (machine name/IPs yes, others no)");
}

// 8. Another host name in the certificate, with the next code.
err = Try(() => RfbClient.Connect(new ConnectOptions("localhost", 15901, "tester", password, Code(1)), TrustStore.Load(), Trust).Dispose());
Check(err is null, $"login as 'localhost' with next code {(err is null ? "" : err.Message)}");
Check(prompts == 2, "new host name asked once for trust (per-host pinning)");

// 9. Lockout after repeated failures.
for (int i = 0; i < 5; i++)
    Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "tester", "bad password " + i, "000000"), TrustStore.Load(), Trust).Dispose());
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "tester", password, Code(1)), TrustStore.Load(), Trust).Dispose());
Check(err is AuthenticationException && err.Message.Contains("Too many"), $"lockout after failed attempts ({err?.Message})");

server.Stop();
Thread.Sleep(300);

// ===== Central mode: SecureVNC Auth Server decides, the computer only asks =====
var authPaths = new AuthPaths(Path.Combine(temp, "auth"));
const string master = "correct horse master battery";
AuthData.Initialize(authPaths, master, _ => { });
var authConfig = AuthConfig.Load(authPaths);
authConfig.Port = 15902;
authConfig.Save(authPaths);
UserStore.SealSecret = secret => Vault.SealToText(authPaths, secret);   // as the Auth Console does
var adminSecret = Totp.NewSecret();
var admins = UserStore.Load(authPaths.UsersFile);
admins.Users.Add(UserStore.CreateRecord("central", password, adminSecret, acceptedStep: 0));
var adminSecret2 = Totp.NewSecret();
admins.Users.Add(UserStore.CreateRecord("central2", password, adminSecret2, acceptedStep: 0));
admins.Save();
UserStore.SealSecret = secret => Convert.ToBase64String(Dpapi.Protect(secret));   // computers keep using DPAPI

// ----- Master password: everything secret on the auth server is sealed -----
Check(UserStore.Load(authPaths.UsersFile).Users.All(u => Vault.IsSealedText(u.TotpSecret))
      && !File.Exists(authPaths.LegacyCaKeyFile) && !File.Exists(authPaths.LegacyJoinKeyFile) && !File.Exists(authPaths.LegacyTlsCertFile)
      && Try(() => AuthData.OpenCa(authPaths)) is not null,
    "auth server secrets sealed: CA key and authenticator secrets unreadable without the master password");
var auth = new CentralAuthService(authPaths);
auth.Start("127.0.0.1", unlockPipe: false);
const string authAddress = "127.0.0.1:15902";
err = Try(() => CentralClient.Join(authAddress, new string('A', 64), "x", _ => { }));
Check(auth.State == "locked" && err is not null, $"after a restart the auth server is locked and not on the network ({err?.Message})");
err = Try(() => auth.Unlock("this is not the master password"));
Check(err is not null && auth.State == "locked", $"wrong master password refused ({err?.Message})");
auth.Unlock(master);
Check(auth.State == "unlocked", "master password unlocks the auth server");
string fingerprint = AuthData.CaFingerprint(authPaths), joinKey = AuthData.ReadJoinKey(authPaths);

err = Try(() => CentralClient.Join(authAddress, new string('A', 64), joinKey, _ => { }));
Check(err is not null, $"join refuses an auth server with another CA fingerprint ({err?.Message})");
err = Try(() => CentralClient.Join(authAddress, fingerprint, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", _ => { }));
Check(err?.Message.Contains("Wrong join key") == true, $"join refused with a wrong join key ({err?.Message})");
err = Try(() => CentralClient.Join(authAddress, fingerprint, joinKey, _ => { }));
Check(err is null && ServerConfig.Load().IsCentral && !File.Exists(ServerPaths.CaKeyFile), $"computer joined the auth server {err?.Message}");
File.Delete(ServerPaths.UsersFile);   // no local emergency users

server = new RfbServer(config);
server.Start();
string CentralCode(int offset) => Totp.Compute(adminSecret, Totp.CurrentStep(DateTimeOffset.UtcNow) + offset);
var centralCode0 = CentralCode(0);
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "central", password, centralCode0), TrustStore.Load(), Trust).Dispose());
Check(err is null, $"central login with a ticket (password + TOTP go only to the auth server) {err?.Message}");
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "central", password, centralCode0), TrustStore.Load(), Trust).Dispose());
Check(err is AuthenticationException, $"central: reused code rejected ({err?.Message})");
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "tester", password, Code(1)), TrustStore.Load(), Trust).Dispose());
Check(err is AuthenticationException, $"central: local-only user rejected ({err?.Message})");
Check(AuthData.RecentAudit(authPaths, 20).Any(l => l.Contains("LOGIN  user 'central'")), "auth server audit log has the login");

using (var issued = CertificateManager.LoadProtected(ServerPaths.ServerCertFile))
    Check(issued.NotAfter <= DateTime.Now.AddDays(7).AddHours(1), $"computer certificate lives 7 days (until {issued.NotAfter:yyyy-MM-dd HH:mm})");

// Someone with the join key enrolls another computer from an address a registered computer uses.
string NewPublicKey() { using var k = System.Security.Cryptography.ECDsa.Create(); return Convert.ToBase64String(k.ExportSubjectPublicKeyInfo()); }
var fake = CentralClient.Request(authAddress, fingerprint, null, new CentralRequest
{
    Op = "enroll", JoinKey = joinKey, MachineName = "FAKE-PC", MachineGuid = Guid.NewGuid().ToString(), PublicKey = NewPublicKey(),
});
using (var fakeCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(Convert.FromBase64String(fake.Certificate ?? "")))
    Check(fake.Ok && CertificateManager.SanAddresses(fakeCert).Count == 0, "address used by another computer is left out of a new certificate");

var approvalConfig = AuthConfig.Load(authPaths);
approvalConfig.RequireApproval = true;
approvalConfig.Save(authPaths);
var waiting = CentralClient.Request(authAddress, fingerprint, null, new CentralRequest
{
    Op = "enroll", JoinKey = joinKey, MachineName = "WAIT-PC", MachineGuid = Guid.NewGuid().ToString(), PublicKey = NewPublicKey(),
});
Check(waiting.Ok && ComputerStore.Load(authPaths).Computers.Single(c => c.Name == "WAIT-PC").Pending, "with approval required, a new computer waits");
approvalConfig.RequireApproval = false;
approvalConfig.Save(authPaths);

ComputerStore.Update(authPaths, s => s.Computers[0].Revoked = true);
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "central", password, CentralCode(1)), TrustStore.Load(), Trust).Dispose());
Check(err is AuthenticationException, $"central: blocked computer cannot log anyone in ({err?.Message})");
err = Try(() => CentralClient.Join(authAddress, fingerprint, joinKey, _ => { }));
Check(err?.Message.Contains("blocked") == true, $"blocked computer cannot unblock itself by joining again ({err?.Message})");
ComputerStore.Update(authPaths, s => s.Computers[0].Revoked = false);

// ----- Tickets: what a computer accepts -----
var orgCa = new System.Security.Cryptography.X509Certificates.X509Certificate2(authPaths.CaCertFile);
string myName;
using (var mine = CertificateManager.LoadProtected(ServerPaths.ServerCertFile))
{
    myName = Tickets.MyRegisteredName(mine);
    Check(!Tickets.IsAuthServer(mine, myName, orgCa), "a computer certificate cannot pose as the auth server");
}
var nonceA = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
var tr = Tickets.RequestTicket(authAddress, orgCa, "central2", password,
    Totp.Compute(adminSecret2, Totp.CurrentStep(DateTimeOffset.UtcNow)), myName, nonceA);
Check(tr.Ok, $"auth server issues a ticket {tr.Error}");
if (tr.Ok)
{
    var tk = Convert.FromBase64String(tr.Ticket!);
    var sg = Convert.FromBase64String(tr.Signature!);
    TicketPayload? payload = null;
    err = Try(() => payload = Tickets.Check(tk, sg, orgCa, myName, nonceA, "127.0.0.1"));
    Check(err is null && payload?.User == "central2", $"valid ticket accepted {err?.Message}");
    Check(Try(() => Tickets.Check(tk, sg, orgCa, myName, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), "127.0.0.1")) is not null,
        "ticket for another connection (nonce) refused");
    Check(Try(() => Tickets.Check(tk, sg, orgCa, "OTHER-PC", nonceA, "127.0.0.1")) is not null, "ticket for another computer refused");
    Check(Try(() => Tickets.Check(tk, sg, orgCa, myName, nonceA, "192.168.1.99")) is not null, "ticket used from another address refused");
    var forged = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(tk).Replace("central2", "centralX"));
    Check(Try(() => Tickets.Check(forged, sg, orgCa, myName, nonceA, "127.0.0.1")) is AuthenticationException, "changed ticket (forged user) refused");
    var confirm1 = CentralClient.ConfirmTicket(ServerConfig.Load(), payload!.Id, payload.Nonce);
    var confirm2 = CentralClient.ConfirmTicket(ServerConfig.Load(), payload.Id, payload.Nonce);
    Check(confirm1.Ok && confirm1.User == "central2" && !confirm2.Ok, "auth server confirms a ticket to its computer exactly once");
}

// Local emergency account: only with "Emergency login", password checked on the computer itself.
var rescueSecret = Totp.NewSecret();
var rescue = new UserStore();
rescue.Users.Add(UserStore.CreateRecord("rescue", password, rescueSecret, acceptedStep: 0));
rescue.Save();
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "rescue", password,
    Totp.Compute(rescueSecret, Totp.CurrentStep(DateTimeOffset.UtcNow)), Emergency: true), TrustStore.Load(), Trust).Dispose());
Check(err is null, $"emergency login with a local account {err?.Message}");
File.Delete(ServerPaths.UsersFile);

// Half-open connections are capped per address; the cap frees up again.
var raw = new List<System.Net.Sockets.TcpClient>();
for (int i = 0; i < 4; i++) { var t = new System.Net.Sockets.TcpClient(); t.Connect("127.0.0.1", 15901); raw.Add(t); }
Thread.Sleep(300);
var extra = new System.Net.Sockets.TcpClient();
extra.Connect("127.0.0.1", 15901);
extra.GetStream().ReadTimeout = 3000;
int readResult = -2;
try { readResult = extra.GetStream().Read(new byte[1], 0, 1); } catch (IOException) { readResult = -1; }
Check(readResult <= 0, $"5th half-open connection from one address is closed at once (read={readResult})");
extra.Dispose();
foreach (var t in raw) t.Dispose();
Thread.Sleep(500);

Check(Log.OneLine("bob\r\n2026-01-01 LOGIN  user 'admin'") == "bob  2026-01-01 LOGIN  user 'admin'", "log lines cannot be split by names from the network");

auth.Stop();
Thread.Sleep(300);
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "central", password, CentralCode(1)), TrustStore.Load(), Trust).Dispose());
Check(err is not null && err.Message.Contains("not reachable"), $"central: auth server down -> nobody logs in ({err?.Message})");

// A clone: the saved identity is another computer's -> joins again with the saved join key.
auth = new CentralAuthService(authPaths);
auth.Start("127.0.0.1", unlockPipe: false);
auth.Unlock(master);
File.WriteAllText(ServerPaths.IdentityFile, """{"machineGuid":"00000000-0000-0000-0000-000000000000","machineName":"ORIGINAL-PC"}""");
bool rejoined = false;
err = Try(() => rejoined = MachineIdentity.Guard(_ => { }));
Check(err is null && rejoined && MachineIdentity.Saved is { } id && MachineIdentity.Matches(id, MachineIdentity.Current),
    $"cloned computer joins again by itself {err?.Message}");
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "central2", password,
    Totp.Compute(adminSecret2, Totp.CurrentStep(DateTimeOffset.UtcNow) + 1)), TrustStore.Load(), Trust).Dispose());
Check(err is null, $"central login after re-join {err?.Message}");

// ----- Master password: lock, change -----
auth.Lock("test");
err = Try(() => Tickets.RequestTicket(authAddress, orgCa, "central2", password, "000000", myName, nonceA));
Check(err is not null && auth.State == "locked", $"Lock now: the auth server leaves the network at once ({err?.Message})");
auth.Unlock(master);
Vault.ChangePassword(authPaths, master, "a completely new master password");
Check(Try(() => Vault.Open(authPaths, master).Dispose()) is not null && Try(() => Vault.Open(authPaths, "a completely new master password").Dispose()) is null,
    "master password change: the old one stops working, the new one opens the vault");

// ----- Second audit -----
// A: only Administrators / SYSTEM (or a member of Administrators) may own SecureVNC data.
Check(LocalAdmins.IsTrustedOwner(new System.Security.Principal.SecurityIdentifier("S-1-5-32-544"))
      && LocalAdmins.IsTrustedOwner(new System.Security.Principal.SecurityIdentifier("S-1-5-18"))
      && !LocalAdmins.IsTrustedOwner(new System.Security.Principal.SecurityIdentifier("S-1-5-32-545"))
      && !LocalAdmins.IsTrustedOwner(new System.Security.Principal.SecurityIdentifier("S-1-1-0")),
    "data folder owner check: Administrators/SYSTEM yes, Users/Everyone no");

// C: with the organization CA imported, a computer with another CA is refused (no password goes to it).
using (var foreignCa = CertificateManager.CreateCa("Impostor CA"))
using (var foreignLeaf = CertificateManager.IssueServerCertificate(foreignCa, ["fake-host"], [System.Net.IPAddress.Loopback]))
using (var foreignCaPublic = new System.Security.Cryptography.X509Certificates.X509Certificate2(foreignCa.RawData))
{
    var orgCaFile = Path.Combine(temp, "org-ca.cer");
    File.Copy(authPaths.CaCertFile, orgCaFile, overwrite: true);
    var orgTrust = TrustStore.Load();
    orgTrust.Import(orgCaFile);
    int asked = 0;
    err = Try(() => RfbClient.VerifyServer("fake-host", foreignLeaf, foreignCaPublic, orgTrust, (_, _) => { asked++; return true; }));
    Check(err is AuthenticationException && asked == 0, $"organization CA imported: impostor with its own CA refused without asking ({err?.Message})");
    err = Try(() => RfbClient.VerifyServer("fake-host", foreignLeaf, foreignCaPublic, orgTrust, (_, _) => { asked++; return true; }, emergency: true));
    Check(err is null && asked == 1, "with Emergency login the user may still decide (asked once)");
}

// D: millions of made-up user names cannot fill memory.
var bounded = new AuthThrottle(5, TimeSpan.FromMinutes(5));
for (int i = 0; i < 25_000; i++) bounded.Fail($"user:made-up-{i}");
Check(bounded.TrackedCount <= 10_000, $"lockout memory stays bounded ({bounded.TrackedCount} entries after 25000 names)");

// E: writing a log never creates the data folder (setup creates it locked).
var realDataDir = ServerPaths.DataDir;
var missing = Path.Combine(temp, "not-created");
ServerPaths.UseDataDir(missing);
Log.Info("test");
bool created = Directory.Exists(missing);
ServerPaths.UseDataDir(realDataDir);
Check(!created, "a log line does not create a missing data folder");

server.Stop();
auth.Stop();
Thread.Sleep(300);
if (failures == 0)
{
    try { Directory.Delete(temp, recursive: true); } catch { /* key files may still be open */ }
}
else
{
    foreach (var f in Directory.GetFiles(ServerPaths.LogDir)) Console.WriteLine(File.ReadAllText(f));
}
Console.WriteLine(failures == 0 ? "\nALL PASSED" : $"\n{failures} FAILED");
return failures == 0 ? 0 : 1;
