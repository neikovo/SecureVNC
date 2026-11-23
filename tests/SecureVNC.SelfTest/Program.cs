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
AuthData.Initialize(authPaths, _ => { });
var authConfig = AuthConfig.Load(authPaths);
authConfig.Port = 15902;
authConfig.Save(authPaths);
var adminSecret = Totp.NewSecret();
var admins = UserStore.Load(authPaths.UsersFile);
admins.Users.Add(UserStore.CreateRecord("central", password, adminSecret, acceptedStep: 0));
var adminSecret2 = Totp.NewSecret();
admins.Users.Add(UserStore.CreateRecord("central2", password, adminSecret2, acceptedStep: 0));
admins.Save();
var auth = new CentralAuthService(authPaths);
auth.Start("127.0.0.1");
string fingerprint = AuthData.CaFingerprint(authPaths), joinKey = AuthData.ReadJoinKey(authPaths);
const string authAddress = "127.0.0.1:15902";

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
auth.Start("127.0.0.1");
File.WriteAllText(ServerPaths.IdentityFile, """{"machineGuid":"00000000-0000-0000-0000-000000000000","machineName":"ORIGINAL-PC"}""");
bool rejoined = false;
err = Try(() => rejoined = MachineIdentity.Guard(_ => { }));
Check(err is null && rejoined && MachineIdentity.Saved is { } id && MachineIdentity.Matches(id, MachineIdentity.Current),
    $"cloned computer joins again by itself {err?.Message}");
err = Try(() => RfbClient.Connect(new ConnectOptions("127.0.0.1", 15901, "central2", password,
    Totp.Compute(adminSecret2, Totp.CurrentStep(DateTimeOffset.UtcNow) + 1)), TrustStore.Load(), Trust).Dispose());
Check(err is null, $"central login after re-join {err?.Message}");

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
