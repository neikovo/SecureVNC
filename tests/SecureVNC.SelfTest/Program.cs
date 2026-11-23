using System.Security.Authentication;
using System.Text;
using SecureVNC.Client;
using SecureVNC.Server;
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
