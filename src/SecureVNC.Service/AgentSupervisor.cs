using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using SecureVNC.Shared.Hosting;
using static SecureVNC.Service.Native;

namespace SecureVNC.Service;

/// <summary>
/// Keeps exactly one agent (SecureVNC.Server.exe --agent) running as SYSTEM in the active console session.
/// When the console session changes (logoff, user switch) the agent is stopped and started in the new one.
/// The agent sits in a kill-on-close job, so it dies with the service.
/// </summary>
internal sealed class AgentSupervisor : IDisposable
{
    private static readonly TimeSpan QuickExit = TimeSpan.FromSeconds(30);

    private readonly string _agentExe = Path.Combine(AppContext.BaseDirectory, "SecureVNC.Server.exe");
    private readonly AutoResetEvent _wake = new(false);
    private readonly IntPtr _job;
    private Thread? _thread;
    private volatile bool _stopping;

    private IntPtr _process;
    private uint _agentSession = NoConsoleSession;
    private EventWaitHandle? _stopEvent;
    private DateTime _startedUtc;
    private int _quickExits;

    public AgentSupervisor()
    {
        _job = CreateJobObject(IntPtr.Zero, null);
        if (_job == IntPtr.Zero) throw new Win32Exception();
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(_job, JobObjectExtendedLimitInformation, ref info, Marshal.SizeOf(info)))
            throw new Win32Exception();
    }

    public void Start()
    {
        if (!File.Exists(_agentExe)) throw new FileNotFoundException("Agent not found", _agentExe);
        _thread = new Thread(Loop) { IsBackground = true, Name = "agent supervisor" };
        _thread.Start();
    }

    /// <summary>Re-check now (called on session change notifications).</summary>
    public void Poke() => _wake.Set();

    private void Loop()
    {
        while (!_stopping)
        {
            try
            {
                Tick();
            }
            catch (Exception ex)
            {
                Log.Info($"Supervisor error: {ex.Message}");
            }
            _wake.WaitOne(TimeSpan.FromSeconds(3));
        }
        StopAgent();
    }

    private void Tick()
    {
        if (_process != IntPtr.Zero && WaitForSingleObject(_process, 0) == WAIT_OBJECT_0)
        {
            GetExitCodeProcess(_process, out uint code);
            Log.Info($"Agent exited (code {code})");
            _quickExits = DateTime.UtcNow - _startedUtc < QuickExit ? _quickExits + 1 : 0;
            ReleaseAgent();
        }

        uint console = WTSGetActiveConsoleSessionId();
        bool running = _process != IntPtr.Zero;
        if (console == NoConsoleSession)
        {
            if (running) StopAgent();   // session is being switched
            return;
        }
        if (running && _agentSession == console) return;
        if (running)
        {
            Log.Info($"Console session changed {_agentSession} -> {console}");
            StopAgent();
        }

        // Crash-loop protection: wait longer after each agent that dies right away.
        if (_quickExits >= 3 && DateTime.UtcNow - _startedUtc < TimeSpan.FromSeconds(30 * Math.Min(_quickExits, 10))) return;
        StartAgent(console);
    }

    private void StartAgent(uint session)
    {
        string stopName = $@"Global\SecureVNC.AgentStop.{Guid.NewGuid():N}";
        var stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, stopName);

        IntPtr token = IntPtr.Zero, primary = IntPtr.Zero;
        try
        {
            // Our own SYSTEM token, moved to the console session: the agent can then open the Winlogon desktop.
            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT, out token))
                throw new Win32Exception();
            if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out primary))
                throw new Win32Exception();
            uint sid = session;
            if (!SetTokenInformation(primary, TokenSessionId, ref sid, sizeof(uint)))
                throw new Win32Exception();

            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            var cmd = new StringBuilder($"\"{_agentExe}\" {ServiceIpc.AgentArg} {ServiceIpc.StopEventArg} {stopName}");
            if (!CreateProcessAsUser(primary, _agentExe, cmd, IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero,
                    AppContext.BaseDirectory, ref si, out var pi))
                throw new Win32Exception();

            if (!AssignProcessToJobObject(_job, pi.hProcess))
                Log.Info($"Could not put the agent in the job: {new Win32Exception().Message}");
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);

            _process = pi.hProcess;
            _agentSession = session;
            _stopEvent = stopEvent;
            _startedUtc = DateTime.UtcNow;
            Log.Info($"Agent started in session {session} (pid {pi.dwProcessId})");
        }
        catch (Exception ex)
        {
            stopEvent.Dispose();
            _startedUtc = DateTime.UtcNow;
            _quickExits++;
            Log.Info($"Cannot start agent in session {session}: {ex.Message}");
        }
        finally
        {
            if (primary != IntPtr.Zero) CloseHandle(primary);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    /// <summary>Asks the agent to exit cleanly (releases held keys, closes sessions), then forces it.</summary>
    private void StopAgent()
    {
        if (_process == IntPtr.Zero) return;
        _stopEvent?.Set();
        if (WaitForSingleObject(_process, 5000) != WAIT_OBJECT_0)
        {
            Log.Info("Agent did not stop in time; terminating");
            TerminateProcess(_process, 1);
            WaitForSingleObject(_process, 3000);
        }
        Log.Info("Agent stopped");
        ReleaseAgent();
    }

    private void ReleaseAgent()
    {
        if (_process != IntPtr.Zero) CloseHandle(_process);
        _process = IntPtr.Zero;
        _agentSession = NoConsoleSession;
        _stopEvent?.Dispose();
        _stopEvent = null;
    }

    public void Dispose()
    {
        _stopping = true;
        _wake.Set();
        _thread?.Join(TimeSpan.FromSeconds(15));
        if (_job != IntPtr.Zero) CloseHandle(_job);
    }
}
