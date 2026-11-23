namespace SecureVNC.Server;

/// <summary>Locks out an IP address or user name after too many failed logins.</summary>
internal sealed class AuthThrottle(int maxFailures, TimeSpan lockout)
{
    private readonly Dictionary<string, (int Fails, DateTime Until)> _state = [];

    public bool IsLocked(string key)
    {
        lock (_state)
            return _state.TryGetValue(key, out var s) && s.Until > DateTime.UtcNow;
    }

    public void Fail(string key)
    {
        lock (_state)
        {
            _state.TryGetValue(key, out var s);
            if (s.Until != default && s.Until <= DateTime.UtcNow) s = default;   // lockout expired: start over
            int fails = s.Fails + 1;
            _state[key] = (fails, fails >= maxFailures ? DateTime.UtcNow + lockout : default);
        }
    }

    public void Success(string key)
    {
        lock (_state) _state.Remove(key);
    }
}
