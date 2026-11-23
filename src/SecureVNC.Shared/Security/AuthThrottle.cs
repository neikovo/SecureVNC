namespace SecureVNC.Shared.Security;

/// <summary>Locks out an IP address or user name after too many failed logins.</summary>
public sealed class AuthThrottle(int maxFailures, TimeSpan lockout)
{
    private readonly Dictionary<string, (int Fails, DateTime Until)> _state = [];

    public bool IsLocked(string key)
    {
        lock (_state)
            return _state.TryGetValue(key, out var s) && s.Until > DateTime.UtcNow;
    }

    /// <summary>Entries kept at most before forgetting those that are not locked (millions of made-up names must not fill memory).</summary>
    private const int MaxTracked = 10_000;

    public int TrackedCount
    {
        get { lock (_state) return _state.Count; }
    }

    public void Fail(string key)
    {
        lock (_state)
        {
            if (_state.Count >= MaxTracked && !_state.ContainsKey(key))
            {
                var now = DateTime.UtcNow;
                foreach (var k in _state.Where(kv => kv.Value.Until <= now).Select(kv => kv.Key).ToList()) _state.Remove(k);
                if (_state.Count >= MaxTracked) return;   // everything tracked is locked: do not grow further
            }
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
