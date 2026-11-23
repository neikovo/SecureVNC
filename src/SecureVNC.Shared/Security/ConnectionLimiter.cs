using System.Net;

namespace SecureVNC.Shared.Security;

/// <summary>
/// Caps connections that have not logged in yet, in total and per address, so that a flood of half-open
/// connections from the network cannot use up threads and memory. Connections over the cap are closed at once.
/// </summary>
public sealed class ConnectionLimiter(int maxTotal, int maxPerAddress)
{
    private readonly Dictionary<IPAddress, int> _perAddress = [];
    private int _total;
    private DateTime _lastWarningUtc;

    public bool TryEnter(IPAddress address, Action<string> log)
    {
        lock (_perAddress)
        {
            _perAddress.TryGetValue(address, out int count);
            if (_total >= maxTotal || count >= maxPerAddress)
            {
                if (DateTime.UtcNow - _lastWarningUtc > TimeSpan.FromMinutes(1))
                {
                    _lastWarningUtc = DateTime.UtcNow;
                    log($"{address}: too many connections that have not logged in (total {_total}, from this address {count}); refusing new ones");
                }
                return false;
            }
            _perAddress[address] = count + 1;
            _total++;
            return true;
        }
    }

    public void Leave(IPAddress address)
    {
        lock (_perAddress)
        {
            if (!_perAddress.TryGetValue(address, out int count)) return;
            if (count <= 1) _perAddress.Remove(address); else _perAddress[address] = count - 1;
            _total--;
        }
    }
}
