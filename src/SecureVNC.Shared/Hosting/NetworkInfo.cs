using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SecureVNC.Shared.Hosting;

public static class NetworkInfo
{
    /// <summary>
    /// IPv4 addresses clients can use: interfaces that are up and have a default gateway (the real LAN),
    /// or every up interface when none has a gateway. Virtual switches (WSL, Hyper-V) usually have no gateway.
    /// </summary>
    public static IReadOnlyList<string> LanAddresses()
    {
        var up = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                        && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
            .Select(n => n.GetIPProperties())
            .ToList();
        var withGateway = up.Where(p => p.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork
                                                                    && !g.Address.Equals(IPAddress.Any))).ToList();
        return (withGateway.Count > 0 ? withGateway : up)
            .SelectMany(p => p.UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a.Address))
            .Select(a => a.Address.ToString())
            .Distinct()
            .ToList();
    }

    /// <summary>Shows ::ffff:192.168.1.5 (dual-mode socket) as 192.168.1.5.</summary>
    public static string Display(IPAddress address) =>
        (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
}
