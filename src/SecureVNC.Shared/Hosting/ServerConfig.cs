using System.Net;
using System.Text.Json;
using SecureVNC.Shared.Protocol;

namespace SecureVNC.Shared.Hosting;

public sealed class ServerConfig
{
    public int Port { get; set; } = Rfb.DefaultPort;

    /// <summary>"::" = all interfaces (IPv4 and IPv6); or one local address such as "192.168.1.10".</summary>
    public string ListenAddress { get; set; } = "::";

    /// <summary>Only clients from these networks may connect (local network by default).</summary>
    public List<string> AllowedNetworks { get; set; } =
    [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "::1/128", "fc00::/7", "fe80::/10",
    ];

    /// <summary>When true, remote users can watch but not control the screen.</summary>
    public bool ViewOnly { get; set; }

    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 5;
    public int MaxFramesPerSecond { get; set; } = 30;

    internal static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public IReadOnlyList<IPNetwork> ParseAllowedNetworks() => AllowedNetworks.Select(IPNetwork.Parse).ToList();

    public static ServerConfig Load() =>
        File.Exists(ServerPaths.ConfigFile)
            ? JsonSerializer.Deserialize<ServerConfig>(File.ReadAllText(ServerPaths.ConfigFile), Json) ?? new()
            : new();

    public void Save() => File.WriteAllText(ServerPaths.ConfigFile, JsonSerializer.Serialize(this, Json));
}
