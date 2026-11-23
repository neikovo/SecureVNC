using System.Text.Json;
using Microsoft.Win32;
using SecureVNC.Shared.Central;
using SecureVNC.Shared.Security;

namespace SecureVNC.Shared.Hosting;

/// <summary>
/// Detects cloned (or renamed) computers. Keys are made for one machine; when the computer name or the
/// Windows machine GUID differs from the one recorded next to the keys, this copy makes its own keys:
/// local mode = new CA and certificate (users are kept), central mode = joins the auth server again.
/// A plain disk clone keeps the machine GUID, but it must get a new name on the network, so either one counts.
/// </summary>
public static class MachineIdentity
{
    public sealed record Identity(string MachineGuid, string MachineName);

    public static Identity Current => new(ReadMachineGuid(), Environment.MachineName);

    public static Identity? Saved =>
        File.Exists(ServerPaths.IdentityFile)
            ? JsonSerializer.Deserialize<Identity>(File.ReadAllText(ServerPaths.IdentityFile), ServerConfig.Json)
            : null;

    public static void SaveCurrent() =>
        File.WriteAllText(ServerPaths.IdentityFile, JsonSerializer.Serialize(Current, ServerConfig.Json));

    public static bool Matches(Identity a, Identity b) =>
        string.Equals(a.MachineGuid, b.MachineGuid, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.MachineName, b.MachineName, StringComparison.OrdinalIgnoreCase);

    /// <summary>Call before using the keys (agent start, Manager, Admin). Returns true when new keys were made.</summary>
    public static bool Guard(Action<string> log)
    {
        if (!ServerPaths.IsInitialized) return false;
        var saved = Saved;
        var current = Current;
        if (saved is null)
        {
            SaveCurrent();   // installs from before this check
            return false;
        }
        if (Matches(saved, current)) return false;

        log($"Computer identity changed ({saved.MachineName} -> {current.MachineName}): cloned or renamed, making new keys");
        var config = ServerConfig.Load();
        if (config.IsCentral)
        {
            if (!File.Exists(ServerPaths.JoinKeyFile))
                throw new InvalidOperationException("Cloned computer: no saved join key. Join the auth server again in SecureVNC Manager.");
            var joinKey = System.Text.Encoding.UTF8.GetString(Dpapi.Unprotect(File.ReadAllBytes(ServerPaths.JoinKeyFile)));
            CentralClient.Join(config.AuthServer!, config.AuthServerFingerprint!, joinKey, log);
        }
        else
        {
            CertificateManager.InitializePki(force: true).Dispose();
        }
        SaveCurrent();
        return true;
    }

    private static string ReadMachineGuid()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid") as string ?? "";
        }
        catch
        {
            return "";
        }
    }
}
