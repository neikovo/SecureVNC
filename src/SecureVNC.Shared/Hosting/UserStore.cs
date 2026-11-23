using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecureVNC.Shared.Security;

namespace SecureVNC.Shared.Hosting;

public sealed class UserRecord
{
    public string Name { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    /// <summary>TOTP seed, DPAPI-protected (machine scope), base64.</summary>
    public string TotpSecret { get; set; } = "";
    /// <summary>Last accepted TOTP step: a code can be used only once.</summary>
    public long LastTotpStep { get; set; }
    public DateTime CreatedUtc { get; set; }
}

public sealed partial class UserStore
{
    private static readonly object FileLock = new();

    private string _file = ServerPaths.UsersFile;

    public List<UserRecord> Users { get; set; } = [];

    [GeneratedRegex("^[A-Za-z0-9._-]{1,32}$")]
    private static partial Regex NamePattern();

    public static bool IsValidName(string name) => NamePattern().IsMatch(name);

    public const string NameRules = "1-32 characters: letters, digits . _ -";

    /// <summary>Returns null when the password is acceptable, otherwise the reason.</summary>
    public static string? CheckPassword(string password)
    {
        if (password.Length < 10) return "The password must be at least 10 characters.";
        if (System.Text.Encoding.UTF8.GetByteCount(password) > 128) return "The password is too long.";
        return null;
    }

    public static UserStore Load() => Load(ServerPaths.UsersFile);

    public static UserStore Load(string file)
    {
        lock (FileLock)
        {
            var store = File.Exists(file)
                ? JsonSerializer.Deserialize<UserStore>(File.ReadAllText(file), ServerConfig.Json) ?? new()
                : new();
            store._file = file;
            return store;
        }
    }

    public void Save()
    {
        lock (FileLock)
        {
            var tmp = _file + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this, ServerConfig.Json));
            File.Move(tmp, _file, overwrite: true);
        }
    }

    public UserRecord? Find(string name) =>
        Users.FirstOrDefault(u => string.Equals(u.Name, name, StringComparison.OrdinalIgnoreCase));

    public static UserRecord CreateRecord(string name, string password, byte[] totpSecret, long acceptedStep) => new()
    {
        Name = name,
        PasswordHash = PasswordHasher.Hash(password),
        TotpSecret = Convert.ToBase64String(Dpapi.Protect(totpSecret)),
        LastTotpStep = acceptedStep,
        CreatedUtc = DateTime.UtcNow,
    };

    /// <summary>
    /// Verifies password + TOTP. Re-reads the file each time so changes made by
    /// SecureVNC.Admin apply without restarting the server.
    /// </summary>
    public static bool Authenticate(string name, string password, string code) =>
        Authenticate(ServerPaths.UsersFile, name, password, code);

    public static bool Authenticate(string file, string name, string password, string code)
    {
        lock (FileLock)
        {
            var store = Load(file);
            var user = store.Find(name);
            if (user is null)
            {
                PasswordHasher.BurnTime(password);
                return false;
            }
            if (!PasswordHasher.Verify(password, user.PasswordHash)) return false;

            var secret = Dpapi.Unprotect(Convert.FromBase64String(user.TotpSecret));
            long step;
            try { step = Totp.Verify(secret, code, DateTimeOffset.UtcNow); }
            finally { CryptographicOperations.ZeroMemory(secret); }

            if (step < 0 || step <= user.LastTotpStep) return false;
            user.LastTotpStep = step;
            store.Save();
            return true;
        }
    }
}
