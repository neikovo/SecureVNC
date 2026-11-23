using System.Security.Cryptography;

namespace SecureVNC.Shared.Security;

/// <summary>PBKDF2-SHA256 password hashing. Format: pbkdf2-sha256$iterations$salt$hash (base64).</summary>
public static class PasswordHasher
{
    private const int Iterations = 210_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private static readonly Lazy<string> Dummy = new(() => Hash(Guid.NewGuid().ToString()));

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string stored)
    {
        var p = stored.Split('$');
        if (p.Length != 4 || p[0] != "pbkdf2-sha256" || !int.TryParse(p[1], out int iterations)) return false;
        var salt = Convert.FromBase64String(p[2]);
        var expected = Convert.FromBase64String(p[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>Spends the same time as a real check, so unknown user names are not revealed by timing.</summary>
    public static void BurnTime(string password) => Verify(password, Dummy.Value);
}
