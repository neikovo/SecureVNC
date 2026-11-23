using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Shared.Central;

public sealed class VaultFile
{
    public int V { get; set; } = 1;
    public string Kdf { get; set; } = "PBKDF2-SHA256";
    public int Iterations { get; set; }
    public string Salt { get; set; } = "";
    /// <summary>Public half of the vault key pair: anyone (the Auth Console) can seal new secrets with it.</summary>
    public string PublicKey { get; set; } = "";
    /// <summary>Private half, encrypted with a key derived from the master password (AES-256-GCM: nonce | tag | data).</summary>
    public string WrappedPrivateKey { get; set; } = "";
}

/// <summary>
/// The auth server's secrets (organization CA key, administrators' authenticator secrets, join key) are sealed to a
/// key pair whose private half is encrypted with the master password. The password is never stored: after every
/// restart the auth server stays locked - no network, no tickets - until an administrator enters it.
/// A stolen disk, backup or switched-off server therefore holds nothing usable.
/// Sealing needs only the public key, so administrators can be added while the vault is locked.
/// </summary>
public static class Vault
{
    public const int MinPasswordLength = 12;
    private const int Iterations = 600_000;
    private const string SealPrefix = "sealed:";
    private static readonly byte[] WrapContext = Encoding.ASCII.GetBytes("SecureVNC-vault-v1");
    private static readonly byte[] SealContext = Encoding.ASCII.GetBytes("SecureVNC-seal-v1");
    private static readonly object Gate = new();
    private static ECDiffieHellman? _unlocked;

    public static string FilePath(AuthPaths paths) => Path.Combine(paths.DataDir, "vault.json");
    public static bool Exists(AuthPaths paths) => File.Exists(FilePath(paths));
    public static bool IsUnlocked { get { lock (Gate) return _unlocked is not null; } }

    public static string? CheckNewPassword(string password) =>
        password.Length < MinPasswordLength ? $"The master password must be at least {MinPasswordLength} characters." : null;

    /// <summary>New vault (new key pair) protected by this master password.</summary>
    public static void Create(AuthPaths paths, string masterPassword)
    {
        if (CheckNewPassword(masterPassword) is { } problem) throw new ArgumentException(problem);
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Write(paths, key, masterPassword);
    }

    /// <summary>Decrypts the private key with the master password; throws CryptographicException when it is wrong.</summary>
    public static ECDiffieHellman Open(AuthPaths paths, string masterPassword)
    {
        var file = Read(paths);
        var kek = DeriveKey(masterPassword, Convert.FromBase64String(file.Salt), file.Iterations);
        var wrapped = Convert.FromBase64String(file.WrappedPrivateKey);
        var pkcs8 = new byte[wrapped.Length - 28];
        try
        {
            using var aes = new AesGcm(kek, 16);
            aes.Decrypt(wrapped.AsSpan(0, 12), wrapped.AsSpan(28), wrapped.AsSpan(12, 16), pkcs8, WrapContext);
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new CryptographicException("Wrong master password.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
        var key = ECDiffieHellman.Create();
        key.ImportPkcs8PrivateKey(pkcs8, out _);
        CryptographicOperations.ZeroMemory(pkcs8);
        return key;
    }

    /// <summary>Unlocks this process (the auth service): sealed secrets can be read until <see cref="Lock"/>.</summary>
    public static void Unlock(AuthPaths paths, string masterPassword)
    {
        var key = Open(paths, masterPassword);
        lock (Gate)
        {
            _unlocked?.Dispose();
            _unlocked = key;
        }
    }

    public static void Lock()
    {
        lock (Gate)
        {
            _unlocked?.Dispose();
            _unlocked = null;
        }
    }

    public static void ChangePassword(AuthPaths paths, string oldPassword, string newPassword)
    {
        if (CheckNewPassword(newPassword) is { } problem) throw new ArgumentException(problem);
        using var key = Open(paths, oldPassword);
        Write(paths, key, newPassword);
    }

    /// <summary>Encrypts for the vault (public key only): ephemeral ECDH P-256 + AES-256-GCM.</summary>
    public static byte[] Seal(AuthPaths paths, byte[] data)
    {
        using var recipient = ECDiffieHellman.Create();
        recipient.ImportSubjectPublicKeyInfo(Convert.FromBase64String(Read(paths).PublicKey), out _);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var aesKey = ephemeral.DeriveKeyFromHash(recipient.PublicKey, HashAlgorithmName.SHA256, SealContext, null);
        var ephemeralPublic = ephemeral.ExportSubjectPublicKeyInfo();
        var output = new byte[2 + ephemeralPublic.Length + 12 + 16 + data.Length];
        output[0] = (byte)(ephemeralPublic.Length >> 8);
        output[1] = (byte)ephemeralPublic.Length;
        ephemeralPublic.CopyTo(output, 2);
        var nonce = output.AsSpan(2 + ephemeralPublic.Length, 12);
        RandomNumberGenerator.Fill(nonce);
        using (var aes = new AesGcm(aesKey, 16))
            aes.Encrypt(nonce, data, output.AsSpan(2 + ephemeralPublic.Length + 28), output.AsSpan(2 + ephemeralPublic.Length + 12, 16), SealContext);
        CryptographicOperations.ZeroMemory(aesKey);
        return output;
    }

    /// <summary>Decrypts with the unlocked vault of this process.</summary>
    public static byte[] Unseal(byte[] sealedData)
    {
        lock (Gate)
        {
            var key = _unlocked ?? throw new InvalidOperationException("The SecureVNC Auth Server is locked: enter the master password in the Auth Console.");
            int pubLen = (sealedData[0] << 8) | sealedData[1];
            using var sender = ECDiffieHellman.Create();
            sender.ImportSubjectPublicKeyInfo(sealedData.AsSpan(2, pubLen), out _);
            var aesKey = key.DeriveKeyFromHash(sender.PublicKey, HashAlgorithmName.SHA256, SealContext, null);
            var data = new byte[sealedData.Length - 2 - pubLen - 28];
            using (var aes = new AesGcm(aesKey, 16))
                aes.Decrypt(sealedData.AsSpan(2 + pubLen, 12), sealedData.AsSpan(2 + pubLen + 28),
                    sealedData.AsSpan(2 + pubLen + 12, 16), data, SealContext);
            CryptographicOperations.ZeroMemory(aesKey);
            return data;
        }
    }

    /// <summary>Text form for a users file entry: "sealed:" + base64.</summary>
    public static string SealToText(AuthPaths paths, byte[] data) => SealPrefix + Convert.ToBase64String(Seal(paths, data));

    public static bool IsSealedText(string text) => text.StartsWith(SealPrefix, StringComparison.Ordinal);

    public static byte[] UnsealText(string text) => Unseal(Convert.FromBase64String(text[SealPrefix.Length..]));

    private static VaultFile Read(AuthPaths paths) =>
        JsonSerializer.Deserialize<VaultFile>(File.ReadAllText(FilePath(paths)), ServerConfig.Json)
        ?? throw new InvalidDataException("Bad vault file.");

    private static void Write(AuthPaths paths, ECDiffieHellman key, string masterPassword)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var kek = DeriveKey(masterPassword, salt, Iterations);
        var pkcs8 = key.ExportPkcs8PrivateKey();
        var wrapped = new byte[28 + pkcs8.Length];
        RandomNumberGenerator.Fill(wrapped.AsSpan(0, 12));
        using (var aes = new AesGcm(kek, 16))
            aes.Encrypt(wrapped.AsSpan(0, 12), pkcs8, wrapped.AsSpan(28), wrapped.AsSpan(12, 16), WrapContext);
        CryptographicOperations.ZeroMemory(kek);
        CryptographicOperations.ZeroMemory(pkcs8);

        var file = new VaultFile
        {
            Iterations = Iterations,
            Salt = Convert.ToBase64String(salt),
            PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
            WrappedPrivateKey = Convert.ToBase64String(wrapped),
        };
        var tmp = FilePath(paths) + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(file, ServerConfig.Json));
        File.Move(tmp, FilePath(paths), overwrite: true);
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);
}
