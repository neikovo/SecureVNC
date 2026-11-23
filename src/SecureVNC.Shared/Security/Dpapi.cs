using System.Security.Cryptography;

namespace SecureVNC.Shared.Security;

/// <summary>Windows DPAPI (machine scope) for secrets at rest: TOTP seeds and private keys.</summary>
public static class Dpapi
{
    private static readonly byte[] Entropy = "SecureVNC.v1"u8.ToArray();

    public static byte[] Protect(byte[] data) =>
        ProtectedData.Protect(data, Entropy, DataProtectionScope.LocalMachine);

    public static byte[] Unprotect(byte[] data) =>
        ProtectedData.Unprotect(data, Entropy, DataProtectionScope.LocalMachine);
}
