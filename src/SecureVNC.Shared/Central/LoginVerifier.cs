using SecureVNC.Shared.Hosting;

namespace SecureVNC.Shared.Central;

public enum LoginResult { Ok, Failed, Unavailable }

/// <summary>
/// Checks a login on this computer. Local mode: the local users file. Central mode: the auth server decides;
/// only when it cannot be reached are local users (emergency accounts, none by default) accepted.
/// </summary>
public static class LoginVerifier
{
    public static LoginResult Verify(string user, string password, string code, string clientAddress)
    {
        var config = ServerConfig.Load();
        if (!config.IsCentral)
            return UserStore.Authenticate(user, password, code) ? LoginResult.Ok : LoginResult.Failed;

        try
        {
            var response = CentralClient.Verify(config, user, password, code, clientAddress);
            if (!response.Ok && response.Error is { } error) Log.Info($"Auth server: {error}");
            return response.Ok ? LoginResult.Ok : LoginResult.Failed;
        }
        catch (Exception ex)
        {
            Log.Info($"Auth server unreachable: {ex.Message}");
            if (UserStore.Load().Users.Count == 0) return LoginResult.Unavailable;
            Log.Info($"Checking '{user}' against the local emergency users");
            return UserStore.Authenticate(user, password, code) ? LoginResult.Ok : LoginResult.Failed;
        }
    }
}
