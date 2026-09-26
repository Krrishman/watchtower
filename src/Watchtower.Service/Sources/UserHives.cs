using Microsoft.Win32;

namespace Watchtower.Service.Sources;

public sealed record UserHive(string Sid, RegistryKey Root, string? ProfilePath) : IDisposable
{
    public void Dispose() => Root.Dispose();
}

/// <summary>
/// The service runs as SYSTEM, whose HKEY_CURRENT_USER is its own. Per-user settings
/// (Run keys, camera/mic ledger, proxy) are read from each signed-in user's hive under HKEY_USERS.
/// </summary>
public static class UserHives
{
    public static IEnumerable<UserHive> Loaded()
    {
        foreach (var sid in Registry.Users.GetSubKeyNames())
        {
            if (!IsRealUser(sid)) continue;
            var root = Registry.Users.OpenSubKey(sid);
            if (root is null) continue;
            yield return new UserHive(sid, root, ProfilePath(sid));
        }
    }

    public static RegistryKey? Open(string sid, bool writable = false) =>
        IsRealUser(sid) ? Registry.Users.OpenSubKey(sid, writable) : null;

    public static bool IsRealUser(string sid) =>
        (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.StartsWith("S-1-12-1-", StringComparison.Ordinal))
        && !sid.EndsWith("_Classes", StringComparison.Ordinal);

    public static string? ProfilePath(string sid)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        return key?.GetValue("ProfileImagePath") as string;
    }

    public static string? AccountName(string sid)
    {
        try
        {
            return new System.Security.Principal.SecurityIdentifier(sid).Translate(typeof(System.Security.Principal.NTAccount)).Value;
        }
        catch (Exception ex) when (ex is System.Security.Principal.IdentityNotMappedException or SystemException)
        {
            return null;
        }
    }
}
