using System.Runtime.InteropServices;
using System.Security.Principal;
using static Watchtower.Service.Native.NativeMethods;

namespace Watchtower.Service.Native;

public static class TokenInfo
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>
    /// Whether the account is an administrator, elevated or not. With UAC, an admin's
    /// normal token carries Administrators as "deny only"; WindowsIdentity.Groups hides
    /// that entry, so the raw token groups are read instead. Standard users never
    /// have the group at all, so they can't use Watchtower to act as SYSTEM.
    /// </summary>
    public static bool IsAdministratorAccount(WindowsIdentity identity)
    {
        var token = identity.AccessToken.DangerousGetHandle();
        GetTokenInformation(token, TokenGroups, IntPtr.Zero, 0, out var length);
        if (length == 0) return false;
        var buffer = Marshal.AllocHGlobal(length);
        try
        {
            if (!GetTokenInformation(token, TokenGroups, buffer, length, out _)) return false;
            var count = Marshal.ReadInt32(buffer);
            var size = Marshal.SizeOf<SID_AND_ATTRIBUTES>();
            var first = buffer + IntPtr.Size; // DWORD GroupCount, padded to pointer alignment
            for (var i = 0; i < count; i++)
            {
                var entry = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(first + i * size);
                if (new SecurityIdentifier(entry.Sid) == Administrators &&
                    (entry.Attributes & (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY)) != 0)
                {
                    return true;
                }
            }
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static int SessionId(WindowsIdentity identity)
    {
        var buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            return GetTokenInformation(identity.AccessToken.DangerousGetHandle(), TokenSessionId, buffer, sizeof(int), out _)
                ? Marshal.ReadInt32(buffer)
                : -1;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
