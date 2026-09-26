using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using Watchtower.Core.Monitoring;
using static Watchtower.Service.Native.NativeMethods;

namespace Watchtower.Service.Native;

/// <summary>Terminal Services session list: who is signed in, and whether over Remote Desktop.</summary>
public static class Sessions
{
    private const int ProtocolRdp = 2;
    private static readonly string[] States = ["Active", "Connected", "ConnectQuery", "Shadow", "Disconnected", "Idle", "Listen", "Reset", "Down", "Init"];

    public static IReadOnlyList<SessionInfo> Read()
    {
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out var buffer, out var count)) return [];
        var result = new List<SessionInfo>();
        try
        {
            var size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (var i = 0; i < count; i++)
            {
                var s = Marshal.PtrToStructure<WTS_SESSION_INFO>(buffer + i * size);
                var user = QueryString(s.SessionId, WTSUserName);
                if (string.IsNullOrEmpty(user)) continue;
                var protocol = QueryUShort(s.SessionId, WTSClientProtocolType);
                var remote = protocol == ProtocolRdp || s.WinStationName.StartsWith("RDP-", StringComparison.OrdinalIgnoreCase);
                result.Add(new SessionInfo(
                    s.SessionId,
                    user,
                    QueryString(s.SessionId, WTSDomainName) ?? "",
                    s.WinStationName ?? "",
                    remote,
                    s.State >= 0 && s.State < States.Length ? States[s.State] : "Unknown",
                    remote ? QueryString(s.SessionId, WTSClientName) : null,
                    remote ? QueryAddress(s.SessionId) : null));
            }
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
        return result;
    }

    public static void Logoff(int sessionId)
    {
        if (!WTSLogoffSession(IntPtr.Zero, sessionId, false)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public static int ConsoleSessionId => WTSGetActiveConsoleSessionId();

    private static string? QueryString(int session, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, infoClass, out var buf, out _)) return null;
        try
        {
            return Marshal.PtrToStringUni(buf);
        }
        finally
        {
            WTSFreeMemory(buf);
        }
    }

    private static int QueryUShort(int session, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, infoClass, out var buf, out _)) return -1;
        try
        {
            return (ushort)Marshal.ReadInt16(buf);
        }
        finally
        {
            WTSFreeMemory(buf);
        }
    }

    private static unsafe string? QueryAddress(int session)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, WTSClientAddress, out var buf, out _)) return null;
        try
        {
            var a = (WTS_CLIENT_ADDRESS*)buf;
            return a->AddressFamily switch
            {
                // For IPv4 the address starts at byte 2 of the array (after the port).
                AF_INET => new IPAddress(new ReadOnlySpan<byte>(a->Address + 2, 4)).ToString(),
                AF_INET6 => new IPAddress(new ReadOnlySpan<byte>(a->Address + 2, 16)).ToString(),
                _ => null,
            };
        }
        finally
        {
            WTSFreeMemory(buf);
        }
    }
}
