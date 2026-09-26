using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Watchtower.Service.Native;

internal static class NativeMethods
{
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, char[] buffer, ref int size);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, out int info, int length, out int returnLength);

    public const int ProcessBreakOnTermination = 29;

    // ---- IP Helper: TCP tables ----

    public const int AF_INET = 2;
    public const int AF_INET6 = 23;
    public const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public int OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public fixed byte RemoteAddr[16];
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public int OwningPid;
    }

    public const uint MIB_TCP_STATE_LISTEN = 2;
    public const uint MIB_TCP_STATE_ESTAB = 5;

    // ---- WTS sessions ----

    public const int WTSUserName = 5;
    public const int WTSDomainName = 7;
    public const int WTSClientName = 10;
    public const int WTSClientAddress = 14;
    public const int WTSClientProtocolType = 16;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTS_SESSION_INFO
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPWStr)] public string WinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct WTS_CLIENT_ADDRESS
    {
        public int AddressFamily;
        public fixed byte Address[20];
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSLogoffSession(IntPtr server, int sessionId, bool wait);

    [DllImport("kernel32.dll")]
    public static extern int WTSGetActiveConsoleSessionId();

    // ---- Named pipes ----

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out int clientProcessId);

    // ---- Tokens ----

    public const int TokenGroups = 2;
    public const int TokenSessionId = 12;
    public const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x10;
    public const uint SE_GROUP_ENABLED = 0x4;

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    // ---- Services ----

    public const uint SC_MANAGER_CONNECT = 0x0001;
    public const uint SERVICE_CHANGE_CONFIG = 0x0002;
    public const uint SERVICE_QUERY_CONFIG = 0x0001;
    public const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ChangeServiceConfigW(IntPtr service, uint type, uint startType, uint errorControl,
        string? binaryPath, string? loadOrderGroup, IntPtr tagId, string? dependencies, string? startName, string? password, string? displayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr handle);

    // ---- Shares ----

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetShareEnum(string? server, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_2
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string shi2_netname;
        public uint shi2_type;
        [MarshalAs(UnmanagedType.LPWStr)] public string shi2_remark;
        public uint shi2_permissions;
        public uint shi2_max_uses;
        public uint shi2_current_uses;
        [MarshalAs(UnmanagedType.LPWStr)] public string shi2_path;
        [MarshalAs(UnmanagedType.LPWStr)] public string shi2_passwd;
    }

    public const uint STYPE_SPECIAL = 0x80000000;

    // ---- Local accounts ----

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetUserEnum(string? server, int level, int filter, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref int resumeHandle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_name;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_home_dir;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_comment;
        public uint usri1_flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri1_script_path;
    }

    public const int FILTER_NORMAL_ACCOUNT = 2;
    public const uint UF_ACCOUNTDISABLE = 0x2;
}
