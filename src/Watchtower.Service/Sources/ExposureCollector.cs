using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Watchtower.Core.Exposure;
using Watchtower.Service.Native;
using static Watchtower.Service.Native.NativeMethods;

namespace Watchtower.Service.Sources;

/// <summary>Gathers what this machine exposes to the network, entirely from local sources: no outbound lookups.</summary>
public sealed class ExposureCollector(ProcessInfo processes)
{
    public ExposureReport Scan(string? userSid)
    {
        var report = new ExposureReport
        {
            Listening = Listening(),
            Adapters = Adapters(),
            Firewall = Firewall(),
            Rdp = Rdp(),
            Dns = Dns(),
            Hosts = Hosts(),
            Proxy = Proxy(userSid),
            Tunnels = Tunnels(),
            Shares = Shares(),
            ScannedAt = DateTimeOffset.UtcNow.ToString("o"),
        };
        return ExposureAnalyzer.Analyze(report);
    }

    private IReadOnlyList<ListeningPort> Listening()
    {
        var seen = new Dictionary<string, ListeningPort>();
        foreach (var row in TcpTable.Read().Where(r => r.Listening))
        {
            var scope = ExposureAnalyzer.ClassifyBinding(row.LocalAddress);
            var key = $"{row.LocalPort}|{scope}|{row.Pid}";
            if (seen.ContainsKey(key)) continue;
            var proc = processes.Lookup(row.Pid);
            seen[key] = new ListeningPort(row.LocalPort, row.LocalAddress, scope, scope != "local-only", row.Pid, proc.Name, proc.Path,
                ExposureAnalyzer.NotablePorts.TryGetValue(row.LocalPort, out var svc) ? svc : null);
        }
        return seen.Values.OrderByDescending(l => l.Exposed).ThenBy(l => l.Port).ToList();
    }

    private static IReadOnlyList<AdapterAddress> Adapters() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(a => new AdapterAddress(a.Address.ToString(), n.Name, ExposureAnalyzer.ClassifyIp(a.Address.ToString()))))
            .ToList();

    private static IReadOnlyList<FirewallProfile> Firewall()
    {
        var result = new List<FirewallProfile>();
        foreach (var (name, key) in new[] { ("Domain", "DomainProfile"), ("Private", "StandardProfile"), ("Public", "PublicProfile") })
        {
            // Group Policy settings override the local ones when present.
            using var policy = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{key}");
            using var local = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{key}");
            var enabled = (policy?.GetValue("EnableFirewall") ?? local?.GetValue("EnableFirewall")) is int e ? e != 0 : true;
            var inbound = (policy?.GetValue("DefaultInboundAction") ?? local?.GetValue("DefaultInboundAction")) is int i && i == 0 ? "Allow" : "Block";
            result.Add(new FirewallProfile(name, enabled, inbound));
        }
        return result;
    }

    private static RdpStatus Rdp()
    {
        using var ts = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
        using var tcp = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
        return new RdpStatus(
            ts?.GetValue("fDenyTSConnections") is int deny && deny == 0,
            tcp?.GetValue("PortNumber") is int port ? port : 3389,
            tcp?.GetValue("UserAuthentication") is not int nla || nla == 1);
    }

    private static IReadOnlyList<DnsConfig> Dns() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Select(n => new DnsConfig(n.Name, n.GetIPProperties().DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToList()))
            .Where(d => d.Servers.Count > 0)
            .ToList();

    private static IReadOnlyList<HostsEntry> Hosts()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
        try
        {
            return File.ReadAllLines(path)
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith('#'))
                .Where(l => !System.Text.RegularExpressions.Regex.IsMatch(l, @"^(127\.0\.0\.1|::1)\s+localhost$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                .Select(l =>
                {
                    var parts = l.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                    return new HostsEntry(parts[0], string.Join(' ', parts.Skip(1)), l);
                })
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static ProxyStatus Proxy(string? userSid)
    {
        bool enabled = false;
        string? server = null, pac = null;
        var sids = userSid is not null ? [userSid] : UserHives.Loaded().Select(h => { h.Dispose(); return h.Sid; }).ToList();
        foreach (var sid in sids)
        {
            using var root = UserHives.Open(sid);
            using var key = root?.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key is null) continue;
            if (key.GetValue("ProxyEnable") is int e && e == 1)
            {
                enabled = true;
                server ??= key.GetValue("ProxyServer") as string;
            }
            pac ??= key.GetValue("AutoConfigURL") as string;
        }
        return new ProxyStatus(enabled, server, pac, WinHttpProxy());
    }

    /// <summary>Machine-wide proxy used by services, stored as a small binary blob.</summary>
    private static string? WinHttpProxy()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
        if (key?.GetValue("WinHttpSettings") is not byte[] blob || blob.Length < 16) return null;
        var flags = BitConverter.ToInt32(blob, 8);
        if ((flags & 2) == 0) return "Direct access (no proxy server).";
        var len = BitConverter.ToInt32(blob, 12);
        return len > 0 && 16 + len <= blob.Length ? $"Proxy server: {System.Text.Encoding.ASCII.GetString(blob, 16, len)}" : "Proxy server set.";
    }

    private static IReadOnlyList<TunnelAdapter> Tunnels() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Select(n =>
            {
                var hay = $"{n.Name} {n.Description}";
                var recognized = ExposureAnalyzer.IsRecognizedTunnel(hay);
                var tunnelish = recognized || n.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp
                                || System.Text.RegularExpressions.Regex.IsMatch(hay, @"tunnel|vpn|\btap\b|\btun\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                return tunnelish
                    ? new TunnelAdapter(n.Name, n.Description, n.OperationalStatus.ToString(), n.OperationalStatus == OperationalStatus.Up, recognized)
                    : null;
            })
            .OfType<TunnelAdapter>()
            .ToList();

    private static IReadOnlyList<Share> Shares()
    {
        var shares = new List<Share>();
        var resume = 0;
        if (NetShareEnum(null, 2, out var buffer, -1, out var read, out _, ref resume) != 0) return shares;
        try
        {
            var size = Marshal.SizeOf<SHARE_INFO_2>();
            for (var i = 0; i < read; i++)
            {
                var s = Marshal.PtrToStructure<SHARE_INFO_2>(buffer + i * size);
                shares.Add(new Share(s.shi2_netname, s.shi2_path, (s.shi2_type & STYPE_SPECIAL) != 0 || s.shi2_netname.EndsWith('$')));
            }
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
        return shares;
    }
}
