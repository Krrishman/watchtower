using System.Net;
using System.Net.Sockets;
using Watchtower.Core.Alerts;
using Watchtower.Core.Safety;

namespace Watchtower.Core.Exposure;

public sealed record ListeningPort(int Port, string Address, string Scope, bool Exposed, int Pid, string Name, string? Path, string? Service);
public sealed record AdapterAddress(string Ip, string Adapter, string Kind);
public sealed record FirewallProfile(string Profile, bool Enabled, string DefaultInbound);
public sealed record RdpStatus(bool Enabled, int Port, bool NlaRequired);
public sealed record DnsConfig(string Adapter, IReadOnlyList<string> Servers);
public sealed record HostsEntry(string Ip, string Hosts, string Line);
public sealed record ProxyStatus(bool Enabled, string? Server, string? AutoConfigUrl, string? WinHttp);
public sealed record TunnelAdapter(string Name, string Description, string Status, bool Active, bool Recognized);
public sealed record Share(string Name, string? Path, bool Administrative);
public sealed record Finding(string Severity, string Title, string Detail);

public sealed record ExposureReport
{
    public IReadOnlyList<ListeningPort> Listening { get; init; } = [];
    public IReadOnlyList<AdapterAddress> Adapters { get; init; } = [];
    public IReadOnlyList<FirewallProfile> Firewall { get; init; } = [];
    public RdpStatus Rdp { get; init; } = new(false, 3389, true);
    public IReadOnlyList<DnsConfig> Dns { get; init; } = [];
    public IReadOnlyList<HostsEntry> Hosts { get; init; } = [];
    public ProxyStatus Proxy { get; init; } = new(false, null, null, null);
    public IReadOnlyList<TunnelAdapter> Tunnels { get; init; } = [];
    public IReadOnlyList<Share> Shares { get; init; } = [];
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public string ScannedAt { get; init; } = "";
}

/// <summary>Turns raw network facts into "what can reach this machine" findings, most serious first.</summary>
public static class ExposureAnalyzer
{
    public static readonly IReadOnlyDictionary<int, string> NotablePorts = new Dictionary<int, string>
    {
        [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [135] = "RPC",
        [139] = "NetBIOS", [445] = "SMB file sharing", [1433] = "SQL Server",
        [3306] = "MySQL", [3389] = "Remote Desktop", [5432] = "PostgreSQL",
        [5900] = "VNC", [5985] = "WinRM (HTTP)", [5986] = "WinRM (HTTPS)",
        [6379] = "Redis", [27017] = "MongoDB",
    };

    public static readonly string[] KnownVpnHints =
    [
        "wireguard", "openvpn", "tap-windows", "tailscale", "zerotier",
        "nordlynx", "expressvpn", "proton", "mullvad", "hamachi", "softether",
        "cisco anyconnect", "globalprotect", "forticlient", "pulse", "radmin vpn",
        "wan miniport", "teredo", "isatap", "hyper-v",
    ];

    public static string ClassifyBinding(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return "unknown";
        if (IPAddress.IsLoopback(ip)) return "local-only";
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return "all-interfaces";
        return "specific-interface";
    }

    public static string ClassifyIp(string address)
    {
        if (!IPAddress.TryParse(address.Split('%')[0], out var ip)) return "unknown";
        if (IPAddress.IsLoopback(ip)) return "loopback";
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal) return "link-local";
            return ActionGuard.IsPrivate(ip) ? "private" : "ipv6";
        }
        var b = ip.GetAddressBytes();
        if (b[0] == 169 && b[1] == 254) return "link-local";
        if (ActionGuard.IsPrivate(ip)) return "private";
        if (b[0] == 100 && b[1] is >= 64 and <= 127) return "cgnat";
        return "public";
    }

    public static bool IsRecognizedTunnel(string haystack) =>
        KnownVpnHints.Any(h => haystack.Contains(h, StringComparison.OrdinalIgnoreCase));

    public static ExposureReport Analyze(ExposureReport data) => data with { Findings = BuildFindings(data) };

    public static IReadOnlyList<Finding> BuildFindings(ExposureReport d)
    {
        var findings = new List<Finding>();

        foreach (var l in d.Listening.Where(l => l.Exposed))
        {
            var label = l.Service is null ? $"Port {l.Port}" : $"{l.Service} (port {l.Port})";
            findings.Add(new(l.Service is null ? Severity.Warn : Severity.Critical,
                $"{label} is reachable from your network",
                $"{l.Name} is accepting connections on {l.Address}. Other devices on your network can try to connect, and so can the internet if your router forwards this port."));
        }

        foreach (var a in d.Adapters.Where(a => a.Kind == "public"))
        {
            findings.Add(new(Severity.Critical, "This PC is directly on the internet",
                $"{a.Adapter} has the public address {a.Ip}. There's no router shielding this PC, so every open port above can be reached from anywhere."));
        }

        foreach (var f in d.Firewall.Where(f => !f.Enabled))
        {
            findings.Add(new(Severity.Critical, $"Windows Firewall is off for {f.Profile} networks",
                "Incoming connections aren't being filtered on this type of network. Turn the firewall back on unless another firewall product replaces it."));
        }

        if (d.Rdp.Enabled)
        {
            findings.Add(d.Rdp.NlaRequired
                ? new(Severity.Warn, $"Remote Desktop is turned on (port {d.Rdp.Port})",
                    "People can sign in to this PC from elsewhere if they know an account password. It's set up the safer way (Network Level Authentication). Turn it off if you don't use it.")
                : new(Severity.Critical, $"Remote Desktop is on without Network Level Authentication (port {d.Rdp.Port})",
                    "Anyone who can reach this PC can get to its sign-in screen without a password, which exposes it to known attacks. Turn on Network Level Authentication, or turn Remote Desktop off."));
        }

        if (d.Proxy.Enabled && d.Proxy.Server is not null)
        {
            findings.Add(new(Severity.Critical, "Your web traffic goes through a proxy",
                $"Traffic is routed via {d.Proxy.Server}. If you (or your workplace) didn't set this up, something may be reading your browsing."));
        }
        if (d.Proxy.AutoConfigUrl is not null)
        {
            findings.Add(new(Severity.Warn, "Proxy settings are loaded from a web address",
                $"Windows fetches its proxy settings from {d.Proxy.AutoConfigUrl}. Make sure you recognize it."));
        }

        if (d.Hosts.Count > 0)
        {
            findings.Add(new(Severity.Warn, $"{d.Hosts.Count} custom hosts-file {(d.Hosts.Count == 1 ? "entry" : "entries")}",
                "The hosts file can quietly send a website's name to a different server. Ad-blockers use it legitimately, but so does malware. Check the entries below."));
        }

        foreach (var t in d.Tunnels.Where(t => t.Active && !t.Recognized))
        {
            findings.Add(new(Severity.Warn, "An unrecognized network tunnel is active",
                $"\"{t.Name}\" ({t.Description}) is connected but doesn't match any known VPN software. If you didn't install a VPN, look into this."));
        }

        foreach (var s in d.Shares.Where(s => !s.Administrative))
        {
            findings.Add(new(Severity.Warn, $"A folder is shared on your network: {s.Name}",
                $"{s.Path} can be opened by other computers on your network. Stop sharing it if you don't need to."));
        }

        var dns = d.Dns.SelectMany(x => x.Servers).Distinct().ToList();
        if (dns.Count > 0 && dns.All(s => ClassifyIp(s) is "public" or "ipv6"))
        {
            findings.Add(new(Severity.Info, "DNS is set to public servers",
                $"Using {string.Join(", ", dns)}. That's normal if you chose them (Cloudflare, Google, Quad9). If you didn't, someone may be redirecting which websites you reach."));
        }

        return findings.OrderByDescending(f => Severity.Rank(f.Severity)).ToList();
    }
}
