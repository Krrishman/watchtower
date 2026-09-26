using System.Net;
using System.Net.Sockets;

namespace Watchtower.Core.Safety;

public enum GuardVerdict
{
    Allow,
    /// <summary>Allowed, but the user must confirm after reading <see cref="GuardDecision.Reason"/>.</summary>
    Confirm,
    Deny,
}

public sealed record GuardDecision(GuardVerdict Verdict, string Reason)
{
    public static GuardDecision Allow() => new(GuardVerdict.Allow, "");
    public static GuardDecision Confirm(string reason) => new(GuardVerdict.Confirm, reason);
    public static GuardDecision Deny(string reason) => new(GuardVerdict.Deny, reason);
}

public sealed record ProcessFacts
{
    public int Pid { get; init; }
    public string Name { get; init; } = "";
    public string? Path { get; init; }
    /// <summary>Windows marks some processes critical; terminating one bugchecks the machine.</summary>
    public bool IsOsCritical { get; init; }
    public bool SignedByMicrosoft { get; init; }
    public bool IsWatchtower { get; init; }
}

public sealed record NetworkFacts
{
    public IReadOnlyCollection<string> LocalAddresses { get; init; } = [];
    public IReadOnlyCollection<string> Gateways { get; init; } = [];
    public IReadOnlyCollection<string> DnsServers { get; init; } = [];
}

public sealed record StartupFacts
{
    public string Name { get; init; } = "";
    public string Command { get; init; } = "";
    public string Location { get; init; } = "";
}

/// <summary>
/// Decides whether a user-requested action is safe. The UI shows the reason; the
/// service enforces the verdict, so a compromised or buggy UI can't bypass it.
/// </summary>
public static class ActionGuard
{
    public static GuardDecision CanKill(ProcessFacts p, string systemRoot)
    {
        if (p.Pid is 0 or 4) return GuardDecision.Deny("This is the Windows kernel itself and can't be ended.");
        if (p.IsWatchtower) return GuardDecision.Deny("Watchtower won't end its own processes. Use the tray menu to quit the window, or uninstall Watchtower.");
        if (p.IsOsCritical) return GuardDecision.Deny($"Windows marks {p.Name} as critical. Ending it would crash the PC immediately.");

        var genuine = SystemProcesses.IsGenuine(p.Name, p.Path, systemRoot) && p.SignedByMicrosoft;
        var lower = p.Name.ToLowerInvariant();

        if (genuine && SystemProcesses.Critical.Contains(lower))
        {
            return GuardDecision.Deny($"{p.Name} is a core part of Windows. Ending it would crash the PC or sign everyone out.");
        }
        if (genuine && SystemProcesses.Security.Contains(lower))
        {
            return GuardDecision.Deny($"{p.Name} is part of Windows Security. Watchtower won't turn off your antivirus.");
        }
        if (genuine && SystemProcesses.Important.TryGetValue(lower, out var effect))
        {
            return GuardDecision.Confirm($"{p.Name} is part of Windows. Ending it {effect}.");
        }
        if (!genuine && SystemProcesses.ExpectedLocation(p.Name, systemRoot) is not null)
        {
            return GuardDecision.Confirm($"This program is named like a Windows file ({p.Name}) but isn't the real one. Ending it is recommended.");
        }
        return GuardDecision.Confirm($"End {p.Name}? Anything unsaved in it will be lost.");
    }

    public static GuardDecision CanBlock(string address, NetworkFacts net)
    {
        if (!IPAddress.TryParse(address, out var ip)) return GuardDecision.Deny($"\"{address}\" isn't a valid IP address.");

        if (IPAddress.IsLoopback(ip)) return GuardDecision.Deny("This is the PC itself. Blocking it would break many apps.");
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast) || ip.Equals(IPAddress.None))
        {
            return GuardDecision.Deny("That's a special address that can't be blocked on its own.");
        }
        if (IsMulticast(ip)) return GuardDecision.Deny("That's a multicast address used for local device discovery. Blocking it can break printing and casting.");

        var norm = ip.ToString();
        if (Contains(net.LocalAddresses, norm)) return GuardDecision.Deny("That's this PC's own address.");
        if (Contains(net.Gateways, norm)) return GuardDecision.Deny("That's your router. Blocking it would cut this PC off from the internet.");
        if (Contains(net.DnsServers, norm)) return GuardDecision.Deny("That's the DNS server this PC uses to look up websites. Blocking it would break browsing.");

        if (IsPrivate(ip)) return GuardDecision.Confirm($"{norm} is a device on your local network. Block all traffic to and from it?");
        return GuardDecision.Confirm($"Block all traffic to and from {norm} with a Windows Firewall rule?");
    }

    public static GuardDecision CanRemoveStartup(StartupFacts s)
    {
        var hay = $"{s.Name} {s.Command}".ToLowerInvariant();
        if (hay.Contains("securityhealth") || hay.Contains("windows defender") || hay.Contains("msmpeng"))
        {
            return GuardDecision.Deny("This starts Windows Security. Watchtower won't remove it.");
        }
        if (hay.Contains("watchtower")) return GuardDecision.Deny("This starts Watchtower itself.");
        if (hay.Contains(@"\windows\system32\") || hay.Contains(@"\windows\syswow64\"))
        {
            return GuardDecision.Confirm($"\"{s.Name}\" runs a Windows component. Removing it may turn off a Windows feature. The program itself won't be uninstalled.");
        }
        return GuardDecision.Confirm($"Stop \"{s.Name}\" from starting automatically? The program itself won't be uninstalled.");
    }

    public static GuardDecision CanDisconnect(bool isConsoleSession, bool isCallersSession)
    {
        if (isCallersSession) return GuardDecision.Confirm("This is your own session. You'll be signed out and lose unsaved work.");
        if (isConsoleSession) return GuardDecision.Confirm("This is the person at the keyboard of this PC. They'll be signed out and lose unsaved work.");
        return GuardDecision.Confirm("Sign this person out now? They'll lose unsaved work in that session.");
    }

    private static bool Contains(IEnumerable<string> set, string ip) =>
        set.Any(a => IPAddress.TryParse(a, out var x) && x.ToString() == ip);

    private static bool IsMulticast(IPAddress ip) => ip.AddressFamily == AddressFamily.InterNetworkV6
        ? ip.IsIPv6Multicast
        : ip.GetAddressBytes()[0] is >= 224 and <= 239;

    public static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) return IsPrivate(ip.MapToIPv4());
            var b = ip.GetAddressBytes();
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
        }
        var v = ip.GetAddressBytes();
        return v[0] == 10
            || (v[0] == 172 && v[1] is >= 16 and <= 31)
            || (v[0] == 192 && v[1] == 168)
            || (v[0] == 169 && v[1] == 254);
    }
}
