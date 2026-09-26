using System.Net;
using Watchtower.Core.Alerts;
using Watchtower.Core.Safety;

namespace Watchtower.Core.Monitoring;

/// <summary>First outbound connection per program and destination, and inbound connections from the internet.</summary>
public sealed class NetworkTracker
{
    private readonly PersistentSet _outbound;
    private readonly PersistentSet _inbound;

    public NetworkTracker(PersistentSet outbound, PersistentSet inbound)
    {
        _outbound = outbound;
        _inbound = inbound;
    }

    public void Seed(IEnumerable<Connection> current)
    {
        if (_outbound.Count > 0) return;
        foreach (var c in current.Where(c => !c.Inbound && IsRoutable(c.RemoteAddress))) _outbound.Add(Key(c));
    }

    public IReadOnlyList<AlertDraft> Observe(Connection c, SignatureInfo sig)
    {
        if (!IsRoutable(c.RemoteAddress)) return [];

        if (c.Inbound)
        {
            // Inbound traffic from the local network (printers, casting, file sharing)
            // is normal; only visitors from the internet are worth a warning.
            if (!IPAddress.TryParse(c.RemoteAddress, out var ip) || ActionGuard.IsPrivate(ip)) return [];
            return _inbound.Add(Key(c)) ? [Draft(AlertKinds.InboundConnection, c, sig)] : [];
        }

        return _outbound.Add(Key(c)) ? [Draft(AlertKinds.FirstConnection, c, sig)] : [];
    }

    public void Flush()
    {
        _outbound.Flush();
        _inbound.Flush();
    }

    private static string Key(Connection c) => $"{c.ProcessPath ?? c.ProcessName}|{c.RemoteAddress}";

    private static AlertDraft Draft(string kind, Connection c, SignatureInfo sig) => AlertDraft.Of(kind,
        (SubjectKeys.ProcessName, c.ProcessName),
        (SubjectKeys.ProcessPath, c.ProcessPath),
        (SubjectKeys.Pid, c.Pid.ToString()),
        (SubjectKeys.RemoteAddress, c.RemoteAddress),
        (SubjectKeys.RemotePort, c.RemotePort.ToString()),
        (SubjectKeys.LocalPort, c.LocalPort.ToString()),
        (SubjectKeys.Signer, sig.Signer),
        (SubjectKeys.SignatureStatus, sig.Status));

    public static bool IsRoutable(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;
        return ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ip.GetAddressBytes() is not [169, 254, ..];
    }

    public static bool IsLoopbackBinding(string address) =>
        IPAddress.TryParse(address, out var ip) && IPAddress.IsLoopback(ip);
}
