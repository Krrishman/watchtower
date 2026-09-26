namespace Watchtower.Core.Monitoring;

public sealed record SignatureInfo(string Status, string? Signer, bool IsMicrosoft)
{
    public static readonly SignatureInfo Unknown = new("Unknown", null, false);
    public bool IsValid => Status == "Valid";
}

public sealed record ProcessStart(int Pid, int ParentPid, string Name, string? Path, string? CommandLine);

public sealed record Connection(int Pid, string ProcessName, string? ProcessPath, string RemoteAddress, int RemotePort, int LocalPort, bool Inbound);

public sealed record Listener(int Pid, string ProcessName, string? ProcessPath, string Address, int Port);

public sealed record SessionInfo(int Id, string User, string Domain, string StationName, bool IsRemote, string State, string? ClientName, string? ClientAddress);

public sealed record StartupItem(string Key, string Name, string Command, string Location, bool IsService);

public sealed record DeviceUse(string Device, string AppKey, long Start, long Stop)
{
    public bool Active => Stop == 0;
}

public sealed record LogonEvent(int EventId, DateTimeOffset Time, IReadOnlyDictionary<string, string> Data);
