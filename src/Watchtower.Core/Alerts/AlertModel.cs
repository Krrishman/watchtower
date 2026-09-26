namespace Watchtower.Core.Alerts;

public static class Severity
{
    public const string Info = "info";
    public const string Warn = "warn";
    public const string Critical = "critical";

    public static int Rank(string severity) => severity switch
    {
        Critical => 2,
        Warn => 1,
        _ => 0,
    };
}

public static class SubjectKeys
{
    public const string ProcessName = "processName";
    public const string ProcessPath = "processPath";
    public const string Pid = "pid";
    public const string ParentName = "parentName";
    public const string Signer = "signer";
    public const string SignatureStatus = "signatureStatus";
    public const string RemoteAddress = "remoteAddress";
    public const string RemotePort = "remotePort";
    public const string LocalPort = "localPort";
    public const string Account = "account";
    public const string Domain = "domain";
    public const string SessionId = "sessionId";
    public const string SessionName = "sessionName";
    public const string ClientName = "clientName";
    public const string ClientAddress = "clientAddress";
    public const string LogonType = "logonType";
    public const string Duration = "duration";
    public const string Count = "count";
    public const string Window = "window";
    public const string Device = "device";
    public const string AppName = "appName";
    public const string StillActive = "stillActive";
    public const string StartupKey = "startupKey";
    public const string StartupName = "startupName";
    public const string StartupCommand = "startupCommand";
    public const string StartupLocation = "startupLocation";
    public const string RelatedProgram = "relatedProgram";
    public const string ExpectedLocation = "expectedLocation";
    public const string From = "from";
    public const string To = "to";
    public const string Reason = "reason";
    public const string Version = "version";
    public const string PreviousVersion = "previousVersion";
    public const string RuleType = "ruleType";
    public const string RuleValue = "ruleValue";
    public const string Actor = "actor";
    public const string ActionName = "action";
    public const string Target = "target";
    public const string ThreatName = "threatName";
}

/// <summary>What a monitor reports. Rendering, trust and logging happen in <see cref="AlertPipeline"/>.</summary>
public sealed record AlertDraft(string Kind, IReadOnlyDictionary<string, string> Subject)
{
    public string? SeverityOverride { get; init; }

    public static AlertDraft Of(string kind, params (string Key, string? Value)[] subject)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in subject)
        {
            if (!string.IsNullOrEmpty(value)) dict[key] = value;
        }
        return new AlertDraft(kind, dict);
    }
}

public sealed record TrustOption(string Type, string Value, string Label, string? ProcessPath = null);

/// <summary>An alert as shown to the user: the stored history entry plus the catalog's plain-English guidance.</summary>
public sealed record Alert
{
    public required string Id { get; init; }
    public long Seq { get; init; }
    public required string Time { get; init; }
    public required string Kind { get; init; }
    public required string Source { get; init; }
    public required string Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public string Explanation { get; init; } = "";
    public string Advice { get; init; } = "";
    public IReadOnlyDictionary<string, string> Subject { get; init; } = new Dictionary<string, string>();
    public IReadOnlyList<string> Actions { get; init; } = [];
    public IReadOnlyList<TrustOption> TrustOptions { get; init; } = [];
    public string? SuppressedBy { get; init; }
}
