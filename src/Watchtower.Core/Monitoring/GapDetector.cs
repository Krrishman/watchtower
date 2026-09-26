using Watchtower.Core.Alerts;

namespace Watchtower.Core.Monitoring;

public static class StopReasons
{
    public const string Shutdown = "shutdown";
    public const string Stop = "stop";
    public const string Update = "update";
}

/// <summary>Written every few seconds while running, and once more on a clean stop.</summary>
public sealed record Heartbeat
{
    public required string Time { get; init; }
    public bool Clean { get; init; }
    public string? Reason { get; init; }
    public string? Version { get; init; }
}

/// <summary>
/// On startup, works out why monitoring was offline and how worried to be: a
/// reboot is routine, an admin stopping the service is notable, and the process
/// vanishing while the PC stayed up is exactly what an attacker would do.
/// </summary>
public static class GapDetector
{
    public static AlertDraft? Evaluate(Heartbeat? last, DateTimeOffset bootTime, DateTimeOffset now)
    {
        if (last is null || !DateTimeOffset.TryParse(last.Time, out var lastTime)) return null;

        var from = lastTime.ToString("u");
        var to = now.ToString("u");
        var rebootedSince = lastTime < bootTime;

        if (last.Clean)
        {
            return last.Reason switch
            {
                StopReasons.Update => null,
                StopReasons.Stop => Gap(AlertKinds.MonitoringStopped, from, to, "stopped by an administrator"),
                _ => Gap(AlertKinds.MonitoringGap, from, to, "the PC was shut down or restarted"),
            };
        }

        return rebootedSince
            ? Gap(AlertKinds.MonitoringGap, from, to, "the PC lost power or crashed")
            : Gap(AlertKinds.MonitoringKilled, from, to, "the process ended unexpectedly");
    }

    private static AlertDraft Gap(string kind, string from, string to, string reason) =>
        AlertDraft.Of(kind, (SubjectKeys.From, from), (SubjectKeys.To, to), (SubjectKeys.Reason, reason));
}
