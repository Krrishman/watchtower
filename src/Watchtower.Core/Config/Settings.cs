namespace Watchtower.Core.Config;

public static class UpdateRings
{
    /// <summary>Gets a release as soon as its rollout starts.</summary>
    public const string Early = "early";
    /// <summary>Gets a release when this machine's rollout bucket is reached.</summary>
    public const string Standard = "standard";
    /// <summary>Waits until a release has been fully rolled out for a week.</summary>
    public const string Delayed = "delayed";

    public static bool IsValid(string ring) => ring is Early or Standard or Delayed;
}

public sealed record OffsiteSettings
{
    public string? Destination { get; init; }
    public bool Enabled { get; init; }
    public int IntervalMinutes { get; init; } = 15;
    public string? LastSync { get; init; }
    public string? LastError { get; init; }
}

public sealed record WatchlistSettings
{
    public List<string> Custom { get; init; } = [];
    public List<string> Disabled { get; init; } = [];
}

public sealed record WatchtowerSettings
{
    public string InstallId { get; init; } = Guid.NewGuid().ToString("N");
    public bool SetupCompleted { get; init; }
    public string? LearningUntil { get; init; }
    public string UpdateRing { get; init; } = UpdateRings.Standard;
    public bool AutoUpdate { get; init; } = true;
    public bool CrashReports { get; init; }
    public string NotifyMinSeverity { get; init; } = "warn";
    public OffsiteSettings Offsite { get; init; } = new();
    public WatchlistSettings Watchlist { get; init; } = new();
    public List<string> Acknowledged { get; init; } = [];

    public bool IsLearning(DateTimeOffset now) =>
        LearningUntil is { } until && DateTimeOffset.TryParse(until, out var t) && now < t;
}
