using Watchtower.Core.Config;

namespace Watchtower.Core.Updates;

public sealed record UpdateState
{
    public string? PendingVersion { get; init; }
    public string? PreviousVersion { get; init; }
    /// <summary>Installer for the version we came from, kept so a failed update can be undone offline.</summary>
    public string? PreviousPackage { get; init; }
    public string? StartedAt { get; init; }
    public int Starts { get; init; }
    public bool RollingBack { get; init; }
    public string? RollbackReason { get; init; }
    public long LastManifestSequence { get; init; }
    public List<string> FailedVersions { get; init; } = [];
}

public enum GateAction
{
    None,
    /// <summary>New version is running; keep watching until it has proven healthy.</summary>
    Probation,
    /// <summary>New version keeps failing to start; reinstall the previous one.</summary>
    Rollback,
    /// <summary>The installer didn't take; the previous version is still running.</summary>
    InstallFailed,
    /// <summary>A rollback finished; report it.</summary>
    RolledBack,
    /// <summary>The new version passed probation; report the update.</summary>
    Verified,
}

public sealed record GateResult(GateAction Action, string? Version, string? PreviousVersion, string? Package, string? Reason);

/// <summary>
/// Health-gates each update on the machine itself. The service restarts after a
/// crash (Windows service recovery), and each start counts. If the new version
/// can't stay up long enough to prove itself, the previous version goes back on.
/// </summary>
public sealed class UpdateHealthGate
{
    public const int MaxStartsBeforeRollback = 3;
    public static readonly TimeSpan Probation = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan InstallTimeout = TimeSpan.FromMinutes(30);

    private readonly JsonFileStore<UpdateState> _store;

    public UpdateHealthGate(string path) => _store = new JsonFileStore<UpdateState>(path);

    public UpdateState State => _store.Value;

    public void BeginInstall(string from, string to, string? previousPackage, DateTimeOffset now) =>
        _store.Update(s => s with
        {
            PendingVersion = to,
            PreviousVersion = from,
            PreviousPackage = previousPackage,
            StartedAt = now.ToString("o"),
            Starts = 0,
            RollingBack = false,
            RollbackReason = null,
        });

    public void RecordManifestSequence(long sequence) =>
        _store.Update(s => s with { LastManifestSequence = Math.Max(s.LastManifestSequence, sequence) });

    /// <summary>Call first thing on every service start, before anything that could crash.</summary>
    public GateResult OnServiceStart(string runningVersion, DateTimeOffset now)
    {
        var s = _store.Value;
        if (s.PendingVersion is null) return new(GateAction.None, null, null, null, null);

        if (s.RollingBack)
        {
            if (runningVersion == s.PreviousVersion)
            {
                Clear(failed: s.PendingVersion);
                return new(GateAction.RolledBack, s.PendingVersion, s.PreviousVersion, null, s.RollbackReason);
            }
            // Still on the bad version: the rollback installer hasn't run or failed. Try again.
            return new(GateAction.Rollback, s.PendingVersion, s.PreviousVersion, s.PreviousPackage, s.RollbackReason);
        }

        if (runningVersion != s.PendingVersion)
        {
            var started = DateTimeOffset.TryParse(s.StartedAt, out var t) ? t : now;
            if (now - started < InstallTimeout) return new(GateAction.None, null, null, null, null);
            Clear(failed: s.PendingVersion);
            return new(GateAction.InstallFailed, s.PendingVersion, runningVersion, null, "the installer did not complete");
        }

        var starts = s.Starts + 1;
        if (starts > MaxStartsBeforeRollback && s.PreviousPackage is not null)
        {
            var reason = $"it stopped unexpectedly {starts - 1} times";
            _store.Update(x => x with { Starts = starts, RollingBack = true, RollbackReason = reason });
            return new(GateAction.Rollback, s.PendingVersion, s.PreviousVersion, s.PreviousPackage, reason);
        }
        _store.Update(x => x with { Starts = starts });
        return new(GateAction.Probation, s.PendingVersion, s.PreviousVersion, null, null);
    }

    /// <summary>Call once the new version has run cleanly for <see cref="Probation"/>.</summary>
    public GateResult MarkHealthy()
    {
        var s = _store.Value;
        if (s.PendingVersion is null || s.RollingBack) return new(GateAction.None, null, null, null, null);
        Clear(failed: null);
        return new(GateAction.Verified, s.PendingVersion, s.PreviousVersion, null, null);
    }

    private void Clear(string? failed) => _store.Update(s => s with
    {
        PendingVersion = null,
        PreviousVersion = null,
        PreviousPackage = null,
        StartedAt = null,
        Starts = 0,
        RollingBack = false,
        RollbackReason = null,
        FailedVersions = failed is null || s.FailedVersions.Contains(failed) ? s.FailedVersions : [.. s.FailedVersions, failed],
    });
}
