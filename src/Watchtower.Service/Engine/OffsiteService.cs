using Watchtower.Core.Alerts;
using Watchtower.Core.Backup;

namespace Watchtower.Service.Engine;

/// <summary>Mirrors history off the machine on a timer, and within seconds of any critical alert.</summary>
public sealed class OffsiteService(EngineContext ctx, ILogger<OffsiteService> log) : BackgroundService
{
    private readonly SemaphoreSlim _urgent = new(0, 1);

    public void OnAlert(Alert alert)
    {
        if (alert.Severity == Severity.Critical && alert.SuppressedBy is null && _urgent.CurrentCount == 0)
        {
            try
            {
                _urgent.Release();
            }
            catch (SemaphoreFullException)
            {
            }
        }
    }

    public SyncResult SyncNow()
    {
        var s = ctx.Settings.Value.Offsite;
        if (s.Destination is null) return new(false, 0, null, "Choose a backup folder first.");
        var result = OffsiteBackup.Sync(ctx.History.DirectoryPath, s.Destination, Environment.MachineName, DateTimeOffset.UtcNow);
        ctx.Settings.Update(x => x with
        {
            Offsite = x.Offsite with
            {
                LastSync = result.Ok ? DateTimeOffset.UtcNow.ToString("o") : x.Offsite.LastSync,
                LastError = result.Ok ? null : result.Error,
            },
        });
        return result;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var last = DateTimeOffset.MinValue;
        while (!ct.IsCancellationRequested)
        {
            // Wake on a critical alert, or every minute to check whether a scheduled sync is due.
            var urgent = await _urgent.WaitAsync(TimeSpan.FromMinutes(1), ct);
            var s = ctx.Settings.Value.Offsite;
            if (!s.Enabled || s.Destination is null) continue;

            if (urgent)
            {
                // Let a burst of related alerts land first so one sync captures them all.
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
            else if (DateTimeOffset.UtcNow - last < TimeSpan.FromMinutes(Math.Max(1, s.IntervalMinutes)))
            {
                continue;
            }

            var result = SyncNow();
            last = DateTimeOffset.UtcNow;
            if (!result.Ok) log.LogWarning("Off-machine backup failed: {Error}", result.Error);
        }
    }
}
