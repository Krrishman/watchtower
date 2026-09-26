using Watchtower.Core.Alerts;

namespace Watchtower.Core.Monitoring;

public sealed class SessionTracker
{
    private readonly HashSet<string> _known = [];

    public IReadOnlyList<AlertDraft> Observe(IReadOnlyList<SessionInfo> sessions)
    {
        var drafts = new List<AlertDraft>();
        var current = new HashSet<string>();
        foreach (var s in sessions.Where(s => s.IsRemote && s.User.Length > 0))
        {
            var key = $"{s.Id}|{s.Domain}\\{s.User}|{s.StationName}";
            current.Add(key);
            if (_known.Add(key))
            {
                drafts.Add(AlertDraft.Of(AlertKinds.RdpSessionActive,
                    (SubjectKeys.Account, s.Domain.Length > 0 ? $"{s.Domain}\\{s.User}" : s.User),
                    (SubjectKeys.SessionId, s.Id.ToString()),
                    (SubjectKeys.SessionName, s.StationName),
                    (SubjectKeys.ClientName, s.ClientName),
                    (SubjectKeys.ClientAddress, s.ClientAddress)));
            }
        }
        // Forget ended sessions so a later reconnect alerts again.
        _known.IntersectWith(current);
        return drafts;
    }
}

/// <summary>
/// Windows keeps a per-app ledger of camera and microphone use. Historic entries
/// seen at startup are learned silently; only new use after that alerts.
/// </summary>
public sealed class DeviceTracker
{
    private readonly Dictionary<string, long> _lastStart = new(StringComparer.OrdinalIgnoreCase);
    private bool _primed;

    public IReadOnlyList<AlertDraft> Observe(IReadOnlyList<DeviceUse> uses)
    {
        var drafts = new List<AlertDraft>();
        foreach (var use in uses)
        {
            if (use.Start == 0) continue;
            var key = $"{use.Device}|{use.AppKey}";
            var seenBefore = _lastStart.TryGetValue(key, out var previous);
            _lastStart[key] = use.Start;
            if (seenBefore && previous == use.Start) continue;
            if (!_primed && !use.Active) continue;

            var (name, path) = Describe(use.AppKey);
            drafts.Add(AlertDraft.Of(use.Device == "webcam" ? AlertKinds.CameraUsed : AlertKinds.MicrophoneUsed,
                    (SubjectKeys.Device, use.Device),
                    (SubjectKeys.AppName, name),
                    (SubjectKeys.ProcessPath, path),
                    (SubjectKeys.StillActive, use.Active ? "yes" : "no"))
                with { SeverityOverride = use.Active ? null : Severity.Info });
        }
        _primed = true;
        return drafts;
    }

    /// <summary>Desktop apps are stored as their path with '#' for '\'; Store apps by package family name.</summary>
    public static (string Name, string? Path) Describe(string appKey)
    {
        if (appKey.Contains('#'))
        {
            var path = appKey.Replace('#', '\\');
            return (Safety.SystemProcesses.WinFileName(path), path);
        }
        var family = appKey.Split('_')[0];
        var dot = family.LastIndexOf('.');
        return (dot >= 0 ? family[(dot + 1)..] : family, null);
    }
}

/// <summary>Diffs everything that starts automatically (Run keys, Startup folders, scheduled tasks, services).</summary>
public sealed class StartupTracker
{
    private readonly PersistentSet _known;

    public StartupTracker(PersistentSet known) => _known = known;

    public IReadOnlyList<AlertDraft> Observe(IReadOnlyList<StartupItem> snapshot, string? relatedProgram)
    {
        if (_known.Count == 0)
        {
            foreach (var item in snapshot) _known.Add(item.Key);
            _known.Flush();
            return [];
        }

        var drafts = new List<AlertDraft>();
        foreach (var item in snapshot)
        {
            if (!_known.Add(item.Key)) continue;
            drafts.Add(AlertDraft.Of(item.IsService ? AlertKinds.ServiceInstalled : AlertKinds.StartupEntryAdded,
                (SubjectKeys.StartupKey, item.Key),
                (SubjectKeys.StartupName, item.Name),
                (SubjectKeys.StartupCommand, item.Command),
                (SubjectKeys.StartupLocation, item.Location),
                (SubjectKeys.RelatedProgram, relatedProgram)));
        }
        _known.Flush();
        return drafts;
    }
}
