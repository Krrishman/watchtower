using Watchtower.Core.Alerts;
using Watchtower.Core.Safety;

namespace Watchtower.Core.Monitoring;

/// <summary>
/// Watches process launches: remote-control tools, programs disguised as Windows
/// files, and never-before-seen executables, which get five minutes of closer
/// scrutiny for opening ports or phoning home.
/// </summary>
public sealed class ProgramTracker
{
    private sealed record Observation(string Name, string Path, SignatureInfo Signature, DateTimeOffset Until)
    {
        public HashSet<int> Ports { get; } = [];
        public HashSet<string> Remotes { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly PersistentSet _known;
    private readonly Func<DateTimeOffset> _clock;
    private readonly string _systemRoot;
    private readonly TimeSpan _window;
    private readonly Dictionary<int, Observation> _observed = [];
    private readonly HashSet<string> _masqueradeReported = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _toolReported = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ProgramTracker(PersistentSet known, Func<DateTimeOffset> clock, string systemRoot, TimeSpan? window = null)
    {
        _known = known;
        _clock = clock;
        _systemRoot = systemRoot;
        _window = window ?? TimeSpan.FromMinutes(5);
    }

    /// <summary>On the very first run, everything already installed is simply learned.</summary>
    public void Seed(IEnumerable<string> runningPaths)
    {
        if (_known.Count > 0) return;
        foreach (var path in runningPaths) _known.Add(path);
    }

    public IReadOnlyList<AlertDraft> OnProcessStart(ProcessStart p, SignatureInfo sig, ISet<string> watchlist)
    {
        var drafts = new List<AlertDraft>();
        var now = _clock();
        lock (_gate)
        {
            if (SystemProcesses.Masquerade(p.Name, p.Path, _systemRoot) is { } expected && _masqueradeReported.Add(p.Path!))
            {
                drafts.Add(Draft(AlertKinds.ProgramMasquerading, p, sig, (SubjectKeys.ExpectedLocation, expected)));
            }

            if (watchlist.Contains(p.Name.ToLowerInvariant()) &&
                (!_toolReported.TryGetValue(p.Name, out var last) || now - last > TimeSpan.FromMinutes(1)))
            {
                // Remote tools launch several helper processes at once; one alert is enough.
                _toolReported[p.Name] = now;
                drafts.Add(Draft(AlertKinds.RemoteToolStarted, p, sig));
            }

            if (p.Path is not null && _known.Add(p.Path))
            {
                _observed[p.Pid] = new Observation(p.Name, p.Path, sig, now + _window);
                drafts.Add(Draft(AlertKinds.ProgramFirstSeen, p, sig));
            }
            else if (p.Path is not null && _observed.Values.FirstOrDefault(o => string.Equals(o.Path, p.Path, StringComparison.OrdinalIgnoreCase)) is { } parent)
            {
                // A second process of a program still under observation is watched too.
                _observed[p.Pid] = parent;
            }
        }
        return drafts;
    }

    public IReadOnlyList<AlertDraft> OnConnection(Connection c)
    {
        lock (_gate)
        {
            if (c.Inbound || !_observed.TryGetValue(c.Pid, out var obs) || _clock() > obs.Until) return [];
            if (!obs.Remotes.Add($"{c.RemoteAddress}:{c.RemotePort}")) return [];
            return [ObservedDraft(AlertKinds.ProgramNewOutbound, obs, c.Pid,
                (SubjectKeys.RemoteAddress, c.RemoteAddress), (SubjectKeys.RemotePort, c.RemotePort.ToString()))];
        }
    }

    public IReadOnlyList<AlertDraft> OnListeners(IEnumerable<Listener> listeners)
    {
        var drafts = new List<AlertDraft>();
        lock (_gate)
        {
            var now = _clock();
            foreach (var l in listeners)
            {
                if (!_observed.TryGetValue(l.Pid, out var obs) || now > obs.Until) continue;
                if (NetworkTracker.IsLoopbackBinding(l.Address)) continue;
                if (obs.Ports.Add(l.Port))
                {
                    drafts.Add(ObservedDraft(AlertKinds.ProgramNewListener, obs, l.Pid, (SubjectKeys.LocalPort, l.Port.ToString())));
                }
            }
        }
        return drafts;
    }

    /// <summary>Name of a program currently under first-run observation, to explain where a new startup entry came from.</summary>
    public string? RecentlyStartedNewProgram()
    {
        lock (_gate)
        {
            var now = _clock();
            return _observed.Values.Where(o => now <= o.Until).Select(o => o.Name).FirstOrDefault();
        }
    }

    public bool IsObserving
    {
        get { lock (_gate) return _observed.Count > 0; }
    }

    public void Expire()
    {
        lock (_gate)
        {
            var now = _clock();
            foreach (var pid in _observed.Where(kv => now > kv.Value.Until).Select(kv => kv.Key).ToList()) _observed.Remove(pid);
            foreach (var name in _toolReported.Where(kv => now - kv.Value > TimeSpan.FromMinutes(10)).Select(kv => kv.Key).ToList()) _toolReported.Remove(name);
        }
        _known.Flush();
    }

    private static AlertDraft Draft(string kind, ProcessStart p, SignatureInfo sig, params (string, string?)[] extra) =>
        AlertDraft.Of(kind, [
            (SubjectKeys.ProcessName, p.Name),
            (SubjectKeys.ProcessPath, p.Path),
            (SubjectKeys.Pid, p.Pid.ToString()),
            (SubjectKeys.Signer, sig.Signer),
            (SubjectKeys.SignatureStatus, sig.Status),
            .. extra,
        ]);

    private static AlertDraft ObservedDraft(string kind, Observation o, int pid, params (string, string?)[] extra) =>
        AlertDraft.Of(kind, [
            (SubjectKeys.ProcessName, o.Name),
            (SubjectKeys.ProcessPath, o.Path),
            (SubjectKeys.Pid, pid.ToString()),
            (SubjectKeys.Signer, o.Signature.Signer),
            (SubjectKeys.SignatureStatus, o.Signature.Status),
            .. extra,
        ]);
}
