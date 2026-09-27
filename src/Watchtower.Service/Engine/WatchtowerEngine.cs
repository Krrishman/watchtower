using System.Threading.Channels;
using Watchtower.Core.Alerts;
using Watchtower.Core.Monitoring;
using Watchtower.Core.Safety;
using Watchtower.Service.Hosting;
using Watchtower.Service.Native;
using Watchtower.Service.Sources;

namespace Watchtower.Service.Engine;

public sealed record SensorStatus(string Name, string Mode, string? Detail);
public sealed record NetworkRow(string Process, string? Path, int Pid, string RemoteAddress, int RemotePort, int LocalPort, bool Inbound);
public sealed record ProcessRow(int Pid, string Name, string? Path, bool Signed, string SignatureStatus, string? Signer, bool Networked, bool Killable, string? Protection);
public sealed record RemoteToolRow(string Name, int Pid, string? Path);
public sealed record DeviceRow(string Device, string App, string? Path, bool Active);

/// <summary>
/// The monitoring engine. Real-time sources (ETW, the Security log) feed a bounded
/// queue that one consumer drains; cheap native snapshots run on timers. Every
/// periodic task is isolated, so one failing check can't stop the others.
/// </summary>
public sealed class WatchtowerEngine : BackgroundService
{
    private static readonly string SystemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private readonly EngineContext _ctx;
    private readonly ProcessInfo _processes;
    private readonly SignatureVerifier _signatures;
    private readonly IEventSink _events;
    private readonly HeartbeatFile _heartbeat;
    private readonly ILogger<WatchtowerEngine> _log;
    private readonly Channel<EngineEvent> _queue;

    private readonly ProgramTracker _programs;
    private readonly NetworkTracker _network;
    private readonly SessionTracker _sessions = new();
    private readonly DeviceTracker _devices = new();
    private readonly StartupTracker _startup;
    private readonly LogonTracker _logons;
    private readonly PersistentSet _defenderSeen;

    private EtwSource? _etw;
    private SecurityLogSource? _securityLog;
    private long _dropped;
    private long _processStarts;
    private long _tcpEvents;
    private HashSet<int> _polledPids = [];
    private HashSet<string> _polledConnections = [];
    private long? _reportedTamperSeq;

    public WatchtowerEngine(EngineContext ctx, ProcessInfo processes, SignatureVerifier signatures, IEventSink events, HeartbeatFile heartbeat, ILogger<WatchtowerEngine> log)
    {
        _ctx = ctx;
        _processes = processes;
        _signatures = signatures;
        _events = events;
        _heartbeat = heartbeat;
        _log = log;
        _queue = Channel.CreateBounded<EngineEvent>(
            new BoundedChannelOptions(20_000) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true },
            _ => Interlocked.Increment(ref _dropped));

        var paths = ctx.Paths;
        _programs = new ProgramTracker(new PersistentSet(paths.Baseline("programs")), () => DateTimeOffset.UtcNow, SystemRoot);
        _network = new NetworkTracker(new PersistentSet(paths.Baseline("network-out")), new PersistentSet(paths.Baseline("network-in")));
        _startup = new StartupTracker(new PersistentSet(paths.Baseline("startup")));
        _defenderSeen = new PersistentSet(paths.Baseline("defender"));
        _logons = new LogonTracker(account => ctx.Trust.HasAccountRules ? ctx.Trust.IsAccountTrusted(account) : null);
    }

    // ---- state the UI reads ----

    public IReadOnlyList<SessionInfo> CurrentSessions { get; private set; } = [];
    public IReadOnlyList<NetworkRow> CurrentNetwork { get; private set; } = [];
    public IReadOnlyList<ProcessRow> CurrentProcessTable { get; private set; } = [];
    public IReadOnlyList<RemoteToolRow> CurrentRemoteTools { get; private set; } = [];
    public IReadOnlyList<DeviceRow> CurrentDevices { get; private set; } = [];
    public IReadOnlyList<StartupItem> CurrentStartup { get; private set; } = [];
    public long ProcessStartsSeen => Interlocked.Read(ref _processStarts);
    public long TcpEventsSeen => Interlocked.Read(ref _tcpEvents);
    public bool RealTimeProcesses => _etw?.IsLive == true;
    public bool IsHealthy { get; private set; }

    public IReadOnlyList<SensorStatus> Sensors() =>
    [
        new("Process launches", _etw?.IsLive == true ? "live" : "polling", _etw?.IsLive == true ? null : _etw?.FailureReason),
        new("Network connections", _etw?.IsLive == true ? "live" : "polling", null),
        new("Sign-ins", _securityLog?.IsLive == true ? "live" : "unavailable", _securityLog?.FailureReason),
        new("Dropped events", Interlocked.Read(ref _dropped) == 0 ? "none" : Interlocked.Read(ref _dropped).ToString(), null),
    ];

    public object StateSnapshot() => new
    {
        sessions = SessionRows(),
        network = CurrentNetwork,
        processTable = CurrentProcessTable,
        processes = CurrentRemoteTools,
        cameraMic = CurrentDevices,
        sensors = Sensors(),
        learningUntil = _ctx.Settings.Value.LearningUntil,
        version = AppVersion.Current,
    };

    private object SessionRows() => CurrentSessions.Select(s => new
    {
        id = s.Id,
        username = s.Domain.Length > 0 ? $"{s.Domain}\\{s.User}" : s.User,
        sessionName = s.StationName,
        state = s.State,
        remote = s.IsRemote,
        clientName = s.ClientName,
        clientAddress = s.ClientAddress,
    }).ToList();

    public string? RecentNewProgram => _programs.RecentlyStartedNewProgram();

    // ---- lifecycle ----

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Yield();
        ReportGap();
        _heartbeat.Write(clean: false);

        Seed();
        StartRealTime();

        var consumer = Task.Run(() => ConsumeAsync(ct), ct);
        var loops = new[]
        {
            Every(TimeSpan.FromSeconds(5), "sessions and devices", PollSessionsAndDevices, ct),
            Every(TimeSpan.FromSeconds(10), "network", PollNetwork, ct),
            Every(TimeSpan.FromSeconds(15), "process table", PollProcesses, ct),
            Every(TimeSpan.FromSeconds(15), "heartbeat", () => _heartbeat.Write(clean: false), ct),
            Every(TimeSpan.FromSeconds(60), "startup items", ScanStartup, ct),
            Every(TimeSpan.FromSeconds(60), "baselines", FlushBaselines, ct),
            Every(TimeSpan.FromMinutes(5), "Defender", CheckDefender, ct),
            Every(TimeSpan.FromMinutes(60), "history integrity", VerifyHistory, ct),
        };
        IsHealthy = true;

        try
        {
            await Task.WhenAll(loops.Append(consumer));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken ct)
    {
        _etw?.Dispose();
        _securityLog?.Dispose();
        _queue.Writer.TryComplete();
        await base.StopAsync(ct);
        FlushBaselines();
        _heartbeat.Write(clean: true, StopReason.Current);
    }

    private void ReportGap()
    {
        var draft = GapDetector.Evaluate(_heartbeat.Read(), HeartbeatFile.BootTime, DateTimeOffset.UtcNow);
        if (draft is not null) _ctx.Publish(draft);
    }

    private void Seed()
    {
        try
        {
            _programs.Seed(_processes.Snapshot().Select(p => p.Path).OfType<string>());
            var rows = TcpTable.Read();
            _network.Seed(rows.Where(r => r.Established).Select(r => ToConnection(r, inbound: false)));
            _polledPids = _processes.Snapshot().Select(p => p.Pid).ToHashSet();
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Baseline seeding failed");
        }
    }

    private void StartRealTime()
    {
        _etw = new EtwSource(_queue.Writer, _log);
        if (!_etw.Start())
        {
            _ctx.Publish(AlertDraft.Of(AlertKinds.DegradedCoverage, (SubjectKeys.Reason, $"{_etw.FailureReason} Program launches and connections are checked every few seconds instead.")));
        }
        _etw.Stopped += reason =>
        {
            _ctx.Publish(AlertDraft.Of(AlertKinds.DegradedCoverage, (SubjectKeys.Reason, reason)));
            PushSensors();
        };

        _securityLog = new SecurityLogSource(e =>
        {
            foreach (var d in _logons.Observe(e)) _ctx.Publish(d);
        }, _log);
        if (!_securityLog.Start())
        {
            _ctx.Publish(AlertDraft.Of(AlertKinds.DegradedCoverage, (SubjectKeys.Reason, $"{_securityLog.FailureReason} Remote sign-ins won't be recorded.")));
        }
        PushSensors();
    }

    private void PushSensors() => _events.Broadcast("snapshot", new { key = "sensors", rows = Sensors() });

    private async Task ConsumeAsync(CancellationToken ct)
    {
        await foreach (var e in _queue.Reader.ReadAllAsync(ct))
        {
            try
            {
                Handle(e);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to handle {Event}", e.GetType().Name);
            }
        }
    }

    private void Handle(EngineEvent e)
    {
        switch (e)
        {
            case ProcessStarted p:
            {
                Interlocked.Increment(ref _processStarts);
                // A process that already exited can't be opened for its path; fall back to the
                // command line from the kernel event so short-lived programs are still tracked.
                var record = _processes.Remember(p.Pid, p.ImageName, ProcessInfo.ImagePath(p.Pid) ?? PathFromCommandLine(p.CommandLine));
                var sig = _signatures.Check(record.Path);
                var watchlist = Watchlist.Active(_ctx.Settings.Value.Watchlist);
                foreach (var d in _programs.OnProcessStart(new ProcessStart(p.Pid, p.ParentPid, record.Name, record.Path, p.CommandLine), sig, watchlist))
                {
                    _ctx.Publish(d);
                }
                break;
            }
            case ProcessStopped s:
                _processes.Forget(s.Pid);
                break;
            case TcpEvent t:
            {
                Interlocked.Increment(ref _tcpEvents);
                var record = _processes.Lookup(t.Pid);
                var conn = new Connection(t.Pid, record.Name, record.Path, t.RemoteAddress, t.RemotePort, t.LocalPort, t.Inbound);
                foreach (var d in _programs.OnConnection(conn)) _ctx.Publish(d);
                foreach (var d in _network.Observe(conn, _signatures.Check(record.Path))) _ctx.Publish(d);
                break;
            }
        }
    }

    // ---- periodic checks ----

    private Task Every(TimeSpan interval, string name, Action work, CancellationToken ct) => Task.Run(async () =>
    {
        using var timer = new PeriodicTimer(interval);
        do
        {
            try
            {
                work();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning(ex, "Periodic check '{Name}' failed", name);
            }
        }
        while (await timer.WaitForNextTickAsync(ct));
    }, ct);

    private void PollSessionsAndDevices()
    {
        CurrentSessions = Sessions.Read();
        foreach (var d in _sessions.Observe(CurrentSessions)) _ctx.Publish(d);
        _events.Broadcast("snapshot", new { key = "sessions", rows = SessionRows() });

        var uses = DeviceUsageReader.Read();
        foreach (var d in _devices.Observe(uses)) _ctx.Publish(d);
        CurrentDevices = uses.Select(u =>
        {
            var (name, path) = DeviceTracker.Describe(u.AppKey);
            return new DeviceRow(u.Device, name, path, u.Active);
        }).ToList();
        _events.Broadcast("snapshot", new { key = "cameraMic", rows = CurrentDevices });
    }

    private void PollNetwork()
    {
        var rows = TcpTable.Read();
        var listeners = rows.Where(r => r.Listening).ToList();
        var listeningPorts = listeners.Select(r => r.LocalPort).ToHashSet();

        foreach (var d in _programs.OnListeners(listeners.Select(r =>
                 {
                     var p = _processes.Lookup(r.Pid);
                     return new Listener(r.Pid, p.Name, p.Path, r.LocalAddress, r.LocalPort);
                 })))
        {
            _ctx.Publish(d);
        }

        var established = rows.Where(r => r.Established && NetworkTracker.IsRoutable(r.RemoteAddress)).ToList();
        CurrentNetwork = established.Select(r =>
        {
            var p = _processes.Lookup(r.Pid);
            return new NetworkRow(p.Name, p.Path, r.Pid, r.RemoteAddress, r.RemotePort, r.LocalPort, listeningPorts.Contains(r.LocalPort));
        }).ToList();
        _events.Broadcast("snapshot", new { key = "network", rows = CurrentNetwork });

        if (_etw?.IsLive == true) return;

        // Polling fallback: new rows since last time stand in for connect events.
        var current = new HashSet<string>();
        foreach (var r in established)
        {
            var key = $"{r.Pid}|{r.RemoteAddress}|{r.RemotePort}|{r.LocalPort}";
            current.Add(key);
            if (!_polledConnections.Contains(key))
            {
                _queue.Writer.TryWrite(new TcpEvent(r.Pid, r.RemoteAddress, r.RemotePort, r.LocalPort, listeningPorts.Contains(r.LocalPort)));
            }
        }
        _polledConnections = current;
    }

    private void PollProcesses()
    {
        var snapshot = _processes.Snapshot();
        var byNet = CurrentNetwork.Select(n => n.Pid).ToHashSet();
        var watchlist = Watchlist.Active(_ctx.Settings.Value.Watchlist);

        CurrentProcessTable = snapshot
            .Where(p => p.Pid > 4)
            .Select(p =>
            {
                var sig = _signatures.Check(p.Path);
                var guard = ActionGuard.CanKill(new ProcessFacts
                {
                    Pid = p.Pid,
                    Name = p.Name,
                    Path = p.Path,
                    IsOsCritical = ProcessInfo.IsOsCritical(p.Pid),
                    SignedByMicrosoft = sig.IsMicrosoft,
                    IsWatchtower = p.Pid == Environment.ProcessId,
                }, SystemRoot);
                var denied = guard.Verdict == GuardVerdict.Deny;
                return new ProcessRow(p.Pid, p.Name, p.Path, sig.IsValid, sig.Status, sig.Signer, byNet.Contains(p.Pid), !denied, denied ? guard.Reason : null);
            })
            .OrderByDescending(p => p.Networked)
            .ToList();
        _events.Broadcast("snapshot", new { key = "processTable", rows = CurrentProcessTable });

        CurrentRemoteTools = snapshot.Where(p => watchlist.Contains(p.Name.ToLowerInvariant()))
            .Select(p => new RemoteToolRow(p.Name, p.Pid, p.Path)).ToList();
        _events.Broadcast("snapshot", new { key = "processes", rows = CurrentRemoteTools });

        if (_etw?.IsLive == true)
        {
            _polledPids = snapshot.Select(p => p.Pid).ToHashSet();
            return;
        }
        foreach (var p in snapshot.Where(p => !_polledPids.Contains(p.Pid)))
        {
            _queue.Writer.TryWrite(new ProcessStarted(p.Pid, 0, p.Name, null));
        }
        _polledPids = snapshot.Select(p => p.Pid).ToHashSet();
    }

    private void ScanStartup()
    {
        CurrentStartup = StartupScanner.Scan(_log);
        foreach (var d in _startup.Observe(CurrentStartup, _programs.RecentlyStartedNewProgram())) _ctx.Publish(d);
        PushSensors();
    }

    private void FlushBaselines()
    {
        _programs.Expire();
        _network.Flush();
        _defenderSeen.Flush();
    }

    private void CheckDefender()
    {
        foreach (var threat in DefenderReader.Threats())
        {
            if (!_defenderSeen.Add(threat.Id)) continue;
            _ctx.Publish(AlertDraft.Of(AlertKinds.DefenderThreat,
                (SubjectKeys.ThreatName, threat.Name),
                (SubjectKeys.ProcessName, threat.Process),
                (SubjectKeys.Target, threat.Resources)));
        }
    }

    private void VerifyHistory()
    {
        _ctx.History.TrimIfNeeded();
        var result = _ctx.History.Verify();
        if (result.Ok || result.BrokenAtSeq == _reportedTamperSeq) return;
        _reportedTamperSeq = result.BrokenAtSeq;
        _ctx.Publish(AlertDraft.Of(AlertKinds.HistoryTampered, (SubjectKeys.Reason, result.Message)));
    }

    private static string? PathFromCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var exe = StartupScanner.ExecutableOf(commandLine) is { } raw ? Core.Safety.SystemProcesses.StripNtPrefix(raw) : null;
        return exe is not null && Path.IsPathFullyQualified(exe) && File.Exists(exe) ? exe : null;
    }

    private Connection ToConnection(TcpRow r, bool inbound)
    {
        var p = _processes.Lookup(r.Pid);
        return new Connection(r.Pid, p.Name, p.Path, r.RemoteAddress, r.RemotePort, r.LocalPort, inbound);
    }
}
