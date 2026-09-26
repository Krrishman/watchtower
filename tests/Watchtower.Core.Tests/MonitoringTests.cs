using Watchtower.Core.Alerts;
using Watchtower.Core.Exposure;
using Watchtower.Core.Monitoring;

namespace Watchtower.Core.Tests;

public class MonitoringTests
{
    private static readonly SignatureInfo Unsigned = new("NotSigned", null, false);
    private static readonly HashSet<string> Tools = new(StringComparer.OrdinalIgnoreCase) { "anydesk.exe" };

    [Fact]
    public void NewProgramIsWatchedForListenersAndOutbound()
    {
        var now = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var tracker = new ProgramTracker(new PersistentSet(null), () => now, @"C:\Windows");
        tracker.Seed([@"C:\Windows\explorer.exe"]);

        var start = tracker.OnProcessStart(new ProcessStart(50, 1, "evil.exe", @"C:\Temp\evil.exe", null), Unsigned, Tools);
        Assert.Equal([AlertKinds.ProgramFirstSeen], start.Select(d => d.Kind));

        var listen = tracker.OnListeners([new Listener(50, "evil.exe", null, "0.0.0.0", 4444), new Listener(50, "evil.exe", null, "127.0.0.1", 5555)]);
        Assert.Equal("4444", Assert.Single(listen).Subject[SubjectKeys.LocalPort]);
        Assert.Empty(tracker.OnListeners([new Listener(50, "evil.exe", null, "0.0.0.0", 4444)]));

        Assert.Single(tracker.OnConnection(new Connection(50, "evil.exe", null, "203.0.113.9", 443, 50000, false)));
        Assert.Empty(tracker.OnConnection(new Connection(50, "evil.exe", null, "203.0.113.9", 443, 50001, false)));

        now = now.AddMinutes(6);
        Assert.Empty(tracker.OnConnection(new Connection(50, "evil.exe", null, "198.51.100.1", 443, 50002, false)));
    }

    [Fact]
    public void KnownProgramsAndSeededProgramsDoNotAlert()
    {
        var tracker = new ProgramTracker(new PersistentSet(null), () => DateTimeOffset.UtcNow, @"C:\Windows");
        tracker.Seed([@"C:\App\app.exe"]);
        Assert.Empty(tracker.OnProcessStart(new ProcessStart(1, 0, "app.exe", @"C:\App\app.exe", null), Unsigned, Tools));
    }

    [Fact]
    public void RemoteToolAlertsOncePerBurst()
    {
        var tracker = new ProgramTracker(new PersistentSet(null), () => DateTimeOffset.UtcNow, @"C:\Windows");
        tracker.Seed([@"C:\AnyDesk\AnyDesk.exe"]);
        var first = tracker.OnProcessStart(new ProcessStart(1, 0, "AnyDesk.exe", @"C:\AnyDesk\AnyDesk.exe", null), Unsigned, Tools);
        var second = tracker.OnProcessStart(new ProcessStart(2, 1, "AnyDesk.exe", @"C:\AnyDesk\AnyDesk.exe", null), Unsigned, Tools);
        Assert.Contains(first, d => d.Kind == AlertKinds.RemoteToolStarted);
        Assert.Empty(second);
    }

    [Fact]
    public void MasqueradeReportedOncePerPath()
    {
        var tracker = new ProgramTracker(new PersistentSet(null), () => DateTimeOffset.UtcNow, @"C:\Windows");
        tracker.Seed([@"C:\x"]);
        var p = new ProcessStart(1, 0, "svchost.exe", @"C:\Users\a\AppData\svchost.exe", null);
        Assert.Contains(tracker.OnProcessStart(p, Unsigned, Tools), d => d.Kind == AlertKinds.ProgramMasquerading);
        Assert.DoesNotContain(tracker.OnProcessStart(p with { Pid = 2 }, Unsigned, Tools), d => d.Kind == AlertKinds.ProgramMasquerading);
    }

    [Fact]
    public void NetworkTrackerIgnoresLanInboundButFlagsInternetInbound()
    {
        var net = new NetworkTracker(new PersistentSet(null), new PersistentSet(null));
        Assert.Empty(net.Observe(new Connection(1, "game.exe", @"C:\g.exe", "192.168.1.9", 5000, 27015, true), Unsigned));
        Assert.Equal(AlertKinds.InboundConnection, Assert.Single(net.Observe(new Connection(1, "game.exe", @"C:\g.exe", "203.0.113.2", 5000, 27015, true), Unsigned)).Kind);
        Assert.Empty(net.Observe(new Connection(1, "x", null, "127.0.0.1", 1, 2, false), Unsigned));
    }

    [Fact]
    public void NetworkSeedLearnsExistingConnections()
    {
        var net = new NetworkTracker(new PersistentSet(null), new PersistentSet(null));
        var c = new Connection(1, "chrome.exe", @"C:\chrome.exe", "142.250.1.1", 443, 5000, false);
        net.Seed([c]);
        Assert.Empty(net.Observe(c, Unsigned));
        Assert.Single(net.Observe(c with { RemoteAddress = "142.250.1.2" }, Unsigned));
    }

    [Fact]
    public void SessionTrackerAlertsOnNewRdpAndAgainAfterReconnect()
    {
        var tracker = new SessionTracker();
        var rdp = new SessionInfo(2, "bob", "PC", "RDP-Tcp#0", true, "Active", "LAPTOP", "10.0.0.5");
        var console = new SessionInfo(1, "me", "PC", "Console", false, "Active", null, null);

        Assert.Single(tracker.Observe([console, rdp]));
        Assert.Empty(tracker.Observe([console, rdp]));
        Assert.Empty(tracker.Observe([console]));
        Assert.Single(tracker.Observe([console, rdp]));
    }

    [Fact]
    public void DeviceTrackerLearnsHistoryThenAlertsOnNewUse()
    {
        var tracker = new DeviceTracker();
        Assert.Empty(tracker.Observe([new DeviceUse("webcam", "C:#Zoom#Zoom.exe", 100, 200)]));
        var alerts = tracker.Observe([new DeviceUse("webcam", "C:#Zoom#Zoom.exe", 300, 0)]);
        var alert = Assert.Single(alerts);
        Assert.Equal(AlertKinds.CameraUsed, alert.Kind);
        Assert.Equal("Zoom.exe", alert.Subject[SubjectKeys.AppName]);
        Assert.Equal(@"C:\Zoom\Zoom.exe", alert.Subject[SubjectKeys.ProcessPath]);
        Assert.Null(alert.SeverityOverride);
        Assert.Empty(tracker.Observe([new DeviceUse("webcam", "C:#Zoom#Zoom.exe", 300, 0)]));
    }

    [Fact]
    public void DeviceTrackerAlertsImmediatelyIfInUseAtStartup() =>
        Assert.Single(new DeviceTracker().Observe([new DeviceUse("microphone", "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe", 5, 0)]));

    [Fact]
    public void StartupTrackerSeedsThenReportsAdditions()
    {
        using var dir = new TempDir();
        var tracker = new StartupTracker(new PersistentSet(dir.File("startup.json")));
        var a = new StartupItem("run|a", "A", "a.exe", "HKLM Run", false);
        Assert.Empty(tracker.Observe([a], null));

        var reloaded = new StartupTracker(new PersistentSet(dir.File("startup.json")));
        var svc = new StartupItem("svc|evil", "EvilSvc", @"C:\evil.exe", "Services", true);
        var drafts = reloaded.Observe([a, svc], "installer.exe");
        Assert.Equal(AlertKinds.ServiceInstalled, Assert.Single(drafts).Kind);
        Assert.Equal("installer.exe", drafts[0].Subject[SubjectKeys.RelatedProgram]);
    }

    private static LogonEvent Evt(int id, int second, params (string, string)[] data) =>
        new(id, DateTimeOffset.Parse("2026-01-01T00:00:00Z").AddSeconds(second), data.ToDictionary(d => d.Item1, d => d.Item2));

    [Fact]
    public void LogonTrackerRemoteSuccessAndLogoffDuration()
    {
        var tracker = new LogonTracker(_ => null);
        var success = tracker.Observe(Evt(4624, 0, ("LogonType", "10"), ("TargetUserName", "bob"), ("TargetDomainName", "PC"), ("TargetLogonId", "0x1a"), ("IpAddress", "10.0.0.8")));
        Assert.Equal(AlertKinds.RemoteLogon, Assert.Single(success).Kind);
        Assert.Equal(@"PC\bob", success[0].Subject[SubjectKeys.Account]);

        var end = tracker.Observe(Evt(4634, 3700, ("TargetLogonId", "0x1a")));
        Assert.Equal("1h 1m", Assert.Single(end).Subject[SubjectKeys.Duration]);
        Assert.Empty(tracker.Observe(Evt(4634, 3800, ("TargetLogonId", "0x1a"))));
    }

    [Fact]
    public void LogonTrackerIgnoresLocalAndMachineLogons()
    {
        var tracker = new LogonTracker(_ => null);
        Assert.Empty(tracker.Observe(Evt(4624, 0, ("LogonType", "2"), ("TargetUserName", "bob"))));
        Assert.Empty(tracker.Observe(Evt(4624, 0, ("LogonType", "10"), ("TargetUserName", "PC$"))));
        Assert.Empty(tracker.Observe(Evt(4625, 0, ("LogonType", "3"), ("TargetUserName", "bob"), ("IpAddress", "127.0.0.1"))));
    }

    [Fact]
    public void UntrustedAccountEscalates()
    {
        var tracker = new LogonTracker(a => a.EndsWith("alice"));
        var alerts = tracker.Observe(Evt(4624, 0, ("LogonType", "10"), ("TargetUserName", "mallory"), ("TargetDomainName", "PC")));
        Assert.Equal(AlertKinds.RemoteLogonUnrecognized, Assert.Single(alerts).Kind);
    }

    [Fact]
    public void RepeatedFailuresBecomeOnePasswordGuessingAlert()
    {
        var tracker = new LogonTracker(_ => null, threshold: 5);
        var kinds = new List<string>();
        for (var i = 0; i < 20; i++)
        {
            kinds.AddRange(tracker.Observe(Evt(4625, i * 10, ("LogonType", "3"), ("TargetUserName", "admin"), ("IpAddress", "::ffff:203.0.113.50"))).Select(d => d.Kind));
        }
        Assert.Equal([AlertKinds.RemoteLogonFailed, AlertKinds.PasswordGuessing], kinds);

        var later = tracker.Observe(Evt(4625, 3600, ("LogonType", "3"), ("TargetUserName", "admin"), ("IpAddress", "203.0.113.50")));
        Assert.Equal(AlertKinds.RemoteLogonFailed, Assert.Single(later).Kind);
    }

    [Fact]
    public void GapDetectorClassifiesWhyMonitoringStopped()
    {
        var boot = DateTimeOffset.Parse("2026-01-02T08:00:00Z");
        var now = DateTimeOffset.Parse("2026-01-02T09:00:00Z");
        Heartbeat Hb(string t, bool clean, string? reason = null) => new() { Time = t, Clean = clean, Reason = reason };

        Assert.Null(GapDetector.Evaluate(null, boot, now));
        Assert.Equal(AlertKinds.MonitoringKilled, GapDetector.Evaluate(Hb("2026-01-02T08:30:00Z", false), boot, now)!.Kind);
        Assert.Equal(AlertKinds.MonitoringGap, GapDetector.Evaluate(Hb("2026-01-01T22:00:00Z", false), boot, now)!.Kind);
        Assert.Equal(AlertKinds.MonitoringGap, GapDetector.Evaluate(Hb("2026-01-01T22:00:00Z", true, StopReasons.Shutdown), boot, now)!.Kind);
        Assert.Equal(AlertKinds.MonitoringStopped, GapDetector.Evaluate(Hb("2026-01-02T08:30:00Z", true, StopReasons.Stop), boot, now)!.Kind);
        Assert.Null(GapDetector.Evaluate(Hb("2026-01-02T08:30:00Z", true, StopReasons.Update), boot, now));
    }

    [Fact]
    public void PersistentSetIsBoundedAndPersists()
    {
        using var dir = new TempDir();
        var set = new PersistentSet(dir.File("s.json"), capacity: 10);
        for (var i = 0; i < 25; i++) set.Add($"item{i}");
        Assert.True(set.Count <= 10);
        Assert.True(set.Contains("item24"));
        set.Flush();
        Assert.True(new PersistentSet(dir.File("s.json")).Contains("item24"));
    }

    [Theory]
    [InlineData("10.1.2.3", "private")]
    [InlineData("172.20.0.1", "private")]
    [InlineData("172.32.0.1", "public")]
    [InlineData("100.64.0.1", "cgnat")]
    [InlineData("169.254.3.3", "link-local")]
    [InlineData("8.8.8.8", "public")]
    [InlineData("fe80::1%12", "link-local")]
    [InlineData("fd00::1", "private")]
    [InlineData("2001:db8::1", "ipv6")]
    public void ClassifyIp(string ip, string expected) => Assert.Equal(expected, ExposureAnalyzer.ClassifyIp(ip));

    [Fact]
    public void ExposureFindingsAreSortedAndPlain()
    {
        var report = ExposureAnalyzer.Analyze(new ExposureReport
        {
            Listening = [new ListeningPort(3389, "0.0.0.0", "all-interfaces", true, 1, "svchost.exe", null, "Remote Desktop")],
            Firewall = [new FirewallProfile("Public", false, "Block")],
            Rdp = new RdpStatus(true, 3389, false),
            Dns = [new DnsConfig("Wi-Fi", ["192.168.1.1"])],
        });
        Assert.All(report.Findings.Take(3), f => Assert.Equal(Severity.Critical, f.Severity));
        Assert.Contains(report.Findings, f => f.Title.Contains("without Network Level Authentication"));
        Assert.DoesNotContain(report.Findings, f => f.Title.Contains("DNS"));
    }
}
