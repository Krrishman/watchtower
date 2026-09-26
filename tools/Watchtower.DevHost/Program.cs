using System.IO.Pipes;
using System.Text.Json;
using Watchtower.Core.Alerts;
using Watchtower.Core.Config;
using Watchtower.Core.Exposure;
using Watchtower.Core.History;
using Watchtower.Core.Ipc;
using Watchtower.Core.Monitoring;
using Watchtower.Core.Safety;
using Watchtower.Core.Trust;

// Development stand-in for the Windows service. Runs the real Core logic (alert
// pipeline, trust rules, safety guards, tamper-evident history) behind the same RPC
// methods, with simulated Windows data, so the UI can be built and tested anywhere.
//
//   dotnet run --project tools/Watchtower.DevHost -- [--standard-user] [--fresh] [--data <dir>]
//
// On Windows it serves \\.\pipe\Watchtower.v1; elsewhere .NET maps that to a Unix socket.

var admin = !args.Contains("--standard-user");
var fresh = args.Contains("--fresh");
var dataDir = args.SkipWhile(a => a != "--data").Skip(1).FirstOrDefault() ?? Path.Combine(Path.GetTempPath(), "watchtower-devhost");
if (fresh && Directory.Exists(dataDir)) Directory.Delete(dataDir, recursive: true);
Directory.CreateDirectory(dataDir);

var settings = new JsonFileStore<WatchtowerSettings>(Path.Combine(dataDir, "settings.json"));
settings.Update(s => s.LearningUntil is null ? s with { LearningUntil = DateTimeOffset.UtcNow.AddHours(-1).ToString("o") } : s);
var trust = new TrustStore(Path.Combine(dataDir, "trust.json"));
var history = new HistoryLog(Path.Combine(dataDir, "history"));
var pipeline = new AlertPipeline(history, trust, () => DateTimeOffset.UtcNow, now => settings.Value.IsLearning(now));
var connections = new List<RpcConnection>();
var blocked = new List<string>();
var caller = new Caller(@"DESKTOP-DEMO\alex", admin, 1, 0, "S-1-5-21-1-2-3-1001");
const string SystemRoot = @"C:\Windows";

pipeline.Published += alert =>
{
    lock (connections) foreach (var c in connections) _ = c.SendEventAsync("alert", alert, CancellationToken.None);
};

var processes = new[]
{
    (Pid: 4, Name: "System", Path: (string?)null, Signer: "Microsoft Windows", Net: false),
    (Pid: 680, Name: "lsass.exe", Path: @"C:\Windows\System32\lsass.exe", Signer: "Microsoft Windows", Net: false),
    (Pid: 5120, Name: "explorer.exe", Path: @"C:\Windows\explorer.exe", Signer: "Microsoft Windows", Net: false),
    (Pid: 7788, Name: "chrome.exe", Path: @"C:\Program Files\Google\Chrome\Application\chrome.exe", Signer: "Google LLC", Net: true),
    (Pid: 9001, Name: "AnyDesk.exe", Path: @"C:\Users\alex\Downloads\AnyDesk.exe", Signer: "philandro Software GmbH", Net: true),
    (Pid: 9120, Name: "svchost.exe", Path: @"C:\Users\alex\AppData\Roaming\svchost.exe", Signer: (string?)null, Net: true),
    (Pid: 9200, Name: "helper.exe", Path: @"C:\Users\alex\AppData\Local\Temp\helper.exe", Signer: (string?)null, Net: true),
};

ProcessFacts Facts(int pid)
{
    var p = processes.FirstOrDefault(x => x.Pid == pid);
    return new ProcessFacts { Pid = pid, Name = p.Name ?? $"pid {pid}", Path = p.Path, SignedByMicrosoft = p.Signer == "Microsoft Windows" && p.Path?.StartsWith(SystemRoot) == true };
}

var startupItems = new List<StartupItem>
{
    new(@"run|HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run|Updater|C:\Users\alex\AppData\Local\Temp\helper.exe --silent", "Updater", @"C:\Users\alex\AppData\Local\Temp\helper.exe --silent", "Starts when DESKTOP-DEMO\\alex signs in", false),
    new(@"run|HKLM\Software\Microsoft\Windows\CurrentVersion\Run|SecurityHealth|%windir%\system32\SecurityHealthSystray.exe", "SecurityHealth", @"%windir%\system32\SecurityHealthSystray.exe", "Starts for every user", false),
};

var rpc = new RpcDispatcher();
rpc.Register("hello", Access.Read, (c, _) => new { protocol = RpcDispatcher.ProtocolVersion, version = "0.2.0-dev", user = c.UserName, isAdmin = c.IsAdministrator, setupCompleted = settings.Value.SetupCompleted });
rpc.Register("state.get", Access.Read, (_, _) => new
{
    sessions = new object[]
    {
        new { id = 1, username = @"DESKTOP-DEMO\alex", sessionName = "Console", state = "Active", remote = false },
        new { id = 3, username = @"DESKTOP-DEMO\support", sessionName = "RDP-Tcp#4", state = "Active", remote = true, clientName = "UNKNOWN-PC", clientAddress = "203.0.113.45" },
    },
    network = new object[]
    {
        new { process = "chrome.exe", pid = 7788, remoteAddress = "142.250.72.14", remotePort = 443, localPort = 50122, inbound = false },
        new { process = "AnyDesk.exe", pid = 9001, remoteAddress = "198.51.100.23", remotePort = 7070, localPort = 50310, inbound = false },
        new { process = "svchost.exe", pid = 9120, remoteAddress = "203.0.113.45", remotePort = 4444, localPort = 50400, inbound = false },
    },
    processTable = processes.Select(p =>
    {
        var guard = ActionGuard.CanKill(Facts(p.Pid), SystemRoot);
        return new { pid = p.Pid, name = p.Name, path = p.Path, signed = p.Signer is not null, signatureStatus = p.Signer is null ? "NotSigned" : "Valid", signer = p.Signer, networked = p.Net, killable = guard.Verdict != GuardVerdict.Deny, protection = guard.Verdict == GuardVerdict.Deny ? guard.Reason : null };
    }),
    processes = new[] { new { name = "AnyDesk.exe", pid = 9001 } },
    cameraMic = new[] { new { device = "webcam", app = "Zoom.exe", active = false } },
    sensors = new[]
    {
        new { name = "Process launches", mode = "live" },
        new { name = "Network connections", mode = "live" },
        new { name = "Sign-ins", mode = "live" },
        new { name = "Dropped events", mode = "none" },
    },
});
rpc.Register("alerts.recent", Access.Read, (_, a) =>
{
    var ack = settings.Value.Acknowledged.ToHashSet();
    return history.Read(new HistoryQuery { Limit = Args.OptInt(a, "limit", 200), IncludeSuppressed = false }).Where(e => !ack.Contains(e.Id) && e.Source != "audit").Select(AlertPipeline.Present);
});
rpc.Register("alerts.dismiss", Access.Act, (_, a) =>
{
    var ids = a.GetProperty("ids").EnumerateArray().Select(x => x.GetString()!).ToList();
    settings.Update(s => s with { Acknowledged = [.. s.Acknowledged, .. ids] });
    return new { dismissed = ids.Count };
});
rpc.Register("history.get", Access.Read, (_, a) => history.Read(new HistoryQuery { Limit = Args.OptInt(a, "limit", 300), Source = Args.OptStr(a, "source") is { Length: > 0 } s ? s : null }).Select(AlertPipeline.Present));
rpc.Register("history.verify", Access.Read, (_, _) => history.Verify());
rpc.Register("history.export", Access.Read, (_, a) =>
{
    var tmp = Path.GetTempFileName();
    var count = history.Export(tmp, Args.OptStr(a, "format") ?? "csv", new HistoryQuery());
    var content = File.ReadAllText(tmp);
    File.Delete(tmp);
    return new { count, content };
});
rpc.Register("trust.list", Access.Read, (_, _) => trust.Rules);
rpc.Register("trust.add", Access.Act, (c, a) =>
{
    var rule = trust.Add(new TrustRule { Type = Args.Str(a, "type"), Value = Args.Str(a, "value"), ProcessPath = Args.OptStr(a, "processPath"), Label = Args.OptStr(a, "label"), CreatedBy = c.UserName, CreatedAt = DateTimeOffset.UtcNow.ToString("o") });
    pipeline.Publish(AlertDraft.Of(AlertKinds.TrustAdded, (SubjectKeys.Actor, c.UserName), (SubjectKeys.RuleType, rule.Type), (SubjectKeys.RuleValue, rule.Label ?? rule.Value)));
    return rule;
});
rpc.Register("trust.remove", Access.Act, (c, a) =>
{
    var rule = trust.Remove(Args.Str(a, "id")) ?? throw new RpcException(RpcErrors.Failed, "Gone.");
    pipeline.Publish(AlertDraft.Of(AlertKinds.TrustRemoved, (SubjectKeys.Actor, c.UserName), (SubjectKeys.RuleType, rule.Type), (SubjectKeys.RuleValue, rule.Label ?? rule.Value)));
    return trust.Rules;
});
var net = new NetworkFacts { LocalAddresses = ["192.168.1.20"], Gateways = ["192.168.1.1"], DnsServers = ["192.168.1.1"] };
rpc.Register("guard.kill", Access.Read, (_, a) => ActionGuard.CanKill(Facts(Args.Int(a, "pid")), SystemRoot));
rpc.Register("guard.block", Access.Read, (_, a) => ActionGuard.CanBlock(Args.Str(a, "address"), net));
rpc.Register("guard.disconnect", Access.Read, (c, a) => ActionGuard.CanDisconnect(Args.Int(a, "sessionId") == 1, Args.Int(a, "sessionId") == c.SessionId));
rpc.Register("guard.removeStartup", Access.Read, (_, a) =>
{
    var item = startupItems.First(i => i.Key == Args.Str(a, "key"));
    return ActionGuard.CanRemoveStartup(new StartupFacts { Name = item.Name, Command = item.Command });
});
void Act(Caller c, string action, string target) =>
    pipeline.Publish(AlertDraft.Of(AlertKinds.ActionTaken, (SubjectKeys.Actor, c.UserName), (SubjectKeys.ActionName, action), (SubjectKeys.Target, target)));
rpc.Register("process.kill", Access.Act, (c, a) =>
{
    var pid = Args.Int(a, "pid");
    var d = ActionGuard.CanKill(Facts(pid), SystemRoot);
    if (d.Verdict == GuardVerdict.Deny) throw new RpcException(RpcErrors.Denied, d.Reason);
    Act(c, "end a program", $"PID {pid}");
    return new { ok = true };
});
rpc.Register("session.disconnect", Access.Act, (c, a) => { Act(c, "sign out a session", $"session {Args.Int(a, "sessionId")}"); return new { ok = true }; });
rpc.Register("network.blocked", Access.Read, (_, _) => blocked);
rpc.Register("network.block", Access.Act, (c, a) =>
{
    var addr = Args.Str(a, "address");
    var d = ActionGuard.CanBlock(addr, net);
    if (d.Verdict == GuardVerdict.Deny) throw new RpcException(RpcErrors.Denied, d.Reason);
    blocked.Add(addr);
    Act(c, "block an address", addr);
    return blocked;
});
rpc.Register("network.unblock", Access.Act, (c, a) => { blocked.Remove(Args.Str(a, "address")); Act(c, "unblock an address", Args.Str(a, "address")); return blocked; });
rpc.Register("startup.remove", Access.Act, (c, a) => { Act(c, "remove a startup item", Args.Str(a, "key")); return new { ok = true }; });
rpc.Register("defender.status", Access.Read, (_, _) => DefenderStatus());
rpc.Register("defender.scan", Access.Read, (_, _) => new { started = true });
rpc.Register("health.run", Access.Read, (_, _) => new
{
    defender = DefenderStatus(),
    threats = new[] { new { id = "1", name = "Trojan:Win32/Wacatac.B!ml", process = "helper.exe", detectedAt = DateTimeOffset.UtcNow.AddMinutes(-40).ToString("o") } },
    startupFindings = startupItems.Select(i =>
    {
        var g = ActionGuard.CanRemoveStartup(new StartupFacts { Name = i.Name, Command = i.Command });
        return new { key = i.Key, name = i.Name, command = i.Command, location = i.Location, signatureText = i.Name == "Updater" ? "not digitally signed" : "digitally signed", suspectDir = i.Command.Contains(@"\Temp\"), removable = g.Verdict != GuardVerdict.Deny, protection = g.Verdict == GuardVerdict.Deny ? g.Reason : null };
    }).Where(i => i.name == "Updater"),
    listeningFindings = new[] { new { pid = 9120, port = 4444, name = "svchost.exe", path = @"C:\Users\alex\AppData\Roaming\svchost.exe", signatureText = "not digitally signed" } },
});
rpc.Register("exposure.scan", Access.Read, (_, _) => ExposureAnalyzer.Analyze(new ExposureReport
{
    Listening =
    [
        new(3389, "0.0.0.0", "all-interfaces", true, 1100, "svchost.exe", null, "Remote Desktop"),
        new(4444, "0.0.0.0", "all-interfaces", true, 9120, "svchost.exe", @"C:\Users\alex\AppData\Roaming\svchost.exe", null),
        new(5939, "127.0.0.1", "local-only", false, 9001, "AnyDesk.exe", null, null),
    ],
    Adapters = [new("192.168.1.20", "Wi-Fi", "private")],
    Firewall = [new("Domain", true, "Block"), new("Private", true, "Block"), new("Public", false, "Block")],
    Rdp = new RdpStatus(true, 3389, false),
    Dns = [new DnsConfig("Wi-Fi", ["192.168.1.1"])],
    Hosts = [new HostsEntry("0.0.0.0", "ads.example.com", "0.0.0.0 ads.example.com")],
    Proxy = new ProxyStatus(false, null, null, "Direct access (no proxy server)."),
    Tunnels = [new TunnelAdapter("Local Area Connection* 12", "Unknown Tunnel Adapter", "Up", true, false)],
    Shares = [new Share("C$", @"C:\", true), new Share("Photos", @"C:\Users\alex\Pictures", false)],
    ScannedAt = DateTimeOffset.UtcNow.ToString("o"),
}));
object PublicSettings()
{
    var s = settings.Value;
    return new { s.SetupCompleted, s.LearningUntil, learning = s.IsLearning(DateTimeOffset.UtcNow), s.UpdateRing, s.AutoUpdate, s.CrashReports, crashReportsAvailable = true, updatesConfigured = true, s.NotifyMinSeverity, s.Offsite };
}
rpc.Register("settings.get", Access.Read, (_, _) => PublicSettings());
rpc.Register("settings.update", Access.Act, (_, a) =>
{
    settings.Update(s => s with
    {
        UpdateRing = Args.OptStr(a, "updateRing") ?? s.UpdateRing,
        NotifyMinSeverity = Args.OptStr(a, "notifyMinSeverity") ?? s.NotifyMinSeverity,
        AutoUpdate = a.TryGetProperty("autoUpdate", out var au) ? au.GetBoolean() : s.AutoUpdate,
        CrashReports = a.TryGetProperty("crashReports", out var cr) ? cr.GetBoolean() : s.CrashReports,
    });
    return PublicSettings();
});
rpc.Register("accounts.list", Access.Read, (_, _) => new[]
{
    new { name = "alex", isAdmin = true, isYou = true },
    new { name = "sam", isAdmin = false, isYou = false },
    new { name = "support", isAdmin = true, isYou = false },
});
rpc.Register("setup.complete", Access.Act, (c, a) =>
{
    foreach (var acct in a.GetProperty("trustedAccounts").EnumerateArray()) trust.Add(new TrustRule { Type = TrustTypes.Account, Value = acct.GetString()!, CreatedBy = c.UserName });
    var tools = a.GetProperty("usedTools").EnumerateArray().Select(x => x.GetString()!).ToList();
    settings.Update(s => s with
    {
        SetupCompleted = true,
        UpdateRing = Args.OptStr(a, "updateRing") ?? "standard",
        AutoUpdate = a.GetProperty("autoUpdate").GetBoolean(),
        CrashReports = a.GetProperty("crashReports").GetBoolean(),
        LearningUntil = a.GetProperty("learning").GetBoolean() ? DateTimeOffset.UtcNow.AddHours(24).ToString("o") : DateTimeOffset.UtcNow.ToString("o"),
        Watchlist = s.Watchlist with { Disabled = [.. s.Watchlist.Disabled, .. tools] },
    });
    Act(c, "finish setup", "setup guide");
    return PublicSettings();
});
object WatchlistInfo() => new { defaults = Watchlist.Defaults.Select(n => new { name = n, disabled = settings.Value.Watchlist.Disabled.Contains(n) }), custom = settings.Value.Watchlist.Custom };
rpc.Register("watchlist.get", Access.Read, (_, _) => WatchlistInfo());
rpc.Register("watchlist.add", Access.Act, (_, a) => { settings.Update(s => s with { Watchlist = s.Watchlist with { Custom = [.. s.Watchlist.Custom, Watchlist.Normalize(Args.Str(a, "name"))] } }); return WatchlistInfo(); });
rpc.Register("watchlist.remove", Access.Act, (_, a) => { var n = Args.Str(a, "name"); settings.Update(s => s with { Watchlist = s.Watchlist with { Custom = s.Watchlist.Custom.Where(x => x != n).ToList(), Disabled = s.Watchlist.Custom.Contains(n) ? s.Watchlist.Disabled : [.. s.Watchlist.Disabled, n] } }); return WatchlistInfo(); });
rpc.Register("watchlist.restore", Access.Act, (_, a) => { var n = Args.Str(a, "name"); settings.Update(s => s with { Watchlist = s.Watchlist with { Disabled = s.Watchlist.Disabled.Where(x => x != n).ToList() } }); return WatchlistInfo(); });
rpc.Register("offsite.setDestination", Access.Act, (_, a) => { settings.Update(s => s with { Offsite = s.Offsite with { Destination = Args.Str(a, "path") } }); return PublicSettings(); });
rpc.Register("offsite.setEnabled", Access.Act, (_, a) => { settings.Update(s => s with { Offsite = s.Offsite with { Enabled = Args.Bool(a, "enabled") } }); return PublicSettings(); });
rpc.Register("offsite.setInterval", Access.Act, (_, a) => { settings.Update(s => s with { Offsite = s.Offsite with { IntervalMinutes = Args.Int(a, "minutes") } }); return PublicSettings(); });
rpc.Register("offsite.syncNow", Access.Act, (_, _) => new { ok = true, copied = 3, targetDir = settings.Value.Offsite.Destination + "/watchtower-DESKTOP-DEMO" });
rpc.Register("debloat.catalog", Access.Read, (_, _) => new[]
{
    new { id = "bing-search", label = "Bing / web results in search", description = "Removes Bing web results from Start menu and taskbar search, so it shows local files and apps only." },
    new { id = "copilot", label = "Microsoft Copilot", description = "Removes the Copilot taskbar button and blocks it by policy." },
    new { id = "recall", label = "Windows Recall", description = "Turns off Recall and blocks it by policy. Only present on Copilot+ PCs." },
});
rpc.Register("debloat.states", Access.Read, (_, _) => new Dictionary<string, string> { ["bing-search"] = "on", ["copilot"] = "off", ["recall"] = "unsupported" });
rpc.Register("debloat.set", Access.Act, (_, _) => new { ok = true });
rpc.Register("update.status", Access.Read, (_, _) => new { currentVersion = "0.2.0", message = "Up to date for this update ring.", configured = true });
rpc.Register("update.check", Access.Read, (_, _) => new { currentVersion = "0.2.0", message = "Up to date for this update ring.", configured = true });
rpc.Register("update.install", Access.Act, (_, _) => new { message = "Nothing to install." });

static object DefenderStatus() => new { available = true, antivirusEnabled = true, realTimeProtectionEnabled = true, signaturesUpdated = DateTimeOffset.UtcNow.AddHours(-3).ToString("o"), lastQuickScan = DateTimeOffset.UtcNow.AddDays(-2).ToString("o") };

if (history.Read(new HistoryQuery { Limit = 1 }).Count == 0) Seed();

void Seed()
{
    pipeline.Publish(AlertDraft.Of(AlertKinds.MonitoringGap, (SubjectKeys.From, "2026-09-26 07:58:02Z"), (SubjectKeys.To, "2026-09-26 08:01:40Z"), (SubjectKeys.Reason, "the PC was shut down or restarted")));
    pipeline.Publish(AlertDraft.Of(AlertKinds.FirstConnection, (SubjectKeys.ProcessName, "chrome.exe"), (SubjectKeys.ProcessPath, @"C:\Program Files\Google\Chrome\Application\chrome.exe"), (SubjectKeys.Pid, "7788"), (SubjectKeys.RemoteAddress, "142.250.72.14"), (SubjectKeys.RemotePort, "443"), (SubjectKeys.Signer, "Google LLC"), (SubjectKeys.SignatureStatus, "Valid")));
    pipeline.Publish(AlertDraft.Of(AlertKinds.RemoteToolStarted, (SubjectKeys.ProcessName, "AnyDesk.exe"), (SubjectKeys.ProcessPath, @"C:\Users\alex\Downloads\AnyDesk.exe"), (SubjectKeys.Pid, "9001"), (SubjectKeys.Signer, "philandro Software GmbH"), (SubjectKeys.SignatureStatus, "Valid")));
    pipeline.Publish(AlertDraft.Of(AlertKinds.PasswordGuessing, (SubjectKeys.Account, "Administrator"), (SubjectKeys.ClientAddress, "203.0.113.45"), (SubjectKeys.RemoteAddress, "203.0.113.45"), (SubjectKeys.Count, "37"), (SubjectKeys.Window, "10 min")));
    pipeline.Publish(AlertDraft.Of(AlertKinds.RdpSessionActive, (SubjectKeys.Account, @"DESKTOP-DEMO\support"), (SubjectKeys.SessionId, "3"), (SubjectKeys.SessionName, "RDP-Tcp#4"), (SubjectKeys.ClientName, "UNKNOWN-PC"), (SubjectKeys.ClientAddress, "203.0.113.45")));
    pipeline.Publish(AlertDraft.Of(AlertKinds.ProgramMasquerading, (SubjectKeys.ProcessName, "svchost.exe"), (SubjectKeys.ProcessPath, @"C:\Users\alex\AppData\Roaming\svchost.exe"), (SubjectKeys.Pid, "9120"), (SubjectKeys.ExpectedLocation, @"C:\Windows\System32"), (SubjectKeys.SignatureStatus, "NotSigned")));
    pipeline.Publish(AlertDraft.Of(AlertKinds.StartupEntryAdded, (SubjectKeys.StartupKey, startupItems[0].Key), (SubjectKeys.StartupName, "Updater"), (SubjectKeys.StartupCommand, startupItems[0].Command), (SubjectKeys.StartupLocation, startupItems[0].Location)));
}

var pipeName = Environment.GetEnvironmentVariable("WATCHTOWER_PIPE_NAME") ?? "Watchtower.v1";
Console.WriteLine($"Watchtower dev host on pipe '{pipeName}' as {(admin ? "administrator" : "standard user")}, data in {dataDir}");
_ = Task.Run(async () =>
{
    // A live alert every so often, so push notifications can be seen working.
    while (true)
    {
        await Task.Delay(TimeSpan.FromSeconds(45));
        pipeline.Publish(AlertDraft.Of(AlertKinds.CameraUsed, (SubjectKeys.AppName, "Zoom.exe"), (SubjectKeys.ProcessPath, @"C:\Users\alex\AppData\Roaming\Zoom\bin\Zoom.exe"), (SubjectKeys.Device, "webcam"), (SubjectKeys.StillActive, "yes")));
    }
});

while (true)
{
    var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    await server.WaitForConnectionAsync();
    _ = Task.Run(async () =>
    {
        var connection = new RpcConnection(server, rpc, caller);
        lock (connections) connections.Add(connection);
        try
        {
            await connection.RunAsync(CancellationToken.None);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
        }
        finally
        {
            lock (connections) connections.Remove(connection);
            await connection.DisposeAsync();
        }
    });
}
