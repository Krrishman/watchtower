using System.Runtime.InteropServices;
using System.Text.Json;
using Watchtower.Core.Alerts;
using Watchtower.Core.Config;
using Watchtower.Core.History;
using Watchtower.Core.Ipc;
using Watchtower.Core.Monitoring;
using Watchtower.Core.Safety;
using Watchtower.Core.Trust;
using Watchtower.Service.Actions;
using Watchtower.Service.Engine;
using Watchtower.Service.Hosting;
using Watchtower.Service.Native;
using Watchtower.Service.Sources;
using Watchtower.Service.Updates;
using static Watchtower.Service.Native.NativeMethods;

namespace Watchtower.Service.Ipc;

/// <summary>
/// Every method the UI can call. Read methods show information; Act methods change
/// the system or Watchtower's configuration, require an administrator account, pass
/// the same safety guard the UI shows, and are written to the history log as an audit trail.
/// </summary>
public sealed class Api
{
    private readonly EngineContext _ctx;
    private readonly WatchtowerEngine _engine;
    private readonly Remediator _remediator;
    private readonly DebloatEngine _debloat;
    private readonly ExposureCollector _exposure;
    private readonly SignatureVerifier _signatures;
    private readonly ProcessInfo _processes;
    private readonly OffsiteService _offsite;
    private readonly UpdateService _updates;
    private readonly WatchtowerOptions _options;

    public Api(RpcDispatcher rpc, EngineContext ctx, WatchtowerEngine engine, Remediator remediator, DebloatEngine debloat,
        ExposureCollector exposure, SignatureVerifier signatures, ProcessInfo processes, OffsiteService offsite, UpdateService updates,
        Microsoft.Extensions.Options.IOptions<WatchtowerOptions> options)
    {
        _ctx = ctx;
        _engine = engine;
        _remediator = remediator;
        _debloat = debloat;
        _exposure = exposure;
        _signatures = signatures;
        _processes = processes;
        _offsite = offsite;
        _updates = updates;
        _options = options.Value;
        Register(rpc);
    }

    private void Register(RpcDispatcher rpc)
    {
        // ---- overview ----
        rpc.Register("hello", Access.Read, (c, _) => new
        {
            protocol = RpcDispatcher.ProtocolVersion,
            version = AppVersion.Current,
            user = c.UserName,
            isAdmin = c.IsAdministrator,
            setupCompleted = _ctx.Settings.Value.SetupCompleted,
        });
        rpc.Register("state.get", Access.Read, (_, _) => _engine.StateSnapshot());

        // ---- alerts & history ----
        rpc.Register("alerts.recent", Access.Read, (_, a) =>
        {
            var acknowledged = _ctx.Settings.Value.Acknowledged.ToHashSet();
            return _ctx.History.Read(new HistoryQuery { Limit = Args.OptInt(a, "limit", 200), IncludeSuppressed = false })
                .Where(e => !acknowledged.Contains(e.Id))
                .Select(AlertPipeline.Present);
        });
        rpc.Register("alerts.dismiss", Access.Act, (c, a) =>
        {
            var ids = StrArray(a, "ids");
            _ctx.Settings.Update(s => s with { Acknowledged = s.Acknowledged.Concat(ids).Distinct().TakeLast(5000).ToList() });
            return new { dismissed = ids.Count };
        });
        rpc.Register("history.get", Access.Read, (_, a) => _ctx.History.Read(Query(a)).Select(AlertPipeline.Present));
        rpc.Register("history.verify", Access.Read, (_, _) => _ctx.History.Verify());
        rpc.Register("history.export", Access.Read, (_, a) =>
        {
            // The service returns the content; the UI writes the file as the user.
            // Letting SYSTEM write to a client-chosen path would be a privilege-escalation hole.
            var format = Args.OptStr(a, "format") == "json" ? "json" : "csv";
            var tmp = Path.Combine(_ctx.Paths.State, $"export-{Guid.NewGuid():N}.{format}");
            try
            {
                var count = _ctx.History.Export(tmp, format, Query(a) with { Limit = int.MaxValue });
                return new { count, format, content = File.ReadAllText(tmp) };
            }
            finally
            {
                File.Delete(tmp);
            }
        });

        // ---- trust ----
        rpc.Register("trust.list", Access.Read, (_, _) => _ctx.Trust.Rules);
        rpc.Register("trust.add", Access.Act, (c, a) =>
        {
            var rule = _ctx.Trust.Add(new TrustRule
            {
                Type = Args.Str(a, "type"),
                Value = Args.Str(a, "value"),
                ProcessPath = Args.OptStr(a, "processPath"),
                Label = Args.OptStr(a, "label"),
                CreatedAt = DateTimeOffset.UtcNow.ToString("o"),
                CreatedBy = c.UserName,
            });
            _ctx.Publish(AlertDraft.Of(AlertKinds.TrustAdded, (SubjectKeys.Actor, c.UserName), (SubjectKeys.RuleType, rule.Type), (SubjectKeys.RuleValue, rule.Label ?? rule.Value)));
            return rule;
        });
        rpc.Register("trust.remove", Access.Act, (c, a) =>
        {
            var rule = _ctx.Trust.Remove(Args.Str(a, "id")) ?? throw new RpcException(RpcErrors.Failed, "That trust rule no longer exists.");
            _ctx.Publish(AlertDraft.Of(AlertKinds.TrustRemoved, (SubjectKeys.Actor, c.UserName), (SubjectKeys.RuleType, rule.Type), (SubjectKeys.RuleValue, rule.Label ?? rule.Value)));
            return _ctx.Trust.Rules;
        });

        // ---- guarded actions: check first (the UI shows the reason), then act ----
        rpc.Register("guard.kill", Access.Read, (_, a) => _remediator.CheckKill(Args.Int(a, "pid")));
        rpc.Register("guard.block", Access.Read, (_, a) => _remediator.CheckBlock(Args.Str(a, "address")));
        rpc.Register("guard.disconnect", Access.Read, (c, a) => _remediator.CheckDisconnect(Args.Int(a, "sessionId"), c));
        rpc.Register("guard.removeStartup", Access.Read, (_, a) => Remediator.CheckRemoveStartup(StartupItemFor(Args.Str(a, "key"))));

        rpc.Register("process.kill", Access.Act, (c, a) =>
        {
            var pid = Args.Int(a, "pid");
            var name = _remediator.Kill(pid);
            _ctx.Audit(c.UserName, "end a program", $"{name}, PID {pid}");
            return new { ok = true };
        });
        rpc.Register("session.disconnect", Access.Act, (c, a) =>
        {
            var id = Args.Int(a, "sessionId");
            _remediator.Disconnect(id);
            _ctx.Audit(c.UserName, "sign out a session", $"session {id}");
            return new { ok = true };
        });
        rpc.Register("network.block", Access.Act, (c, a) =>
        {
            var address = Args.Str(a, "address");
            _remediator.Block(address);
            _ctx.Audit(c.UserName, "block an address", address);
            return FirewallManager.Blocked();
        });
        rpc.Register("network.unblock", Access.Act, (c, a) =>
        {
            var address = Args.Str(a, "address");
            FirewallManager.Unblock(address);
            _ctx.Audit(c.UserName, "unblock an address", address);
            return FirewallManager.Blocked();
        });
        rpc.Register("network.blocked", Access.Read, (_, _) => Safe(FirewallManager.Blocked, []));
        rpc.Register("startup.remove", Access.Act, (c, a) =>
        {
            var item = StartupItemFor(Args.Str(a, "key"));
            var what = Remediator.RemoveStartup(item);
            _ctx.Audit(c.UserName, "remove a startup item", $"{item.Name}: {what}");
            return new { ok = true, action = what };
        });

        // ---- health & exposure ----
        rpc.Register("defender.status", Access.Read, (_, _) => DefenderReader.Status());
        rpc.Register("defender.scan", Access.Read, (_, _) =>
        {
            var (started, error) = DefenderReader.StartQuickScan();
            return new { started, error };
        });
        rpc.Register("health.run", Access.Read, (_, _) => HealthReport());
        rpc.Register("exposure.scan", Access.Read, (c, _) => _exposure.Scan(c.Sid.Length > 0 ? c.Sid : null));

        // ---- settings ----
        rpc.Register("settings.get", Access.Read, (_, _) => PublicSettings());
        rpc.Register("settings.update", Access.Act, (c, a) =>
        {
            var ring = Args.OptStr(a, "updateRing");
            if (ring is not null && !UpdateRings.IsValid(ring)) throw RpcException.BadRequest("Unknown update ring.");
            var notify = Args.OptStr(a, "notifyMinSeverity");
            if (notify is not null && notify is not (Severity.Info or Severity.Warn or Severity.Critical)) throw RpcException.BadRequest("Unknown severity.");
            var updated = _ctx.Settings.Update(s => s with
            {
                UpdateRing = ring ?? s.UpdateRing,
                AutoUpdate = OptBool(a, "autoUpdate") ?? s.AutoUpdate,
                CrashReports = OptBool(a, "crashReports") ?? s.CrashReports,
                NotifyMinSeverity = notify ?? s.NotifyMinSeverity,
            });
            CrashReporting.Configure(_options.SentryDsn, updated.CrashReports);
            _ctx.Audit(c.UserName, "change settings", string.Join(", ", ChangedKeys(a)));
            return PublicSettings();
        });
        rpc.Register("accounts.list", Access.Read, (c, _) => LocalAccounts(c));
        rpc.Register("setup.complete", Access.Act, (c, a) =>
        {
            foreach (var account in StrArray(a, "trustedAccounts"))
            {
                _ctx.Trust.Add(new TrustRule { Type = TrustTypes.Account, Value = account, CreatedAt = DateTimeOffset.UtcNow.ToString("o"), CreatedBy = c.UserName });
            }
            var tools = StrArray(a, "usedTools").Select(Watchlist.Normalize).Where(t => t.Length > 0).ToList();
            var ring = Args.OptStr(a, "updateRing") ?? UpdateRings.Standard;
            if (!UpdateRings.IsValid(ring)) throw RpcException.BadRequest("Unknown update ring.");
            var learn = OptBool(a, "learning") ?? true;
            var updated = _ctx.Settings.Update(s => s with
            {
                SetupCompleted = true,
                UpdateRing = ring,
                AutoUpdate = OptBool(a, "autoUpdate") ?? true,
                CrashReports = OptBool(a, "crashReports") ?? false,
                LearningUntil = learn ? DateTimeOffset.UtcNow.AddHours(24).ToString("o") : DateTimeOffset.UtcNow.ToString("o"),
                Watchlist = s.Watchlist with { Disabled = s.Watchlist.Disabled.Concat(tools).Distinct().ToList() },
            });
            CrashReporting.Configure(_options.SentryDsn, updated.CrashReports);
            _ctx.Audit(c.UserName, "finish setup", $"{_ctx.Trust.Rules.Count(r => r.Type == TrustTypes.Account)} trusted accounts, updates: {ring}");
            return PublicSettings();
        });

        // ---- watchlist ----
        rpc.Register("watchlist.get", Access.Read, (_, _) => WatchlistInfo());
        rpc.Register("watchlist.add", Access.Act, (c, a) =>
        {
            var name = Watchlist.Normalize(Args.Str(a, "name"));
            _ctx.Settings.Update(s => s with { Watchlist = s.Watchlist with { Custom = s.Watchlist.Custom.Append(name).Distinct().ToList(), Disabled = s.Watchlist.Disabled.Where(d => d != name).ToList() } });
            _ctx.Audit(c.UserName, "add to the remote-tool watchlist", name);
            return WatchlistInfo();
        });
        rpc.Register("watchlist.remove", Access.Act, (c, a) =>
        {
            var name = Watchlist.Normalize(Args.Str(a, "name"));
            _ctx.Settings.Update(s => s.Watchlist.Custom.Contains(name)
                ? s with { Watchlist = s.Watchlist with { Custom = s.Watchlist.Custom.Where(n => n != name).ToList() } }
                : s with { Watchlist = s.Watchlist with { Disabled = s.Watchlist.Disabled.Append(name).Distinct().ToList() } });
            _ctx.Audit(c.UserName, "stop watching for a remote tool", name);
            return WatchlistInfo();
        });
        rpc.Register("watchlist.restore", Access.Act, (c, a) =>
        {
            var name = Watchlist.Normalize(Args.Str(a, "name"));
            _ctx.Settings.Update(s => s with { Watchlist = s.Watchlist with { Disabled = s.Watchlist.Disabled.Where(n => n != name).ToList() } });
            _ctx.Audit(c.UserName, "resume watching for a remote tool", name);
            return WatchlistInfo();
        });

        // ---- off-machine backup ----
        rpc.Register("offsite.setDestination", Access.Act, (c, a) =>
        {
            var path = Path.GetFullPath(Args.Str(a, "path"));
            if (!Directory.Exists(path)) throw RpcException.BadRequest("That folder doesn't exist.");
            _ctx.Settings.Update(s => s with { Offsite = s.Offsite with { Destination = path, LastError = null } });
            _ctx.Audit(c.UserName, "set the backup folder", path);
            return PublicSettings();
        });
        rpc.Register("offsite.setEnabled", Access.Act, (c, a) =>
        {
            var enabled = Args.Bool(a, "enabled");
            _ctx.Settings.Update(s => s with { Offsite = s.Offsite with { Enabled = enabled && s.Offsite.Destination is not null } });
            _ctx.Audit(c.UserName, enabled ? "turn on off-machine backup" : "turn off off-machine backup", _ctx.Settings.Value.Offsite.Destination ?? "");
            return PublicSettings();
        });
        rpc.Register("offsite.setInterval", Access.Act, (_, a) =>
        {
            var minutes = Math.Clamp(Args.Int(a, "minutes"), 5, 24 * 60);
            _ctx.Settings.Update(s => s with { Offsite = s.Offsite with { IntervalMinutes = minutes } });
            return PublicSettings();
        });
        rpc.Register("offsite.syncNow", Access.Act, (_, _) => _offsite.SyncNow());

        // ---- debloat ----
        rpc.Register("debloat.catalog", Access.Read, (_, _) => _debloat.Catalog());
        rpc.Register("debloat.states", Access.Read, (c, _) => _debloat.States(c.Sid));
        rpc.Register("debloat.set", Access.Act, (c, a) =>
        {
            var id = Args.Str(a, "id");
            var enable = Args.Bool(a, "enable");
            var result = _debloat.Set(id, enable, c.Sid);
            if (result.Ok) _ctx.Audit(c.UserName, enable ? "turn on a privacy setting" : "turn off a privacy setting", id);
            return result;
        });

        // ---- updates ----
        rpc.Register("update.status", Access.Read, (_, _) => _updates.Status);
        rpc.Register("update.check", Access.Read, (_, _, ct) => Box(_updates.CheckAsync(install: false, ct)));
        rpc.Register("update.install", Access.Act, (c, _, ct) =>
        {
            _ctx.Audit(c.UserName, "install an update", "latest eligible version");
            return Box(_updates.CheckAsync(install: true, ct));
        });
    }

    private static async Task<object?> Box<T>(Task<T> task) => await task;

    private static T Safe<T>(Func<T> f, T fallback)
    {
        try
        {
            return f();
        }
        catch (COMException)
        {
            return fallback;
        }
    }

    private StartupItem StartupItemFor(string key) =>
        _engine.CurrentStartup.FirstOrDefault(i => i.Key == key)
        ?? throw new RpcException(RpcErrors.Failed, "That startup entry wasn't found in the latest scan. It may already be gone.");

    private static HistoryQuery Query(JsonElement a) => new()
    {
        Limit = Math.Clamp(Args.OptInt(a, "limit", 300), 1, 5000),
        Source = Args.OptStr(a, "source") is { Length: > 0 } s ? s : null,
        Kind = Args.OptStr(a, "kind"),
        Since = Args.OptStr(a, "since"),
        IncludeSuppressed = !Args.OptBool(a, "hideSuppressed"),
    };

    private object PublicSettings()
    {
        var s = _ctx.Settings.Value;
        return new
        {
            s.SetupCompleted,
            s.LearningUntil,
            learning = s.IsLearning(DateTimeOffset.UtcNow),
            s.UpdateRing,
            s.AutoUpdate,
            s.CrashReports,
            crashReportsAvailable = !string.IsNullOrWhiteSpace(_options.SentryDsn),
            updatesConfigured = _options.UpdatesConfigured,
            s.NotifyMinSeverity,
            s.Offsite,
        };
    }

    private object WatchlistInfo()
    {
        var w = _ctx.Settings.Value.Watchlist;
        var disabled = w.Disabled.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new
        {
            defaults = Watchlist.Defaults.Select(n => new { name = n, disabled = disabled.Contains(n) }),
            custom = w.Custom,
        };
    }

    private object HealthReport()
    {
        var startupFindings = _engine.CurrentStartup
            .Where(i => !i.IsService)
            .Select(i =>
            {
                var exe = StartupScanner.ExecutableOf(i.Command);
                var sig = _signatures.Check(exe);
                var suspectDir = i.Command.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) || i.Command.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase);
                var guard = Remediator.CheckRemoveStartup(i);
                return new
                {
                    key = i.Key, name = i.Name, command = i.Command, location = i.Location,
                    signatureStatus = sig.Status, signatureText = AlertCatalog.DescribeSignature(sig.Status), signer = sig.Signer,
                    suspectDir, review = !sig.IsValid || suspectDir,
                    removable = guard.Verdict != GuardVerdict.Deny, protection = guard.Verdict == GuardVerdict.Deny ? guard.Reason : null,
                };
            })
            .Where(f => f.review)
            .ToList();

        var listeningFindings = TcpTable.Read()
            .Where(r => r.Listening && !NetworkTracker.IsLoopbackBinding(r.LocalAddress))
            .GroupBy(r => (r.Pid, r.LocalPort))
            .Select(g =>
            {
                var p = _processes.Lookup(g.Key.Pid);
                var sig = _signatures.Check(p.Path);
                return new { pid = g.Key.Pid, port = g.Key.LocalPort, name = p.Name, path = p.Path, signatureStatus = sig.Status, signatureText = AlertCatalog.DescribeSignature(sig.Status), valid = sig.IsValid };
            })
            .Where(f => !f.valid && f.pid > 4)
            .ToList();

        return new
        {
            defender = DefenderReader.Status(),
            threats = DefenderReader.Threats(),
            startupFindings,
            listeningFindings,
            ranAt = DateTimeOffset.UtcNow.ToString("o"),
        };
    }

    public sealed record AccountRow(string Name, bool IsAdmin, bool IsYou);

    private static IReadOnlyList<AccountRow> LocalAccounts(Caller caller)
    {
        var accounts = new List<AccountRow>();
        var resume = 0;
        if (NetUserEnum(null, 1, FILTER_NORMAL_ACCOUNT, out var buffer, -1, out var read, out _, ref resume) == 0)
        {
            try
            {
                var size = Marshal.SizeOf<USER_INFO_1>();
                for (var i = 0; i < read; i++)
                {
                    var u = Marshal.PtrToStructure<USER_INFO_1>(buffer + i * size);
                    if ((u.usri1_flags & UF_ACCOUNTDISABLE) != 0) continue;
                    accounts.Add(new AccountRow(u.usri1_name, u.usri1_priv == 2, caller.UserName.EndsWith("\\" + u.usri1_name, StringComparison.OrdinalIgnoreCase)));
                }
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }
        // Microsoft-account and domain users aren't in the local list; always offer the caller.
        var bare = caller.UserName[(caller.UserName.LastIndexOf('\\') + 1)..];
        if (!accounts.Any(a => a.IsYou)) accounts.Insert(0, new AccountRow(bare, caller.IsAdministrator, true));
        return accounts;
    }

    private static List<string> StrArray(JsonElement a, string name) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!.Trim()).Where(x => x.Length > 0).Take(200).ToList()
            : [];

    private static bool? OptBool(JsonElement a, string name) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;

    private static IEnumerable<string> ChangedKeys(JsonElement a) =>
        a.ValueKind == JsonValueKind.Object ? a.EnumerateObject().Select(p => $"{p.Name}={p.Value}") : [];
}
