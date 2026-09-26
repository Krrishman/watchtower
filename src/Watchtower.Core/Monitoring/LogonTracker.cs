using Watchtower.Core.Alerts;

namespace Watchtower.Core.Monitoring;

/// <summary>
/// Interprets Security-log sign-in events. Fields are read by name from the
/// event's structured data, not from the rendered message, so this works on
/// every Windows display language.
/// </summary>
public sealed class LogonTracker
{
    public const int Success = 4624;
    public const int Failure = 4625;
    public const int Logoff = 4634;
    public const int UserLogoff = 4647;
    public const int Reconnect = 4778;
    public const int Disconnect = 4779;
    public static readonly int[] EventIds = [Success, Failure, Logoff, UserLogoff, Reconnect, Disconnect];

    private const int RemoteInteractive = 10;
    private const int Network = 3;

    private sealed record OpenSession(string Account, DateTimeOffset Start);
    private sealed class FailureWindow
    {
        public DateTimeOffset Start;
        public int Count;
        public bool Escalated;
    }

    private readonly Func<string, bool?> _isAccountTrusted;
    private readonly int _threshold;
    private readonly TimeSpan _window;
    private readonly Dictionary<string, OpenSession> _open = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FailureWindow> _failures = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="isAccountTrusted">null when no trusted accounts are configured yet.</param>
    public LogonTracker(Func<string, bool?> isAccountTrusted, int threshold = 5, TimeSpan? window = null)
    {
        _isAccountTrusted = isAccountTrusted;
        _threshold = threshold;
        _window = window ?? TimeSpan.FromMinutes(10);
    }

    public IReadOnlyList<AlertDraft> Observe(LogonEvent e)
    {
        string Get(string key) => e.Data.TryGetValue(key, out var v) ? v.Trim() : "";

        switch (e.EventId)
        {
            case Success:
            {
                if (!int.TryParse(Get("LogonType"), out var type) || type != RemoteInteractive) return [];
                var account = Account(Get("TargetDomainName"), Get("TargetUserName"));
                if (IsNoise(Get("TargetUserName"))) return [];
                var logonId = Get("TargetLogonId");
                if (logonId.Length > 0) _open[logonId] = new OpenSession(account, e.Time);

                var trusted = _isAccountTrusted(account);
                var kind = trusted == false ? AlertKinds.RemoteLogonUnrecognized : AlertKinds.RemoteLogon;
                return [AlertDraft.Of(kind,
                    (SubjectKeys.Account, account),
                    (SubjectKeys.ClientAddress, Address(Get("IpAddress"))),
                    (SubjectKeys.ClientName, Clean(Get("WorkstationName"))),
                    (SubjectKeys.LogonType, type.ToString()))];
            }

            case Failure:
            {
                // With Network Level Authentication, a wrong RDP password is logged as a
                // network (type 3) failure, not type 10, so both count as remote attempts.
                if (!int.TryParse(Get("LogonType"), out var type) || type is not (RemoteInteractive or Network)) return [];
                var address = Address(Get("IpAddress"));
                if (address is null) return [];
                var account = Account(Get("TargetDomainName"), Get("TargetUserName"));
                return CountFailure(address, account, e.Time);
            }

            case Logoff or UserLogoff:
            {
                var logonId = Get("TargetLogonId");
                if (!_open.Remove(logonId, out var session)) return [];
                return [AlertDraft.Of(AlertKinds.RemoteLogonEnded,
                    (SubjectKeys.Account, session.Account),
                    (SubjectKeys.Duration, AlertCatalog.HumanDuration(e.Time - session.Start)))];
            }

            case Reconnect or Disconnect:
            {
                var account = Account(Get("AccountDomain"), Get("AccountName"));
                return [AlertDraft.Of(e.EventId == Reconnect ? AlertKinds.SessionReconnected : AlertKinds.SessionDisconnected,
                    (SubjectKeys.Account, account),
                    (SubjectKeys.ClientName, Clean(Get("ClientName"))),
                    (SubjectKeys.ClientAddress, Address(Get("ClientAddress"))))];
            }
        }
        return [];
    }

    private IReadOnlyList<AlertDraft> CountFailure(string address, string account, DateTimeOffset time)
    {
        if (!_failures.TryGetValue(address, out var w) || time - w.Start > _window)
        {
            w = new FailureWindow { Start = time };
            _failures[address] = w;
        }
        w.Count++;

        if (w.Count == 1)
        {
            return [AlertDraft.Of(AlertKinds.RemoteLogonFailed, (SubjectKeys.Account, account), (SubjectKeys.ClientAddress, address))];
        }
        if (w.Count >= _threshold && !w.Escalated)
        {
            w.Escalated = true;
            return [AlertDraft.Of(AlertKinds.PasswordGuessing,
                (SubjectKeys.Account, account),
                (SubjectKeys.ClientAddress, address),
                (SubjectKeys.RemoteAddress, address),
                (SubjectKeys.Count, w.Count.ToString()),
                (SubjectKeys.Window, AlertCatalog.HumanDuration(_window)))];
        }
        // Between the first failure and the threshold, stay quiet: one alert per burst.
        return [];
    }

    private static string Account(string domain, string user) =>
        domain.Length > 0 && domain != "-" ? $"{domain}\\{user}" : user;

    private static bool IsNoise(string user) =>
        user.EndsWith('$') || user.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase) || user.Length == 0;

    private static string? Address(string raw)
    {
        var a = raw.Trim();
        if (a.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase)) a = a[7..];
        return a is "" or "-" or "127.0.0.1" or "::1" ? null : a;
    }

    private static string? Clean(string raw) => raw is "" or "-" ? null : raw;
}
