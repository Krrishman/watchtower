using Watchtower.Core.Alerts;
using Watchtower.Core.Config;

namespace Watchtower.Core.Trust;

public sealed record TrustRule
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    public required string Type { get; init; }
    public required string Value { get; init; }
    /// <summary>Optional narrowing: an address rule can be limited to one program.</summary>
    public string? ProcessPath { get; init; }
    public string? Label { get; init; }
    public string? CreatedAt { get; init; }
    public string? CreatedBy { get; init; }
}

public sealed record TrustDocument
{
    public List<TrustRule> Rules { get; init; } = [];
}

public sealed class TrustStore
{
    private readonly JsonFileStore<TrustDocument> _store;

    public TrustStore(string path) => _store = new JsonFileStore<TrustDocument>(path);

    public IReadOnlyList<TrustRule> Rules => _store.Value.Rules;

    public bool HasAccountRules => Rules.Any(r => r.Type == TrustTypes.Account);

    public TrustRule Add(TrustRule rule)
    {
        Validate(rule);
        var existing = Rules.FirstOrDefault(r =>
            r.Type == rule.Type &&
            string.Equals(r.Value, rule.Value, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.ProcessPath, rule.ProcessPath, StringComparison.OrdinalIgnoreCase));
        if (existing is not null) return existing;
        _store.Update(doc => doc with { Rules = [.. doc.Rules, rule] });
        return rule;
    }

    public TrustRule? Remove(string id)
    {
        var rule = Rules.FirstOrDefault(r => r.Id == id);
        if (rule is null) return null;
        _store.Update(doc => doc with { Rules = doc.Rules.Where(r => r.Id != id).ToList() });
        return rule;
    }

    private static void Validate(TrustRule rule)
    {
        if (string.IsNullOrWhiteSpace(rule.Value)) throw new ArgumentException("A trust rule needs a value.");
        if (rule.Type is not (TrustTypes.Program or TrustTypes.Publisher or TrustTypes.Address or TrustTypes.Account or TrustTypes.Startup or TrustTypes.Kind))
        {
            throw new ArgumentException($"Unknown trust rule type '{rule.Type}'.");
        }
        if (rule.Type == TrustTypes.Kind && (!AlertCatalog.IsKnown(rule.Value) || !AlertCatalog.Get(rule.Value).Mutable))
        {
            throw new ArgumentException("That kind of alert can't be muted.");
        }
    }

    public bool IsAccountTrusted(string account) =>
        Rules.Any(r => r.Type == TrustTypes.Account && AccountMatches(r.Value, account));

    /// <summary>Returns the rule that makes this alert expected, or null.</summary>
    public TrustRule? Match(string kind, IReadOnlyDictionary<string, string> subject)
    {
        var entry = AlertCatalog.Get(kind);
        foreach (var rule in Rules)
        {
            if (rule.Type == TrustTypes.Kind)
            {
                if (entry.Mutable && rule.Value == kind) return rule;
                continue;
            }
            if (!entry.TrustBy.Contains(rule.Type)) continue;
            if (Matches(rule, subject)) return rule;
        }
        return null;
    }

    private static bool Matches(TrustRule rule, IReadOnlyDictionary<string, string> s)
    {
        string? Get(string key) => s.TryGetValue(key, out var v) ? v : null;

        return rule.Type switch
        {
            TrustTypes.Program => PathEquals(rule.Value, Get(SubjectKeys.ProcessPath)) || PathEquals(rule.Value, Get(SubjectKeys.AppName)),
            // Publisher trust only counts when the signature actually verified;
            // otherwise anyone could claim a trusted publisher's name.
            TrustTypes.Publisher => Get(SubjectKeys.SignatureStatus) == "Valid" &&
                                    string.Equals(rule.Value, Get(SubjectKeys.Signer), StringComparison.OrdinalIgnoreCase),
            TrustTypes.Address => (string.Equals(rule.Value, Get(SubjectKeys.RemoteAddress), StringComparison.OrdinalIgnoreCase) ||
                                   string.Equals(rule.Value, Get(SubjectKeys.ClientAddress), StringComparison.OrdinalIgnoreCase)) &&
                                  (rule.ProcessPath is null || PathEquals(rule.ProcessPath, Get(SubjectKeys.ProcessPath))),
            TrustTypes.Account => Get(SubjectKeys.Account) is { } account && AccountMatches(rule.Value, account),
            TrustTypes.Startup => string.Equals(rule.Value, Get(SubjectKeys.StartupKey), StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    private static bool PathEquals(string a, string? b) =>
        b is not null && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    /// <summary>"alice" matches "DESKTOP\alice" and "alice@contoso.com"; a qualified rule must match exactly.</summary>
    internal static bool AccountMatches(string rule, string account)
    {
        if (string.Equals(rule, account, StringComparison.OrdinalIgnoreCase)) return true;
        if (rule.Contains('\\') || rule.Contains('@')) return false;
        var bare = account.Contains('\\') ? account[(account.LastIndexOf('\\') + 1)..]
                 : account.Contains('@') ? account[..account.IndexOf('@')]
                 : account;
        return string.Equals(rule, bare, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The "Trust…" choices offered on an alert, derived from what it's about.</summary>
    public static IReadOnlyList<TrustOption> OptionsFor(string kind, IReadOnlyDictionary<string, string> s)
    {
        var entry = AlertCatalog.Get(kind);
        var options = new List<TrustOption>();
        string? Get(string key) => s.TryGetValue(key, out var v) && v.Length > 0 ? v : null;

        foreach (var type in entry.TrustBy)
        {
            switch (type)
            {
                case TrustTypes.Program when Get(SubjectKeys.ProcessPath) is { } path:
                    options.Add(new(type, path, $"Trust {Get(SubjectKeys.ProcessName) ?? Safety.SystemProcesses.WinFileName(path)}"));
                    break;
                case TrustTypes.Program when Get(SubjectKeys.AppName) is { } app:
                    options.Add(new(type, app, $"Trust {app}"));
                    break;
                case TrustTypes.Publisher when Get(SubjectKeys.SignatureStatus) == "Valid" && Get(SubjectKeys.Signer) is { } signer:
                    options.Add(new(type, signer, $"Trust everything from {signer}"));
                    break;
                case TrustTypes.Address when (Get(SubjectKeys.RemoteAddress) ?? Get(SubjectKeys.ClientAddress)) is { } addr:
                    options.Add(new(type, addr, $"Trust {addr}", Get(SubjectKeys.ProcessPath)));
                    break;
                case TrustTypes.Account when Get(SubjectKeys.Account) is { } account:
                    options.Add(new(type, account, $"Trust account \"{account}\""));
                    break;
                case TrustTypes.Startup when Get(SubjectKeys.StartupKey) is { } key:
                    options.Add(new(type, key, $"Keep \"{Get(SubjectKeys.StartupName) ?? key}\" in startup"));
                    break;
            }
        }
        if (entry.Mutable && entry.Severity != Severity.Critical)
        {
            options.Add(new(TrustTypes.Kind, kind, "Don't alert me about this kind of thing"));
        }
        return options;
    }
}
