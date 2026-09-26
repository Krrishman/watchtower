using Watchtower.Core.History;
using Watchtower.Core.Trust;

namespace Watchtower.Core.Alerts;

/// <summary>
/// Single path every alert takes: render plain-English text, apply trust and the
/// learning period, write to the tamper-evident log, then notify listeners.
/// Suppressed alerts are still logged so the record stays complete.
/// </summary>
public sealed class AlertPipeline
{
    private readonly HistoryLog _history;
    private readonly TrustStore _trust;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<DateTimeOffset, bool> _isLearning;

    public AlertPipeline(HistoryLog history, TrustStore trust, Func<DateTimeOffset> clock, Func<DateTimeOffset, bool> isLearning)
    {
        _history = history;
        _trust = trust;
        _clock = clock;
        _isLearning = isLearning;
    }

    /// <summary>Raised for every alert, including suppressed ones (check <see cref="Alert.SuppressedBy"/>).</summary>
    public event Action<Alert>? Published;

    /// <returns>null when the draft was only baseline learning and wasn't recorded.</returns>
    public Alert? Publish(AlertDraft draft)
    {
        var entry = AlertCatalog.Get(draft.Kind);
        var now = _clock();

        // While learning, routine "first time" observations just build the baseline;
        // logging thousands of them would bury the entries that matter.
        if (entry.QuietWhileLearning && _isLearning(now)) return null;

        string? suppressedBy = null;
        if (_trust.Match(draft.Kind, draft.Subject) is { } rule)
        {
            suppressedBy = $"trust:{rule.Id}";
        }

        var logged = _history.Append(new HistoryEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            Time = now.UtcDateTime.ToString("o"),
            Kind = draft.Kind,
            Source = entry.Source,
            Severity = draft.SeverityOverride ?? entry.Severity,
            Title = AlertCatalog.Render(entry.Title, draft.Subject),
            Detail = AlertCatalog.Render(entry.Detail, draft.Subject),
            Subject = new Dictionary<string, string>(draft.Subject, StringComparer.Ordinal),
            SuppressedBy = suppressedBy,
        });

        var alert = Present(logged);
        Published?.Invoke(alert);
        return alert;
    }

    /// <summary>Adds catalog guidance to a stored entry. Guidance isn't stored, so wording can improve over time.</summary>
    public static Alert Present(HistoryEntry e)
    {
        var entry = AlertCatalog.IsKnown(e.Kind) ? AlertCatalog.Get(e.Kind) : null;
        return new Alert
        {
            Id = e.Id,
            Seq = e.Seq,
            Time = e.Time,
            Kind = e.Kind,
            Source = e.Source,
            Severity = e.Severity,
            Title = e.Title,
            Detail = e.Detail,
            Explanation = entry is null ? "" : AlertCatalog.Render(entry.Explanation, e.Subject),
            Advice = entry is null ? "" : AlertCatalog.Render(entry.Advice, e.Subject),
            Subject = e.Subject,
            Actions = entry?.Actions ?? [],
            TrustOptions = entry is null || e.SuppressedBy is not null ? [] : TrustStore.OptionsFor(e.Kind, e.Subject),
            SuppressedBy = e.SuppressedBy,
        };
    }
}
