using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Watchtower.Core.Monitoring;

namespace Watchtower.Service.Sources;

/// <summary>
/// Subscribes to sign-in events in the Security log. Windows pushes each event as it's
/// written, so there's no polling window. Runs as SYSTEM, so no elevation prompt is needed.
/// </summary>
public sealed class SecurityLogSource : IDisposable
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";
    private readonly Action<LogonEvent> _onEvent;
    private readonly ILogger _log;
    private EventLogWatcher? _watcher;

    public SecurityLogSource(Action<LogonEvent> onEvent, ILogger log)
    {
        _onEvent = onEvent;
        _log = log;
    }

    public bool IsLive { get; private set; }
    public string? FailureReason { get; private set; }

    public bool Start()
    {
        try
        {
            var ids = string.Join(" or ", LogonTracker.EventIds.Select(id => $"EventID={id}"));
            var query = new EventLogQuery("Security", PathType.LogName, $"*[System[({ids})]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnRecord;
            _watcher.Enabled = true;
            IsLive = true;
            return true;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            FailureReason = $"Can't read the Security log ({ex.Message}).";
            _log.LogWarning(ex, "Security log subscription failed");
            return false;
        }
    }

    private void OnRecord(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;
        using var record = e.EventRecord;
        try
        {
            _onEvent(new LogonEvent(record.Id, record.TimeCreated ?? DateTime.UtcNow, Parse(record.ToXml())));
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Couldn't interpret Security event {Id}", record.Id);
        }
    }

    /// <summary>EventData fields by name, so parsing doesn't depend on the display language.</summary>
    internal static Dictionary<string, string> Parse(string xml)
    {
        var doc = XDocument.Parse(xml);
        return doc.Descendants(Ns + "Data")
            .Where(d => d.Attribute("Name") is not null)
            .GroupBy(d => d.Attribute("Name")!.Value)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal);
    }

    public void Dispose()
    {
        IsLive = false;
        if (_watcher is null) return;
        _watcher.Enabled = false;
        _watcher.Dispose();
        _watcher = null;
    }
}
