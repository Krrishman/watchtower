using Watchtower.Core.Alerts;
using Watchtower.Core.Config;
using Watchtower.Core.History;
using Watchtower.Core.Trust;
using Watchtower.Service.Hosting;

namespace Watchtower.Service.Engine;

/// <summary>Shared state every part of the service works against.</summary>
public sealed class EngineContext
{
    public EngineContext(ServicePaths paths)
    {
        Paths = paths;
        Settings = new JsonFileStore<WatchtowerSettings>(paths.SettingsFile);
        // First run: persist the generated install ID and start the learning period.
        Settings.Update(s => s.LearningUntil is null ? s with { LearningUntil = DateTimeOffset.UtcNow.AddHours(24).ToString("o") } : s);
        Trust = new TrustStore(paths.TrustFile);
        History = new HistoryLog(paths.History);
        Pipeline = new AlertPipeline(History, Trust, () => DateTimeOffset.UtcNow, now => Settings.Value.IsLearning(now));
    }

    public ServicePaths Paths { get; }
    public JsonFileStore<WatchtowerSettings> Settings { get; }
    public TrustStore Trust { get; }
    public HistoryLog History { get; }
    public AlertPipeline Pipeline { get; }

    public Alert? Publish(AlertDraft draft) => Pipeline.Publish(draft);

    public void Audit(string actor, string action, string target) =>
        Publish(AlertDraft.Of(AlertKinds.ActionTaken, (SubjectKeys.Actor, actor), (SubjectKeys.ActionName, action), (SubjectKeys.Target, target)));
}

/// <summary>Pushes events to every connected UI.</summary>
public interface IEventSink
{
    void Broadcast(string name, object? data);
}
