using System.Security.AccessControl;
using System.Security.Principal;

namespace Watchtower.Service.Hosting;

/// <summary>
/// All state lives under %ProgramData%\Watchtower, locked to SYSTEM and Administrators.
/// Standard users can't read or edit the log, baselines or trust rules directly;
/// they see them only through the service, which enforces permissions per request.
/// </summary>
public sealed class ServicePaths
{
    public required string Root { get; init; }
    public string History => Path.Combine(Root, "history");
    public string State => Path.Combine(Root, "state");
    public string Crashes => Path.Combine(Root, "crashes");
    public string Updates => Path.Combine(Root, "updates");
    public string KnownGood => Path.Combine(Updates, "known-good");

    public string SettingsFile => Path.Combine(State, "settings.json");
    public string TrustFile => Path.Combine(State, "trust.json");
    public string UpdateStateFile => Path.Combine(State, "update.json");
    public string HeartbeatFile => Path.Combine(State, "heartbeat.json");
    public string DebloatFile => Path.Combine(State, "debloat.json");
    public string EngineStateFile => Path.Combine(State, "engine.json");
    public string Baseline(string name) => Path.Combine(State, $"baseline-{name}.json");

    public static ServicePaths Create(string? overrideRoot)
    {
        var paths = new ServicePaths
        {
            Root = overrideRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Watchtower"),
        };
        foreach (var dir in new[] { paths.Root, paths.History, paths.State, paths.Crashes, paths.Updates, paths.KnownGood })
        {
            Directory.CreateDirectory(dir);
        }
        if (overrideRoot is null && OperatingSystem.IsWindows()) Harden(paths.Root);
        return paths;
    }

    private static void Harden(string dir)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        new DirectoryInfo(dir).SetAccessControl(security);
    }
}
