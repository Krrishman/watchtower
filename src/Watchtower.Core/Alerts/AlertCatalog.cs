using System.Text.RegularExpressions;

namespace Watchtower.Core.Alerts;

public static class AlertKinds
{
    public const string RdpSessionActive = "rdp.session_active";
    public const string RemoteToolStarted = "remote_tool.started";
    public const string RemoteLogon = "logon.remote_success";
    public const string RemoteLogonUnrecognized = "logon.remote_unrecognized";
    public const string RemoteLogonFailed = "logon.remote_failed";
    public const string PasswordGuessing = "logon.bruteforce";
    public const string RemoteLogonEnded = "logon.remote_ended";
    public const string SessionReconnected = "session.reconnected";
    public const string SessionDisconnected = "session.disconnected";
    public const string FirstConnection = "network.first_connection";
    public const string InboundConnection = "network.inbound_accept";
    public const string CameraUsed = "device.camera";
    public const string MicrophoneUsed = "device.microphone";
    public const string ProgramFirstSeen = "program.first_seen";
    public const string ProgramNewListener = "program.new_listener";
    public const string ProgramNewOutbound = "program.new_outbound";
    public const string ProgramMasquerading = "program.masquerading";
    public const string StartupEntryAdded = "startup.entry_added";
    public const string ServiceInstalled = "startup.service_installed";
    public const string DefenderThreat = "defender.threat";
    public const string MonitoringGap = "watchtower.offline_gap";
    public const string MonitoringKilled = "watchtower.killed";
    public const string MonitoringStopped = "watchtower.stopped";
    public const string HistoryTampered = "watchtower.history_tampered";
    public const string DegradedCoverage = "watchtower.degraded";
    public const string CoverageRestored = "watchtower.coverage_ok";
    public const string UpdateInstalled = "watchtower.update_installed";
    public const string UpdateRolledBack = "watchtower.update_rolled_back";
    public const string TrustAdded = "audit.trust_added";
    public const string TrustRemoved = "audit.trust_removed";
    public const string ActionTaken = "audit.action";
}

public static class AlertActions
{
    public const string Kill = "kill";
    public const string Block = "block";
    public const string Disconnect = "disconnect";
    public const string RemoveStartup = "removeStartup";
    public const string OpenWindowsSecurity = "openWindowsSecurity";
    public const string OpenRdpSettings = "openRdpSettings";
    public const string VerifyHistory = "verifyHistory";
}

public static class TrustTypes
{
    public const string Program = "program";
    public const string Publisher = "publisher";
    public const string Address = "address";
    public const string Account = "account";
    public const string Startup = "startup";
    public const string Kind = "kind";
}

public sealed record CatalogEntry
{
    public required string Source { get; init; }
    public required string Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required string Explanation { get; init; }
    public required string Advice { get; init; }
    public string[] TrustBy { get; init; } = [];
    public string[] Actions { get; init; } = [];
    /// <summary>Whether the whole kind may be muted. Tamper and self-protection alerts can never be muted.</summary>
    public bool Mutable { get; init; } = true;
    /// <summary>Kinds that are pure noise while Watchtower is still learning what is normal for this PC.</summary>
    public bool QuietWhileLearning { get; init; }
}

public static partial class AlertCatalog
{
    private static readonly Dictionary<string, CatalogEntry> Entries = new(StringComparer.Ordinal)
    {
        [AlertKinds.RdpSessionActive] = new()
        {
            Source = "sessions",
            Severity = Severity.Critical,
            Title = "Someone is connected to this PC with Remote Desktop",
            Detail = "\"{account}\" is signed in over Remote Desktop from {clientName}.",
            Explanation = "Remote Desktop lets a person see and control this PC from another computer. Whoever is connected can do anything the signed-in account can do.",
            Advice = "If this is you or someone you asked for help, you can trust this account. If you don't recognize it, disconnect the session and change the account's password.",
            TrustBy = [TrustTypes.Account],
            Actions = [AlertActions.Disconnect, AlertActions.OpenRdpSettings],
        },
        [AlertKinds.RemoteToolStarted] = new()
        {
            Source = "processes",
            Severity = Severity.Warn,
            Title = "Remote-control program started: {processName}",
            Detail = "{processName} started (from {processPath}).",
            Explanation = "This program lets someone view or control your screen from elsewhere. It's normal if you use it for IT support, but scammers often ask people to install it.",
            Advice = "If you didn't start it and nobody you trust is helping you right now, end it and uninstall it.",
            TrustBy = [TrustTypes.Program, TrustTypes.Publisher],
            Actions = [AlertActions.Kill],
        },
        [AlertKinds.RemoteLogon] = new()
        {
            Source = "eventlog",
            Severity = Severity.Warn,
            Title = "\"{account}\" signed in remotely",
            Detail = "\"{account}\" signed in to this PC from {clientAddress}.",
            Explanation = "Someone used this account's password to sign in from another computer.",
            Advice = "If this was you or someone you know, trust the account so it doesn't alert again. If not, change that account's password now.",
            TrustBy = [TrustTypes.Account],
        },
        [AlertKinds.RemoteLogonUnrecognized] = new()
        {
            Source = "eventlog",
            Severity = Severity.Critical,
            Title = "An account you haven't approved signed in remotely",
            Detail = "\"{account}\" signed in from {clientAddress}. It isn't on your list of trusted accounts.",
            Explanation = "You've told Watchtower which accounts are expected to sign in remotely. This one isn't one of them.",
            Advice = "Change this account's password, and disconnect any active session from the Processes tab. Trust the account only if you're sure you know who this is.",
            TrustBy = [TrustTypes.Account],
            Actions = [AlertActions.OpenRdpSettings],
        },
        [AlertKinds.RemoteLogonFailed] = new()
        {
            Source = "eventlog",
            Severity = Severity.Warn,
            Title = "Failed remote sign-in attempt",
            Detail = "Someone at {clientAddress} tried to sign in as \"{account}\" and got the password wrong.",
            Explanation = "A single failed attempt is often just a typo. Many attempts in a row usually means someone is guessing passwords.",
            Advice = "If this wasn't you, make sure the account has a strong, unique password. Watchtower will warn you if the attempts continue.",
            TrustBy = [TrustTypes.Address],
            Actions = [AlertActions.Block],
        },
        [AlertKinds.PasswordGuessing] = new()
        {
            Source = "eventlog",
            Severity = Severity.Critical,
            Title = "Someone is guessing passwords on this PC",
            Detail = "{count} failed sign-in attempts from {clientAddress} in the last {window}.",
            Explanation = "Repeated failed sign-ins from one place is what an automated password-guessing attack looks like.",
            Advice = "Block this address, turn off Remote Desktop if you don't use it, and make sure every account has a strong password.",
            Actions = [AlertActions.Block, AlertActions.OpenRdpSettings],
        },
        [AlertKinds.RemoteLogonEnded] = new()
        {
            Source = "eventlog",
            Severity = Severity.Info,
            Title = "Remote session ended",
            Detail = "\"{account}\" signed out after {duration}.",
            Explanation = "A remote sign-in that Watchtower recorded earlier has now finished.",
            Advice = "Nothing to do. This is logged so you can see how long remote sessions lasted.",
            TrustBy = [TrustTypes.Account],
        },
        [AlertKinds.SessionReconnected] = new()
        {
            Source = "eventlog",
            Severity = Severity.Info,
            Title = "A session was reconnected",
            Detail = "\"{account}\" reconnected to a session from {clientName}.",
            Explanation = "This happens with Remote Desktop, and also when switching between users on the same PC.",
            Advice = "Nothing to do unless you don't recognize the account or computer name.",
            TrustBy = [TrustTypes.Account],
        },
        [AlertKinds.SessionDisconnected] = new()
        {
            Source = "eventlog",
            Severity = Severity.Info,
            Title = "A session was disconnected",
            Detail = "\"{account}\" disconnected from a session.",
            Explanation = "This happens with Remote Desktop, and also when switching between users on the same PC.",
            Advice = "Nothing to do.",
            TrustBy = [TrustTypes.Account],
        },
        [AlertKinds.FirstConnection] = new()
        {
            Source = "network",
            Severity = Severity.Info,
            Title = "{processName} connected somewhere new",
            Detail = "{processName} connected to {remoteAddress} (port {remotePort}) for the first time.",
            Explanation = "Most programs talk to the internet, so this is usually normal. It's recorded so you can spot a program that shouldn't be online.",
            Advice = "If you don't recognize the program, look it up or block the address.",
            TrustBy = [TrustTypes.Program, TrustTypes.Publisher, TrustTypes.Address],
            Actions = [AlertActions.Block, AlertActions.Kill],
            QuietWhileLearning = true,
        },
        [AlertKinds.InboundConnection] = new()
        {
            Source = "network",
            Severity = Severity.Warn,
            Title = "A computer on the internet connected in to {processName}",
            Detail = "{remoteAddress} opened a connection to {processName} on port {localPort}.",
            Explanation = "Normally your PC reaches out to the internet, not the other way round. An incoming connection means this program is accepting visitors from outside your network.",
            Advice = "If you run a server or game host on purpose, trust this program. Otherwise block the address and check the Exposure tab.",
            TrustBy = [TrustTypes.Program, TrustTypes.Publisher, TrustTypes.Address],
            Actions = [AlertActions.Block, AlertActions.Kill],
        },
        [AlertKinds.CameraUsed] = new()
        {
            Source = "cameraMic",
            Severity = Severity.Warn,
            Title = "{appName} used your camera",
            Detail = "{appName} turned on the camera.",
            Explanation = "Windows records every app that uses the camera. This alert appears the first time an app starts using it.",
            Advice = "If you were on a call or taking a photo, this is expected. If not, close the app, or turn off its camera access in Windows Settings > Privacy.",
            TrustBy = [TrustTypes.Program],
        },
        [AlertKinds.MicrophoneUsed] = new()
        {
            Source = "cameraMic",
            Severity = Severity.Warn,
            Title = "{appName} used your microphone",
            Detail = "{appName} turned on the microphone.",
            Explanation = "Windows records every app that uses the microphone. This alert appears the first time an app starts using it.",
            Advice = "If you were on a call or using voice typing, this is expected. If not, close the app, or turn off its microphone access in Windows Settings > Privacy.",
            TrustBy = [TrustTypes.Program],
        },
        [AlertKinds.ProgramFirstSeen] = new()
        {
            Source = "newProgramWatch",
            Severity = Severity.Info,
            Title = "New program: {processName}",
            Detail = "{processName} ran for the first time ({signatureStatus}). Watchtower is keeping a close eye on it for 5 minutes.",
            Explanation = "Watchtower watches brand-new programs closely at first, because that's when malware usually tries to open a back door or set itself to start automatically.",
            Advice = "Nothing to do if you just installed or opened this. You'll get another alert if it does anything risky.",
            TrustBy = [TrustTypes.Program, TrustTypes.Publisher],
            Actions = [AlertActions.Kill],
            QuietWhileLearning = true,
        },
        [AlertKinds.ProgramNewListener] = new()
        {
            Source = "newProgramWatch",
            Severity = Severity.Critical,
            Title = "A new program opened a door into this PC",
            Detail = "{processName} started accepting connections on port {localPort} right after its first run.",
            Explanation = "Opening a listening port lets other computers connect in. It's what remote-access malware does, but some legitimate apps (games, file sharing) do it too.",
            Advice = "If you don't recognize {processName}, end it and uninstall it. Check the Exposure tab to see if the port is reachable from outside.",
            TrustBy = [TrustTypes.Program, TrustTypes.Publisher],
            Actions = [AlertActions.Kill],
        },
        [AlertKinds.ProgramNewOutbound] = new()
        {
            Source = "newProgramWatch",
            Severity = Severity.Warn,
            Title = "A new program went online right away",
            Detail = "{processName} connected to {remoteAddress} (port {remotePort}) shortly after its first run.",
            Explanation = "Lots of apps check for updates when they start. Malware also \"phones home\" as soon as it runs.",
            Advice = "If you just installed this from a source you trust, this is fine. If you don't recognize it, end it and block the address.",
            TrustBy = [TrustTypes.Program, TrustTypes.Publisher],
            Actions = [AlertActions.Kill, AlertActions.Block],
        },
        [AlertKinds.ProgramMasquerading] = new()
        {
            Source = "processes",
            Severity = Severity.Critical,
            Title = "A program is pretending to be part of Windows",
            Detail = "{processName} is running from {processPath}, but the real Windows file lives in {expectedLocation}.",
            Explanation = "Malware often copies the names of Windows system files so it blends in. The real ones never run from anywhere else.",
            Advice = "End this program and run a full scan from the Health Check tab.",
            TrustBy = [TrustTypes.Program],
            Actions = [AlertActions.Kill, AlertActions.OpenWindowsSecurity],
        },
        [AlertKinds.StartupEntryAdded] = new()
        {
            Source = "startup",
            Severity = Severity.Warn,
            Title = "Something set itself to start automatically",
            Detail = "\"{startupName}\" will now run every time Windows starts: {startupCommand}",
            Explanation = "Programs that start on their own keep running in the background. That's normal for apps you install, and it's also how malware survives a restart.",
            Advice = "If you just installed the app this belongs to, it's fine. If you don't recognize it, remove it from startup. That doesn't uninstall the program.",
            TrustBy = [TrustTypes.Startup],
            Actions = [AlertActions.RemoveStartup],
        },
        [AlertKinds.ServiceInstalled] = new()
        {
            Source = "startup",
            Severity = Severity.Warn,
            Title = "A new background service was installed",
            Detail = "\"{startupName}\" was installed as a Windows service and starts automatically: {startupCommand}",
            Explanation = "Services run with full system rights before anyone signs in. Installers add them routinely, and so does serious malware.",
            Advice = "If you just installed software, this is probably part of it. If not, look up the service name before doing anything else.",
            TrustBy = [TrustTypes.Startup],
        },
        [AlertKinds.DefenderThreat] = new()
        {
            Source = "health",
            Severity = Severity.Critical,
            Title = "Windows Security found a threat",
            Detail = "Microsoft Defender detected {threatName}.",
            Explanation = "Microsoft's antivirus found something it recognizes as malicious.",
            Advice = "Open Windows Security and follow its steps to remove it.",
            Actions = [AlertActions.OpenWindowsSecurity],
            Mutable = false,
        },
        [AlertKinds.MonitoringGap] = new()
        {
            Source = "watchtower",
            Severity = Severity.Info,
            Title = "Watchtower was off while the PC was shut down",
            Detail = "No monitoring from {from} to {to} ({reason}).",
            Explanation = "Watchtower can only watch while the PC is on. This gap is expected after a restart or shutdown.",
            Advice = "Nothing to do.",
            Mutable = false,
        },
        [AlertKinds.MonitoringKilled] = new()
        {
            Source = "watchtower",
            Severity = Severity.Critical,
            Title = "Watchtower was stopped while the PC was running",
            Detail = "Monitoring stopped unexpectedly at {from} and resumed at {to}.",
            Explanation = "Watchtower didn't shut down normally. It may have crashed, or something may have forced it to stop. Attackers sometimes do this to go unnoticed.",
            Advice = "Check the History tab for anything logged just before {from}. If this keeps happening, run a full scan.",
            Mutable = false,
        },
        [AlertKinds.MonitoringStopped] = new()
        {
            Source = "watchtower",
            Severity = Severity.Warn,
            Title = "Watchtower's monitoring was turned off",
            Detail = "The Watchtower service was stopped at {from} and started again at {to}.",
            Explanation = "Someone with administrator rights stopped the Watchtower service. Nothing was monitored in between.",
            Advice = "If you did this, nothing to do. If not, someone with administrator access to this PC may be trying to avoid detection.",
            Mutable = false,
        },
        [AlertKinds.HistoryTampered] = new()
        {
            Source = "watchtower",
            Severity = Severity.Critical,
            Title = "Watchtower's history log was changed",
            Detail = "{reason}",
            Explanation = "Every history entry is linked to the one before it, so edits or deletions are detectable. The log no longer matches what Watchtower wrote.",
            Advice = "Compare against your off-machine backup copy, which will still hold the original entries.",
            Actions = [AlertActions.VerifyHistory],
            Mutable = false,
        },
        [AlertKinds.DegradedCoverage] = new()
        {
            Source = "watchtower",
            Severity = Severity.Warn,
            Title = "Some monitoring is running in reduced mode",
            Detail = "{reason}",
            Explanation = "Watchtower couldn't start one of its real-time sensors, so it's checking on a timer instead. Very short-lived activity could be missed.",
            Advice = "Restarting the PC usually fixes this. If it keeps happening, another security tool may be using the same Windows feature.",
            Mutable = false,
        },
        [AlertKinds.CoverageRestored] = new()
        {
            Source = "watchtower",
            Severity = Severity.Info,
            Title = "Real-time monitoring is active",
            Detail = "{reason}",
            Explanation = "Watchtower is receiving live events from Windows.",
            Advice = "Nothing to do.",
            Mutable = false,
        },
        [AlertKinds.UpdateInstalled] = new()
        {
            Source = "watchtower",
            Severity = Severity.Info,
            Title = "Watchtower updated to {version}",
            Detail = "Updated from {previousVersion} to {version}.",
            Explanation = "A new version was installed and has been running normally.",
            Advice = "Nothing to do.",
            Mutable = false,
        },
        [AlertKinds.UpdateRolledBack] = new()
        {
            Source = "watchtower",
            Severity = Severity.Warn,
            Title = "An update didn't work, so Watchtower went back to {previousVersion}",
            Detail = "Version {version} failed its health check ({reason}), so the previous version was reinstalled.",
            Explanation = "Watchtower checks that each update runs properly and undoes it automatically if it doesn't.",
            Advice = "Nothing to do. Watchtower will skip the faulty version.",
            Mutable = false,
        },
        [AlertKinds.TrustAdded] = new()
        {
            Source = "audit",
            Severity = Severity.Info,
            Title = "{actor} trusted {ruleValue}",
            Detail = "{actor} added a trust rule ({ruleType}: {ruleValue}). Matching activity will be logged quietly instead of alerting.",
            Explanation = "Trust decisions are logged so there's a record of who approved what.",
            Advice = "You can remove trust rules in Settings > Trusted.",
            Mutable = false,
        },
        [AlertKinds.TrustRemoved] = new()
        {
            Source = "audit",
            Severity = Severity.Info,
            Title = "{actor} removed trust for {ruleValue}",
            Detail = "{actor} removed a trust rule ({ruleType}: {ruleValue}).",
            Explanation = "Trust decisions are logged so there's a record of who approved what.",
            Advice = "Nothing to do.",
            Mutable = false,
        },
        [AlertKinds.ActionTaken] = new()
        {
            Source = "audit",
            Severity = Severity.Info,
            Title = "{actor}: {action}",
            Detail = "{actor} used Watchtower to {action} ({target}).",
            Explanation = "Actions taken from Watchtower are logged so there's a record of what was changed.",
            Advice = "Nothing to do.",
            Mutable = false,
        },
    };

    public static IReadOnlyDictionary<string, CatalogEntry> All => Entries;

    public static CatalogEntry Get(string kind) =>
        Entries.TryGetValue(kind, out var entry)
            ? entry
            : throw new KeyNotFoundException($"Unknown alert kind '{kind}'.");

    public static bool IsKnown(string kind) => Entries.ContainsKey(kind);

    [GeneratedRegex(@"\{([A-Za-z]+)\}")]
    internal static partial Regex Placeholder();

    public static string Render(string template, IReadOnlyDictionary<string, string> subject) =>
        Placeholder().Replace(template, m =>
            subject.TryGetValue(m.Groups[1].Value, out var value) && value.Length > 0
                ? Fallback(m.Groups[1].Value, value)
                : Missing(m.Groups[1].Value));

    private static string Fallback(string key, string value) =>
        key == SubjectKeys.SignatureStatus ? DescribeSignature(value) : value;

    private static string Missing(string key) => key switch
    {
        SubjectKeys.ClientName or SubjectKeys.ClientAddress => "an unknown computer",
        SubjectKeys.ProcessName or SubjectKeys.AppName => "An unknown program",
        SubjectKeys.SignatureStatus => "signature not checked",
        _ => "unknown",
    };

    public static string DescribeSignature(string status) => status switch
    {
        "Valid" => "digitally signed",
        "NotSigned" => "not digitally signed",
        "HashMismatch" => "signature doesn't match the file, so it may have been modified",
        "Untrusted" => "signed with a certificate Windows doesn't trust",
        "Expired" => "signed with an expired certificate",
        "Revoked" => "signed with a revoked certificate",
        _ => "signature couldn't be checked",
    };

    /// <summary>Formats a duration the way a person would say it.</summary>
    public static string HumanDuration(TimeSpan span)
    {
        if (span < TimeSpan.FromMinutes(1)) return "under a minute";
        if (span < TimeSpan.FromHours(1)) return $"{(int)span.TotalMinutes} min";
        if (span < TimeSpan.FromDays(1)) return $"{(int)span.TotalHours}h {span.Minutes}m";
        return $"{(int)span.TotalDays}d {span.Hours}h";
    }
}
