using System.Runtime.InteropServices;
using System.Text;

namespace Watchtower.Service.Hosting;

/// <summary>
/// Always writes crash reports locally. Uploads to Sentry only when the build has a
/// DSN and the user opted in during setup: a security tool must not quietly send
/// data off the machine. Sentry's per-release crash-free rate is also the signal the
/// release process watches before widening a rollout.
/// </summary>
public static class CrashReporting
{
    private static string? _dir;
    private static IDisposable? _sentry;

    public static void InstallLocalHandlers(ServicePaths paths)
    {
        _dir = paths.Crashes;
        AppDomain.CurrentDomain.UnhandledException += (_, e) => WriteLocal("unhandled", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            WriteLocal("unobserved-task", e.Exception);
            e.SetObserved();
        };
    }

    public static void Configure(string? dsn, bool consent)
    {
        if (!consent || string.IsNullOrWhiteSpace(dsn))
        {
            _sentry?.Dispose();
            _sentry = null;
            return;
        }
        if (_sentry is not null) return;
        _sentry = SentrySdk.Init(o =>
        {
            o.Dsn = dsn;
            o.Release = $"watchtower@{AppVersion.Current}";
            o.AutoSessionTracking = true;
            o.SendDefaultPii = false;
            o.ServerName = "";
            o.AttachStacktrace = true;
            // Breadcrumbs and messages can carry alert text (usernames, file names); send only the crash itself.
            o.MaxBreadcrumbs = 0;
            o.SetBeforeSend(e =>
            {
                e.User = new SentryUser();
                e.Message = null;
                return e;
            });
        });
    }

    public static void WriteLocal(string kind, Exception? ex)
    {
        if (_dir is null) return;
        try
        {
            var sb = new StringBuilder()
                .AppendLine($"Watchtower {AppVersion.Current} {kind} at {DateTimeOffset.UtcNow:o}")
                .AppendLine($"OS: {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})")
                .AppendLine($"Runtime: {RuntimeInformation.FrameworkDescription}")
                .AppendLine()
                .AppendLine(ex?.ToString() ?? "(no exception object)");
            File.WriteAllText(Path.Combine(_dir, $"crash-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{kind}.txt"), sb.ToString());
            foreach (var old in new DirectoryInfo(_dir).GetFiles("crash-*.txt").OrderByDescending(f => f.CreationTimeUtc).Skip(20))
            {
                old.Delete();
            }
        }
        catch (Exception writeFailure) when (writeFailure is IOException or UnauthorizedAccessException)
        {
            // Nothing else can be done while crashing.
        }
    }
}
