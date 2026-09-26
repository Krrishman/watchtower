using System.Text.Json;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Watchtower.Core.Monitoring;

namespace Watchtower.Service.Hosting;

/// <summary>Why the service is stopping, so the next start can explain the gap.</summary>
public static class StopReason
{
    private static string _current = StopReasons.Stop;
    public static string Current => Volatile.Read(ref _current);
    public static void Set(string reason) => Volatile.Write(ref _current, reason);
}

/// <summary>Distinguishes "Windows is shutting down" from "someone stopped the service".</summary>
public sealed class WatchtowerLifetime(
    IHostEnvironment environment,
    IHostApplicationLifetime applicationLifetime,
    ILoggerFactory loggerFactory,
    IOptions<HostOptions> hostOptions,
    IOptions<WindowsServiceLifetimeOptions> serviceOptions)
    : WindowsServiceLifetime(environment, applicationLifetime, loggerFactory, hostOptions, serviceOptions)
{
    protected override void OnShutdown()
    {
        StopReason.Set(StopReasons.Shutdown);
        base.OnShutdown();
    }
}

public sealed class HeartbeatFile(ServicePaths paths)
{
    public Heartbeat? Read()
    {
        try
        {
            return JsonSerializer.Deserialize<Heartbeat>(File.ReadAllText(paths.HeartbeatFile), JsonSerializerOptions.Web);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void Write(bool clean, string? reason = null)
    {
        var hb = new Heartbeat { Time = DateTimeOffset.UtcNow.ToString("o"), Clean = clean, Reason = reason, Version = AppVersion.Current };
        var tmp = paths.HeartbeatFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(hb, JsonSerializerOptions.Web));
        File.Move(tmp, paths.HeartbeatFile, overwrite: true);
    }

    public static DateTimeOffset BootTime => DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
}
