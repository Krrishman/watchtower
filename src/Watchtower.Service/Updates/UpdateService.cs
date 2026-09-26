using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Watchtower.Core.Alerts;
using Watchtower.Core.Updates;
using Watchtower.Service.Engine;
using Watchtower.Service.Hosting;
using Watchtower.Service.Ipc;
using Watchtower.Service.Native;

namespace Watchtower.Service.Updates;

/// <summary>The update gate's verdict from the very start of this process, before anything else ran.</summary>
public sealed record StartupGate(UpdateHealthGate Gate, GateResult Result);

public sealed record UpdateStatus(string CurrentVersion, string? LastCheck, string Message, string? Available, bool Configured);

/// <summary>
/// Staged, verified, self-healing updates:
/// 1. Fetch the signed manifest; verify signature, expiry and sequence before using it.
/// 2. Take a release only when this machine's rollout bucket and ring allow it.
/// 3. Check the download's size, SHA-256 and Authenticode publisher.
/// 4. Install, then keep the new version on probation. If it can't stay up, the
///    update gate reinstalls the previous version automatically.
/// Code and detection content ship together in the one signed installer, so there is no
/// separate fast channel that could bypass the staged rollout.
/// </summary>
public sealed class UpdateService(
    EngineContext ctx,
    StartupGate startup,
    IOptions<WatchtowerOptions> options,
    SignatureVerifier signatures,
    WatchtowerEngine engine,
    PipeServer pipe,
    ILogger<UpdateService> log) : BackgroundService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(10) };
    private readonly WatchtowerOptions _options = options.Value;
    private readonly SemaphoreSlim _checkLock = new(1, 1);

    public UpdateStatus Status { get; private set; } = new(AppVersion.Current, null, "Not checked yet.", null, options.Value.UpdatesConfigured);

    private string KnownGoodCurrent => Path.Combine(ctx.Paths.KnownGood, "current.msi");
    private string RollbackPackage => Path.Combine(ctx.Paths.KnownGood, "rollback.msi");

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        ReportStartupGate();

        if (startup.Result.Action == GateAction.Probation)
        {
            await Task.Delay(UpdateHealthGate.Probation, ct);
            if (engine.IsHealthy && pipe.Listening)
            {
                var verified = startup.Gate.MarkHealthy();
                if (verified.Action == GateAction.Verified)
                {
                    PromoteToKnownGood(verified.Version!);
                    ctx.Publish(AlertDraft.Of(AlertKinds.UpdateInstalled, (SubjectKeys.Version, verified.Version), (SubjectKeys.PreviousVersion, verified.PreviousVersion)));
                }
            }
        }

        // Spread checks out so a new release isn't fetched by every machine in the same minute.
        await Task.Delay(TimeSpan.FromMinutes(Random.Shared.Next(2, 30)), ct);
        while (!ct.IsCancellationRequested)
        {
            await CheckAsync(install: ctx.Settings.Value.AutoUpdate, ct);
            await Task.Delay(TimeSpan.FromHours(Math.Max(1, _options.UpdateCheckHours)) + TimeSpan.FromMinutes(Random.Shared.Next(0, 30)), ct);
        }
    }

    private void ReportStartupGate()
    {
        var r = startup.Result;
        if (r.Action is GateAction.RolledBack or GateAction.InstallFailed)
        {
            ctx.Publish(AlertDraft.Of(AlertKinds.UpdateRolledBack,
                (SubjectKeys.Version, r.Version), (SubjectKeys.PreviousVersion, r.PreviousVersion), (SubjectKeys.Reason, r.Reason)));
        }
    }

    public async Task<UpdateStatus> CheckAsync(bool install, CancellationToken ct)
    {
        if (!await _checkLock.WaitAsync(0, ct)) return Status;
        try
        {
            Status = await CheckCoreAsync(install, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException or UnauthorizedAccessException)
        {
            log.LogWarning(ex, "Update check failed");
            Status = Status with { LastCheck = Now(), Message = $"Couldn't check for updates: {ex.Message}" };
        }
        finally
        {
            _checkLock.Release();
        }
        return Status;
    }

    private async Task<UpdateStatus> CheckCoreAsync(bool install, CancellationToken ct)
    {
        if (!_options.UpdatesConfigured) return Status with { Message = "Automatic updates aren't set up in this build.", Configured = false };

        var manifestBytes = await FetchSmallAsync(_options.UpdateManifestUrl!, ct);
        var signature = System.Text.Encoding.UTF8.GetString(await FetchSmallAsync(_options.UpdateManifestUrl + ".sig", ct));
        var verified = ManifestVerifier.Verify(manifestBytes, signature, _options.UpdateSigningKeys, startup.Gate.State.LastManifestSequence, DateTimeOffset.UtcNow);
        if (!verified.Ok) return Status with { LastCheck = Now(), Message = $"Update information was rejected: {verified.Error}" };

        var manifest = verified.Manifest!;
        startup.Gate.RecordManifestSequence(manifest.Sequence);
        var settings = ctx.Settings.Value;
        var decision = RolloutPolicy.Decide(manifest, AppVersion.Current, settings.InstallId, settings.UpdateRing, DateTimeOffset.UtcNow, startup.Gate.State.FailedVersions);

        if (decision.Action == UpdateAction.None) return Status with { LastCheck = Now(), Message = decision.Reason, Available = null };
        var release = decision.Release!;
        if (!install) return Status with { LastCheck = Now(), Message = $"{decision.Reason} It will install when you choose.", Available = release.Version };

        var msi = await DownloadAsync(release, ct);
        await EnsureRollbackPackageAsync(manifest, ct);
        startup.Gate.BeginInstall(AppVersion.Current, release.Version, File.Exists(RollbackPackage) ? RollbackPackage : null, DateTimeOffset.UtcNow);

        StopReason.Set(Core.Monitoring.StopReasons.Update);
        LaunchInstaller(msi, ctx.Paths, log);
        return Status with { LastCheck = Now(), Message = $"Installing {release.Version}…", Available = release.Version };
    }

    private async Task<string> DownloadAsync(ReleaseInfo release, CancellationToken ct)
    {
        var target = Path.Combine(ctx.Paths.Updates, $"Watchtower-{release.Version}.msi");
        if (File.Exists(target) && Verify(target, release) is null) return target;

        var partial = target + ".partial";
        using (var response = await Http.GetAsync(release.Url, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            response.EnsureSuccessStatusCode();
            var limit = release.Size > 0 ? release.Size : 500L * 1024 * 1024;
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            await using var output = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None);
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await input.ReadAsync(buffer, ct)) > 0)
            {
                total += read;
                if (total > limit) throw new IOException("Download is larger than the manifest says.");
                await output.WriteAsync(buffer.AsMemory(0, read), ct);
            }
        }
        File.Move(partial, target, overwrite: true);

        if (Verify(target, release) is { } problem)
        {
            File.Delete(target);
            throw new IOException(problem);
        }
        return target;
    }

    private string? Verify(string path, ReleaseInfo release)
    {
        using (var stream = File.OpenRead(path))
        {
            if (release.Size > 0 && stream.Length != release.Size) return "Download is the wrong size.";
            if (!Convert.ToHexStringLower(SHA256.HashData(stream)).Equals(release.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                return "Download doesn't match the published checksum.";
            }
        }
        var sig = signatures.Check(path);
        if (!sig.IsValid || !string.Equals(sig.Signer, _options.InstallerPublisher, StringComparison.OrdinalIgnoreCase))
        {
            return $"Installer isn't signed by {_options.InstallerPublisher} ({sig.Status}, {sig.Signer ?? "no signer"}).";
        }
        return null;
    }

    /// <summary>Keeps an installer for the running version so a bad update can be undone even offline.</summary>
    private async Task EnsureRollbackPackageAsync(ReleaseManifest manifest, CancellationToken ct)
    {
        if (File.Exists(KnownGoodCurrent))
        {
            File.Copy(KnownGoodCurrent, RollbackPackage, overwrite: true);
            return;
        }
        var current = manifest.Releases.FirstOrDefault(r => r.Version == AppVersion.Current);
        if (current is null) return;
        try
        {
            File.Copy(await DownloadAsync(current, ct), RollbackPackage, overwrite: true);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            log.LogWarning(ex, "Couldn't fetch rollback package for {Version}", AppVersion.Current);
        }
    }

    private void PromoteToKnownGood(string version)
    {
        var msi = Path.Combine(ctx.Paths.Updates, $"Watchtower-{version}.msi");
        if (File.Exists(msi)) File.Copy(msi, KnownGoodCurrent, overwrite: true);
    }

    public static void LaunchInstaller(string msi, ServicePaths paths, ILogger? log)
    {
        var logFile = Path.Combine(paths.Updates, $"install-{DateTime.UtcNow:yyyyMMdd-HHmmss}.log");
        var msiexec = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "msiexec.exe");
        // The installer stops this service as part of the upgrade, so it must run as its own process.
        Process.Start(new ProcessStartInfo(msiexec)
        {
            ArgumentList = { "/i", msi, "/qn", "/norestart", "/l*v", logFile },
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        log?.LogInformation("Launched installer {Msi}", msi);
    }

    private static async Task<byte[]> FetchSmallAsync(string url, CancellationToken ct)
    {
        using var response = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > 1024 * 1024) throw new IOException("Update information is unexpectedly large.");
        return await response.Content.ReadAsByteArrayAsync(ct);
    }

    private static string Now() => DateTimeOffset.UtcNow.ToString("o");
}
