using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Watchtower.Core.Config;

namespace Watchtower.Core.Updates;

public enum UpdateAction
{
    None,
    Install,
    /// <summary>The running version was recalled by the publisher; move to a known-good one even if it's older.</summary>
    Recall,
}

public sealed record UpdateDecision(UpdateAction Action, ReleaseInfo? Release, string Reason);

/// <summary>
/// Decides whether this machine should take a release yet. Machines are spread
/// across rollout buckets per release, so a bad build reaches 1% of machines
/// before 100%, and customers pick how early they want to be.
/// </summary>
public static class RolloutPolicy
{
    public static readonly TimeSpan DelayedRingSoak = TimeSpan.FromDays(7);

    public static UpdateDecision Decide(ReleaseManifest manifest, string currentVersion, string installId, string ring, DateTimeOffset now, IReadOnlyCollection<string> locallyFailed)
    {
        var current = SemVer.Parse(currentVersion);
        var blocked = new HashSet<string>(manifest.BlockedVersions, StringComparer.OrdinalIgnoreCase);

        if (blocked.Contains(currentVersion))
        {
            var safe = manifest.Releases
                .Where(r => !r.Paused && r.RolloutPercent >= 100 && !blocked.Contains(r.Version) && !locallyFailed.Contains(r.Version))
                .OrderByDescending(r => SemVer.Parse(r.Version))
                .FirstOrDefault();
            return safe is null
                ? new(UpdateAction.None, null, $"Version {currentVersion} was recalled, but there's no safe version to move to yet.")
                : new(UpdateAction.Recall, safe, $"Version {currentVersion} was recalled by the publisher.");
        }

        if (manifest.HaltAll) return new(UpdateAction.None, null, "The publisher has paused all updates.");

        var candidates = manifest.Releases
            .Where(r => SemVer.Parse(r.Version) > current)
            .Where(r => !r.Paused && !blocked.Contains(r.Version) && !locallyFailed.Contains(r.Version))
            .Where(r => r.MinFromVersion is null || current >= SemVer.Parse(r.MinFromVersion))
            .OrderByDescending(r => SemVer.Parse(r.Version));

        foreach (var release in candidates)
        {
            if (IsEligible(release, installId, ring, now)) return new(UpdateAction.Install, release, $"Version {release.Version} is available.");
        }
        return new(UpdateAction.None, null, "Up to date for this update ring.");
    }

    public static bool IsEligible(ReleaseInfo release, string installId, string ring, DateTimeOffset now) => ring switch
    {
        UpdateRings.Early => release.RolloutPercent > 0,
        UpdateRings.Delayed => release.RolloutPercent >= 100
                               && DateTimeOffset.TryParse(release.FullRolloutAt, out var full)
                               && now - full >= DelayedRingSoak,
        _ => Bucket(installId, release.Version) < release.RolloutPercent,
    };

    /// <summary>Stable 0–99.99 position of this machine in a release's rollout. Salted by version so the same machines aren't always first.</summary>
    public static double Bucket(string installId, string version)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{installId}|{version}"));
        return BinaryPrimitives.ReadUInt32BigEndian(hash) % 10_000 / 100.0;
    }
}
