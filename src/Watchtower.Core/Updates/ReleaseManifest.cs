using System.Text.Json;
using System.Text.Json.Serialization;

namespace Watchtower.Core.Updates;

public sealed record ReleaseInfo
{
    public required string Version { get; init; }
    public required string Url { get; init; }
    public required string Sha256 { get; init; }
    public long Size { get; init; }
    /// <summary>0–100. Share of standard-ring machines offered this release.</summary>
    public double RolloutPercent { get; init; }
    /// <summary>When the rollout reached 100%; the delayed ring waits a week after this.</summary>
    public string? FullRolloutAt { get; init; }
    public bool Paused { get; init; }
    /// <summary>Oldest version allowed to upgrade straight to this one (for migrations that need a stepping stone).</summary>
    public string? MinFromVersion { get; init; }
    public string? Notes { get; init; }
}

public sealed record ReleaseManifest
{
    public int Schema { get; init; }
    public string Product { get; init; } = "";
    public string Channel { get; init; } = "stable";
    /// <summary>Strictly increasing per publish. Clients refuse anything older than what they've seen (replay protection).</summary>
    public long Sequence { get; init; }
    public string IssuedAt { get; init; } = "";
    /// <summary>Clients refuse stale manifests, so an attacker can't freeze a machine on an old, vulnerable version.</summary>
    public string ExpiresAt { get; init; } = "";
    /// <summary>Publisher kill switch: stops every rollout immediately.</summary>
    public bool HaltAll { get; init; }
    /// <summary>Known-bad versions. Machines running one are moved to the newest fully-rolled-out release, even if that's older.</summary>
    public List<string> BlockedVersions { get; init; } = [];
    public List<ReleaseInfo> Releases { get; init; } = [];

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
        WriteIndented = true,
    };
}

public sealed record SignatureEnvelope(string KeyId, string Sig);

public static class SemVer
{
    public static Version Parse(string v)
    {
        var core = v.Split('-', '+')[0];
        var parts = core.Split('.');
        if (parts.Length is < 2 or > 4 || !parts.All(p => int.TryParse(p, out var n) && n >= 0))
        {
            throw new FormatException($"'{v}' isn't a valid version.");
        }
        return Version.Parse(parts.Length == 2 ? core + ".0" : core);
    }

    public static bool TryParse(string? v, out Version version)
    {
        try
        {
            version = Parse(v ?? "");
            return true;
        }
        catch (FormatException)
        {
            version = new Version(0, 0);
            return false;
        }
    }

    public static int Compare(string a, string b) => Parse(a).CompareTo(Parse(b));
}
