using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Watchtower.Core.Config;
using Watchtower.Core.Updates;

namespace Watchtower.Core.Tests;

public class UpdateTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-06-01T00:00:00Z");

    private static ReleaseInfo Release(string v, double pct, string? fullAt = null, bool paused = false) => new()
    {
        Version = v,
        Url = $"https://updates.example.com/Watchtower-{v}.msi",
        Sha256 = new string('a', 64),
        RolloutPercent = pct,
        FullRolloutAt = fullAt,
        Paused = paused,
    };

    private static ReleaseManifest Manifest(params ReleaseInfo[] releases) => new()
    {
        Schema = 1,
        Product = "watchtower",
        Sequence = 10,
        IssuedAt = Now.AddHours(-1).ToString("o"),
        ExpiresAt = Now.AddDays(7).ToString("o"),
        Releases = [.. releases],
    };

    private static (Dictionary<string, string> Keys, ECDsa Key) KeyPair()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (new() { ["k1"] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) }, key);
    }

    private static byte[] Bytes(ReleaseManifest m) => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(m, ReleaseManifest.Json));

    [Fact]
    public void ValidSignatureVerifies()
    {
        var (keys, key) = KeyPair();
        var bytes = Bytes(Manifest(Release("1.1.0", 10)));
        var result = ManifestVerifier.Verify(bytes, ManifestVerifier.Sign(bytes, key, "k1"), keys, 0, Now);
        Assert.True(result.Ok, result.Error);
        Assert.Equal("1.1.0", result.Manifest!.Releases[0].Version);
    }

    [Fact]
    public void TamperedManifestIsRejected()
    {
        var (keys, key) = KeyPair();
        var bytes = Bytes(Manifest(Release("1.1.0", 10)));
        var sig = ManifestVerifier.Sign(bytes, key, "k1");
        var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("\"rolloutPercent\": 10", "\"rolloutPercent\": 100"));
        Assert.NotEqual(bytes, tampered);
        Assert.Contains("invalid", ManifestVerifier.Verify(tampered, sig, keys, 0, Now).Error);
    }

    [Fact]
    public void UnknownKeyIsRejected()
    {
        var (keys, _) = KeyPair();
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = Bytes(Manifest());
        Assert.Contains("unknown key", ManifestVerifier.Verify(bytes, ManifestVerifier.Sign(bytes, other, "k9"), keys, 0, Now).Error);
    }

    [Fact]
    public void ExpiredAndReplayedManifestsAreRejected()
    {
        var (keys, key) = KeyPair();
        var bytes = Bytes(Manifest());
        var sig = ManifestVerifier.Sign(bytes, key, "k1");
        Assert.Contains("expired", ManifestVerifier.Verify(bytes, sig, keys, 0, Now.AddDays(8)).Error);
        Assert.Contains("older", ManifestVerifier.Verify(bytes, sig, keys, 11, Now).Error);
        Assert.True(ManifestVerifier.Verify(bytes, sig, keys, 10, Now).Ok);
    }

    [Fact]
    public void NonHttpsDownloadIsRejected()
    {
        var (keys, key) = KeyPair();
        var bytes = Bytes(Manifest(Release("1.1.0", 10) with { Url = "http://evil.example.com/x.msi" }));
        Assert.False(ManifestVerifier.Verify(bytes, ManifestVerifier.Sign(bytes, key, "k1"), keys, 0, Now).Ok);
    }

    [Fact]
    public void BucketsAreStableAndRoughlyUniform()
    {
        Assert.Equal(RolloutPolicy.Bucket("abc", "1.0.0"), RolloutPolicy.Bucket("abc", "1.0.0"));
        var inTenPercent = Enumerable.Range(0, 10_000).Count(i => RolloutPolicy.Bucket($"machine{i}", "2.0.0") < 10);
        Assert.InRange(inTenPercent, 850, 1150);
    }

    [Fact]
    public void StandardRingFollowsRolloutPercentage()
    {
        var m = Manifest(Release("1.1.0", 10));
        var eligible = Enumerable.Range(0, 2000)
            .Count(i => RolloutPolicy.Decide(m, "1.0.0", $"m{i}", UpdateRings.Standard, Now, []).Action == UpdateAction.Install);
        Assert.InRange(eligible, 140, 260);
    }

    [Fact]
    public void EarlyRingGetsAnyStartedRolloutAndDelayedWaitsAWeek()
    {
        var early = Manifest(Release("1.1.0", 1));
        Assert.Equal(UpdateAction.Install, RolloutPolicy.Decide(early, "1.0.0", "x", UpdateRings.Early, Now, []).Action);

        var justFull = Manifest(Release("1.1.0", 100, Now.AddDays(-2).ToString("o")));
        Assert.Equal(UpdateAction.None, RolloutPolicy.Decide(justFull, "1.0.0", "x", UpdateRings.Delayed, Now, []).Action);

        var soaked = Manifest(Release("1.1.0", 100, Now.AddDays(-8).ToString("o")));
        Assert.Equal(UpdateAction.Install, RolloutPolicy.Decide(soaked, "1.0.0", "x", UpdateRings.Delayed, Now, []).Action);
    }

    [Fact]
    public void HaltPauseAndLocalFailuresStopRollout()
    {
        Assert.Equal(UpdateAction.None, RolloutPolicy.Decide(Manifest(Release("1.1.0", 100)) with { HaltAll = true }, "1.0.0", "x", UpdateRings.Early, Now, []).Action);
        Assert.Equal(UpdateAction.None, RolloutPolicy.Decide(Manifest(Release("1.1.0", 100, paused: true)), "1.0.0", "x", UpdateRings.Early, Now, []).Action);
        Assert.Equal(UpdateAction.None, RolloutPolicy.Decide(Manifest(Release("1.1.0", 100)), "1.0.0", "x", UpdateRings.Early, Now, ["1.1.0"]).Action);
    }

    [Fact]
    public void RecalledVersionMovesToNewestFullyRolledOutRelease()
    {
        var m = Manifest(Release("1.0.0", 100), Release("1.1.0", 100), Release("1.2.0", 5)) with { BlockedVersions = ["1.2.0"] };
        var decision = RolloutPolicy.Decide(m, "1.2.0", "x", UpdateRings.Standard, Now, []);
        Assert.Equal(UpdateAction.Recall, decision.Action);
        Assert.Equal("1.1.0", decision.Release!.Version);
    }

    [Fact]
    public void HealthGateRollsBackAfterRepeatedCrashes()
    {
        using var dir = new TempDir();
        var gate = new UpdateHealthGate(dir.File("update.json"));
        gate.BeginInstall("1.0.0", "1.1.0", @"C:\cache\1.0.0.msi", Now);

        for (var i = 0; i < UpdateHealthGate.MaxStartsBeforeRollback; i++)
        {
            Assert.Equal(GateAction.Probation, new UpdateHealthGate(dir.File("update.json")).OnServiceStart("1.1.0", Now).Action);
        }
        var rollback = new UpdateHealthGate(dir.File("update.json")).OnServiceStart("1.1.0", Now);
        Assert.Equal(GateAction.Rollback, rollback.Action);
        Assert.Equal(@"C:\cache\1.0.0.msi", rollback.Package);

        var after = new UpdateHealthGate(dir.File("update.json"));
        var done = after.OnServiceStart("1.0.0", Now);
        Assert.Equal(GateAction.RolledBack, done.Action);
        Assert.Contains("1.1.0", after.State.FailedVersions);
        Assert.Equal(GateAction.None, after.OnServiceStart("1.0.0", Now).Action);
    }

    [Fact]
    public void HealthGateVerifiesAfterProbation()
    {
        using var dir = new TempDir();
        var gate = new UpdateHealthGate(dir.File("update.json"));
        gate.BeginInstall("1.0.0", "1.1.0", null, Now);
        Assert.Equal(GateAction.Probation, gate.OnServiceStart("1.1.0", Now).Action);
        var verified = gate.MarkHealthy();
        Assert.Equal(GateAction.Verified, verified.Action);
        Assert.Equal("1.0.0", verified.PreviousVersion);
        Assert.Null(gate.State.PendingVersion);
    }

    [Fact]
    public void HealthGateReportsInstallerThatNeverCompleted()
    {
        using var dir = new TempDir();
        var gate = new UpdateHealthGate(dir.File("update.json"));
        gate.BeginInstall("1.0.0", "1.1.0", null, Now);
        Assert.Equal(GateAction.None, gate.OnServiceStart("1.0.0", Now.AddMinutes(5)).Action);
        Assert.Equal(GateAction.InstallFailed, gate.OnServiceStart("1.0.0", Now.AddHours(1)).Action);
        Assert.Contains("1.1.0", gate.State.FailedVersions);
    }
}
