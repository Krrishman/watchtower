using Watchtower.Core.Backup;
using Watchtower.Core.History;

namespace Watchtower.Core.Tests;

public class BackupTests
{
    [Fact]
    public void SyncCopiesVerifiableLogIntoPerMachineFolder()
    {
        using var dir = new TempDir();
        var historyDir = dir.File("history");
        var log = new HistoryLog(historyDir);
        log.Append(new HistoryEntry { Id = "1", Time = "t", Kind = "k", Source = "s", Severity = "info", Title = "a", Detail = "b" });
        var dest = dir.File("cloud");
        Directory.CreateDirectory(dest);

        var result = OffsiteBackup.Sync(historyDir, dest, "MY PC/1", DateTimeOffset.UtcNow);

        Assert.True(result.Ok, result.Error);
        Assert.EndsWith("watchtower-MY_PC_1", result.TargetDir);
        Assert.True(new HistoryLog(result.TargetDir!).Verify().Ok);
    }

    [Fact]
    public void MissingDestinationIsReportedPlainly()
    {
        using var dir = new TempDir();
        var result = OffsiteBackup.Sync(dir.Path, dir.File("gone"), "pc", DateTimeOffset.UtcNow);
        Assert.False(result.Ok);
        Assert.Contains("isn't reachable", result.Error);
    }
}
