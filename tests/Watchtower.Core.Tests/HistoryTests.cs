using System.Text.Json;
using Watchtower.Core.History;

namespace Watchtower.Core.Tests;

public class HistoryTests
{
    private static HistoryEntry Draft(int i, string source = "test") => new()
    {
        Id = $"id{i}",
        Time = $"2026-01-01T00:00:{i:00}Z",
        Kind = "rdp.session_active",
        Source = source,
        Severity = "info",
        Title = $"title {i}",
        Detail = "detail with \"quotes\", commas, ünïcödé and \n newline",
        Subject = new() { ["account"] = $"user{i}" },
    };

    [Fact]
    public void AppendedEntriesVerify()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 10; i++) log.Append(Draft(i));

        var result = log.Verify();
        Assert.True(result.Ok, result.Message);
        Assert.Equal(10, result.Checked);
    }

    [Fact]
    public void SequenceAndChainContinueAcrossInstances()
    {
        using var dir = new TempDir();
        new HistoryLog(dir.Path).Append(Draft(1));
        var second = new HistoryLog(dir.Path).Append(Draft(2));
        Assert.Equal(2, second.Seq);
        Assert.True(new HistoryLog(dir.Path).Verify().Ok);
    }

    [Fact]
    public void DetectsEditedEntry()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 5; i++) log.Append(Draft(i));

        var path = dir.File(HistoryLog.LogFileName);
        var lines = File.ReadAllLines(path);
        lines[2] = lines[2].Replace("title 2", "nothing to see");
        File.WriteAllLines(path, lines);

        var result = new HistoryLog(dir.Path).Verify();
        Assert.False(result.Ok);
        Assert.Equal(3, result.BrokenAtSeq);
        Assert.Contains("modified", result.Message);
    }

    [Fact]
    public void DetectsEditedSubject()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 3; i++) log.Append(Draft(i));

        var path = dir.File(HistoryLog.LogFileName);
        var lines = File.ReadAllLines(path);
        lines[1] = lines[1].Replace("user1", "someoneelse");
        File.WriteAllLines(path, lines);

        Assert.False(new HistoryLog(dir.Path).Verify().Ok);
    }

    [Fact]
    public void DetectsDeletionFromMiddle()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 5; i++) log.Append(Draft(i));

        var path = dir.File(HistoryLog.LogFileName);
        var lines = File.ReadAllLines(path).ToList();
        lines.RemoveAt(2);
        File.WriteAllLines(path, lines);

        var result = new HistoryLog(dir.Path).Verify();
        Assert.False(result.Ok);
        Assert.Contains("missing", result.Message);
    }

    [Fact]
    public void DetectsTailTruncation()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 5; i++) log.Append(Draft(i));

        var path = dir.File(HistoryLog.LogFileName);
        File.WriteAllLines(path, File.ReadAllLines(path).Take(3));

        var result = new HistoryLog(dir.Path).Verify();
        Assert.False(result.Ok);
        Assert.Contains("2 most recent entries were deleted", result.Message);
    }

    [Fact]
    public void AppendAfterWipeKeepsSequenceSoGapIsVisible()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 3; i++) log.Append(Draft(i));
        File.Delete(dir.File(HistoryLog.LogFileName));

        var next = new HistoryLog(dir.Path).Append(Draft(9));
        Assert.Equal(4, next.Seq);
    }

    [Fact]
    public void TrimKeepsChainVerifiable()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path, maxEntries: 10);
        for (var i = 0; i < 25; i++) log.Append(Draft(i));
        log.TrimIfNeeded();

        Assert.Equal(5, File.ReadAllLines(dir.File(HistoryLog.LogFileName)).Length);
        var result = log.Verify();
        Assert.True(result.Ok, result.Message);
        Assert.Equal(26, log.Append(Draft(99)).Seq);
        Assert.True(log.Verify().Ok);
    }

    [Fact]
    public void ReadReturnsNewestFirstWithFilters()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 6; i++) log.Append(Draft(i, i % 2 == 0 ? "even" : "odd"));

        var odd = log.Read(new HistoryQuery { Source = "odd", Limit = 2 });
        Assert.Equal(["id5", "id3"], odd.Select(e => e.Id));
    }

    [Fact]
    public void CsvExportNeutralizesFormulas()
    {
        Assert.Equal("'=cmd|' /C calc'!A0", HistoryLog.Csv("=cmd|' /C calc'!A0"));
        Assert.Equal("\"a,b\"", HistoryLog.Csv("a,b"));
        Assert.Equal("plain", HistoryLog.Csv("plain"));
    }

    [Fact]
    public void JsonExportRoundTripsAndIncludesHashes()
    {
        using var dir = new TempDir();
        var log = new HistoryLog(dir.Path);
        for (var i = 0; i < 3; i++) log.Append(Draft(i));
        var outFile = dir.File("export.json");

        Assert.Equal(3, log.Export(outFile, "json", new HistoryQuery()));
        var entries = JsonSerializer.Deserialize<List<HistoryEntry>>(File.ReadAllText(outFile), HistoryLog.Json)!;
        Assert.All(entries, e => Assert.Equal(e.ComputeHash(), e.Hash));
    }

    [Fact]
    public void CanonicalJsonMatchesJavaScriptStringify()
    {
        var json = CanonicalJson.Serialize(new Dictionary<string, object?>
        {
            ["b"] = "x\"y\\z\n\u0001é😀",
            ["a"] = 5L,
            ["skip"] = null,
            ["c"] = (IReadOnlyDictionary<string, string>)new Dictionary<string, string> { ["z"] = "1", ["y"] = "2" },
        });
        Assert.Equal("{\"a\":5,\"b\":\"x\\\"y\\\\z\\n\\u0001é😀\",\"c\":{\"y\":\"2\",\"z\":\"1\"}}", json);
    }
}
