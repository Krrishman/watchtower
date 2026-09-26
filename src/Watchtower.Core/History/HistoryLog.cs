using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Watchtower.Core.History;

public sealed record HistoryEntry
{
    public int V { get; init; } = 2;
    public long Seq { get; init; }
    public required string Id { get; init; }
    public required string Time { get; init; }
    public required string Kind { get; init; }
    public required string Source { get; init; }
    public required string Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public Dictionary<string, string> Subject { get; init; } = new(StringComparer.Ordinal);
    public string? SuppressedBy { get; init; }
    public string PrevHash { get; init; } = "";
    public string Hash { get; init; } = "";

    internal string ComputeHash()
    {
        var payload = CanonicalJson.Serialize(new Dictionary<string, object?>
        {
            ["v"] = V,
            ["seq"] = Seq,
            ["id"] = Id,
            ["time"] = Time,
            ["kind"] = Kind,
            ["source"] = Source,
            ["severity"] = Severity,
            ["title"] = Title,
            ["detail"] = Detail,
            ["subject"] = (IReadOnlyDictionary<string, string>)Subject,
            ["suppressedBy"] = SuppressedBy,
            ["prevHash"] = PrevHash,
        });
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }
}

public sealed record HistoryQuery
{
    public int Limit { get; init; } = 500;
    public string? Source { get; init; }
    public string? Kind { get; init; }
    public string? Since { get; init; }
    public bool IncludeSuppressed { get; init; } = true;
}

public sealed record VerifyResult(bool Ok, int Checked, string Message, bool Unverifiable = false, long? BrokenAtSeq = null);

/// <summary>
/// Append-only, hash-chained log. Each entry commits to the one before it, a
/// separate high-water mark catches deletion of the newest entries, and an
/// anchor lets intentional trimming keep verifying. Tampering becomes
/// detectable, not impossible; the off-machine copy is what preserves the original.
/// </summary>
public sealed class HistoryLog
{
    public const string LogFileName = "history.jsonl";
    public const string AnchorFileName = "history-anchor.json";
    public const string HighWaterFileName = "history-highwater.json";
    public static readonly string[] AllFiles = [LogFileName, AnchorFileName, HighWaterFileName];

    private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";
    private const int CacheSize = 5000;

    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly object _gate = new();
    private readonly string _dir;
    private readonly int _maxEntries;
    private readonly LinkedList<HistoryEntry> _recent = new();
    private (long Seq, string Hash)? _tail;
    private bool _cacheComplete;

    public HistoryLog(string directory, int maxEntries = 50_000)
    {
        _dir = directory;
        _maxEntries = maxEntries;
        Directory.CreateDirectory(_dir);
    }

    public string DirectoryPath => _dir;
    private string LogPath => Path.Combine(_dir, LogFileName);
    private string AnchorPath => Path.Combine(_dir, AnchorFileName);
    private string HighWaterPath => Path.Combine(_dir, HighWaterFileName);

    public HistoryEntry Append(HistoryEntry draft)
    {
        lock (_gate)
        {
            var (prevSeq, prevHash) = LoadTail();
            var entry = draft with { V = 2, Seq = prevSeq + 1, PrevHash = prevHash, Hash = "" };
            entry = entry with { Hash = entry.ComputeHash() };

            var line = JsonSerializer.Serialize(entry, Json) + "\n";
            using (var fs = new FileStream(LogPath, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                var bytes = Encoding.UTF8.GetBytes(line);
                fs.Write(bytes);
                fs.Flush(flushToDisk: true);
            }

            _tail = (entry.Seq, entry.Hash);
            WriteSmallFile(HighWaterPath, JsonSerializer.Serialize(new { seq = entry.Seq, hash = entry.Hash }));
            _recent.AddLast(entry);
            if (_recent.Count > CacheSize)
            {
                _recent.RemoveFirst();
                _cacheComplete = false;
            }
            return entry;
        }
    }

    public IReadOnlyList<HistoryEntry> Read(HistoryQuery query)
    {
        lock (_gate)
        {
            LoadTail();
            var fromCache = Filter(_recent, query).Reverse().Take(query.Limit).ToList();
            if (_cacheComplete || fromCache.Count >= query.Limit) return fromCache;
            return Filter(ReadAllEntries(), query).Reverse().Take(query.Limit).ToList();
        }
    }

    private static IEnumerable<HistoryEntry> Filter(IEnumerable<HistoryEntry> entries, HistoryQuery q) =>
        entries.Where(e =>
            (q.Source is null || e.Source == q.Source) &&
            (q.Kind is null || e.Kind == q.Kind) &&
            (q.Since is null || string.CompareOrdinal(e.Time, q.Since) >= 0) &&
            (q.IncludeSuppressed || e.SuppressedBy is null));

    public VerifyResult Verify()
    {
        lock (_gate)
        {
            var lines = ReadLines();
            if (lines.Count == 0) return new VerifyResult(true, 0, "No history recorded yet.");

            var (anchorSeq, anchorHash) = ReadAnchor();
            var prevHash = anchorHash;
            var expectedSeq = anchorSeq + 1;

            for (var i = 0; i < lines.Count; i++)
            {
                HistoryEntry? e;
                try
                {
                    e = JsonSerializer.Deserialize<HistoryEntry>(lines[i], Json);
                }
                catch (JsonException)
                {
                    e = null;
                }
                if (e is null || e.Hash.Length == 0)
                {
                    return new VerifyResult(false, i, $"Line {i + 1} of the log is unreadable. It was damaged or edited by hand.", BrokenAtSeq: expectedSeq);
                }
                if (e.V != 2)
                {
                    return new VerifyResult(false, i, $"Entry {i + 1} uses an unknown format and can't be verified.", Unverifiable: true, BrokenAtSeq: e.Seq);
                }
                if (e.Seq != expectedSeq)
                {
                    return new VerifyResult(false, i, $"Entries are missing: expected #{expectedSeq} but found #{e.Seq}. Something was deleted from the middle of the log.", BrokenAtSeq: expectedSeq);
                }
                if (e.PrevHash != prevHash)
                {
                    return new VerifyResult(false, i, $"The link before entry #{e.Seq} ({e.Time}) is broken. An earlier entry was changed or removed.", BrokenAtSeq: e.Seq);
                }
                if (e.ComputeHash() != e.Hash)
                {
                    return new VerifyResult(false, i, $"Entry #{e.Seq} ({e.Time}) was modified after it was written.", BrokenAtSeq: e.Seq);
                }
                prevHash = e.Hash;
                expectedSeq++;
            }

            var lastSeq = expectedSeq - 1;
            var highWater = ReadHighWater();
            if (highWater > lastSeq)
            {
                return new VerifyResult(false, lines.Count,
                    $"The log ends at entry #{lastSeq}, but entries up to #{highWater} were written. The {highWater - lastSeq} most recent entries were deleted.",
                    BrokenAtSeq: lastSeq + 1);
            }

            return new VerifyResult(true, lines.Count, $"All {lines.Count} entries verified. No signs of tampering.");
        }
    }

    public void TrimIfNeeded()
    {
        lock (_gate)
        {
            var lines = ReadLines();
            if (lines.Count <= _maxEntries) return;

            var kept = lines.Skip(lines.Count - _maxEntries / 2).ToList();
            var first = JsonSerializer.Deserialize<HistoryEntry>(kept[0], Json);
            if (first is not null)
            {
                // Trimming discards the start of the chain; the anchor records where the
                // retained part begins so verification doesn't report the trim as tampering.
                WriteSmallFile(AnchorPath, JsonSerializer.Serialize(new { seq = first.Seq - 1, hash = first.PrevHash }));
            }
            var tmp = LogPath + ".tmp";
            File.WriteAllText(tmp, string.Join("\n", kept) + "\n", Encoding.UTF8);
            File.Move(tmp, LogPath, overwrite: true);
            _tail = null;
        }
    }

    public int Export(string path, string format, HistoryQuery query)
    {
        List<HistoryEntry> entries;
        lock (_gate)
        {
            entries = Filter(ReadAllEntries(), query with { Limit = int.MaxValue }).ToList();
        }

        if (format == "json")
        {
            File.WriteAllText(path, JsonSerializer.Serialize(entries, new JsonSerializerOptions(Json) { WriteIndented = true }), Encoding.UTF8);
            return entries.Count;
        }

        var sb = new StringBuilder();
        sb.Append("seq,time,severity,kind,source,title,detail,suppressedBy,hash\r\n");
        foreach (var e in entries)
        {
            sb.AppendJoin(',', new[] { e.Seq.ToString(), e.Time, e.Severity, e.Kind, e.Source, e.Title, e.Detail, e.SuppressedBy ?? "", e.Hash }.Select(Csv));
            sb.Append("\r\n");
        }
        // BOM so Excel reads UTF-8 paths and names correctly.
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        return entries.Count;
    }

    internal static string Csv(string value)
    {
        // A leading =, +, - or @ makes Excel evaluate the cell as a formula; alert
        // text includes attacker-influenced names, so neutralize it.
        if (value.Length > 0 && "=+-@\t\r".Contains(value[0])) value = "'" + value;
        return value.IndexOfAny(['"', ',', '\n', '\r']) >= 0 ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }

    private (long Seq, string Hash) LoadTail()
    {
        if (_tail is { } tail) return tail;
        _recent.Clear();
        var entries = ReadAllEntries();
        foreach (var e in entries.TakeLast(CacheSize)) _recent.AddLast(e);
        _cacheComplete = entries.Count <= CacheSize;
        if (entries.Count == 0)
        {
            var anchor = ReadAnchor();
            var hw = ReadHighWaterFull();
            // If the log is empty but entries were written before, continue the
            // sequence so the gap stays visible to Verify rather than restarting at 1.
            _tail = hw.Seq > anchor.Seq ? hw : anchor;
        }
        else
        {
            var last = entries[^1];
            _tail = (last.Seq, last.Hash);
        }
        return _tail.Value;
    }

    private List<string> ReadLines()
    {
        try
        {
            using var fs = new FileStream(LogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs, Encoding.UTF8);
            var lines = new List<string>();
            while (reader.ReadLine() is { } line)
            {
                if (line.Length > 0) lines.Add(line);
            }
            return lines;
        }
        catch (FileNotFoundException)
        {
            return [];
        }
    }

    private List<HistoryEntry> ReadAllEntries()
    {
        var result = new List<HistoryEntry>();
        foreach (var line in ReadLines())
        {
            try
            {
                if (JsonSerializer.Deserialize<HistoryEntry>(line, Json) is { } e) result.Add(e);
            }
            catch (JsonException)
            {
                // Unreadable lines are reported by Verify, not here.
            }
        }
        return result;
    }

    private (long Seq, string Hash) ReadAnchor()
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(AnchorPath));
            return (doc.RootElement.GetProperty("seq").GetInt64(), doc.RootElement.GetProperty("hash").GetString() ?? Genesis);
        }
        catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return (0, Genesis);
        }
    }

    private long ReadHighWater() => ReadHighWaterFull().Seq;

    private (long Seq, string Hash) ReadHighWaterFull()
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(HighWaterPath));
            var hash = doc.RootElement.TryGetProperty("hash", out var h) ? h.GetString() ?? Genesis : Genesis;
            return (doc.RootElement.GetProperty("seq").GetInt64(), hash);
        }
        catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return (0, Genesis);
        }
    }

    private static void WriteSmallFile(string path, string content)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content, Encoding.UTF8);
        File.Move(tmp, path, overwrite: true);
    }
}
