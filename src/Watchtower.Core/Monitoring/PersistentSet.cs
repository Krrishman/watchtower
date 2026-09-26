using System.Text.Json;

namespace Watchtower.Core.Monitoring;

/// <summary>
/// A remembered set of strings (baselines like "programs seen before"), saved in
/// batches rather than on every add. Bounded: the least recently seen entries are
/// dropped first so it can't grow without limit on busy machines.
/// </summary>
public sealed class PersistentSet
{
    private readonly string? _path;
    private readonly int _capacity;
    private readonly Dictionary<string, long> _lastSeen = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private long _clock;
    private bool _dirty;

    public PersistentSet(string? path, int capacity = 100_000)
    {
        _path = path;
        _capacity = capacity;
        if (path is not null && File.Exists(path))
        {
            try
            {
                foreach (var item in JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) ?? [])
                {
                    _lastSeen[item] = ++_clock;
                }
            }
            catch (Exception ex) when (ex is IOException or JsonException)
            {
                // Losing a baseline means some "first time" alerts repeat; never fatal.
            }
        }
    }

    public int Count
    {
        get { lock (_gate) return _lastSeen.Count; }
    }

    /// <summary>Records the item; returns true if it had never been seen before.</summary>
    public bool Add(string item)
    {
        lock (_gate)
        {
            var isNew = !_lastSeen.ContainsKey(item);
            _lastSeen[item] = ++_clock;
            _dirty |= isNew;
            if (_lastSeen.Count > _capacity) Prune();
            return isNew;
        }
    }

    public bool Contains(string item)
    {
        lock (_gate) return _lastSeen.ContainsKey(item);
    }

    public void Flush()
    {
        if (_path is null) return;
        List<string> snapshot;
        lock (_gate)
        {
            if (!_dirty) return;
            snapshot = _lastSeen.OrderBy(kv => kv.Value).Select(kv => kv.Key).ToList();
            _dirty = false;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(snapshot));
        File.Move(tmp, _path, overwrite: true);
    }

    private void Prune()
    {
        foreach (var key in _lastSeen.OrderBy(kv => kv.Value).Take(_capacity / 5).Select(kv => kv.Key).ToList())
        {
            _lastSeen.Remove(key);
        }
        _dirty = true;
    }
}
