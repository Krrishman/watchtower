using System.Text.Json;
using System.Text.Json.Serialization;

namespace Watchtower.Core.Config;

/// <summary>Small JSON document persisted with write-to-temp-then-rename so a crash never leaves a half-written file.</summary>
public sealed class JsonFileStore<T> where T : class, new()
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _path;
    private readonly object _gate = new();
    private T _value;

    public JsonFileStore(string path)
    {
        _path = path;
        _value = Load();
    }

    public T Value
    {
        get { lock (_gate) return _value; }
    }

    public T Update(Func<T, T> change)
    {
        lock (_gate)
        {
            var next = change(_value);
            Save(next);
            _value = next;
            return next;
        }
    }

    private T Load()
    {
        try
        {
            return JsonSerializer.Deserialize<T>(File.ReadAllText(_path), Options) ?? new T();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A missing or corrupt file must never stop monitoring; defaults are always safe.
            return new T();
        }
    }

    private void Save(T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, Options));
        File.Move(tmp, _path, overwrite: true);
    }
}
