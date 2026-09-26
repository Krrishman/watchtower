using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Watchtower.Core.Ipc;

public enum Access
{
    /// <summary>Any signed-in user of this PC may call it.</summary>
    Read,
    /// <summary>Changes the system or Watchtower's configuration: caller must be an administrator account.</summary>
    Act,
}

/// <summary>Who is on the other end of the pipe, as established by the transport (never by the client's own claims).</summary>
public sealed record Caller(string UserName, bool IsAdministrator, int SessionId, int ProcessId);

public sealed class RpcException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;

    public static RpcException BadRequest(string message) => new(RpcErrors.BadRequest, message);
}

public static class RpcErrors
{
    public const string BadRequest = "bad_request";
    public const string UnknownMethod = "unknown_method";
    public const string Forbidden = "forbidden";
    public const string Denied = "denied";
    public const string Failed = "failed";
}

public delegate Task<object?> RpcHandler(Caller caller, JsonElement args, CancellationToken ct);

/// <summary>
/// Newline-delimited JSON request/response plus server-pushed events:
/// → {"id":1,"method":"history.get","params":{...}}
/// ← {"id":1,"result":...} | {"id":1,"error":{"code":"...","message":"..."}}
/// ← {"event":"alert","data":{...}}
/// </summary>
public sealed class RpcDispatcher
{
    public const int ProtocolVersion = 1;
    public const int MaxMessageBytes = 1024 * 1024;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly Dictionary<string, (Access Access, RpcHandler Handler)> _methods = new(StringComparer.Ordinal);

    public void Register(string method, Access access, RpcHandler handler) => _methods[method] = (access, handler);

    public void Register(string method, Access access, Func<Caller, JsonElement, object?> handler) =>
        Register(method, access, (caller, args, _) => Task.FromResult(handler(caller, args)));

    public IReadOnlyCollection<string> Methods => _methods.Keys;

    public async Task<string> HandleAsync(string line, Caller caller, CancellationToken ct)
    {
        JsonElement id = default;
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw RpcException.BadRequest("Request must be a JSON object.");
            if (root.TryGetProperty("id", out var idProp)) id = idProp.Clone();
            if (!root.TryGetProperty("method", out var m) || m.ValueKind != JsonValueKind.String) throw RpcException.BadRequest("Missing method.");
            var method = m.GetString()!;
            var args = root.TryGetProperty("params", out var p) ? p.Clone() : default;

            if (!_methods.TryGetValue(method, out var entry)) throw new RpcException(RpcErrors.UnknownMethod, $"Unknown method '{method}'.");
            if (entry.Access == Access.Act && !caller.IsAdministrator)
            {
                throw new RpcException(RpcErrors.Forbidden, "This needs an administrator account on this PC. Ask the PC's administrator to do it, or sign in as an administrator.");
            }

            var result = await entry.Handler(caller, args, ct).ConfigureAwait(false);
            return Serialize(new Dictionary<string, object?> { ["id"] = id, ["result"] = result });
        }
        catch (JsonException)
        {
            return Error(id, RpcErrors.BadRequest, "Request isn't valid JSON.");
        }
        catch (RpcException ex)
        {
            return Error(id, ex.Code, ex.Message);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or InvalidOperationException or KeyNotFoundException)
        {
            return Error(id, RpcErrors.BadRequest, ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Error(id, RpcErrors.Failed, ex.Message);
        }
    }

    public static string Event(string name, object? data) =>
        Serialize(new Dictionary<string, object?> { ["event"] = name, ["data"] = data });

    private static string Error(JsonElement id, string code, string message) =>
        Serialize(new Dictionary<string, object?> { ["id"] = id, ["error"] = new { code, message } });

    private static string Serialize(Dictionary<string, object?> value)
    {
        if (value.TryGetValue("id", out var id) && id is JsonElement { ValueKind: JsonValueKind.Undefined }) value["id"] = null;
        return JsonSerializer.Serialize(value, Json);
    }
}

public static class Args
{
    public static string Str(JsonElement args, string name)
    {
        if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s)
        {
            return s;
        }
        throw RpcException.BadRequest($"Missing '{name}'.");
    }

    public static string? OptStr(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static int Int(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.TryGetInt32(out var i)
            ? i
            : throw RpcException.BadRequest($"Missing number '{name}'.");

    public static int OptInt(JsonElement args, string name, int fallback) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.TryGetInt32(out var i) ? i : fallback;

    public static bool Bool(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? v.GetBoolean()
            : throw RpcException.BadRequest($"Missing true/false '{name}'.");

    public static bool OptBool(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
}

/// <summary>One client connection over any duplex stream (a named pipe in production, anything in tests).</summary>
public sealed class RpcConnection : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly RpcDispatcher _dispatcher;
    private readonly Caller _caller;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public RpcConnection(Stream stream, RpcDispatcher dispatcher, Caller caller)
    {
        _stream = stream;
        _dispatcher = dispatcher;
        _caller = caller;
    }

    public Caller Caller => _caller;

    public async Task RunAsync(CancellationToken ct)
    {
        var reader = new LineReader(_stream, RpcDispatcher.MaxMessageBytes);
        while (!ct.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null) return;
            if (line.Length == 0) continue;
            var response = await _dispatcher.HandleAsync(line, _caller, ct).ConfigureAwait(false);
            await WriteLineAsync(response, ct).ConfigureAwait(false);
        }
    }

    public Task SendEventAsync(string name, object? data, CancellationToken ct) => WriteLineAsync(RpcDispatcher.Event(name, data), ct);

    private async Task WriteLineAsync(string line, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(bytes, ct).ConfigureAwait(false);
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
        _writeLock.Dispose();
    }
}

/// <summary>Reads '\n'-terminated UTF-8 lines, refusing any line over the size cap so a local client can't exhaust memory.</summary>
public sealed class LineReader(Stream stream, int maxBytes)
{
    private readonly byte[] _buffer = new byte[16 * 1024];
    private readonly MemoryStream _pending = new();
    private int _start;
    private int _end;

    public async Task<string?> ReadLineAsync(CancellationToken ct)
    {
        while (true)
        {
            var nl = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
            if (nl >= 0)
            {
                _pending.Write(_buffer, _start, nl - _start);
                _start = nl + 1;
                if (_pending.Length > maxBytes) throw new InvalidDataException("Message too large.");
                var line = Encoding.UTF8.GetString(_pending.GetBuffer(), 0, (int)_pending.Length).TrimEnd('\r');
                _pending.SetLength(0);
                return line;
            }

            _pending.Write(_buffer, _start, _end - _start);
            _start = _end = 0;
            if (_pending.Length > maxBytes) throw new InvalidDataException("Message too large.");

            var read = await stream.ReadAsync(_buffer, ct).ConfigureAwait(false);
            if (read == 0) return null;
            _end = read;
        }
    }
}
