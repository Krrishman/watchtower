using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Watchtower.Core.Ipc;

namespace Watchtower.Core.Tests;

public class RpcTests
{
    private static readonly Caller User = new("PC\\kid", IsAdministrator: false, SessionId: 1, ProcessId: 10);
    private static readonly Caller Admin = new("PC\\parent", IsAdministrator: true, SessionId: 1, ProcessId: 11);

    private static RpcDispatcher Dispatcher()
    {
        var d = new RpcDispatcher();
        d.Register("ping", Access.Read, (_, _) => "pong");
        d.Register("echo", Access.Read, (_, a) => Args.Str(a, "text"));
        d.Register("kill", Access.Act, (c, a) => $"{c.UserName} killed {Args.Int(a, "pid")}");
        d.Register("boom", Access.Read, (_, _) => throw new RpcException(RpcErrors.Denied, "Not allowed: protected."));
        d.Register("guard", Access.Read, (_, _) => Watchtower.Core.Safety.GuardDecision.Deny("nope"));
        return d;
    }

    [Fact]
    public void EnumsAreSentByName() =>
        Assert.Equal("Deny", Handle("{\"id\":9,\"method\":\"guard\"}", User).GetProperty("result").GetProperty("verdict").GetString());

    private static JsonElement Handle(string line, Caller caller) =>
        JsonDocument.Parse(Dispatcher().HandleAsync(line, caller, CancellationToken.None).Result).RootElement;

    [Fact]
    public void ReadMethodsWorkForEveryone()
    {
        var r = Handle("{\"id\":1,\"method\":\"ping\"}", User);
        Assert.Equal(1, r.GetProperty("id").GetInt32());
        Assert.Equal("pong", r.GetProperty("result").GetString());
    }

    [Fact]
    public void ActMethodsRequireAdministrator()
    {
        Assert.Equal("forbidden", Handle("{\"id\":2,\"method\":\"kill\",\"params\":{\"pid\":5}}", User).GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("PC\\parent killed 5", Handle("{\"id\":2,\"method\":\"kill\",\"params\":{\"pid\":5}}", Admin).GetProperty("result").GetString());
    }

    [Theory]
    [InlineData("not json", "bad_request")]
    [InlineData("[1,2]", "bad_request")]
    [InlineData("{\"id\":3}", "bad_request")]
    [InlineData("{\"id\":3,\"method\":\"nope\"}", "unknown_method")]
    [InlineData("{\"id\":3,\"method\":\"echo\",\"params\":{}}", "bad_request")]
    [InlineData("{\"id\":3,\"method\":\"boom\"}", "denied")]
    public void ErrorsAreStructured(string line, string code) =>
        Assert.Equal(code, Handle(line, Admin).GetProperty("error").GetProperty("code").GetString());

    [Fact]
    public async Task ConnectionRoundTripsOverAStreamAndPushesEvents()
    {
        var pipeName = "wt-test-" + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await Task.WhenAll(server.WaitForConnectionAsync(), client.ConnectAsync());

        await using var connection = new RpcConnection(server, Dispatcher(), User);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var run = connection.RunAsync(cts.Token);

        await client.WriteAsync(Encoding.UTF8.GetBytes("{\"id\":7,\"method\":\"echo\",\"params\":{\"text\":\"héllo\"}}\n"), cts.Token);
        var reader = new LineReader(client, 1 << 20);
        var reply = JsonDocument.Parse((await reader.ReadLineAsync(cts.Token))!).RootElement;
        Assert.Equal("héllo", reply.GetProperty("result").GetString());

        await connection.SendEventAsync("alert", new { title = "x" }, cts.Token);
        var evt = JsonDocument.Parse((await reader.ReadLineAsync(cts.Token))!).RootElement;
        Assert.Equal("alert", evt.GetProperty("event").GetString());

        client.Close();
        await run;
    }

    [Fact]
    public async Task OversizedMessagesAreRefused()
    {
        var stream = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 5000) + "\n"));
        await Assert.ThrowsAsync<InvalidDataException>(() => new LineReader(stream, 1000).ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task LineReaderHandlesSplitAndMultipleLines()
    {
        var stream = new MemoryStream(Encoding.UTF8.GetBytes("a\r\nbé\n\nc"));
        var reader = new LineReader(stream, 100);
        Assert.Equal("a", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("bé", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
    }
}
