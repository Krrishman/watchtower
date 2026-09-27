using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Watchtower.Core.Ipc;
using Watchtower.Service.Engine;
using Watchtower.Service.Ipc;
using Watchtower.Service.Native;

namespace Watchtower.Service.Hosting;

public sealed record SmokeTestOptions(int Seconds);

/// <summary>
/// Runs the real engine on a real Windows machine (CI) and checks the parts unit
/// tests can't: ETW delivers process and TCP events, WinVerifyTrust recognizes
/// catalog-signed system files, the TCP table and sessions read, and the pipe
/// answers with the caller's real identity.
/// </summary>
public sealed class SmokeTest(
    SmokeTestOptions smoke,
    WatchtowerEngine engine,
    PipeServer pipe,
    SignatureVerifier signatures,
    EngineContext ctx,
    IOptions<WatchtowerOptions> options,
    IHostApplicationLifetime lifetime,
    ILogger<SmokeTest> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Delay(TimeSpan.FromSeconds(5), ct);

        for (var i = 0; i < 3; i++)
        {
            using var p = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit 0") { UseShellExecute = false, CreateNoWindow = true });
            p?.WaitForExit();
        }
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, ct);
        }
        listener.Stop();

        var hello = await CallPipeAsync(options.Value.PipeName, "hello", ct);
        await Task.Delay(TimeSpan.FromSeconds(Math.Max(10, smoke.Seconds)), ct);

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var notepad = signatures.Check(Path.Combine(system32, "notepad.exe"));
        var kernel32 = signatures.Check(Path.Combine(system32, "kernel32.dll"));
        var self = signatures.Check(Environment.ProcessPath);

        var report = new
        {
            etwLive = engine.RealTimeProcesses,
            processStartsSeen = engine.ProcessStartsSeen,
            tcpEventsSeen = engine.TcpEventsSeen,
            sessions = engine.CurrentSessions.Count,
            processTable = engine.CurrentProcessTable.Count,
            networkRows = engine.CurrentNetwork.Count,
            startupItems = engine.CurrentStartup.Count,
            sensors = engine.Sensors(),
            notepad,
            kernel32,
            self,
            pipeListening = pipe.Listening,
            hello,
            historyVerify = ctx.History.Verify(),
            historyEntries = ctx.History.Read(new Core.History.HistoryQuery { Limit = 50 }).Select(e => $"{e.Severity} {e.Kind}: {e.Title} | {e.Detail}"),
        };
        Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions(RpcDispatcher.Json) { WriteIndented = true }));

        var failures = new List<string>();
        if (!report.etwLive) failures.Add("ETW kernel session is not live");
        if (report.processStartsSeen < 3) failures.Add("ETW did not report the test process launches");
        if (report.tcpEventsSeen < 1) failures.Add("ETW did not report the test TCP connection");
        if (report.processTable < 10) failures.Add("process table is nearly empty");
        if (notepad.Status != "Valid" || !notepad.IsMicrosoft) failures.Add($"notepad.exe signature not recognized ({notepad.Status}, {notepad.Signer})");
        if (!report.pipeListening) failures.Add("pipe server is not listening");
        if (hello is null || !hello.Contains("\"isAdmin\":true")) failures.Add($"pipe hello failed or caller not recognized as admin: {hello}");
        if (!report.historyVerify.Ok) failures.Add($"history does not verify: {report.historyVerify.Message}");
        // A clean CI machine has no disguised programs; any alert here is a false positive.
        foreach (var e in report.historyEntries.Where(e => e.Contains("program.masquerading"))) failures.Add($"false masquerade alert: {e}");

        foreach (var f in failures) log.LogError("SMOKE FAIL: {Failure}", f);
        Console.WriteLine(failures.Count == 0 ? "SMOKE TEST PASSED" : $"SMOKE TEST FAILED ({failures.Count})");
        Environment.ExitCode = failures.Count == 0 ? 0 : 1;
        lifetime.StopApplication();
    }

    private static async Task<string?> CallPipeAsync(string name, string method, CancellationToken ct)
    {
        try
        {
            await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Impersonation);
            await client.ConnectAsync(5000, ct);
            await client.WriteAsync(Encoding.UTF8.GetBytes($"{{\"id\":1,\"method\":\"{method}\"}}\n"), ct);
            var reader = new LineReader(client, 1 << 20);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            while (await reader.ReadLineAsync(timeout.Token) is { } line)
            {
                if (line.StartsWith("{\"id\":1", StringComparison.Ordinal)) return line;
            }
            return null;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException)
        {
            return $"error: {ex.Message}";
        }
    }
}
