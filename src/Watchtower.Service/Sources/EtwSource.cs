using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Watchtower.Service.Sources;

public abstract record EngineEvent;
public sealed record ProcessStarted(int Pid, int ParentPid, string ImageName, string? CommandLine) : EngineEvent;
public sealed record ProcessStopped(int Pid) : EngineEvent;
public sealed record TcpEvent(int Pid, string RemoteAddress, int RemotePort, int LocalPort, bool Inbound) : EngineEvent;

/// <summary>
/// Real-time kernel events via ETW: every process launch and every TCP connect or
/// accept, as they happen. Nothing short-lived slips between polls, and the cost is
/// a fraction of repeatedly spawning PowerShell. Handlers only enqueue; all work
/// happens on the engine's consumer so a slow check can never stall the kernel buffers.
/// </summary>
public sealed class EtwSource : IDisposable
{
    public const string SessionName = "Watchtower-Kernel";

    private readonly ChannelWriter<EngineEvent> _writer;
    private readonly ILogger _log;
    private TraceEventSession? _session;
    private Thread? _thread;

    public EtwSource(ChannelWriter<EngineEvent> writer, ILogger log)
    {
        _writer = writer;
        _log = log;
    }

    public bool IsLive { get; private set; }
    public string? FailureReason { get; private set; }
    public long EventsSeen;

    public event Action<string>? Stopped;

    public bool Start()
    {
        try
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                FailureReason = "Watchtower isn't running with the rights needed for real-time monitoring.";
                return false;
            }

            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.NetworkTCPIP);

            var kernel = _session.Source.Kernel;
            kernel.ProcessStart += OnProcessStart;
            kernel.ProcessStop += d => Write(new ProcessStopped(d.ProcessID));
            kernel.TcpIpConnect += d => Write(new TcpEvent(d.ProcessID, d.daddr.ToString(), d.dport, d.sport, false));
            kernel.TcpIpConnectIPV6 += d => Write(new TcpEvent(d.ProcessID, Normalize(d.daddr), d.dport, d.sport, false));
            kernel.TcpIpAccept += d => Write(new TcpEvent(d.ProcessID, d.daddr.ToString(), d.dport, d.sport, true));
            kernel.TcpIpAcceptIPV6 += d => Write(new TcpEvent(d.ProcessID, Normalize(d.daddr), d.dport, d.sport, true));

            _thread = new Thread(Pump) { IsBackground = true, Name = "etw-kernel" };
            _thread.Start();
            IsLive = true;
            FailureReason = null;
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or System.Runtime.InteropServices.COMException or ArgumentException)
        {
            // Windows allows only a few kernel trace sessions at once; another tool may hold them all.
            FailureReason = $"Real-time sensor couldn't start ({ex.Message}).";
            _log.LogWarning(ex, "ETW kernel session failed to start");
            _session?.Dispose();
            _session = null;
            return false;
        }
    }

    private void OnProcessStart(ProcessTraceData d) =>
        Write(new ProcessStarted(d.ProcessID, d.ParentID, d.ImageFileName, d.CommandLine));

    private void Write(EngineEvent e)
    {
        Interlocked.Increment(ref EventsSeen);
        _writer.TryWrite(e);
    }

    private void Pump()
    {
        try
        {
            _session!.Source.Process();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "ETW processing stopped");
        }
        finally
        {
            var wasLive = IsLive;
            IsLive = false;
            if (wasLive) Stopped?.Invoke("The real-time sensor stopped unexpectedly.");
        }
    }

    private static string Normalize(System.Net.IPAddress ip) => (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();

    public void Dispose()
    {
        IsLive = false;
        _session?.Dispose();
        _session = null;
    }
}
