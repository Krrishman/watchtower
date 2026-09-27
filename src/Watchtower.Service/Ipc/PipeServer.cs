using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using Watchtower.Core.Ipc;
using Watchtower.Service.Engine;
using Watchtower.Service.Hosting;
using Watchtower.Service.Native;

namespace Watchtower.Service.Ipc;

/// <summary>
/// Local named pipe the UI talks to. Security properties:
/// - Only local interactive users may connect; network access to the pipe is denied.
/// - Users can't create instances of the pipe, and the first instance is created
///   exclusively, so another process can't impersonate the service while it runs.
/// - Who the caller is comes from their Windows token (via impersonation), never
///   from anything the client sends. Act methods require an administrator account.
/// </summary>
public sealed class PipeServer : BackgroundService, IEventSink
{
    private const int MaxConnections = 16;

    private readonly RpcDispatcher _dispatcher;
    private readonly string _pipeName;
    private readonly ILogger<PipeServer> _log;
    private readonly ConcurrentDictionary<Guid, RpcConnection> _connections = new();

    public PipeServer(RpcDispatcher dispatcher, IOptions<WatchtowerOptions> options, ILogger<PipeServer> log)
    {
        _dispatcher = dispatcher;
        _pipeName = options.Value.PipeName;
        _log = log;
    }

    public int ConnectionCount => _connections.Count;
    public bool Listening { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var first = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = Create(first);
                first = false;
                Listening = true;
            }
            catch (UnauthorizedAccessException ex)
            {
                // Someone else owns the pipe name: something is impersonating the service.
                _log.LogCritical(ex, "Pipe {Name} is already owned by another process", _pipeName);
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
                continue;
            }
            catch (IOException ex)
            {
                _log.LogWarning(ex, "Couldn't create pipe instance");
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync();
                break;
            }

            _ = Task.Run(() => ServeAsync(pipe, ct), ct);
        }
    }

    private NamedPipeServerStream Create(bool first)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        // Creating each further instance needs CreateNewInstance on the pipe. As a service this
        // is SYSTEM already; in console/test mode it's the admin running it. No one else gets it.
        using (var self = WindowsIdentity.GetCurrent())
        {
            security.AddAccessRule(new PipeAccessRule(self.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        }
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

        var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, MaxConnections, PipeTransmissionMode.Byte, options, 64 * 1024, 64 * 1024, security);
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        // The caller is identified after their first message: Windows refuses to let a pipe
        // server impersonate a client before it has read from the pipe (ERROR_CANNOT_IMPERSONATE).
        var id = Guid.NewGuid();
        var connection = new RpcConnection(pipe, _dispatcher, () => Identify(pipe));
        _connections[id] = connection;
        try
        {
            await connection.RunAsync(ct);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            if (connection.Caller is null) _log.LogWarning(ex, "Rejected pipe client whose identity couldn't be established");
        }
        catch (Exception ex) when (ex is InvalidDataException or OperationCanceledException or ObjectDisposedException)
        {
            // Client went away or sent garbage: just drop it.
        }
        finally
        {
            _connections.TryRemove(id, out _);
            await connection.DisposeAsync();
        }
    }

    private static Caller Identify(NamedPipeServerStream pipe)
    {
        string user = "";
        string sid = "";
        var admin = false;
        var session = -1;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            user = identity.Name;
            sid = identity.User?.Value ?? "";
            admin = TokenInfo.IsAdministratorAccount(identity);
            session = TokenInfo.SessionId(identity);
        });
        NativeMethods.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid);
        if (sid.Length == 0) throw new InvalidOperationException("Anonymous pipe client.");
        return new Caller(user, admin, session, pid, sid);
    }

    public void Broadcast(string name, object? data)
    {
        // Only clients that have identified themselves receive events.
        foreach (var (id, connection) in _connections.Where(c => c.Value.Caller is not null))
        {
            _ = SendAsync(id, connection, name, data);
        }
    }

    private async Task SendAsync(Guid id, RpcConnection connection, string name, object? data)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await connection.SendEventAsync(name, data, timeout.Token);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // A UI that stops reading is dropped rather than allowed to back up the service.
            if (_connections.TryRemove(id, out _)) await connection.DisposeAsync();
        }
    }
}
