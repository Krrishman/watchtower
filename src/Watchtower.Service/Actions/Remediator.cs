using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Watchtower.Core.Ipc;
using Watchtower.Core.Monitoring;
using Watchtower.Core.Safety;
using Watchtower.Service.Native;
using Watchtower.Service.Sources;

namespace Watchtower.Service.Actions;

/// <summary>
/// Carries out user-requested actions after the safety guard approves them. Targets
/// are always looked up in Watchtower's own current view (a PID that's running, a
/// startup entry from the last scan), never taken on the client's word, so the pipe
/// can't be used to delete arbitrary files or registry values as SYSTEM.
/// </summary>
public sealed class Remediator(ProcessInfo processes, SignatureVerifier signatures)
{
    private static readonly string SystemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public ProcessFacts Facts(int pid)
    {
        var record = processes.Lookup(pid);
        var sig = signatures.Check(record.Path);
        return new ProcessFacts
        {
            Pid = pid,
            Name = record.Name,
            Path = record.Path,
            IsOsCritical = ProcessInfo.IsOsCritical(pid),
            SignedByMicrosoft = sig.IsMicrosoft,
            IsWatchtower = pid == Environment.ProcessId ||
                           (record.Path?.StartsWith(AppContext.BaseDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ?? false),
        };
    }

    public GuardDecision CheckKill(int pid) => ActionGuard.CanKill(Facts(pid), SystemRoot);

    public string Kill(int pid)
    {
        var decision = CheckKill(pid);
        if (decision.Verdict == GuardVerdict.Deny) throw new RpcException(RpcErrors.Denied, decision.Reason);
        try
        {
            using var p = Process.GetProcessById(pid);
            var name = p.ProcessName;
            p.Kill(entireProcessTree: false);
            return name;
        }
        catch (ArgumentException)
        {
            throw new RpcException(RpcErrors.Failed, "That program has already closed.");
        }
        catch (Win32Exception ex)
        {
            throw new RpcException(RpcErrors.Failed, $"Windows wouldn't end it: {ex.Message}");
        }
    }

    public GuardDecision CheckDisconnect(int sessionId, Caller caller) =>
        ActionGuard.CanDisconnect(sessionId == Sessions.ConsoleSessionId, sessionId == caller.SessionId);

    public void Disconnect(int sessionId)
    {
        if (!Sessions.Read().Any(s => s.Id == sessionId)) throw new RpcException(RpcErrors.Failed, "That session has already ended.");
        try
        {
            Sessions.Logoff(sessionId);
        }
        catch (Win32Exception ex)
        {
            throw new RpcException(RpcErrors.Failed, $"Windows wouldn't sign that session out: {ex.Message}");
        }
    }

    public static NetworkFacts NetworkFacts()
    {
        var local = new List<string>();
        var gateways = new List<string>();
        var dns = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = nic.GetIPProperties();
            local.AddRange(props.UnicastAddresses.Select(a => a.Address.ToString()));
            gateways.AddRange(props.GatewayAddresses.Select(g => g.Address.ToString()));
            dns.AddRange(props.DnsAddresses.Select(d => d.ToString()));
        }
        return new NetworkFacts { LocalAddresses = local, Gateways = gateways, DnsServers = dns };
    }

    public GuardDecision CheckBlock(string address) => ActionGuard.CanBlock(address, NetworkFacts());

    public void Block(string address)
    {
        var decision = CheckBlock(address);
        if (decision.Verdict == GuardVerdict.Deny) throw new RpcException(RpcErrors.Denied, decision.Reason);
        var normalized = System.Net.IPAddress.Parse(address).ToString();
        try
        {
            FirewallManager.Block(normalized);
        }
        catch (COMException ex)
        {
            throw new RpcException(RpcErrors.Failed, $"Windows Firewall refused the rule: {ex.Message}");
        }
    }

    public static GuardDecision CheckRemoveStartup(StartupItem item)
    {
        if (item.IsService || item.Key.StartsWith("winlogon|", StringComparison.Ordinal))
        {
            return GuardDecision.Deny("Watchtower doesn't remove services or Windows shell settings. Removing the wrong one can stop Windows from starting. Uninstall the program it belongs to instead.");
        }
        return ActionGuard.CanRemoveStartup(new StartupFacts { Name = item.Name, Command = item.Command, Location = item.Location });
    }

    public static string RemoveStartup(StartupItem item)
    {
        var decision = CheckRemoveStartup(item);
        if (decision.Verdict == GuardVerdict.Deny) throw new RpcException(RpcErrors.Denied, decision.Reason);
        var parts = item.Key.Split('|');
        switch (parts[0])
        {
            case "run":
                RemoveRunValue(parts[1], parts[2]);
                return "removed it from the Run list";
            case "folder":
                var file = parts[1];
                var inStartupFolder = StartupScanner.AllStartupFolders().Any(f =>
                    string.Equals(Path.GetDirectoryName(file), f.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
                if (!inStartupFolder) throw new RpcException(RpcErrors.Denied, "That file isn't in a Startup folder.");
                File.Delete(file);
                return "deleted the Startup-folder shortcut";
            case "task":
                DisableTask(parts[1]);
                return "turned off the scheduled task";
            default:
                throw new RpcException(RpcErrors.Denied, "This kind of startup entry can't be removed from Watchtower.");
        }
    }

    private static void RemoveRunValue(string path, string valueName)
    {
        RegistryKey? baseKey;
        string sub;
        if (path.StartsWith(@"HKLM\", StringComparison.Ordinal))
        {
            baseKey = Registry.LocalMachine;
            sub = path[5..];
        }
        else if (path.StartsWith(@"HKU\", StringComparison.Ordinal))
        {
            var rest = path[4..];
            var slash = rest.IndexOf('\\');
            baseKey = UserHives.Open(rest[..slash], writable: false);
            sub = rest[(slash + 1)..];
        }
        else
        {
            throw new RpcException(RpcErrors.Denied, "Unrecognized registry location.");
        }
        if (!sub.Contains(@"\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)) throw new RpcException(RpcErrors.Denied, "That isn't a startup key.");

        try
        {
            using var key = baseKey?.OpenSubKey(sub, writable: true) ?? throw new RpcException(RpcErrors.Failed, "The startup entry is already gone.");
            key.DeleteValue(valueName, throwOnMissingValue: false);
        }
        finally
        {
            if (baseKey != Registry.LocalMachine) baseKey?.Dispose();
        }
    }

    private static void DisableTask(string taskPath)
    {
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
        try
        {
            service.Connect();
            var idx = taskPath.LastIndexOf('\\');
            dynamic folder = service.GetFolder(idx <= 0 ? "\\" : taskPath[..idx]);
            dynamic task = folder.GetTask(taskPath[(idx + 1)..]);
            task.Enabled = false;
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }
    }
}
