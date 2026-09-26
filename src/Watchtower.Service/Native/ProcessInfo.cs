using System.Collections.Concurrent;
using System.Diagnostics;
using static Watchtower.Service.Native.NativeMethods;

namespace Watchtower.Service.Native;

public sealed record ProcessRecord(int Pid, string Name, string? Path);

/// <summary>Process names and full paths via native calls, cached per PID for fast lookup from event handlers.</summary>
public sealed class ProcessInfo
{
    private readonly ConcurrentDictionary<int, ProcessRecord> _byPid = new();

    public static string? ImagePath(int pid)
    {
        if (pid is 0 or 4) return null;
        using var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle.IsInvalid) return null;
        var buffer = new char[32768];
        var size = buffer.Length;
        return QueryFullProcessImageNameW(handle, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
    }

    /// <summary>True when Windows would bugcheck if this process were terminated.</summary>
    public static bool IsOsCritical(int pid)
    {
        using var handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (handle.IsInvalid) return false;
        return NtQueryInformationProcess(handle, ProcessBreakOnTermination, out var critical, sizeof(int), out _) == 0 && critical != 0;
    }

    public ProcessRecord Remember(int pid, string name, string? path)
    {
        var record = new ProcessRecord(pid, name, path ?? ImagePath(pid));
        _byPid[pid] = record;
        return record;
    }

    public void Forget(int pid) => _byPid.TryRemove(pid, out _);

    public ProcessRecord Lookup(int pid)
    {
        if (_byPid.TryGetValue(pid, out var r)) return r;
        string name;
        try
        {
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName + ".exe";
        }
        catch (ArgumentException)
        {
            name = $"pid {pid}";
        }
        catch (InvalidOperationException)
        {
            name = $"pid {pid}";
        }
        return Remember(pid, name, null);
    }

    /// <summary>Full refresh of the running process list (cheap: no WMI, no PowerShell).</summary>
    public IReadOnlyList<ProcessRecord> Snapshot()
    {
        var list = new List<ProcessRecord>();
        var alive = new HashSet<int>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                alive.Add(p.Id);
                var name = p.Id switch { 0 => "Idle", 4 => "System", _ => p.ProcessName + ".exe" };
                if (p.ProcessName is "Registry" or "Memory Compression" or "Secure System") name = p.ProcessName;
                var existing = _byPid.TryGetValue(p.Id, out var r) && r.Name == name ? r : Remember(p.Id, name, null);
                list.Add(existing);
            }
        }
        foreach (var pid in _byPid.Keys.Where(k => !alive.Contains(k)).ToList()) _byPid.TryRemove(pid, out _);
        return list;
    }
}
