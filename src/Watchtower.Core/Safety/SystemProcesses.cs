namespace Watchtower.Core.Safety;

public static class SystemProcesses
{
    /// <summary>Ending any of these crashes Windows or signs everyone out.</summary>
    public static readonly HashSet<string> Critical = new(StringComparer.OrdinalIgnoreCase)
    {
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
        "lsaiso.exe", "fontdrvhost.exe", "memory compression", "registry", "system",
    };

    public static readonly HashSet<string> Security = new(StringComparer.OrdinalIgnoreCase)
    {
        "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
        "mpdefendercoreservice.exe", "smartscreen.exe",
    };

    /// <summary>Genuine Windows processes that can be ended, with what the user will notice.</summary>
    public static readonly Dictionary<string, string> Important = new(StringComparer.OrdinalIgnoreCase)
    {
        ["explorer.exe"] = "will make the taskbar and desktop disappear until it restarts",
        ["svchost.exe"] = "can stop several Windows services at once (networking, audio, updates)",
        ["dwm.exe"] = "will make the screen flicker or go black briefly",
        ["sihost.exe"] = "can break the Start menu and notifications until you sign in again",
        ["spoolsv.exe"] = "will stop printing",
        ["audiodg.exe"] = "will cut sound until an app restarts audio",
        ["ctfmon.exe"] = "can break typing in some apps",
        ["runtimebroker.exe"] = "can make Store apps misbehave",
    };

    /// <summary>Where each well-known Windows executable genuinely lives, relative to %SystemRoot%.</summary>
    private static readonly Dictionary<string, string[]> Locations = new(StringComparer.OrdinalIgnoreCase)
    {
        ["smss.exe"] = [@"System32"],
        ["csrss.exe"] = [@"System32"],
        ["wininit.exe"] = [@"System32"],
        ["winlogon.exe"] = [@"System32"],
        ["services.exe"] = [@"System32"],
        ["lsass.exe"] = [@"System32"],
        ["lsaiso.exe"] = [@"System32"],
        ["svchost.exe"] = [@"System32", @"SysWOW64"],
        ["dwm.exe"] = [@"System32"],
        ["sihost.exe"] = [@"System32"],
        ["spoolsv.exe"] = [@"System32"],
        ["taskhostw.exe"] = [@"System32"],
        ["conhost.exe"] = [@"System32"],
        ["rundll32.exe"] = [@"System32", @"SysWOW64"],
        ["dllhost.exe"] = [@"System32", @"SysWOW64"],
        ["ctfmon.exe"] = [@"System32", @"SysWOW64"],
        ["audiodg.exe"] = [@"System32"],
        ["fontdrvhost.exe"] = [@"System32"],
        ["runtimebroker.exe"] = [@"System32"],
        ["explorer.exe"] = [@"", @"SysWOW64"],
    };

    public static string? ExpectedLocation(string name, string systemRoot) =>
        Locations.TryGetValue(name, out var dirs)
            ? dirs[0].Length == 0 ? systemRoot : systemRoot.TrimEnd('\\') + "\\" + dirs[0]
            : null;

    // Windows paths are handled as strings so this logic behaves the same when tested off Windows.
    /// <summary>Drops the \\?\ and \??\ prefixes Windows uses in long and kernel-style paths (conhost's command line starts with \??\).</summary>
    public static string StripNtPrefix(string path) =>
        path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal) ? path[4..] : path;

    public static string WinDirectoryName(string path)
    {
        var p = path.Replace('/', '\\');
        var i = p.LastIndexOf('\\');
        return i < 0 ? "" : p[..i];
    }

    public static string WinFileName(string path)
    {
        var p = path.Replace('/', '\\');
        return p[(p.LastIndexOf('\\') + 1)..];
    }

    /// <summary>True when a process with a Windows system name runs from where Windows keeps it.</summary>
    public static bool IsGenuine(string name, string? path, string systemRoot)
    {
        if (path is null) return name.Equals("System", StringComparison.OrdinalIgnoreCase)
                                 || name.Equals("Registry", StringComparison.OrdinalIgnoreCase)
                                 || name.Equals("Memory Compression", StringComparison.OrdinalIgnoreCase);
        var dir = Normalize(WinDirectoryName(path));
        var root = Normalize(systemRoot);

        if (Locations.TryGetValue(name, out var dirs))
        {
            return dirs.Any(d => dir == Normalize(d.Length == 0 ? root : root + "\\" + d));
        }
        return dir.StartsWith(root + "\\", StringComparison.Ordinal) || dir == root;
    }

    /// <summary>
    /// A process named like a core Windows file but running from anywhere else is a
    /// classic disguise. Returns the real location when that's the case.
    /// </summary>
    public static string? Masquerade(string name, string? path, string systemRoot)
    {
        if (path is null || !Locations.ContainsKey(name)) return null;
        return IsGenuine(name, path, systemRoot) ? null : ExpectedLocation(name, systemRoot);
    }

    private static string Normalize(string p)
    {
        p = StripNtPrefix(p.Replace('/', '\\').TrimEnd('\\')).ToLowerInvariant();
        return p;
    }
}
