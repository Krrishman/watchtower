using System.Runtime.InteropServices;
using Microsoft.Win32;
using Watchtower.Core.Monitoring;

namespace Watchtower.Service.Sources;

/// <summary>
/// Everything that runs automatically: Run/RunOnce keys (machine and every user),
/// Startup folders, non-Microsoft scheduled tasks, services and drivers, and the
/// Winlogon shell hooks. Keys include the command, so changing an existing entry
/// to point somewhere else shows up as new.
/// </summary>
public static class StartupScanner
{
    private static readonly string[] RunKeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    public static IReadOnlyList<StartupItem> Scan(ILogger log)
    {
        var items = new List<StartupItem>();
        Try(log, "Run keys", () => ScanRunKeys(items));
        Try(log, "Startup folders", () => ScanFolders(items));
        Try(log, "Winlogon", () => ScanWinlogon(items));
        Try(log, "Services", () => ScanServices(items));
        Try(log, "Scheduled tasks", () => ScanTasks(items));
        return items;
    }

    private static void Try(ILogger log, string what, Action scan)
    {
        try
        {
            scan();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or COMException or InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            log.LogWarning(ex, "Startup scan of {What} failed", what);
        }
    }

    private static void ScanRunKeys(List<StartupItem> items)
    {
        foreach (var sub in RunKeys)
        {
            using var key = Registry.LocalMachine.OpenSubKey(sub);
            AddValues(items, key, $@"HKLM\{sub}", "Starts for every user");
        }
        foreach (var hive in UserHives.Loaded())
        {
            using (hive)
            {
                var who = UserHives.AccountName(hive.Sid) ?? hive.Sid;
                foreach (var sub in RunKeys.Take(2))
                {
                    using var key = hive.Root.OpenSubKey(sub);
                    AddValues(items, key, $@"HKU\{hive.Sid}\{sub}", $"Starts when {who} signs in");
                }
            }
        }
    }

    private static void AddValues(List<StartupItem> items, RegistryKey? key, string path, string location)
    {
        if (key is null) return;
        foreach (var name in key.GetValueNames())
        {
            if (name.Length == 0) continue;
            var command = key.GetValue(name)?.ToString() ?? "";
            items.Add(new StartupItem($"run|{path}|{name}|{command}", name, command, location, false));
        }
    }

    private static void ScanFolders(List<StartupItem> items)
    {
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        AddFolder(items, common, "Startup folder (all users)");
        foreach (var hive in UserHives.Loaded())
        {
            using (hive)
            {
                var folder = UserStartupFolder(hive);
                if (folder is not null) AddFolder(items, folder, $"Startup folder ({UserHives.AccountName(hive.Sid) ?? hive.Sid})");
            }
        }
    }

    public static string? UserStartupFolder(UserHive hive)
    {
        if (hive.ProfilePath is null) return null;
        using var shell = hive.Root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
        var raw = shell?.GetValue("Startup", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        return raw is null
            ? Path.Combine(hive.ProfilePath, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
            : Environment.ExpandEnvironmentVariables(raw.Replace("%USERPROFILE%", hive.ProfilePath, StringComparison.OrdinalIgnoreCase));
    }

    public static IEnumerable<string> AllStartupFolders()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        foreach (var hive in UserHives.Loaded())
        {
            using (hive)
            {
                if (UserStartupFolder(hive) is { } f) yield return f;
            }
        }
    }

    private static void AddFolder(List<StartupItem> items, string folder, string location)
    {
        if (!Directory.Exists(folder)) return;
        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var name = Path.GetFileName(file);
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            items.Add(new StartupItem($"folder|{file}", name, file, location, false));
        }
    }

    private static void ScanWinlogon(List<StartupItem> items)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        if (key is null) return;
        foreach (var name in new[] { "Shell", "Userinit" })
        {
            var value = key.GetValue(name)?.ToString() ?? "";
            items.Add(new StartupItem($"winlogon|{name}|{value}", $"Winlogon {name}", value, "Runs at every sign-in (Windows shell setting)", false));
        }
    }

    private static void ScanServices(List<StartupItem> items)
    {
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (root is null) return;
        foreach (var name in root.GetSubKeyNames())
        {
            using var svc = root.OpenSubKey(name);
            if (svc?.GetValue("Start") is not int start || start > 2) continue;
            if (svc.GetValue("Type") is not int type) continue;
            // Per-user service instances are created at every sign-in with random suffixes; not installs.
            if ((type & 0xC0) != 0) continue;
            var isDriver = (type & 0x3) != 0;
            if (!isDriver && (type & 0x30) == 0) continue;

            var image = svc.GetValue("ImagePath", "", RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
            items.Add(new StartupItem($"svc|{name}|{image}", name, image, isDriver ? "Driver (loads with Windows)" : "Windows service (starts automatically)", true));
        }
    }

    private static void ScanTasks(List<StartupItem> items)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service");
        if (type is null) return;
        dynamic service = Activator.CreateInstance(type)!;
        try
        {
            service.Connect();
            WalkFolder(service.GetFolder("\\"), items);
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }
    }

    private static void WalkFolder(dynamic folder, List<StartupItem> items)
    {
        string path = folder.Path;
        // Windows' own tasks live under \Microsoft\ and change with every update.
        if (path.StartsWith(@"\Microsoft", StringComparison.OrdinalIgnoreCase)) return;

        foreach (dynamic task in folder.GetTasks(1 /* include hidden */))
        {
            if (!(bool)task.Enabled) continue;
            string taskPath = task.Path;
            var commands = new List<string>();
            foreach (dynamic action in task.Definition.Actions)
            {
                if ((int)action.Type == 0) commands.Add($"{action.Path} {action.Arguments}".Trim());
            }
            if (commands.Count == 0) continue;
            var command = string.Join("; ", commands);
            items.Add(new StartupItem($"task|{taskPath}|{command}", taskPath.TrimStart('\\'), command, "Scheduled task", false));
        }
        foreach (dynamic sub in folder.GetFolders(0)) WalkFolder(sub, items);
    }

    /// <summary>The executable a startup command runs, for signature checks.</summary>
    public static string? ExecutableOf(string command)
    {
        var c = Environment.ExpandEnvironmentVariables(command.Trim());
        if (c.StartsWith('"'))
        {
            var end = c.IndexOf('"', 1);
            return end > 1 ? c[1..end] : null;
        }
        var exe = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe > 0) return c[..(exe + 4)];
        var space = c.IndexOf(' ');
        return space > 0 ? c[..space] : c;
    }
}
