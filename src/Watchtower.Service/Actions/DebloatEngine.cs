using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;
using Watchtower.Core.Config;
using Watchtower.Core.Ipc;
using Watchtower.Service.Sources;
using static Watchtower.Service.Native.NativeMethods;

namespace Watchtower.Service.Actions;

public sealed record RegEntry(string Hive, string Path, string Name, int EnableValue);

public sealed record DebloatFeature(string Id, string Label, string Description, string Type)
{
    public RegEntry? Check { get; init; }
    public RegEntry[] Entries { get; init; } = [];
    public string? ServiceName { get; init; }
    public string? TaskPath { get; init; }
}

public sealed record DebloatResult(bool Ok, string? Note = null, string? Error = null);

public sealed record DebloatState
{
    public Dictionary<string, string> PreviousStartTypes { get; init; } = [];
}

/// <summary>
/// Reversible privacy and telemetry switches. "On" always means the annoyance is
/// blocked; turning it off restores Windows' default. Per-user settings are written
/// to the requesting user's own registry hive, not SYSTEM's.
/// </summary>
public sealed class DebloatEngine(JsonFileStore<DebloatState> state)
{
    public static readonly DebloatFeature[] Features =
    [
        new("bing-search", "Bing / web results in search", "Removes Bing web results from Start menu and taskbar search, so it shows local files and apps only.", "registry")
        {
            Check = new("HKCU", @"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1),
            Entries =
            [
                new("HKCU", @"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Search", "CortanaConsent", 0),
            ],
        },
        new("copilot", "Microsoft Copilot", "Removes the Copilot taskbar button and blocks it by policy so it doesn't quietly come back after an update.", "registry")
        {
            Check = new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1),
            Entries =
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1),
                new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCopilotButton", 0),
            ],
        },
        new("widgets", "Widgets", "Hides the Widgets icon from the taskbar.", "registry")
        {
            Check = new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", 0),
            Entries = [new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", 0)],
        },
        new("advertising-id", "Advertising ID", "Stops apps from using your advertising ID to personalize ads.", "registry")
        {
            Check = new("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
            Entries =
            [
                new("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1),
            ],
        },
        new("tailored-experiences", "Tailored experiences", "Stops Windows using your diagnostic data to personalize tips, ads, and recommendations.", "registry")
        {
            Check = new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0),
            Entries = [new("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0)],
        },
        new("activity-history", "Activity History", "Stops Windows recording and uploading a history of the apps and files you use.", "registry")
        {
            Check = new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0),
            Entries =
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0),
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0),
            ],
        },
        new("telemetry-level", "Diagnostic data (telemetry) level", "Sets diagnostic data collection to the minimum Windows allows. On Home and Pro this can't reach zero; only Enterprise and Education can.", "registry")
        {
            Check = new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
            Entries =
            [
                new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
                new("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0),
            ],
        },
        new("diagtrack-service", "Connected User Experiences and Telemetry (DiagTrack)", "The background service that sends most telemetry. Turning this back on restores whatever startup type it had before.", "service")
        {
            ServiceName = "DiagTrack",
        },
        new("ceip-tasks", "Customer Experience Improvement Program tasks", "Scheduled tasks that collect general usage statistics.", "tasks")
        {
            TaskPath = @"\Microsoft\Windows\Customer Experience Improvement Program",
        },
        new("app-experience-tasks", "Application Experience tasks", "Scheduled tasks that send app-compatibility data Microsoft uses to target Windows updates.", "tasks")
        {
            TaskPath = @"\Microsoft\Windows\Application Experience",
        },
        new("recall", "Windows Recall", "Turns off Recall and blocks it by policy. Only present on Copilot+ PCs; shows as unavailable everywhere else.", "recall"),
    ];

    private static readonly RegEntry[] RecallPolicy =
    [
        new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1),
        new("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnablement", 0),
    ];

    public object Catalog() => Features.Select(f => new { f.Id, f.Label, f.Description });

    /// <returns>id → "on" | "off" | "unsupported"</returns>
    public Dictionary<string, string> States(string userSid)
    {
        var states = new Dictionary<string, string>();
        foreach (var f in Features)
        {
            try
            {
                states[f.Id] = f.Type switch
                {
                    "registry" => ReadValue(f.Check!, userSid) == f.Check!.EnableValue ? "on" : "off",
                    "service" => ServiceState(f.ServiceName!),
                    "tasks" => TaskState(f.TaskPath!),
                    "recall" => RecallState(),
                    _ => "unsupported",
                };
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or COMException or InvalidOperationException or System.Security.SecurityException)
            {
                states[f.Id] = "unsupported";
            }
        }
        return states;
    }

    public DebloatResult Set(string id, bool enable, string userSid)
    {
        var f = Features.FirstOrDefault(x => x.Id == id) ?? throw RpcException.BadRequest("Unknown setting.");
        try
        {
            switch (f.Type)
            {
                case "registry":
                    foreach (var e in f.Entries) WriteValue(e, enable, userSid);
                    return new(true, f.Id == "bing-search" ? "Sign out and back in for search to pick this up." : null);
                case "service":
                    SetService(f, enable);
                    return new(true);
                case "tasks":
                    SetTasks(f.TaskPath!, enable);
                    return new(true);
                case "recall":
                    SetRecall(enable, userSid);
                    return new(true, "Restart the PC for this to fully take effect.");
            }
            return new(false, Error: "This setting isn't supported.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or COMException or InvalidOperationException or System.Security.SecurityException or System.ComponentModel.Win32Exception)
        {
            return new(false, Error: ex.Message);
        }
    }

    private static RegistryKey? Root(string hive, string userSid, bool writable) => hive switch
    {
        "HKLM" => Registry.LocalMachine,
        "HKCU" => UserHives.Open(userSid, writable),
        _ => null,
    };

    private static int? ReadValue(RegEntry e, string userSid)
    {
        var root = Root(e.Hive, userSid, false);
        try
        {
            using var key = root?.OpenSubKey(e.Path);
            return key?.GetValue(e.Name) is int v ? v : null;
        }
        finally
        {
            if (root != Registry.LocalMachine) root?.Dispose();
        }
    }

    private static void WriteValue(RegEntry e, bool enable, string userSid)
    {
        var root = Root(e.Hive, userSid, true) ?? throw new InvalidOperationException("Your user settings aren't loaded. Sign in and try again.");
        try
        {
            if (enable)
            {
                using var key = root.CreateSubKey(e.Path, writable: true);
                key.SetValue(e.Name, e.EnableValue, RegistryValueKind.DWord);
            }
            else
            {
                using var key = root.OpenSubKey(e.Path, writable: true);
                key?.DeleteValue(e.Name, throwOnMissingValue: false);
            }
        }
        finally
        {
            if (root != Registry.LocalMachine) root.Dispose();
        }
    }

    private static string ServiceState(string name)
    {
        using var sc = new ServiceController(name);
        return sc.StartType == ServiceStartMode.Disabled ? "on" : "off";
    }

    private void SetService(DebloatFeature f, bool enable)
    {
        using var sc = new ServiceController(f.ServiceName!);
        if (enable)
        {
            var previous = sc.StartType;
            state.Update(s => s with { PreviousStartTypes = new(s.PreviousStartTypes) { [f.Id] = previous.ToString() } });
            if (sc.Status != ServiceControllerStatus.Stopped)
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
            }
            ChangeStartType(f.ServiceName!, ServiceStartMode.Disabled);
        }
        else
        {
            var previous = state.Value.PreviousStartTypes.TryGetValue(f.Id, out var p) && Enum.TryParse<ServiceStartMode>(p, out var mode) && mode != ServiceStartMode.Disabled
                ? mode
                : ServiceStartMode.Automatic;
            ChangeStartType(f.ServiceName!, previous);
            if (previous == ServiceStartMode.Automatic) sc.Start();
        }
    }

    private static void ChangeStartType(string name, ServiceStartMode mode)
    {
        var scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var svc = OpenServiceW(scm, name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
            if (svc == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                if (!ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, (uint)mode, SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    private static string TaskState(string folderPath)
    {
        var tasks = Tasks(folderPath);
        if (tasks is null) return "unsupported";
        return tasks.All(t => !t.Enabled) ? "on" : "off";
    }

    private static void SetTasks(string folderPath, bool block)
    {
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
        try
        {
            service.Connect();
            foreach (dynamic task in service.GetFolder(folderPath).GetTasks(1)) task.Enabled = !block;
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }
    }

    private static List<(string Name, bool Enabled)>? Tasks(string folderPath)
    {
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
        try
        {
            service.Connect();
            var list = new List<(string, bool)>();
            foreach (dynamic task in service.GetFolder(folderPath).GetTasks(1)) list.Add(((string)task.Name, (bool)task.Enabled));
            return list;
        }
        catch (COMException)
        {
            return null;
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }
    }

    private static string RecallState()
    {
        var (code, output) = Dism("/Online /Get-FeatureInfo /FeatureName:Recall /English");
        if (code != 0) return "unsupported";
        return output.Contains("State : Disabled", StringComparison.OrdinalIgnoreCase) ? "on" : "off";
    }

    private static void SetRecall(bool block, string userSid)
    {
        var (code, output) = Dism(block
            ? "/Online /Disable-Feature /FeatureName:Recall /NoRestart /English"
            : "/Online /Enable-Feature /FeatureName:Recall /All /NoRestart /English");
        // 3010 = success, restart required.
        if (code is not (0 or 3010)) throw new InvalidOperationException($"Windows couldn't change Recall (DISM {code}). {output.Trim().Split('\n').LastOrDefault()}");
        foreach (var e in RecallPolicy) WriteValue(e, block, userSid);
    }

    private static (int Code, string Output) Dism(string args)
    {
        var dism = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dism.exe");
        using var p = Process.Start(new ProcessStartInfo(dism, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        var output = p.StandardOutput.ReadToEnd();
        if (!p.WaitForExit(TimeSpan.FromMinutes(2)))
        {
            p.Kill();
            return (-1, "Timed out.");
        }
        return (p.ExitCode, output);
    }
}
