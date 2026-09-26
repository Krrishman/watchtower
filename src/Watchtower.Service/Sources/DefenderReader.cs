using System.Diagnostics;
using System.Management;

namespace Watchtower.Service.Sources;

public sealed record DefenderStatus(bool Available, bool AntivirusEnabled, bool RealTimeProtectionEnabled, string? SignaturesUpdated, string? LastQuickScan, string? Message);
public sealed record DefenderThreat(string Id, string Name, string? Process, string? Resources, string? DetectedAt);

/// <summary>Microsoft Defender status and detections via its WMI provider.</summary>
public static class DefenderReader
{
    private const string Scope = @"root\Microsoft\Windows\Defender";

    public static DefenderStatus Status()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(Scope, "SELECT AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanEndTime FROM MSFT_MpComputerStatus");
            foreach (ManagementObject o in searcher.Get())
            {
                using (o)
                {
                    return new DefenderStatus(true,
                        o["AntivirusEnabled"] is true,
                        o["RealTimeProtectionEnabled"] is true,
                        Date(o["AntivirusSignatureLastUpdated"]),
                        Date(o["QuickScanEndTime"]),
                        null);
                }
            }
            return new DefenderStatus(false, false, false, null, null, "Microsoft Defender didn't report a status. Another antivirus may be installed.");
        }
        catch (ManagementException ex)
        {
            return new DefenderStatus(false, false, false, null, null, $"Microsoft Defender isn't available ({ex.Message}). Another antivirus may be installed.");
        }
    }

    public static IReadOnlyList<DefenderThreat> Threats()
    {
        var threats = new List<DefenderThreat>();
        try
        {
            var names = new Dictionary<string, string>();
            using (var catalog = new ManagementObjectSearcher(Scope, "SELECT ThreatID, ThreatName FROM MSFT_MpThreat"))
            {
                foreach (ManagementObject o in catalog.Get())
                {
                    using (o) names[o["ThreatID"]?.ToString() ?? ""] = o["ThreatName"]?.ToString() ?? "";
                }
            }
            using var detections = new ManagementObjectSearcher(Scope, "SELECT DetectionID, ThreatID, ProcessName, Resources, InitialDetectionTime, ThreatStatusID FROM MSFT_MpThreatDetection");
            foreach (ManagementObject o in detections.Get())
            {
                using (o)
                {
                    // Status 3 = quarantined, 4 = removed, 102/103/104/105/106/107 = cleaned/allowed variants.
                    if (o["ThreatStatusID"] is byte status && status is 3 or 4 or >= 102) continue;
                    var id = o["ThreatID"]?.ToString() ?? "";
                    threats.Add(new DefenderThreat(
                        o["DetectionID"]?.ToString() ?? id,
                        names.TryGetValue(id, out var n) && n.Length > 0 ? n : $"threat {id}",
                        o["ProcessName"]?.ToString(),
                        o["Resources"] is string[] r ? string.Join(", ", r) : null,
                        Date(o["InitialDetectionTime"])));
                }
            }
        }
        catch (ManagementException)
        {
            // No Defender: nothing to report.
        }
        return threats;
    }

    /// <summary>Starts a quick scan with Defender's own command-line tool, detached.</summary>
    public static (bool Started, string? Error) StartQuickScan()
    {
        var tool = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(tool)) return (false, "Microsoft Defender isn't installed on this PC.");
        using var p = Process.Start(new ProcessStartInfo(tool, "-Scan -ScanType 1") { UseShellExecute = false, CreateNoWindow = true });
        return p is null ? (false, "Couldn't start the scan.") : (true, null);
    }

    private static string? Date(object? wmi) => wmi switch
    {
        string s when s.Length > 0 => ManagementDateTimeConverter.ToDateTime(s).ToUniversalTime().ToString("o"),
        DateTime d => d.ToUniversalTime().ToString("o"),
        _ => null,
    };
}
