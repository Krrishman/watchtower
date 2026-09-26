using Microsoft.Win32;
using Watchtower.Core.Monitoring;

namespace Watchtower.Service.Sources;

/// <summary>Reads Windows' own camera/microphone access ledger for every signed-in user.</summary>
public static class DeviceUsageReader
{
    private const string ConsentStore = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public static IReadOnlyList<DeviceUse> Read()
    {
        var uses = new List<DeviceUse>();
        foreach (var hive in UserHives.Loaded())
        {
            using (hive)
            {
                foreach (var device in new[] { "webcam", "microphone" })
                {
                    using var root = hive.Root.OpenSubKey($@"{ConsentStore}\{device}");
                    if (root is not null) Collect(root, device, uses, depth: 0);
                }
            }
        }
        return uses;
    }

    private static void Collect(RegistryKey key, string device, List<DeviceUse> uses, int depth)
    {
        foreach (var name in key.GetSubKeyNames())
        {
            using var sub = key.OpenSubKey(name);
            if (sub is null) continue;
            if (sub.GetValue("LastUsedTimeStart") is long start)
            {
                var stop = sub.GetValue("LastUsedTimeStop") is long s ? s : 0;
                uses.Add(new DeviceUse(device, name, start, stop));
            }
            // Desktop apps live one level down, under "NonPackaged".
            else if (depth == 0)
            {
                Collect(sub, device, uses, depth + 1);
            }
        }
    }
}
