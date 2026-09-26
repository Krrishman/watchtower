using Watchtower.Core.Config;

namespace Watchtower.Core.Monitoring;

public static class Watchlist
{
    /// <summary>Executable names of common remote-access / remote-control software.</summary>
    public static readonly string[] Defaults =
    [
        "teamviewer.exe", "teamviewer_service.exe",
        "anydesk.exe",
        "vncserver.exe", "winvnc.exe", "tvnserver.exe", "uvnc_service.exe", "ultravnc.exe", "winvnc4.exe",
        "rutserv.exe", "rfusclient.exe",
        "aeroadmin.exe",
        "supremo.exe", "supremohelper.exe",
        "ammyy.exe", "ammyyadmin.exe",
        "showmypc.exe",
        "g2mcomm.exe", "g2mupdate.exe", "g2svc.exe",
        "lmiguardiansvc.exe", "lmiignition.exe",
        "remoting_host.exe", "remotingdesktophost.exe",
        "splashtopstreamer.exe", "srserver.exe", "srfeature.exe",
        "screenconnect.windowsclient.exe", "connectwisecontrol.clienthost.exe",
        "dwservice.exe", "dwagent.exe",
        "radmin.exe", "rserver3.exe",
        "rustdesk.exe", "quickassist.exe", "msra.exe",
        "mstsc.exe",
    ];

    public static HashSet<string> Active(WatchlistSettings settings)
    {
        var disabled = new HashSet<string>(settings.Disabled, StringComparer.OrdinalIgnoreCase);
        return new HashSet<string>(
            Defaults.Concat(settings.Custom).Select(n => n.Trim().ToLowerInvariant()).Where(n => n.Length > 0 && !disabled.Contains(n)),
            StringComparer.OrdinalIgnoreCase);
    }

    public static string Normalize(string name)
    {
        var n = name.Trim().ToLowerInvariant();
        return n.EndsWith(".exe", StringComparison.Ordinal) || n.Length == 0 ? n : n + ".exe";
    }
}
