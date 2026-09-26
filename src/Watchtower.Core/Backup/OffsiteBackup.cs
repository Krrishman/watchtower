using Watchtower.Core.History;

namespace Watchtower.Core.Backup;

public sealed record SyncResult(bool Ok, int Copied, string? TargetDir, string? Error);

/// <summary>
/// Mirrors the history log to a folder the user chooses (ideally cloud-synced or a
/// network share) so the record survives this machine being wiped, and the cloud
/// service's own version history defeats an overwrite.
/// </summary>
public static class OffsiteBackup
{
    public static string TargetDirectory(string destination, string machineName)
    {
        var safe = new string(machineName.Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray());
        return Path.Combine(destination, $"watchtower-{(safe.Length > 0 ? safe : "unknown-host")}");
    }

    public static SyncResult Sync(string historyDir, string destination, string machineName, DateTimeOffset now)
    {
        try
        {
            if (!Directory.Exists(destination))
            {
                return new(false, 0, null, "The backup folder isn't reachable. If it's a network share or cloud folder, check that it's still connected.");
            }
            var target = TargetDirectory(destination, machineName);
            Directory.CreateDirectory(target);
            // The service writes with high privileges into a folder others may be able to
            // modify. Refuse to follow a link planted there to redirect the write elsewhere.
            if (new DirectoryInfo(target).Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return new(false, 0, target, "The backup folder has been replaced by a link to somewhere else, so Watchtower won't write to it.");
            }

            var copied = 0;
            foreach (var name in HistoryLog.AllFiles)
            {
                var src = Path.Combine(historyDir, name);
                if (!File.Exists(src)) continue;
                // Copy to a temp name first so an interrupted sync never leaves a truncated log behind.
                var dest = Path.Combine(target, name);
                var tmp = dest + ".tmp";
                File.Delete(tmp);
                using (var input = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var output = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    input.CopyTo(output);
                }
                File.Move(tmp, dest, overwrite: true);
                copied++;
            }
            if (copied == 0) return new(false, 0, target, "Nothing to back up yet. No history has been recorded.");

            File.WriteAllText(Path.Combine(target, "last-sync.txt"), $"Machine: {machineName}\r\nLast sync: {now:o}\r\nFiles: {copied}\r\n");
            return new(true, copied, target, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(false, 0, null, $"Backup failed: {ex.Message}");
        }
    }
}
