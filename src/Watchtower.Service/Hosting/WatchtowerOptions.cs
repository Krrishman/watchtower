namespace Watchtower.Service.Hosting;

/// <summary>Build-time configuration from appsettings.json next to the executable (admin-only location).</summary>
public sealed class WatchtowerOptions
{
    public const string Section = "Watchtower";

    public string? UpdateManifestUrl { get; set; }
    /// <summary>keyId → base64 SubjectPublicKeyInfo of the ECDSA P-256 keys allowed to sign manifests.</summary>
    public Dictionary<string, string> UpdateSigningKeys { get; set; } = [];
    /// <summary>Required Authenticode signer of downloaded installers.</summary>
    public string? InstallerPublisher { get; set; }
    public int UpdateCheckHours { get; set; } = 6;
    public string? SentryDsn { get; set; }
    public string PipeName { get; set; } = "Watchtower.v1";

    public bool UpdatesConfigured =>
        !string.IsNullOrWhiteSpace(UpdateManifestUrl) && UpdateSigningKeys.Count > 0 && !string.IsNullOrWhiteSpace(InstallerPublisher);
}

public sealed record CommandLine(bool Console, int SmokeSeconds, string? DataDir)
{
    public static CommandLine Parse(string[] args)
    {
        var console = args.Contains("--console");
        var smoke = 0;
        string? dataDir = null;
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--smoke-test" && int.TryParse(args[i + 1], out var s)) smoke = s;
            if (args[i] == "--data-dir") dataDir = args[i + 1];
        }
        return new CommandLine(console || smoke > 0, smoke, dataDir);
    }
}

public static class AppVersion
{
    public static string Current { get; } = Resolve();

    private static string Resolve()
    {
        var v = typeof(AppVersion).Assembly.GetName().Version ?? new Version(0, 0, 0);
        return $"{v.Major}.{v.Minor}.{Math.Max(v.Build, 0)}";
    }
}
