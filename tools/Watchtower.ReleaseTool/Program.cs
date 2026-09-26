using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Watchtower.Core.Updates;

// Publisher-side tool for the signed update manifest. Every change bumps the
// sequence number and re-signs, so clients accept it and reject older copies.
//
//   wt-release keygen  --out keys/ --key-id 2026a
//   wt-release add     --manifest manifest.json --msi Watchtower-1.2.0.msi --version 1.2.0 --url https://.../Watchtower-1.2.0.msi --key keys/2026a.pem --key-id 2026a
//   wt-release rollout --manifest manifest.json --version 1.2.0 --percent 10 --key ... --key-id ...
//   wt-release pause   --manifest manifest.json --version 1.2.0 ...      (resume: --resume)
//   wt-release recall  --manifest manifest.json --version 1.2.0 ...      (blocks it; machines on it move to the newest fully rolled-out release)
//   wt-release halt    --manifest manifest.json ...                      (stop every rollout; --off to lift)
//   wt-release refresh --manifest manifest.json ...                      (re-sign with a new expiry; run at least weekly)
//   wt-release verify  --manifest manifest.json --public <base64 SPKI> --key-id 2026a

var command = args.FirstOrDefault() ?? "help";
string? Opt(string name) => args.SkipWhile(a => a != $"--{name}").Skip(1).FirstOrDefault();
string Req(string name) => Opt(name) ?? throw new ArgumentException($"--{name} is required.");
bool Flag(string name) => args.Contains($"--{name}");

try
{
    switch (command)
    {
        case "keygen":
        {
            var dir = Req("out");
            var keyId = Req("key-id");
            Directory.CreateDirectory(dir);
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var pem = Path.Combine(dir, $"{keyId}.pem");
            File.WriteAllText(pem, key.ExportPkcs8PrivateKeyPem());
            var spki = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
            Console.WriteLine($"Private key written to {pem}. Keep it offline or in a hardware-backed secret store; never commit it.");
            Console.WriteLine("Add this to src/Watchtower.Service/appsettings.json under Watchtower:UpdateSigningKeys:");
            Console.WriteLine($"  \"{keyId}\": \"{spki}\"");
            return 0;
        }
        case "add":
        {
            var msi = Req("msi");
            var version = Req("version");
            SemVer.Parse(version);
            var bytes = File.ReadAllBytes(msi);
            return Mutate(m =>
            {
                if (m.Releases.Any(r => r.Version == version)) throw new ArgumentException($"{version} is already in the manifest.");
                var release = new ReleaseInfo
                {
                    Version = version,
                    Url = Req("url"),
                    Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
                    Size = bytes.Length,
                    // New releases start at 0%: nothing ships until someone deliberately starts the rollout.
                    RolloutPercent = 0,
                    Notes = Opt("notes"),
                    MinFromVersion = Opt("min-from"),
                };
                return m with { Releases = [.. m.Releases, release] };
            }, $"Added {version} at 0%. Start it with: rollout --version {version} --percent 1");
        }
        case "rollout":
        {
            var version = Req("version");
            var percent = double.Parse(Req("percent"), System.Globalization.CultureInfo.InvariantCulture);
            if (percent is < 0 or > 100) throw new ArgumentException("--percent must be 0–100.");
            return Mutate(m => Update(m, version, r => r with
            {
                RolloutPercent = percent,
                FullRolloutAt = percent >= 100 ? r.FullRolloutAt ?? DateTimeOffset.UtcNow.ToString("o") : null,
            }), $"{version} now offered to {percent}% of standard-ring machines.");
        }
        case "pause":
        {
            var version = Req("version");
            var resume = Flag("resume");
            return Mutate(m => Update(m, version, r => r with { Paused = !resume }), resume ? $"{version} resumed." : $"{version} paused. Machines that already have it keep it; no new machines get it.");
        }
        case "recall":
        {
            var version = Req("version");
            return Mutate(m =>
            {
                Update(m, version, r => r);
                return m with { BlockedVersions = m.BlockedVersions.Append(version).Distinct().ToList() };
            }, $"{version} recalled. Machines running it will move to the newest fully rolled-out release.");
        }
        case "halt":
        {
            var off = Flag("off");
            return Mutate(m => m with { HaltAll = !off }, off ? "Rollouts resumed." : "All rollouts halted.");
        }
        case "refresh":
            return Mutate(m => m, "Manifest re-signed with a fresh expiry.");
        case "verify":
        {
            var path = Req("manifest");
            var result = ManifestVerifier.Verify(File.ReadAllBytes(path), File.ReadAllText(path + ".sig"),
                new Dictionary<string, string> { [Req("key-id")] = Req("public") }, 0, DateTimeOffset.UtcNow);
            Console.WriteLine(result.Ok ? $"OK: sequence {result.Manifest!.Sequence}, expires {result.Manifest.ExpiresAt}" : $"INVALID: {result.Error}");
            return result.Ok ? 0 : 1;
        }
        default:
            Console.WriteLine("Commands: keygen, add, rollout, pause, recall, halt, refresh, verify. See the comment at the top of Program.cs.");
            return command == "help" ? 0 : 2;
    }
}
catch (Exception ex) when (ex is ArgumentException or FormatException or IOException or CryptographicException or JsonException)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

int Mutate(Func<ReleaseManifest, ReleaseManifest> change, string message)
{
    var path = Req("manifest");
    var current = File.Exists(path)
        ? JsonSerializer.Deserialize<ReleaseManifest>(File.ReadAllBytes(path), ReleaseManifest.Json)!
        : new ReleaseManifest { Schema = 1, Product = "watchtower", Channel = Opt("channel") ?? "stable" };

    var now = DateTimeOffset.UtcNow;
    var next = change(current) with
    {
        Sequence = current.Sequence + 1,
        IssuedAt = now.ToString("o"),
        // Short expiry: a stolen or replayed manifest stops working quickly. Refresh weekly.
        ExpiresAt = now.AddDays(int.Parse(Opt("expires-days") ?? "14")).ToString("o"),
    };

    var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(next, ReleaseManifest.Json));
    using var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(Req("key")));
    var sig = ManifestVerifier.Sign(bytes, key, Req("key-id"));

    File.WriteAllBytes(path, bytes);
    File.WriteAllText(path + ".sig", sig);
    Console.WriteLine($"{message} (sequence {next.Sequence}, expires {next.ExpiresAt})");
    return 0;
}

static ReleaseManifest Update(ReleaseManifest m, string version, Func<ReleaseInfo, ReleaseInfo> change)
{
    if (!m.Releases.Any(r => r.Version == version)) throw new ArgumentException($"{version} isn't in the manifest.");
    return m with { Releases = m.Releases.Select(r => r.Version == version ? change(r) : r).ToList() };
}
