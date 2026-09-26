using System.Security.Cryptography;
using System.Text.Json;

namespace Watchtower.Core.Updates;

public sealed record VerifiedManifest(bool Ok, ReleaseManifest? Manifest, string? Error)
{
    public static VerifiedManifest Fail(string error) => new(false, null, error);
}

/// <summary>
/// Verifies the signed release manifest before any of it is trusted. The signature
/// is checked over the exact downloaded bytes before the JSON is parsed.
/// </summary>
public static class ManifestVerifier
{
    private static readonly TimeSpan ClockSkew = TimeSpan.FromHours(24);

    /// <param name="trustedKeys">keyId → base64 SubjectPublicKeyInfo of an ECDSA P-256 key. Several allow key rotation.</param>
    public static VerifiedManifest Verify(byte[] manifestBytes, string signatureJson, IReadOnlyDictionary<string, string> trustedKeys, long lastSequence, DateTimeOffset now)
    {
        SignatureEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<SignatureEnvelope>(signatureJson, ReleaseManifest.Json);
        }
        catch (JsonException)
        {
            return VerifiedManifest.Fail("Signature file is malformed.");
        }
        if (envelope is null || string.IsNullOrEmpty(envelope.KeyId) || string.IsNullOrEmpty(envelope.Sig))
        {
            return VerifiedManifest.Fail("Signature file is incomplete.");
        }
        if (!trustedKeys.TryGetValue(envelope.KeyId, out var spki))
        {
            return VerifiedManifest.Fail($"Manifest is signed with unknown key '{envelope.KeyId}'.");
        }

        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(spki), out _);
            if (!key.VerifyData(manifestBytes, Convert.FromBase64String(envelope.Sig), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return VerifiedManifest.Fail("Manifest signature is invalid.");
            }
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return VerifiedManifest.Fail("Manifest signature couldn't be checked.");
        }

        ReleaseManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<ReleaseManifest>(manifestBytes, ReleaseManifest.Json);
        }
        catch (JsonException)
        {
            return VerifiedManifest.Fail("Manifest is signed but unreadable.");
        }

        if (manifest is null || manifest.Schema != 1 || manifest.Product != "watchtower")
        {
            return VerifiedManifest.Fail("Manifest isn't a Watchtower schema-1 manifest.");
        }
        if (!DateTimeOffset.TryParse(manifest.ExpiresAt, out var expires) || now > expires)
        {
            return VerifiedManifest.Fail("Manifest has expired. Refusing it in case it's an old copy being replayed.");
        }
        if (!DateTimeOffset.TryParse(manifest.IssuedAt, out var issued) || issued > now + ClockSkew)
        {
            return VerifiedManifest.Fail("Manifest issue date is in the future. Check the system clock.");
        }
        if (manifest.Sequence < lastSequence)
        {
            return VerifiedManifest.Fail($"Manifest sequence {manifest.Sequence} is older than one already seen ({lastSequence}).");
        }
        foreach (var r in manifest.Releases)
        {
            if (!SemVer.TryParse(r.Version, out _) ||
                !Uri.TryCreate(r.Url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
                r.Sha256.Length != 64 || r.RolloutPercent is < 0 or > 100)
            {
                return VerifiedManifest.Fail($"Release entry '{r.Version}' is invalid.");
            }
        }
        return new VerifiedManifest(true, manifest, null);
    }

    public static string Sign(byte[] manifestBytes, ECDsa privateKey, string keyId)
    {
        var sig = privateKey.SignData(manifestBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return JsonSerializer.Serialize(new SignatureEnvelope(keyId, Convert.ToBase64String(sig)), ReleaseManifest.Json);
    }
}
