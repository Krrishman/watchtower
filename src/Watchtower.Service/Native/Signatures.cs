using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Watchtower.Core.Monitoring;

namespace Watchtower.Service.Native;

/// <summary>
/// Authenticode checks through WinVerifyTrust, including catalog signatures (most
/// Windows binaries are catalog-signed, so an embedded-only check would call
/// Notepad "unsigned"). Revocation is checked from cache only: no network calls,
/// so verifying a file never tells anyone what's on this machine.
/// </summary>
public sealed class SignatureVerifier
{
    private static readonly HashSet<string> MicrosoftSigners = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher",
        "Microsoft Windows Hardware Compatibility Publisher", "Microsoft Windows Production PCA 2011",
    };

    private readonly ConcurrentDictionary<string, SignatureInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    public int CacheCount => _cache.Count;

    public SignatureInfo Check(string? path)
    {
        if (string.IsNullOrEmpty(path)) return SignatureInfo.Unknown;
        FileInfo fi;
        try
        {
            fi = new FileInfo(path);
            if (!fi.Exists) return new SignatureInfo("Unavailable", null, false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new SignatureInfo("Unavailable", null, false);
        }

        // Keyed by size and timestamp so a file replaced in place is re-checked.
        var key = $"{path}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}";
        if (_cache.TryGetValue(key, out var cached)) return cached;

        SignatureInfo result;
        try
        {
            result = Verify(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or COMException or ExternalException)
        {
            result = new SignatureInfo("Unavailable", null, false);
        }
        if (_cache.Count > 20_000) _cache.Clear();
        _cache[key] = result;
        return result;
    }

    private static SignatureInfo Verify(string path)
    {
        var (code, signer) = VerifyEmbedded(path);
        if (code is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN)
        {
            var catalog = VerifyCatalog(path, "SHA256") ?? VerifyCatalog(path, null);
            if (catalog is { } c) (code, signer) = c;
        }
        var status = Describe(code);
        return new SignatureInfo(status, signer, status == "Valid" && signer is not null && MicrosoftSigners.Contains(signer));
    }

    private static string Describe(uint code) => code switch
    {
        0 => "Valid",
        TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => "NotSigned",
        TRUST_E_BAD_DIGEST => "HashMismatch",
        CERT_E_EXPIRED => "Expired",
        CERT_E_REVOKED => "Revoked",
        CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or TRUST_E_EXPLICIT_DISTRUST or CERT_E_UNTRUSTEDTESTROOT => "Untrusted",
        _ => "UnknownError",
    };

    private static (uint Code, string? Signer) VerifyEmbedded(string path)
    {
        var pPath = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = pPath };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            return Run(WTD_CHOICE_FILE, pFile);
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
            Marshal.FreeHGlobal(pPath);
        }
    }

    private static (uint Code, string? Signer)? VerifyCatalog(string path, string? hashAlgorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var catAdmin, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0)) return null;
        var catInfo = IntPtr.Zero;
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref size, null, 0);
            if (size == 0) return null;
            var hash = new byte[size];
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref size, hash, 0)) return null;

            catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, size, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero) return null;

            var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref info, 0)) return null;

            var pCatalog = Marshal.StringToHGlobalUni(info.wszCatalogFile);
            var pTag = Marshal.StringToHGlobalUni(Convert.ToHexString(hash));
            var pMember = Marshal.StringToHGlobalUni(path);
            var pHash = Marshal.AllocHGlobal(hash.Length);
            var pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.Copy(hash, 0, pHash, hash.Length);
                Marshal.StructureToPtr(new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = pCatalog,
                    pcwszMemberTag = pTag,
                    pcwszMemberFilePath = pMember,
                    hMemberFile = handle.DangerousGetHandle(),
                    pbCalculatedFileHash = pHash,
                    cbCalculatedFileHash = size,
                    hCatAdmin = catAdmin,
                }, pCat, false);
                return Run(WTD_CHOICE_CATALOG, pCat);
            }
            finally
            {
                Marshal.FreeHGlobal(pCat);
                Marshal.FreeHGlobal(pHash);
                Marshal.FreeHGlobal(pMember);
                Marshal.FreeHGlobal(pTag);
                Marshal.FreeHGlobal(pCatalog);
            }
        }
        finally
        {
            if (catInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    private static (uint Code, string? Signer) Run(uint unionChoice, IntPtr union)
    {
        var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pUnion = union,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        };
        var code = unchecked((uint)WinVerifyTrust(new IntPtr(-1), ref action, ref data));
        string? signer = null;
        try
        {
            if (data.hWVTStateData != IntPtr.Zero) signer = SignerName(data.hWVTStateData);
        }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
        return (code, signer);
    }

    private static string? SignerName(IntPtr state)
    {
        var provData = WTHelperProvDataFromStateData(state);
        if (provData == IntPtr.Zero) return null;
        var sgnr = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
        if (sgnr == IntPtr.Zero) return null;

        // CRYPT_PROVIDER_SGNR: DWORD cbStruct; FILETIME sftVerifyAsOf; DWORD csCertChain; CRYPT_PROVIDER_CERT* pasCertChain
        if (Marshal.ReadInt32(sgnr, 12) == 0) return null;
        var chain = Marshal.ReadIntPtr(sgnr, 16);
        if (chain == IntPtr.Zero) return null;
        // CRYPT_PROVIDER_CERT: DWORD cbStruct; PCCERT_CONTEXT pCert
        var cert = Marshal.ReadIntPtr(chain, IntPtr.Size);
        if (cert == IntPtr.Zero) return null;

        var sb = new StringBuilder(256);
        return CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, sb, (uint)sb.Capacity) > 1 ? sb.ToString() : null;
    }

    // ---- interop ----

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
    private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
    private const uint TRUST_E_BAD_DIGEST = 0x80096010;
    private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
    private const uint CERT_E_EXPIRED = 0x800B0101;
    private const uint CERT_E_REVOKED = 0x800B010C;
    private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
    private const uint CERT_E_CHAINING = 0x800B010A;
    private const uint CERT_E_UNTRUSTEDTESTROOT = 0x800B010D;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll")]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provData, uint signerIndex, bool counterSigner, uint counterSignerIndex);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CertGetNameStringW(IntPtr cert, uint type, uint flags, IntPtr typePara, StringBuilder name, uint chars);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string? hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, SafeFileHandle file, ref uint hashSize, byte[]? hash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize, uint flags, IntPtr prevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CATALOG_INFO info, uint flags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);
}
