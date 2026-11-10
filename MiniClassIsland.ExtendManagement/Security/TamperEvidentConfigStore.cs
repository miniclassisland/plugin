using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Shared;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Models;

namespace MiniClassIsland.ExtendManagement.Security;

/// <summary>
/// 防篡改本地权限开关存储服务。
/// 采用 Windows DPAPI (CryptProtectData) / AES-GCM + 机器特征绑定 HMAC-SHA256 双重密封。
/// 任何外部直接编辑配置文件的行为都会导致校验失败并触发安全熔断（重置全部受控开关为关闭）。
/// </summary>
public sealed class TamperEvidentConfigStore
{
    public const string SecurityAcceptedMarkerFileName = ".security_accepted";

    private readonly ILogger<TamperEvidentConfigStore> _logger;
    private readonly string _primaryFilePath;
    private readonly string _backupFilePath;
    private readonly string _securityAcceptedMarkerPath;
    private readonly object _syncLock = new();
    private byte[]? _cachedSealedBytes;

    public PermissionSwitchesConfig CurrentConfig { get; private set; } = new();

    /// <summary>
    /// 指示上次加载或巡检时是否检测到外部篡改。
    /// </summary>
    public bool IntegrityTamperDetected { get; private set; }

    public event EventHandler? ConfigChanged;

    public TamperEvidentConfigStore(
        ILogger<TamperEvidentConfigStore> logger,
        string pluginConfigFolder,
        string? pluginFolderPath = null)
    {
        _logger = logger;
        Directory.CreateDirectory(pluginConfigFolder);
        _primaryFilePath = Path.Combine(pluginConfigFolder, "permissions.sealed.json");
        _backupFilePath = Path.Combine(pluginConfigFolder, "permissions.sealed.bak");
        _securityAcceptedMarkerPath = !string.IsNullOrWhiteSpace(pluginFolderPath)
            ? Path.Combine(pluginFolderPath, SecurityAcceptedMarkerFileName)
            : Path.Combine(pluginConfigFolder, SecurityAcceptedMarkerFileName);
        LoadOrInitialize();
    }

    public void LoadOrInitialize()
    {
        lock (_syncLock)
        {
            var hasInstallMarker = File.Exists(_securityAcceptedMarkerPath);
            if (TryLoadFromFile(_primaryFilePath, out var cfg) ||
                TryLoadFromFile(_backupFilePath, out cfg))
            {
                CurrentConfig = cfg!;
                if (CurrentConfig.HasAcceptedSecurityWarning && !hasInstallMarker)
                {
                    _logger.LogInformation("检测到插件为全新安装或重装实例（未发现安装目录安全确认标记），已重置首次安全警告确认状态。");
                    CurrentConfig.HasAcceptedSecurityWarning = false;
                }
                SaveInternal(CurrentConfig);
                return;
            }

            if (File.Exists(_primaryFilePath) || File.Exists(_backupFilePath))
            {
                _logger.LogWarning("检测到本地配置文件签名或加密校验失败，已重置默认配置状态。");
                IntegrityTamperDetected = true;
            }

            CurrentConfig = new PermissionSwitchesConfig
            {
                HasAcceptedSecurityWarning = false
            };
            SaveInternal(CurrentConfig);
        }
    }

    public void MarkSecurityWarningAccepted()
    {
        lock (_syncLock)
        {
            var dir = Path.GetDirectoryName(_securityAcceptedMarkerPath);
            if (!string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir))
            {
                File.WriteAllText(
                    _securityAcceptedMarkerPath,
                    $"ACCEPTED|{DateTimeOffset.UtcNow:O}",
                    Encoding.UTF8);
            }

            var clone = CurrentConfig.Clone();
            clone.HasAcceptedSecurityWarning = true;
            CurrentConfig = clone;
            IntegrityTamperDetected = false;
            SaveInternal(CurrentConfig);
        }
        ConfigChanged?.Invoke(this, EventArgs.Empty);
    }

    public void ResetSecurityWarningAcceptanceForUninstall()
    {
        lock (_syncLock)
        {
            try
            {
                if (File.Exists(_securityAcceptedMarkerPath))
                {
                    File.SetAttributes(_securityAcceptedMarkerPath, FileAttributes.Normal);
                    File.Delete(_securityAcceptedMarkerPath);
                }
            }
            catch
            {
                // Ignore
            }

            var clone = CurrentConfig.Clone();
            clone.HasAcceptedSecurityWarning = false;
            clone.IsAppLocked = false;
            CurrentConfig = clone;
            SaveInternal(CurrentConfig);
        }
    }

    /// <summary>
    /// 由集控服务器指令或策略同步设置应用锁定状态，并持久化到防篡改存储。
    /// </summary>
    public void SetAppLockState(bool isLocked)
    {
        var changed = false;
        lock (_syncLock)
        {
            if (CurrentConfig.IsAppLocked != isLocked)
            {
                var clone = CurrentConfig.Clone();
                clone.IsAppLocked = isLocked;
                CurrentConfig = clone;
                IntegrityTamperDetected = false;
                SaveInternal(CurrentConfig);
                changed = true;
            }
        }
        if (changed)
        {
            ConfigChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>
    /// 验证磁盘文件是否被外部篡改；若被篡改则立即恢复为内存中的合法密封镜像。
    /// </summary>
    public void VerifyAndHealDiskFile()
    {
        lock (_syncLock)
        {
            if (_cachedSealedBytes == null)
            {
                return;
            }

            try
            {
                if (!File.Exists(_primaryFilePath))
                {
                    File.WriteAllBytes(_primaryFilePath, _cachedSealedBytes);
                    return;
                }

                var diskBytes = File.ReadAllBytes(_primaryFilePath);
                if (!CryptographicOperations.FixedTimeEquals(diskBytes, _cachedSealedBytes))
                {
                    _logger.LogWarning("检测到本地权限开关文件在运行期被外部修改，正在自动还原合法密封快照。");
                    IntegrityTamperDetected = true;
                    File.WriteAllBytes(_primaryFilePath, _cachedSealedBytes);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "巡检权限密封文件时发生异常。");
            }
        }
    }

    /// <summary>
    /// 仅允许客户端本地经过鉴权后更新配置。
    /// </summary>
    public void UpdateFromLocalUi(Action<PermissionSwitchesConfig> mutator)
    {
        lock (_syncLock)
        {
            var clone = CurrentConfig.Clone();
            mutator(clone);
            CurrentConfig = clone;
            IntegrityTamperDetected = false;
            SaveInternal(CurrentConfig);
        }
        ConfigChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// 更新网络锚定元数据（不涉及任何受控权限开关提权）。
    /// </summary>
    public void UpdateNetworkMetadata(
        string? anchoredMac = null,
        string? lastTenantSlug = null,
        string? defaultDomain = null,
        string? verifiedMiniServerUrl = null,
        bool? isVerifiedMiniServer = null,
        string? verifiedMiniServerFlavor = null,
        string? serverClientDisplayName = null,
        string? serverClientIdentity = null)
    {
        lock (_syncLock)
        {
            var changed = false;
            if (!string.IsNullOrWhiteSpace(anchoredMac) && CurrentConfig.AnchoredMacAddress != anchoredMac)
            {
                CurrentConfig.AnchoredMacAddress = anchoredMac;
                changed = true;
            }
            if (lastTenantSlug != null && CurrentConfig.LastTenantSlug != lastTenantSlug)
            {
                CurrentConfig.LastTenantSlug = lastTenantSlug;
                changed = true;
            }
            if (!string.IsNullOrWhiteSpace(defaultDomain) && CurrentConfig.DefaultBaseDomain != defaultDomain)
            {
                CurrentConfig.DefaultBaseDomain = defaultDomain;
                changed = true;
            }
            if (verifiedMiniServerUrl != null && CurrentConfig.VerifiedMiniServerUrl != verifiedMiniServerUrl)
            {
                CurrentConfig.VerifiedMiniServerUrl = verifiedMiniServerUrl;
                changed = true;
            }
            if (isVerifiedMiniServer.HasValue && CurrentConfig.IsVerifiedMiniServer != isVerifiedMiniServer.Value)
            {
                CurrentConfig.IsVerifiedMiniServer = isVerifiedMiniServer.Value;
                changed = true;
            }
            if (verifiedMiniServerFlavor != null && CurrentConfig.VerifiedMiniServerFlavor != verifiedMiniServerFlavor)
            {
                CurrentConfig.VerifiedMiniServerFlavor = verifiedMiniServerFlavor;
                changed = true;
            }
            if (serverClientDisplayName != null && CurrentConfig.ServerClientDisplayName != serverClientDisplayName)
            {
                CurrentConfig.ServerClientDisplayName = serverClientDisplayName;
                changed = true;
            }
            if (serverClientIdentity != null && CurrentConfig.ServerClientIdentity != serverClientIdentity)
            {
                CurrentConfig.ServerClientIdentity = serverClientIdentity;
                changed = true;
            }

            if (changed)
            {
                SaveInternal(CurrentConfig);
            }
        }
    }

    private bool TryLoadFromFile(string path, out PermissionSwitchesConfig? config)
    {
        config = null;
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            var rawJson = File.ReadAllText(path, Encoding.UTF8);
            var container = JsonSerializer.Deserialize<SealedConfigContainer>(rawJson);
            if (container is null ||
                string.IsNullOrWhiteSpace(container.Nonce) ||
                string.IsNullOrWhiteSpace(container.CipherPayload) ||
                string.IsNullOrWhiteSpace(container.HmacSha256))
            {
                return false;
            }

            var expectedHmac = ComputeContainerHmac(container.Version, container.Nonce, container.UpdatedAtUtc, container.CipherPayload);
            var actualHmacBytes = Convert.FromHexString(container.HmacSha256);
            var expectedHmacBytes = Convert.FromHexString(expectedHmac);

            if (!CryptographicOperations.FixedTimeEquals(actualHmacBytes, expectedHmacBytes))
            {
                return false;
            }

            var cipherBytes = Convert.FromBase64String(container.CipherPayload);
            var plainBytes = UnprotectBytes(cipherBytes, container.Nonce);
            var loaded = JsonSerializer.Deserialize<PermissionSwitchesConfig>(plainBytes);
            if (loaded is null)
            {
                return false;
            }

            config = loaded;
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "读取密封权限配置 {Path} 失败。", path);
            return false;
        }
    }

    private void SaveInternal(PermissionSwitchesConfig config)
    {
        try
        {
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var nowUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var plainBytes = JsonSerializer.SerializeToUtf8Bytes(config);
            var cipherBytes = ProtectBytes(plainBytes, nonce);
            var cipherBase64 = Convert.ToBase64String(cipherBytes);
            var hmac = ComputeContainerHmac(1, nonce, nowUtc, cipherBase64);

            var container = new SealedConfigContainer
            {
                Version = 1,
                Nonce = nonce,
                UpdatedAtUtc = nowUtc,
                CipherPayload = cipherBase64,
                HmacSha256 = hmac
            };

            var serialized = JsonSerializer.SerializeToUtf8Bytes(container, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            _cachedSealedBytes = serialized;
            File.WriteAllBytes(_primaryFilePath, serialized);
            File.WriteAllBytes(_backupFilePath, serialized);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "保存密封权限配置失败。");
        }
    }

    private byte[] GetMachineBindingMaterial()
    {
        var cuid = string.Empty;
        try
        {
            cuid = IAppHost.TryGetService<IManagementService>()?.Persist.ClientUniqueId.ToString() ?? string.Empty;
        }
        catch
        {
            // Ignore when host is not yet built
        }

        var raw = $"MCI-SEAL-V1|{Environment.MachineName}|{Environment.UserName}|{ _primaryFilePath.ToLowerInvariant() }|{cuid}";
        return SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    }

    private string ComputeContainerHmac(int version, string nonce, long updatedAtUtc, string cipherPayload)
    {
        var key = GetMachineBindingMaterial();
        var data = Encoding.UTF8.GetBytes($"V{version}|{nonce}|{updatedAtUtc}|{cipherPayload}");
        using var hmac = new HMACSHA256(key);
        return Convert.ToHexString(hmac.ComputeHash(data));
    }

    private byte[] ProtectBytes(byte[] plainBytes, string nonce)
    {
        var entropy = SHA256.HashData(Encoding.UTF8.GetBytes($"MCI-DPAPI-ENTROPY|{nonce}|{_primaryFilePath}"));
        if (OperatingSystem.IsWindows())
        {
            if (TryDpapiProtect(plainBytes, entropy, out var dpapiOut))
            {
                return dpapiOut;
            }
        }
        return AesGcmEncrypt(plainBytes, entropy);
    }

    private byte[] UnprotectBytes(byte[] cipherBytes, string nonce)
    {
        var entropy = SHA256.HashData(Encoding.UTF8.GetBytes($"MCI-DPAPI-ENTROPY|{nonce}|{_primaryFilePath}"));
        if (OperatingSystem.IsWindows())
        {
            if (TryDpapiUnprotect(cipherBytes, entropy, out var dpapiPlain))
            {
                return dpapiPlain;
            }
        }
        return AesGcmDecrypt(cipherBytes, entropy);
    }

    private byte[] AesGcmEncrypt(byte[] plainBytes, byte[] associatedEntropy)
    {
        var key = GetMachineBindingMaterial();
        var iv = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[plainBytes.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(iv, plainBytes, cipher, tag, associatedEntropy);

        var output = new byte[12 + 16 + cipher.Length];
        Buffer.BlockCopy(iv, 0, output, 0, 12);
        Buffer.BlockCopy(tag, 0, output, 12, 16);
        Buffer.BlockCopy(cipher, 0, output, 28, cipher.Length);
        return output;
    }

    private byte[] AesGcmDecrypt(byte[] combined, byte[] associatedEntropy)
    {
        if (combined.Length < 28)
        {
            throw new CryptographicException("密文长度无效。");
        }

        var key = GetMachineBindingMaterial();
        var iv = new byte[12];
        var tag = new byte[16];
        var cipher = new byte[combined.Length - 28];

        Buffer.BlockCopy(combined, 0, iv, 0, 12);
        Buffer.BlockCopy(combined, 12, tag, 0, 16);
        Buffer.BlockCopy(combined, 28, cipher, 0, cipher.Length);

        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(iv, cipher, tag, plain, associatedEntropy);
        return plain;
    }

    #region Windows Native DPAPI (crypt32.dll)

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string? szDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        IntPtr ppszDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

    private static bool TryDpapiProtect(byte[] plainBytes, byte[] entropyBytes, out byte[] protectedBytes)
    {
        protectedBytes = [];
        var inHandle = GCHandle.Alloc(plainBytes, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(entropyBytes, GCHandleType.Pinned);
        try
        {
            var dataIn = new DATA_BLOB
            {
                cbData = plainBytes.Length,
                pbData = inHandle.AddrOfPinnedObject()
            };
            var entropyBlob = new DATA_BLOB
            {
                cbData = entropyBytes.Length,
                pbData = entropyHandle.AddrOfPinnedObject()
            };

            if (!CryptProtectData(ref dataIn, "MCI_ExtendManagement", ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, out var dataOut))
            {
                return false;
            }

            try
            {
                protectedBytes = new byte[dataOut.cbData];
                Marshal.Copy(dataOut.pbData, protectedBytes, 0, dataOut.cbData);
                return true;
            }
            finally
            {
                if (dataOut.pbData != IntPtr.Zero)
                {
                    LocalFree(dataOut.pbData);
                }
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            inHandle.Free();
            entropyHandle.Free();
        }
    }

    private static bool TryDpapiUnprotect(byte[] cipherBytes, byte[] entropyBytes, out byte[] plainBytes)
    {
        plainBytes = [];
        var inHandle = GCHandle.Alloc(cipherBytes, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(entropyBytes, GCHandleType.Pinned);
        try
        {
            var dataIn = new DATA_BLOB
            {
                cbData = cipherBytes.Length,
                pbData = inHandle.AddrOfPinnedObject()
            };
            var entropyBlob = new DATA_BLOB
            {
                cbData = entropyBytes.Length,
                pbData = entropyHandle.AddrOfPinnedObject()
            };

            if (!CryptUnprotectData(ref dataIn, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, out var dataOut))
            {
                return false;
            }

            try
            {
                plainBytes = new byte[dataOut.cbData];
                Marshal.Copy(dataOut.pbData, plainBytes, 0, dataOut.cbData);
                return true;
            }
            finally
            {
                if (dataOut.pbData != IntPtr.Zero)
                {
                    LocalFree(dataOut.pbData);
                }
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            inHandle.Free();
            entropyHandle.Free();
        }
    }

    #endregion
}
