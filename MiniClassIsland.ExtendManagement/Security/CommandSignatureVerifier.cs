using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClassIsland.Core.Abstractions.Services.Management;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Models;
using MiniClassIsland.ExtendManagement.Services;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore;

namespace MiniClassIsland.ExtendManagement.Security;

/// <summary>
/// 集控指令端到端加密签名校验器与防重放守卫。
/// 要求所有扩展指令必须经过集控服务端私钥（对应客户端固化的 ServerKey.asc）签名，
/// 并强校验时间窗口、目标 ClientUid 与唯一 RequestGuid Nonce。
/// </summary>
public sealed class CommandSignatureVerifier
{
    private const long ClockSkewToleranceSeconds = 180;
    private const long MaxEnvelopeLifetimeSeconds = 600;
    private const int MaxReplayCacheEntries = 2048;

    private readonly ILogger<CommandSignatureVerifier> _logger;
    private readonly IManagementService _managementService;
    private readonly string _replayCachePath;
    private readonly ConcurrentDictionary<string, long> _consumedNonces = new(StringComparer.OrdinalIgnoreCase);
    private string? _cachedPublicKeyArmored;

    public CommandSignatureVerifier(
        ILogger<CommandSignatureVerifier> logger,
        IManagementService managementService,
        string pluginConfigFolder)
    {
        _logger = logger;
        _managementService = managementService;
        _replayCachePath = Path.Combine(pluginConfigFolder, "replay_nonces.json");
        LoadReplayCache();
    }

    /// <summary>
    /// 刷新并锁定集控服务端公钥快照。
    /// </summary>
    public string? GetTrustedServerPublicKey()
    {
        var keyPath = HostRuntimeBridge.ServerPublicKeyPath;
        if (File.Exists(keyPath))
        {
            try
            {
                var content = File.ReadAllText(keyPath, Encoding.UTF8);
                if (!string.IsNullOrWhiteSpace(content) && content.Contains("BEGIN PGP PUBLIC KEY BLOCK", StringComparison.Ordinal))
                {
                    _cachedPublicKeyArmored = content;
                    return content;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "读取 ServerKey.asc 失败。");
            }
        }
        return _cachedPublicKeyArmored;
    }

    /// <summary>
    /// 验证指令信封的完整性、时效性、目标绑定、防重放及服务端 PGP 签名。
    /// </summary>
    public async Task<(bool IsValid, string ErrorCode, string ErrorMessage)> VerifyEnvelopeAsync(SignedCommandEnvelope envelope)
    {
        if (envelope is null)
        {
            return (false, "ERR_EMPTY_ENVELOPE", "指令信封为空。");
        }

        if (string.IsNullOrWhiteSpace(envelope.RequestGuid) || envelope.RequestGuid.Length < 8)
        {
            return (false, "ERR_INVALID_REQUEST_GUID", "指令缺少有效的唯一请求标识。");
        }

        if (string.IsNullOrWhiteSpace(envelope.Action))
        {
            return (false, "ERR_INVALID_ACTION", "指令动作名称为空。");
        }

        // 1. 目标设备绑定校验
        var localUid = _managementService.Persist.ClientUniqueId.ToString();
        var targetUid = envelope.ClientUid.Trim();
        var isReadOnlyBroadcastAllowed = targetUid == "*" && IsBroadcastAllowedAction(envelope.Action);
        if (!isReadOnlyBroadcastAllowed && !string.Equals(targetUid, localUid, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "ERR_CLIENT_UID_MISMATCH", $"指令目标设备不匹配（目标：{targetUid}，本机：{localUid}）。");
        }

        // 2. 时间窗校验
        var nowUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (envelope.IssuedAtUtc <= 0 || envelope.ExpiresAtUtc <= 0 || envelope.ExpiresAtUtc < envelope.IssuedAtUtc)
        {
            return (false, "ERR_INVALID_TIMESTAMP", "指令时间戳无效。");
        }

        if (envelope.ExpiresAtUtc - envelope.IssuedAtUtc > MaxEnvelopeLifetimeSeconds)
        {
            return (false, "ERR_LIFETIME_TOO_LONG", "指令有效期超出安全上限。");
        }

        if (nowUtc < envelope.IssuedAtUtc - ClockSkewToleranceSeconds)
        {
            return (false, "ERR_ISSUED_IN_FUTURE", "指令签发时间超前于本机时钟。");
        }

        if (nowUtc > envelope.ExpiresAtUtc + ClockSkewToleranceSeconds)
        {
            return (false, "ERR_COMMAND_EXPIRED", "指令已过期。");
        }

        // 3. 防重放校验
        PruneExpiredNonces(nowUtc);
        if (_consumedNonces.ContainsKey(envelope.RequestGuid))
        {
            return (false, "ERR_REPLAY_DETECTED", "检测到重复的指令请求标识，已拒绝重放。");
        }

        // 4. OpenPGP 服务端公钥验签
        var pubKeyArmored = GetTrustedServerPublicKey();
        if (string.IsNullOrWhiteSpace(pubKeyArmored))
        {
            return (false, "ERR_SERVER_KEY_MISSING", "本地未找到集控服务器公钥 ServerKey.asc，无法验证指令签名。");
        }

        if (string.IsNullOrWhiteSpace(envelope.Signature))
        {
            return (false, "ERR_SIGNATURE_MISSING", "指令缺少集控服务器加密签名。");
        }

        var payloadBytes = Encoding.UTF8.GetBytes(envelope.PayloadJson ?? "{}");
        var payloadSha256Hex = Convert.ToHexString(SHA256.HashData(payloadBytes)).ToLowerInvariant();
        var canonicalText = envelope.BuildCanonicalSigningText(payloadSha256Hex);

        var signatureValid = await VerifyPgpSignatureAsync(canonicalText, envelope.Signature, pubKeyArmored);
        if (!signatureValid)
        {
            _logger.LogWarning("拒绝执行指令 {Action} ({RequestGuid})：集控服务器 PGP 签名验证失败。", envelope.Action, envelope.RequestGuid);
            return (false, "ERR_SIGNATURE_INVALID", "指令加密签名验证未通过。");
        }

        // 5. 标记 Nonce 已消费并持久化
        _consumedNonces[envelope.RequestGuid] = envelope.ExpiresAtUtc + ClockSkewToleranceSeconds;
        SaveReplayCache();

        return (true, "OK", string.Empty);
    }

    private static bool IsBroadcastAllowedAction(string action)
    {
        var normalized = action.Trim().ToLowerInvariant();
        return normalized is
            "hardware.get_info" or
            "settings.sync_default" or
            "profile.list" or
            "update.get_status" or
            "update.action" or
            "plugin.list" or
            "theme.list";
    }

    private async Task<bool> VerifyPgpSignatureAsync(string canonicalText, string signatureArmored, string publicKeyArmored)
    {
        try
        {
            var cleanPubKey = publicKeyArmored.TrimStart('\uFEFF').Trim();
            var cleanSig = signatureArmored.TrimStart('\uFEFF').Trim();

            if (cleanSig.Contains("BEGIN PGP SIGNED MESSAGE", StringComparison.Ordinal))
            {
                var encryptionKeys = new EncryptionKeys(cleanPubKey);
                using var pgp = new PGP(encryptionKeys);
                await using var clearStream = new MemoryStream(Encoding.UTF8.GetBytes(cleanSig));
                var verified = await pgp.VerifyClearStreamAsync(clearStream);
                if (!verified)
                {
                    return false;
                }
                return cleanSig.Contains(canonicalText, StringComparison.Ordinal);
            }

            if (cleanSig.Contains("BEGIN PGP SIGNATURE", StringComparison.Ordinal))
            {
                await using var keyStream = new MemoryStream(Encoding.UTF8.GetBytes(cleanPubKey));
                using var keyDecoder = PgpUtilities.GetDecoderStream(keyStream);
                var pgpPubRingBundle = new PgpPublicKeyRingBundle(keyDecoder);

                await using var sigStream = new MemoryStream(Encoding.UTF8.GetBytes(cleanSig));
                using var sigDecoder = PgpUtilities.GetDecoderStream(sigStream);
                var pgpFact = new PgpObjectFactory(sigDecoder);
                var nextObj = pgpFact.NextPgpObject();
                if (nextObj is PgpCompressedData compressedData)
                {
                    pgpFact = new PgpObjectFactory(compressedData.GetDataStream());
                    nextObj = pgpFact.NextPgpObject();
                }

                if (nextObj is not PgpSignatureList sigList || sigList.Count == 0)
                {
                    return false;
                }

                var dataBytes = Encoding.UTF8.GetBytes(canonicalText);
                for (var i = 0; i < sigList.Count; i++)
                {
                    var sig = sigList[i];
                    var pubKey = pgpPubRingBundle.GetPublicKey(sig.KeyId);
                    if (pubKey is null)
                    {
                        foreach (PgpPublicKeyRing ring in pgpPubRingBundle.GetKeyRings())
                        {
                            pubKey = ring.GetPublicKey();
                            if (pubKey is not null)
                            {
                                break;
                            }
                        }
                    }

                    if (pubKey is null)
                    {
                        continue;
                    }

                    sig.InitVerify(pubKey);
                    sig.Update(dataBytes, 0, dataBytes.Length);
                    if (sig.Verify())
                    {
                        return true;
                    }
                }

                return false;
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PGP 验签过程发生异常。");
            return false;
        }
    }

    private void PruneExpiredNonces(long nowUtc)
    {
        foreach (var kv in _consumedNonces)
        {
            if (kv.Value < nowUtc)
            {
                _consumedNonces.TryRemove(kv.Key, out _);
            }
        }

        if (_consumedNonces.Count > MaxReplayCacheEntries)
        {
            var oldest = _consumedNonces.OrderBy(x => x.Value).Take(_consumedNonces.Count - MaxReplayCacheEntries);
            foreach (var item in oldest)
            {
                _consumedNonces.TryRemove(item.Key, out _);
            }
        }
    }

    private void LoadReplayCache()
    {
        try
        {
            if (!File.Exists(_replayCachePath))
            {
                return;
            }
            var json = File.ReadAllText(_replayCachePath, Encoding.UTF8);
            var dict = JsonSerializer.Deserialize<Dictionary<string, long>>(json);
            if (dict == null)
            {
                return;
            }
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            foreach (var kv in dict.Where(kv => kv.Value >= now))
            {
                _consumedNonces[kv.Key] = kv.Value;
            }
        }
        catch
        {
            // Ignore corrupted cache
        }
    }

    private void SaveReplayCache()
    {
        try
        {
            var snapshot = _consumedNonces.ToDictionary(k => k.Key, v => v.Value);
            File.WriteAllText(_replayCachePath, JsonSerializer.Serialize(snapshot), Encoding.UTF8);
        }
        catch
        {
            // Ignore write errors
        }
    }
}
