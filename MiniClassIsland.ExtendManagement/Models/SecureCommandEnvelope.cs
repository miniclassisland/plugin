using System.Text.Json;
using System.Text.Json.Serialization;

namespace MiniClassIsland.ExtendManagement.Models;

/// <summary>
/// 集控服务器下发的端到端签名指令信封。
/// </summary>
public sealed class SignedCommandEnvelope
{
    /// <summary>
    /// 协议版本号，当前为 1。
    /// </summary>
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    /// <summary>
    /// 指令唯一请求 GUID（用于防重放与 ConfigUpload 回传关联）。
    /// </summary>
    [JsonPropertyName("requestGuid")]
    public string RequestGuid { get; set; } = string.Empty;

    /// <summary>
    /// 目标客户端唯一标识（必须与当前实例 ClientUniqueId 一致）。
    /// 支持广播标识 "*" 仅限只读低敏指令。
    /// </summary>
    [JsonPropertyName("clientUid")]
    public string ClientUid { get; set; } = string.Empty;

    /// <summary>
    /// 指令签发 UTC 秒级时间戳。
    /// </summary>
    [JsonPropertyName("issuedAtUtc")]
    public long IssuedAtUtc { get; set; }

    /// <summary>
    /// 指令过期 UTC 秒级时间戳（默认签发后 60~120 秒内有效）。
    /// </summary>
    [JsonPropertyName("expiresAtUtc")]
    public long ExpiresAtUtc { get; set; }

    /// <summary>
    /// 指令动作名称（如 hardware.get_info, settings.patch, profile.put, remote.exec_code 等）。
    /// </summary>
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// 业务参数 JSON 字符串。
    /// </summary>
    [JsonPropertyName("payloadJson")]
    public string PayloadJson { get; set; } = "{}";

    /// <summary>
    /// 服务端使用 ServerKey 私钥对规范化主体生成的 OpenPGP 签名（detached armored signature 或 clear-signed）。
    /// </summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;

    /// <summary>
    /// 构造用于签名的规范化字符串：
    /// MCI-EXTCMD-V1|{Version}|{RequestGuid}|{ClientUid}|{IssuedAtUtc}|{ExpiresAtUtc}|{Action}|{SHA256(PayloadJson)}
    /// </summary>
    public string BuildCanonicalSigningText(string payloadSha256Hex)
    {
        return $"MCI-EXTCMD-V1|{Version}|{RequestGuid.Trim()}|{ClientUid.Trim()}|{IssuedAtUtc}|{ExpiresAtUtc}|{Action.Trim().ToLowerInvariant()}|{payloadSha256Hex.ToLowerInvariant()}";
    }
}

/// <summary>
/// 客户端执行扩展指令后的响应信封（通过 ConfigUpload 或 Uplink 回传）。
/// </summary>
public sealed class CommandExecutionResponse
{
    [JsonPropertyName("requestGuid")]
    public string RequestGuid { get; set; } = string.Empty;

    [JsonPropertyName("clientUid")]
    public string ClientUid { get; set; } = string.Empty;

    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("code")]
    public string Code { get; set; } = "OK";

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("respondedAtUtc")]
    public long RespondedAtUtc { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    [JsonPropertyName("data")]
    public JsonElement? Data { get; set; }

    [JsonPropertyName("integritySha256")]
    public string IntegritySha256 { get; set; } = string.Empty;
}
