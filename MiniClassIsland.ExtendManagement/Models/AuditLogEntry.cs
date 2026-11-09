using System.Text.Json.Serialization;

namespace MiniClassIsland.ExtendManagement.Models;

/// <summary>
/// 扩展集控安全审计日志条目。
/// </summary>
public sealed class AuditLogEntry
{
    [JsonPropertyName("timestampUtc")]
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("requestGuid")]
    public string RequestGuid { get; set; } = string.Empty;

    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    [JsonPropertyName("tier")]
    public string Tier { get; set; } = "Base";

    [JsonPropertyName("allowed")]
    public bool Allowed { get; set; }

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;
}
