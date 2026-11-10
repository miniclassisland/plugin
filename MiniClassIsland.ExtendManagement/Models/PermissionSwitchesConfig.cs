using System.Text.Json.Serialization;
using CommunityToolkit.Mvvm.ComponentModel;

namespace MiniClassIsland.ExtendManagement.Models;

/// <summary>
/// 客户端本地安全确认与网络锚定元数据模型。
/// 存储在经过 DPAPI 与 HMAC-SHA256 密封的防篡改容器中。
/// </summary>
public partial class PermissionSwitchesConfig : ObservableObject
{
    // ---- 首次安装安全风险警告确认标记 ----

    [ObservableProperty]
    private bool _hasAcceptedSecurityWarning = false;

    // ---- 网络与接入锚定元数据 ----

    [ObservableProperty]
    private string _anchoredMacAddress = string.Empty;

    [ObservableProperty]
    private string _defaultBaseDomain = "miniclassisland.com";

    [ObservableProperty]
    private string _lastTenantSlug = string.Empty;

    [ObservableProperty]
    private string _verifiedMiniServerUrl = string.Empty;

    [ObservableProperty]
    private bool _isVerifiedMiniServer = false;

    [ObservableProperty]
    private string _verifiedMiniServerFlavor = string.Empty;

    [ObservableProperty]
    private string _serverClientDisplayName = string.Empty;

    [ObservableProperty]
    private string _serverClientIdentity = string.Empty;

    // ---- 服务端受控应用锁定标记 ----

    [ObservableProperty]
    private bool _isAppLocked = false;

    public PermissionSwitchesConfig Clone()
    {
        return new PermissionSwitchesConfig
        {
            HasAcceptedSecurityWarning = HasAcceptedSecurityWarning,
            AnchoredMacAddress = AnchoredMacAddress,
            DefaultBaseDomain = DefaultBaseDomain,
            LastTenantSlug = LastTenantSlug,
            VerifiedMiniServerUrl = VerifiedMiniServerUrl,
            IsVerifiedMiniServer = IsVerifiedMiniServer,
            VerifiedMiniServerFlavor = VerifiedMiniServerFlavor,
            ServerClientDisplayName = ServerClientDisplayName,
            ServerClientIdentity = ServerClientIdentity,
            IsAppLocked = IsAppLocked
        };
    }
}

/// <summary>
/// 本地防篡改存储外壳结构。
/// </summary>
public sealed class SealedConfigContainer
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("updatedAtUtc")]
    public long UpdatedAtUtc { get; set; }

    [JsonPropertyName("cipherPayload")]
    public string CipherPayload { get; set; } = string.Empty;

    [JsonPropertyName("hmacSha256")]
    public string HmacSha256 { get; set; } = string.Empty;
}
