using System.Reflection;
using System.Text;
using System.Text.Json;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Shared;
using PgpCore;

namespace MiniClassIsland.ExtendManagement.Services;

/// <summary>
/// 宿主运行时桥接器。
/// 基于 ClassIsland.PluginSdk 2.0.0.1 公共契约，提供对宿主程序集（ClassIsland.dll）内部服务、路径和状态的无耦合访问。
/// </summary>
public static class HostRuntimeBridge
{
    private static Assembly? _hostAssembly;

    public static string ManagementPresetPath =>
        Path.Combine(CommonDirectories.AppRootFolderPath, "ManagementPreset.json");

    public static string ManagementConfigureFolderPath =>
        Path.Combine(CommonDirectories.AppDataFolderPath, "Management");

    public static string ManagementManifestPath =>
        Path.Combine(ManagementConfigureFolderPath, "Manifest.json");

    public static string ManagementSettingsPath =>
        Path.Combine(ManagementConfigureFolderPath, "Settings.json");

    public static string ManagementPolicyPath =>
        Path.Combine(ManagementConfigureFolderPath, "Policy.json");

    public static string ManagementCredentialsPath =>
        Path.Combine(ManagementConfigureFolderPath, "Credentials.json");

    public static string ManagementComponentsPath =>
        Path.Combine(ManagementConfigureFolderPath, "Components.json");

    public static string ServerPublicKeyPath =>
        Path.Combine(ManagementConfigureFolderPath, "ServerKey.asc");

    public static string PluginsPkgRootPath =>
        Path.Combine(CommonDirectories.AppCacheFolderPath, "PluginPackages");

    public static Assembly? GetHostAssembly()
    {
        if (_hostAssembly != null)
        {
            return _hostAssembly;
        }

        _hostAssembly = AppDomain.CurrentDomain.GetAssemblies()
            .FirstOrDefault(a => string.Equals(a.GetName().Name, "ClassIsland", StringComparison.OrdinalIgnoreCase));
        return _hostAssembly;
    }

    public static Type? GetHostType(string fullName)
    {
        return GetHostAssembly()?.GetType(fullName, throwOnError: false, ignoreCase: false);
    }

    public static object? TryGetHostService(string fullTypeName)
    {
        try
        {
            var type = GetHostType(fullTypeName);
            if (type == null)
            {
                return null;
            }
            return IAppHost.Host?.Services.GetService(type);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 获取宿主的 SettingsService 实例。
    /// </summary>
    public static object? GetSettingsService()
    {
        return TryGetHostService("ClassIsland.Services.SettingsService");
    }

    /// <summary>
    /// 获取宿主的 Settings 实例。
    /// </summary>
    public static object? GetSettingsObject()
    {
        var svc = GetSettingsService();
        if (svc == null)
        {
            return null;
        }
        return svc.GetType().GetProperty("Settings", BindingFlags.Instance | BindingFlags.Public)?.GetValue(svc);
    }

    /// <summary>
    /// 读取 Settings 对象上的指定属性值。
    /// </summary>
    public static T? GetSettingValue<T>(string propertyName, T? defaultValue = default)
    {
        try
        {
            var settings = GetSettingsObject();
            if (settings == null)
            {
                return defaultValue;
            }
            var prop = settings.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
            if (prop == null)
            {
                return defaultValue;
            }
            var val = prop.GetValue(settings);
            if (val is T typed)
            {
                return typed;
            }
            return defaultValue;
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// 设置 Settings 对象上的指定属性值。
    /// </summary>
    public static bool SetSettingValue(string propertyName, object? value)
    {
        try
        {
            var settings = GetSettingsObject();
            if (settings == null)
            {
                return false;
            }
            var prop = settings.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
            if (prop == null || !prop.CanWrite)
            {
                return false;
            }
            prop.SetValue(settings, value);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 调用 SettingsService.SaveSettings(note)。
    /// </summary>
    public static void SaveSettings(string note = "")
    {
        try
        {
            var svc = GetSettingsService();
            if (svc == null)
            {
                return;
            }
            var method = svc.GetType().GetMethod("SaveSettings", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            method?.Invoke(svc, [note]);
        }
        catch
        {
            // Ignore
        }
    }

    /// <summary>
    /// 调用 SettingsService.AddSettingsOverlay(guid, propertyName, value)。
    /// </summary>
    public static bool AddSettingsOverlay(string guid, string propertyName, object? value)
    {
        try
        {
            var svcType = GetHostType("ClassIsland.Services.SettingsService");
            var method = svcType?.GetMethod("AddSettingsOverlay", BindingFlags.Static | BindingFlags.Public);
            if (method == null)
            {
                return false;
            }
            method.Invoke(null, [guid, propertyName, value]);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 调用 SettingsService.RemoveSettingsOverlay(guid, propertyName)。
    /// </summary>
    public static bool RemoveSettingsOverlay(string guid, string propertyName)
    {
        try
        {
            var svcType = GetHostType("ClassIsland.Services.SettingsService");
            var method = svcType?.GetMethod("RemoveSettingsOverlay", BindingFlags.Static | BindingFlags.Public);
            if (method == null)
            {
                return false;
            }
            method.Invoke(null, [guid, propertyName]);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 获取宿主的 UpdateService 实例。
    /// </summary>
    public static object? GetUpdateService()
    {
        return TryGetHostService("ClassIsland.Services.AppUpdating.UpdateService");
    }

    /// <summary>
    /// 检查宿主 App.IsCrashed 状态。
    /// </summary>
    public static bool IsAppCrashed()
    {
        try
        {
            var appType = GetHostType("ClassIsland.App");
            var prop = appType?.GetProperty("IsCrashed", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
            return prop?.GetValue(null) is true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 判断当前连接的集控服务端是否具备 MINI ClassIsland 特征。
    /// 多维特征判定依据（满足其一即确认）：
    /// 1. 集控服务器地址、gRPC 地址包含 miniclassisland / miniopensource，或组织名称包含 MINI ClassIsland；
    /// 2. 密封存储中已记录当前服务端地址通过了 MINI ClassIsland 协议握手或响应头校验（X-MiniClassIsland-Server / ServerFlavor）；
    /// 3. 本地 Manifest.json 包含 ServerFlavor / ServerSoftware 为 miniclassisland；
    /// 4. 本地 ServerKey.asc 的 OpenPGP 公钥 UserID 数据包或装甲注释头包含 MINI ClassIsland / miniclassisland 标识。
    /// </summary>
    public static bool IsJoinedMiniClassIslandServer(IManagementService managementService)
    {
        if (!managementService.IsManagementEnabled)
        {
            return false;
        }

        var server = (managementService.Settings.ManagementServer ?? string.Empty).Trim().TrimEnd('/');
        var grpc = (managementService.Settings.ManagementServerGrpc ?? string.Empty).Trim().TrimEnd('/');
        var orgName = managementService.Manifest.OrganizationName ?? string.Empty;

        if (ContainsMiniClassIslandMarker(server) ||
            ContainsMiniClassIslandMarker(grpc) ||
            orgName.Contains("MINI ClassIsland", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        try
        {
            var store = IAppHost.TryGetService<Security.TamperEvidentConfigStore>();
            if (store != null)
            {
                var cfg = store.CurrentConfig;
                if (cfg.IsVerifiedMiniServer &&
                    !string.IsNullOrWhiteSpace(cfg.VerifiedMiniServerUrl) &&
                    (string.Equals(cfg.VerifiedMiniServerUrl.TrimEnd('/'), server, StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(cfg.VerifiedMiniServerUrl.TrimEnd('/'), grpc, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }

                if (!string.IsNullOrWhiteSpace(cfg.LastTenantSlug))
                {
                    var resolved = Networking.PairingDialogEnhancer.ResolveTenantServerUrl(cfg.LastTenantSlug, cfg.DefaultBaseDomain);
                    if (!string.IsNullOrWhiteSpace(resolved) &&
                        (string.Equals(resolved.TrimEnd('/'), server, StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(resolved.TrimEnd('/'), grpc, StringComparison.OrdinalIgnoreCase)))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }

        if (InspectManifestFileForMiniMarker(out var manifestFlavor, out var manifestDisplayName, out var manifestClientId))
        {
            MarkServerAsVerifiedMiniServer(
                server,
                verified: true,
                serverFlavor: manifestFlavor,
                clientDisplayName: manifestDisplayName,
                clientIdentity: manifestClientId);
            return true;
        }

        if (InspectServerPublicKeyForMiniMarker(out var keyFlavor))
        {
            MarkServerAsVerifiedMiniServer(
                server,
                verified: true,
                serverFlavor: keyFlavor);
            return true;
        }

        return false;
    }

    public static event EventHandler? ServerMetadataUpdated;

    public static void MarkServerAsVerifiedMiniServer(
        string? serverUrl,
        bool verified = true,
        string? serverFlavor = null,
        string? clientDisplayName = null,
        string? clientIdentity = null)
    {
        try
        {
            var normalized = (serverUrl ?? string.Empty).Trim().TrimEnd('/');
            var store = IAppHost.TryGetService<Security.TamperEvidentConfigStore>();
            store?.UpdateNetworkMetadata(
                verifiedMiniServerUrl: string.IsNullOrWhiteSpace(normalized) ? null : normalized,
                isVerifiedMiniServer: verified,
                verifiedMiniServerFlavor: serverFlavor,
                serverClientDisplayName: clientDisplayName,
                serverClientIdentity: clientIdentity);
            ServerMetadataUpdated?.Invoke(null, EventArgs.Empty);
        }
        catch
        {
            // Ignore
        }
    }

    public static string GetMiniServerDisplayKind(IManagementService managementService)
    {
        if (!IsJoinedMiniClassIslandServer(managementService))
        {
            return managementService.Manifest.ServerKind.ToString();
        }

        try
        {
            var store = IAppHost.TryGetService<Security.TamperEvidentConfigStore>();
            var flavor = store?.CurrentConfig.VerifiedMiniServerFlavor ?? string.Empty;
            if (flavor.Contains("ste", StringComparison.OrdinalIgnoreCase))
            {
                return "MINI ClassIsland STE";
            }

            if (InspectManifestFileForMiniMarker(out var manifestFlavor, out _, out _) &&
                manifestFlavor != null &&
                manifestFlavor.Contains("ste", StringComparison.OrdinalIgnoreCase))
            {
                store?.UpdateNetworkMetadata(verifiedMiniServerFlavor: manifestFlavor);
                return "MINI ClassIsland STE";
            }

            if (InspectServerPublicKeyForMiniMarker(out var keyFlavor) &&
                keyFlavor != null &&
                keyFlavor.Contains("ste", StringComparison.OrdinalIgnoreCase))
            {
                store?.UpdateNetworkMetadata(verifiedMiniServerFlavor: keyFlavor);
                return "MINI ClassIsland STE";
            }
        }
        catch
        {
            // Ignore
        }

        return "MINI ClassIsland";
    }

    public static string GetServerClientDisplayName()
    {
        try
        {
            var store = IAppHost.TryGetService<Security.TamperEvidentConfigStore>();
            var cached = store?.CurrentConfig.ServerClientDisplayName?.Trim();
            if (!string.IsNullOrWhiteSpace(cached))
            {
                return cached;
            }

            if (File.Exists(ManagementManifestPath))
            {
                var raw = File.ReadAllText(ManagementManifestPath, Encoding.UTF8);
                using var doc = JsonDocument.Parse(raw);
                var root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object)
                {
                    foreach (var key in new[] { "ClientDisplayName", "clientDisplayName", "client_display_name", "DisplayName", "display_name" })
                    {
                        if (root.TryGetProperty(key, out var prop) && prop.ValueKind == JsonValueKind.String)
                        {
                            var val = prop.GetString()?.Trim();
                            if (!string.IsNullOrWhiteSpace(val))
                            {
                                store?.UpdateNetworkMetadata(serverClientDisplayName: val);
                                return val;
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }

        return "未命名设备";
    }

    public static string GetEffectiveClientIdentity(IManagementService managementService)
    {
        var localId = managementService.Settings.ClassIdentity?.Trim();
        if (!string.IsNullOrWhiteSpace(localId))
        {
            return localId;
        }

        try
        {
            var store = IAppHost.TryGetService<Security.TamperEvidentConfigStore>();
            var serverId = store?.CurrentConfig.ServerClientIdentity?.Trim();
            if (!string.IsNullOrWhiteSpace(serverId))
            {
                return serverId;
            }
        }
        catch
        {
            // Ignore
        }

        return "未设置";
    }

    public static bool InspectHttpResponseForMiniMarker(HttpResponseMessage response, string? rawJsonBody = null)
    {
        var isMini = false;
        string? detectedFlavor = null;
        string? detectedDisplayName = null;
        string? detectedClientId = null;

        try
        {
            if (response.Headers.TryGetValues("X-Server-Flavor", out var flavorHeaders))
            {
                foreach (var v in flavorHeaders)
                {
                    if (!string.IsNullOrWhiteSpace(v))
                    {
                        if (v.Contains("ste", StringComparison.OrdinalIgnoreCase))
                        {
                            isMini = true;
                            detectedFlavor = "miniclassisland-ste";
                        }
                        else if (ContainsMiniClassIslandMarker(v))
                        {
                            isMini = true;
                            detectedFlavor ??= "miniclassisland";
                        }
                    }
                }
            }

            if (response.Headers.TryGetValues("X-MiniClassIsland-Server", out var headerValues))
            {
                foreach (var v in headerValues)
                {
                    if (!string.IsNullOrWhiteSpace(v) && v != "0" && !string.Equals(v, "false", StringComparison.OrdinalIgnoreCase))
                    {
                        isMini = true;
                        if (v.Contains("ste", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedFlavor = "miniclassisland-ste";
                        }
                        else if (detectedFlavor == null)
                        {
                            detectedFlavor = "miniclassisland";
                        }
                    }
                }
            }

            if (response.Headers.TryGetValues("X-Powered-By", out var poweredValues) &&
                poweredValues.Any(ContainsMiniClassIslandMarker))
            {
                isMini = true;
            }

            if (!string.IsNullOrWhiteSpace(rawJsonBody))
            {
                if (InspectJsonForMiniMarker(rawJsonBody, out var jsonFlavor, out var jsonDisplayName, out var jsonClientId))
                {
                    isMini = true;
                }
                if (!string.IsNullOrWhiteSpace(jsonFlavor))
                {
                    detectedFlavor = jsonFlavor;
                }
                if (!string.IsNullOrWhiteSpace(jsonDisplayName))
                {
                    detectedDisplayName = jsonDisplayName;
                }
                if (jsonClientId != null)
                {
                    detectedClientId = jsonClientId;
                }
            }

            if (isMini || detectedFlavor != null || detectedDisplayName != null || detectedClientId != null)
            {
                var store = IAppHost.TryGetService<Security.TamperEvidentConfigStore>();
                store?.UpdateNetworkMetadata(
                    isVerifiedMiniServer: isMini ? true : null,
                    verifiedMiniServerFlavor: detectedFlavor,
                    serverClientDisplayName: detectedDisplayName,
                    serverClientIdentity: detectedClientId);
                ServerMetadataUpdated?.Invoke(null, EventArgs.Empty);
            }
        }
        catch
        {
            // Ignore
        }
        return isMini;
    }

    public static bool InspectJsonForMiniMarker(string rawJson)
    {
        return InspectJsonForMiniMarker(rawJson, out _, out _, out _);
    }

    public static bool InspectJsonForMiniMarker(
        string rawJson,
        out string? detectedFlavor,
        out string? clientDisplayName,
        out string? clientIdentity)
    {
        detectedFlavor = null;
        clientDisplayName = null;
        clientIdentity = null;
        var isMini = false;

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (var nameKey in new[] { "ClientDisplayName", "clientDisplayName", "client_display_name" })
            {
                if (root.TryGetProperty(nameKey, out var nProp) && nProp.ValueKind == JsonValueKind.String)
                {
                    var val = nProp.GetString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(val))
                    {
                        clientDisplayName = val;
                        break;
                    }
                }
            }

            foreach (var idKey in new[] { "ClientIdentity", "clientIdentity", "client_identity", "client_id" })
            {
                if (root.TryGetProperty(idKey, out var idProp) && idProp.ValueKind == JsonValueKind.String)
                {
                    clientIdentity = idProp.GetString()?.Trim() ?? string.Empty;
                    break;
                }
            }

            string[] candidateKeys = ["ServerFlavor", "serverFlavor", "server_flavor", "ServerSoftware", "serverSoftware", "ServerProvider"];
            foreach (var key in candidateKeys)
            {
                if (root.TryGetProperty(key, out var prop) &&
                    prop.ValueKind == JsonValueKind.String)
                {
                    var val = prop.GetString();
                    if (ContainsMiniClassIslandMarker(val))
                    {
                        isMini = true;
                        if (val != null && val.Contains("ste", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedFlavor = "miniclassisland-ste";
                        }
                        else if (detectedFlavor == null)
                        {
                            detectedFlavor = "miniclassisland";
                        }
                    }
                }
            }

            if (root.TryGetProperty("MiniClassIsland", out var boolProp) && boolProp.ValueKind == JsonValueKind.True)
            {
                isMini = true;
                detectedFlavor ??= "miniclassisland";
            }
        }
        catch
        {
            // Ignore
        }
        return isMini;
    }

    private static bool InspectManifestFileForMiniMarker(
        out string? detectedFlavor,
        out string? clientDisplayName,
        out string? clientIdentity)
    {
        detectedFlavor = null;
        clientDisplayName = null;
        clientIdentity = null;
        try
        {
            if (!File.Exists(ManagementManifestPath))
            {
                return false;
            }

            var rawJson = File.ReadAllText(ManagementManifestPath, Encoding.UTF8);
            return InspectJsonForMiniMarker(rawJson, out detectedFlavor, out clientDisplayName, out clientIdentity);
        }
        catch
        {
            return false;
        }
    }

    private static bool InspectServerPublicKeyForMiniMarker(out string? detectedFlavor)
    {
        detectedFlavor = null;
        try
        {
            if (!File.Exists(ServerPublicKeyPath))
            {
                return false;
            }

            var keyText = File.ReadAllText(ServerPublicKeyPath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(keyText))
            {
                return false;
            }

            var isMini = false;
            // 1. 检查 Armored 头部注释
            if (ContainsMiniClassIslandMarker(keyText))
            {
                isMini = true;
                if (keyText.Contains("miniclassisland-ste", StringComparison.OrdinalIgnoreCase) ||
                    keyText.Contains("MINI ClassIsland STE", StringComparison.OrdinalIgnoreCase))
                {
                    detectedFlavor = "miniclassisland-ste";
                }
                else
                {
                    detectedFlavor = "miniclassisland";
                }
            }

            // 2. 解析 OpenPGP 二进制数据包中的 UserID（Base64 解码后的真实签名者信息）
            var encryptionKeys = new EncryptionKeys(keyText);
            foreach (var pubKey in encryptionKeys.PublicKeys)
            {
                foreach (var userIdObj in pubKey.GetUserIds())
                {
                    var uidStr = userIdObj?.ToString();
                    if (ContainsMiniClassIslandMarker(uidStr) ||
                        (uidStr != null && uidStr.Contains("CyreneMSP Server", StringComparison.OrdinalIgnoreCase)))
                    {
                        isMini = true;
                        if (uidStr != null &&
                            (uidStr.Contains("miniclassisland-ste", StringComparison.OrdinalIgnoreCase) ||
                             uidStr.Contains("MINI ClassIsland STE", StringComparison.OrdinalIgnoreCase) ||
                             uidStr.Contains("ste@miniclassisland", StringComparison.OrdinalIgnoreCase)))
                        {
                            detectedFlavor = "miniclassisland-ste";
                        }
                        else
                        {
                            detectedFlavor ??= "miniclassisland";
                        }
                    }
                }
            }

            return isMini;
        }
        catch
        {
            // Ignore malformed key
        }
        return false;
    }

    private static bool ContainsMiniClassIslandMarker(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return text.Contains("miniclassisland", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("MINI ClassIsland", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("MINI-ClassIsland", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("miniopensource", StringComparison.OrdinalIgnoreCase);
    }
}
