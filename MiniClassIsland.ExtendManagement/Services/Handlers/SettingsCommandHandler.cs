using System.Reflection;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core.Abstractions.Services.Management;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Networking;
using MiniClassIsland.ExtendManagement.Security;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// 应用设置管理处理器（settings.get, settings.patch, settings.sync_default, settings.set_overlay, settings.remove_overlay, settings.app_lock）。
/// 修复上游仅在 OOBE 前拉取一次 DefaultSettingsSource 的缺陷，并支持运行时增量变更、Overlay 锁定与服务端受控应用锁定。
/// </summary>
public sealed class SettingsCommandHandler(
    ILogger<SettingsCommandHandler> logger,
    IManagementService managementService,
    NetworkRoamingCoordinator roamingCoordinator,
    AppLockService appLockService)
{
    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "settings.get" => await GetSettingsSnapshotAsync(),
            "settings.patch" => await PatchSettingsAsync(payload),
            "settings.sync_default" => await SyncDefaultSettingsFromServerAsync(force: true),
            "settings.set_overlay" => await SetSettingsOverlayAsync(payload),
            "settings.remove_overlay" => await RemoveSettingsOverlayAsync(payload),
            "settings.app_lock" or "settings.set_app_lock" => ExecuteAppLockCommand(normalized, payload),
            _ => throw new NotSupportedException($"不支持的设置指令：{action}")
        };
    }

    public JsonElement ExecuteAppLockCommand(string action, JsonElement payload)
    {
        var normalized = action.Trim().ToLowerInvariant();
        if (normalized is "lock.status" or "app.lock_status")
        {
            return JsonSerializer.SerializeToElement(new
            {
                isAppLocked = appLockService.IsEffectiveAppLocked
            });
        }

        bool targetLockState;
        if (normalized is "lock.enable" or "app.lock")
        {
            targetLockState = true;
            if (payload.ValueKind == JsonValueKind.Object &&
                TryReadBooleanProperty(payload, out var explicitBool, "locked", "isAppLocked", "enabled", "value"))
            {
                targetLockState = explicitBool;
            }
        }
        else if (normalized is "lock.disable" or "app.unlock")
        {
            targetLockState = false;
        }
        else
        {
            if (payload.ValueKind == JsonValueKind.True || payload.ValueKind == JsonValueKind.False)
            {
                targetLockState = payload.GetBoolean();
            }
            else if (payload.ValueKind == JsonValueKind.Object &&
                     TryReadBooleanProperty(payload, out var parsed, "locked", "isAppLocked", "enabled", "value"))
            {
                targetLockState = parsed;
            }
            else
            {
                targetLockState = true;
            }
        }

        appLockService.SetAppLockedFromServer(targetLockState, $"服务端远程指令 ({normalized})");
        return JsonSerializer.SerializeToElement(new
        {
            updated = true,
            isAppLocked = appLockService.IsEffectiveAppLocked,
            requestedState = targetLockState
        });
    }

    private static bool TryReadBooleanProperty(JsonElement obj, out bool result, params string[] candidateNames)
    {
        foreach (var prop in obj.EnumerateObject())
        {
            if (candidateNames.Any(c => string.Equals(prop.Name, c, StringComparison.OrdinalIgnoreCase)))
            {
                if (prop.Value.ValueKind == JsonValueKind.True)
                {
                    result = true;
                    return true;
                }
                if (prop.Value.ValueKind == JsonValueKind.False)
                {
                    result = false;
                    return true;
                }
            }
        }
        result = false;
        return false;
    }

    public async Task<JsonElement> SyncDefaultSettingsFromServerAsync(bool force = false)
    {
        if (!managementService.IsManagementEnabled)
        {
            return JsonSerializer.SerializeToElement(new { synced = false, reason = "未启用集控" });
        }

        var src = managementService.Manifest.DefaultSettingsSource;
        if (string.IsNullOrWhiteSpace(src.Value))
        {
            return JsonSerializer.SerializeToElement(new { synced = false, reason = "集控未配置 DefaultSettingsSource" });
        }

        if (!force && !src.IsNewerAndNotNull(managementService.Versions.DefaultSettingsVersion))
        {
            return JsonSerializer.SerializeToElement(new { synced = false, reason = "当前已是最新版本" });
        }

        var remoteJson = await roamingCoordinator.GetJsonWithSessionAsync<JsonElement>(src.Value!);
        if (remoteJson.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("远程默认设置格式无效。");
        }

        if (TryReadBooleanProperty(remoteJson, out var remoteAppLock, "IsAppLocked", "AppLockEnabled", "appLock"))
        {
            appLockService.SetAppLockedFromServer(remoteAppLock, "集控默认设置同步 (DefaultSettingsSource)");
        }

        var updatedProps = await ApplyJsonPatchToSettingsObjectAsync(remoteJson);
        managementService.Versions.DefaultSettingsVersion = src.Version;
        logger.LogInformation("已同步集控默认设置（版本 {Version}），共更新 {Count} 项属性。", src.Version, updatedProps.Count);

        return JsonSerializer.SerializeToElement(new
        {
            synced = true,
            version = src.Version,
            updatedCount = updatedProps.Count,
            updatedProperties = updatedProps
        });
    }

    private static async Task<JsonElement> GetSettingsSnapshotAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var settings = HostRuntimeBridge.GetSettingsObject();
            return settings != null
                ? JsonSerializer.SerializeToElement(settings, settings.GetType())
                : JsonSerializer.SerializeToElement(new { });
        });
    }

    private async Task<JsonElement> PatchSettingsAsync(JsonElement payload)
    {
        var patchNode = payload.TryGetProperty("settings", out var inner) && inner.ValueKind == JsonValueKind.Object
            ? inner
            : payload;

        if (patchNode.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("settings.patch 需要提供 JSON 对象格式的设置键值。");
        }

        if (TryReadBooleanProperty(patchNode, out var patchedAppLock, "IsAppLocked", "AppLockEnabled", "appLock"))
        {
            appLockService.SetAppLockedFromServer(patchedAppLock, "settings.patch 增量更新");
        }

        var updated = await ApplyJsonPatchToSettingsObjectAsync(patchNode);
        return JsonSerializer.SerializeToElement(new
        {
            updatedCount = updated.Count,
            updatedProperties = updated
        });
    }

    private async Task<List<string>> ApplyJsonPatchToSettingsObjectAsync(JsonElement patchObject)
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var settings = HostRuntimeBridge.GetSettingsObject();
            if (settings == null)
            {
                return [];
            }

            var settingsType = settings.GetType();
            var updated = new List<string>();
            var isWelcomeShowed = HostRuntimeBridge.GetSettingValue("IsWelcomeWindowShowed", false);

            foreach (var prop in patchObject.EnumerateObject())
            {
                if (string.Equals(prop.Name, "IsWelcomeWindowShowed", StringComparison.OrdinalIgnoreCase) &&
                    isWelcomeShowed)
                {
                    continue;
                }

                var targetProp = settingsType.GetProperty(
                    prop.Name,
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);

                if (targetProp == null || !targetProp.CanWrite)
                {
                    continue;
                }

                try
                {
                    var deserializedVal = prop.Value.Deserialize(targetProp.PropertyType);
                    targetProp.SetValue(settings, deserializedVal);
                    updated.Add(targetProp.Name);
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "更新设置属性 {Property} 失败。", targetProp.Name);
                }
            }

            if (updated.Count > 0)
            {
                HostRuntimeBridge.SaveSettings("集控服务器远程变更应用设置");
            }

            return updated;
        });
    }

    private async Task<JsonElement> SetSettingsOverlayAsync(JsonElement payload)
    {
        var guid = payload.TryGetProperty("guid", out var gProp) && !string.IsNullOrWhiteSpace(gProp.GetString())
            ? gProp.GetString()!
            : "mci-management-overlay";

        if (!payload.TryGetProperty("values", out var valuesObj) || valuesObj.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("settings.set_overlay 需要包含 values 对象。");
        }

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var settings = HostRuntimeBridge.GetSettingsObject();
            if (settings == null)
            {
                return JsonSerializer.SerializeToElement(new { guid, appliedCount = 0 });
            }

            var settingsType = settings.GetType();
            var applied = new List<string>();

            foreach (var prop in valuesObj.EnumerateObject())
            {
                var targetProp = settingsType.GetProperty(
                    prop.Name,
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
                if (targetProp == null || !targetProp.CanWrite)
                {
                    continue;
                }

                try
                {
                    var val = prop.Value.Deserialize(targetProp.PropertyType);
                    if (HostRuntimeBridge.AddSettingsOverlay(guid, targetProp.Name, val))
                    {
                        applied.Add(targetProp.Name);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "设置覆盖层属性 {Property} 失败。", targetProp.Name);
                }
            }

            HostRuntimeBridge.SaveSettings("集控服务器应用设置覆盖层");
            return JsonSerializer.SerializeToElement(new
            {
                guid,
                appliedCount = applied.Count,
                appliedProperties = applied
            });
        });
    }

    private static async Task<JsonElement> RemoveSettingsOverlayAsync(JsonElement payload)
    {
        var guid = payload.TryGetProperty("guid", out var gProp) && !string.IsNullOrWhiteSpace(gProp.GetString())
            ? gProp.GetString()!
            : "mci-management-overlay";

        var properties = new List<string>();
        if (payload.TryGetProperty("properties", out var pArr) && pArr.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in pArr.EnumerateArray())
            {
                var name = item.GetString();
                if (!string.IsNullOrWhiteSpace(name))
                {
                    properties.Add(name);
                }
            }
        }

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            foreach (var propName in properties)
            {
                HostRuntimeBridge.RemoveSettingsOverlay(guid, propName);
            }
            HostRuntimeBridge.SaveSettings("集控服务器移除设置覆盖层");
            return JsonSerializer.SerializeToElement(new
            {
                guid,
                removedProperties = properties
            });
        });
    }
}
