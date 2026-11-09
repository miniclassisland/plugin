using System.Reflection;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Shared.Enums;
using MiniClassIsland.ExtendManagement.Security;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// [第一级受控能力] 客户端更新服务控制器（update.*）。
/// </summary>
public sealed class UpdateCommandHandler(SelfProtectionService selfProtectionService)
{
    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "update.get_status" => await GetUpdateStatusAsync(),
            "update.configure" => await ConfigureUpdateSettingsAsync(payload),
            "update.action" => await TriggerUpdateActionAsync(payload),
            _ => throw new NotSupportedException($"不支持的更新服务指令：{action}")
        };
    }

    private static async Task<JsonElement> GetUpdateStatusAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var updateService = HostRuntimeBridge.GetUpdateService();
            var workingStatus = GetPropValue(updateService, "CurrentWorkingStatus")?.ToString() ?? "Unknown";
            var downloadedCount = GetPropValue<int>(updateService, "DownloadedCount");
            var downloadingCountTotal = GetPropValue<int>(updateService, "DownloadingCountTotal");
            var totalSize = GetPropValue<long>(updateService, "TotalSize");
            var downloadedSize = GetPropValue<long>(updateService, "DownloadedSize");
            var downloadSpeed = GetPropValue<double>(updateService, "DownloadSpeed");
            var networkErr = (GetPropValue(updateService, "NetworkErrorException") as Exception)?.Message;

            return JsonSerializer.SerializeToElement(new
            {
                appVersion = AppBase.AppVersion,
                packagingType = AppBase.Current.PackagingType,
                subChannel = AppBase.Current.AppSubChannel,
                workingStatus,
                lastUpdateStatus = HostRuntimeBridge.GetSettingValue("LastUpdateStatus", UpdateStatus.UpToDate).ToString(),
                updateMode = HostRuntimeBridge.GetSettingValue("UpdateMode", 0),
                selectedChannel = HostRuntimeBridge.GetSettingValue("SelectedUpdateChannelV3", string.Empty),
                lastCheckUpdateTime = HostRuntimeBridge.GetSettingValue("LastCheckUpdateTime", DateTime.MinValue),
                downloadedCount,
                downloadingCountTotal,
                totalSize,
                downloadedSize,
                downloadSpeed,
                networkError = networkErr
            });
        });
    }

    private static async Task<JsonElement> ConfigureUpdateSettingsAsync(JsonElement payload)
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (payload.TryGetProperty("updateMode", out var modeProp) && modeProp.TryGetInt32(out var modeInt))
            {
                HostRuntimeBridge.SetSettingValue("UpdateMode", modeInt);
            }

            if (payload.TryGetProperty("channel", out var chProp) && !string.IsNullOrWhiteSpace(chProp.GetString()))
            {
                HostRuntimeBridge.SetSettingValue("SelectedUpdateChannelV3", chProp.GetString()!);
            }

            HostRuntimeBridge.SaveSettings("集控服务器调整应用更新策略");
            return JsonSerializer.SerializeToElement(new
            {
                updateMode = HostRuntimeBridge.GetSettingValue("UpdateMode", 0),
                selectedChannel = HostRuntimeBridge.GetSettingValue("SelectedUpdateChannelV3", string.Empty)
            });
        });
    }

    private async Task<JsonElement> TriggerUpdateActionAsync(JsonElement payload)
    {
        var updateService = HostRuntimeBridge.GetUpdateService()
                            ?? throw new InvalidOperationException("未找到客户端更新服务实例。");

        var operation = payload.TryGetProperty("operation", out var opProp)
            ? opProp.GetString()?.Trim().ToLowerInvariant()
            : "check";

        var force = payload.TryGetProperty("force", out var fProp) && fProp.ValueKind == JsonValueKind.True;

        switch (operation)
        {
            case "check":
                await InvokeTaskMethodAsync(updateService, "CheckUpdateAsync", [force, false]);
                return await GetUpdateStatusAsync();

            case "download":
                await InvokeTaskMethodAsync(updateService, "DownloadUpdateAsync", []);
                return await GetUpdateStatusAsync();

            case "extract" or "deploy":
                await InvokeTaskMethodAsync(updateService, "ExtractUpdateAsync", []);
                return await GetUpdateStatusAsync();

            case "stop":
                await InvokeTaskMethodAsync(updateService, "StopDownloading", []);
                return await GetUpdateStatusAsync();

            case "check_and_download":
                await InvokeTaskMethodAsync(updateService, "CheckUpdateAsync", [force, false]);
                if (HostRuntimeBridge.GetSettingValue("LastUpdateStatus", UpdateStatus.UpToDate) == UpdateStatus.UpdateAvailable)
                {
                    await InvokeTaskMethodAsync(updateService, "DownloadUpdateAsync", []);
                }
                return await GetUpdateStatusAsync();

            case "restart_to_update":
                selfProtectionService.GrantAuthorizedExit();
                await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    await InvokeTaskMethodAsync(updateService, "RestartAppToUpdateAsync", []);
                });
                return JsonSerializer.SerializeToElement(new { restarting = true });

            default:
                throw new ArgumentException($"未知的更新操作：{operation}");
        }
    }

    private static object? GetPropValue(object? obj, string name)
    {
        return obj?.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)?.GetValue(obj);
    }

    private static T? GetPropValue<T>(object? obj, string name)
    {
        var val = GetPropValue(obj, name);
        return val is T typed ? typed : default;
    }

    private static async Task InvokeTaskMethodAsync(object target, string methodName, object?[] args)
    {
        var method = target.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (method != null && method.Invoke(target, args) is Task task)
        {
            await task;
        }
    }
}
