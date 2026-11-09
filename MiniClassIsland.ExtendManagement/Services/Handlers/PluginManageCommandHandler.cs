using System.Security.Cryptography;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core.Abstractions.Services;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Networking;
using MiniClassIsland.ExtendManagement.Security;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// [第一级受控能力] 客户端插件管理处理器（plugin.*）。
/// </summary>
public sealed class PluginManageCommandHandler(
    ILogger<PluginManageCommandHandler> logger,
    IPluginMarketService pluginMarketService,
    NetworkRoamingCoordinator roamingCoordinator)
{
    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "plugin.list" => await ListPluginsAsync(),
            "plugin.install" => await InstallPluginAsync(payload),
            "plugin.set_enabled" => await SetPluginEnabledAsync(payload),
            "plugin.uninstall" => await SetPluginUninstallStateAsync(payload),
            "plugin.refresh_market" => await RefreshMarketAsync(),
            _ => throw new NotSupportedException($"不支持的插件管理指令：{action}")
        };
    }

    private static async Task<JsonElement> ListPluginsAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var installed = IPluginService.LoadedPlugins.Select(p => new
            {
                id = p.Manifest.Id,
                name = p.Manifest.Name,
                version = p.Manifest.Version,
                author = p.Manifest.Author,
                description = p.Manifest.Description,
                isEnabled = p.IsEnabled,
                isUninstalling = p.IsUninstalling,
                loadStatus = p.LoadStatus.ToString(),
                errorMessage = p.Exception?.Message,
                folderPath = p.PluginFolderPath
            }).ToList();

            return JsonSerializer.SerializeToElement(new
            {
                installedCount = installed.Count,
                plugins = installed
            });
        });
    }

    private async Task<JsonElement> InstallPluginAsync(JsonElement payload)
    {
        var pluginId = payload.TryGetProperty("pluginId", out var idProp) ? idProp.GetString()?.Trim() : null;
        var packageUrl = payload.TryGetProperty("packageUrl", out var urlProp) ? urlProp.GetString()?.Trim() : null;
        var expectedSha256 = payload.TryGetProperty("sha256", out var shaProp) ? shaProp.GetString()?.Trim() : null;

        if (!string.IsNullOrWhiteSpace(packageUrl))
        {
            Directory.CreateDirectory(HostRuntimeBridge.PluginsPkgRootPath);
            var safeName = !string.IsNullOrWhiteSpace(pluginId)
                ? Path.GetFileName(pluginId)
                : Guid.NewGuid().ToString("N");
            var pkgFilePath = Path.Combine(HostRuntimeBridge.PluginsPkgRootPath, $"{safeName}.cipx");

            await roamingCoordinator.DownloadFileWithSessionAsync(packageUrl, pkgFilePath);

            if (!string.IsNullOrWhiteSpace(expectedSha256))
            {
                await using var fs = File.OpenRead(pkgFilePath);
                var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(fs));
                if (!string.Equals(actualHash, expectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(pkgFilePath);
                    throw new InvalidOperationException($"插件包 SHA256 校验未通过（预期：{expectedSha256}，实际：{actualHash}）。");
                }
            }

            logger.LogInformation("集控已将插件包下载至待安装队列：{Path}", pkgFilePath);
            return JsonSerializer.SerializeToElement(new
            {
                queued = true,
                source = "url",
                packagePath = pkgFilePath,
                restartRequired = true
            });
        }

        if (!string.IsNullOrWhiteSpace(pluginId))
        {
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                pluginMarketService.RequestDownloadPlugin(pluginId);
            });

            return JsonSerializer.SerializeToElement(new
            {
                queued = true,
                source = "market",
                pluginId,
                restartRequired = true
            });
        }

        throw new ArgumentException("plugin.install 需要提供 pluginId 或 packageUrl。");
    }

    private static async Task<JsonElement> SetPluginEnabledAsync(JsonElement payload)
    {
        var pluginId = payload.TryGetProperty("pluginId", out var idProp) ? idProp.GetString()?.Trim() : null;
        if (string.IsNullOrWhiteSpace(pluginId))
        {
            throw new ArgumentException("必须提供 pluginId。");
        }

        if (string.Equals(pluginId, SelfProtectionService.PluginId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("集控增强核心组件受自我保护策略保护，不可被禁用。");
        }

        var enabled = !payload.TryGetProperty("enabled", out var enProp) || enProp.ValueKind != JsonValueKind.False;

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var target = IPluginService.LoadedPlugins.FirstOrDefault(
                x => string.Equals(x.Manifest.Id, pluginId, StringComparison.OrdinalIgnoreCase));
            if (target == null)
            {
                throw new KeyNotFoundException($"未找到已安装插件：{pluginId}");
            }

            target.IsEnabled = enabled;
            return JsonSerializer.SerializeToElement(new
            {
                pluginId = target.Manifest.Id,
                isEnabled = target.IsEnabled,
                restartRequired = true
            });
        });
    }

    private static async Task<JsonElement> SetPluginUninstallStateAsync(JsonElement payload)
    {
        var pluginId = payload.TryGetProperty("pluginId", out var idProp) ? idProp.GetString()?.Trim() : null;
        if (string.IsNullOrWhiteSpace(pluginId))
        {
            throw new ArgumentException("必须提供 pluginId。");
        }

        if (string.Equals(pluginId, SelfProtectionService.PluginId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("集控增强核心组件受自我保护策略保护，不可通过远程插件卸载指令移除。");
        }

        var uninstall = !payload.TryGetProperty("uninstall", out var unProp) || unProp.ValueKind != JsonValueKind.False;

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var target = IPluginService.LoadedPlugins.FirstOrDefault(
                x => string.Equals(x.Manifest.Id, pluginId, StringComparison.OrdinalIgnoreCase));
            if (target == null)
            {
                throw new KeyNotFoundException($"未找到已安装插件：{pluginId}");
            }

            target.IsUninstalling = uninstall;
            return JsonSerializer.SerializeToElement(new
            {
                pluginId = target.Manifest.Id,
                isUninstalling = target.IsUninstalling,
                restartRequired = true
            });
        });
    }

    private async Task<JsonElement> RefreshMarketAsync()
    {
        await pluginMarketService.RefreshPluginSourceAsync();
        return JsonSerializer.SerializeToElement(new
        {
            refreshed = true,
            mergedPluginCount = pluginMarketService.MergedPlugins.Count
        });
    }
}
