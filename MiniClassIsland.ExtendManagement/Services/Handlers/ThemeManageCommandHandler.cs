using System.IO.Compression;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Networking;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// [第一级受控能力] 客户端主题管理处理器（theme.*）。
/// </summary>
public sealed class ThemeManageCommandHandler(
    ILogger<ThemeManageCommandHandler> logger,
    IXamlThemeService xamlThemeService,
    NetworkRoamingCoordinator roamingCoordinator)
{
    public string ThemesDirectoryPath => Path.Combine(CommonDirectories.AppRootFolderPath, "Themes");

    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        Directory.CreateDirectory(ThemesDirectoryPath);
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "theme.list" => await ListThemesAsync(),
            "theme.install" => await InstallThemeAsync(payload),
            "theme.set_enabled" => await SetEnabledThemesAsync(payload),
            "theme.set_appearance" => await SetAppearanceSettingsAsync(payload),
            "theme.uninstall" => await UninstallThemeAsync(payload),
            "theme.reload" => await ReloadThemesAsync(),
            _ => throw new NotSupportedException($"不支持的主题管理指令：{action}")
        };
    }

    private async Task<JsonElement> ListThemesAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var themes = xamlThemeService.Themes.Select(t => new
            {
                id = t.Manifest.Id,
                name = t.Manifest.Name,
                version = t.Manifest.Version,
                author = t.Manifest.Author,
                description = t.Manifest.Description,
                isLocal = t.IsLocal,
                isEnabled = xamlThemeService.EnabledThemes.Contains(t.Manifest.Id),
                isError = t.IsError,
                errorMessage = t.Error?.Message
            }).ToList();

            return JsonSerializer.SerializeToElement(new
            {
                themeMode = HostRuntimeBridge.GetSettingValue("Theme", 0),
                colorSource = HostRuntimeBridge.GetSettingValue("ColorSource", 0),
                enabledThemes = xamlThemeService.EnabledThemes.ToList(),
                themes
            });
        });
    }

    private async Task<JsonElement> InstallThemeAsync(JsonElement payload)
    {
        var themeId = payload.TryGetProperty("themeId", out var idProp) ? idProp.GetString()?.Trim() : null;
        var packageUrl = payload.TryGetProperty("packageUrl", out var urlProp) ? urlProp.GetString()?.Trim() : null;
        var enableAfterInstall = payload.TryGetProperty("enable", out var enProp) && enProp.ValueKind == JsonValueKind.True;

        if (!string.IsNullOrWhiteSpace(packageUrl))
        {
            if (string.IsNullOrWhiteSpace(themeId))
            {
                throw new ArgumentException("通过 packageUrl 安装主题时需同时指定 themeId。");
            }

            var cleanId = Path.GetFileName(themeId);
            var tempArchive = Path.Combine(Path.GetTempPath(), $"mci-theme-{cleanId}-{Guid.NewGuid():N}.zip");
            try
            {
                await roamingCoordinator.DownloadFileWithSessionAsync(packageUrl, tempArchive);
                var targetDir = Path.Combine(ThemesDirectoryPath, cleanId);
                if (Directory.Exists(targetDir))
                {
                    Directory.Delete(targetDir, true);
                }
                Directory.CreateDirectory(targetDir);
                ZipFile.ExtractToDirectory(tempArchive, targetDir);
            }
            finally
            {
                if (File.Exists(tempArchive))
                {
                    File.Delete(tempArchive);
                }
            }

            return await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (enableAfterInstall && !xamlThemeService.EnabledThemes.Contains(cleanId))
                {
                    xamlThemeService.EnabledThemes.Add(cleanId);
                }
                xamlThemeService.LoadAllThemes();
                HostRuntimeBridge.SaveSettings("集控服务器安装并加载主题");
                return JsonSerializer.SerializeToElement(new
                {
                    installed = true,
                    themeId = cleanId,
                    enabled = xamlThemeService.EnabledThemes.Contains(cleanId)
                });
            });
        }

        if (!string.IsNullOrWhiteSpace(themeId))
        {
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                xamlThemeService.RequestDownloadTheme(themeId);
                if (enableAfterInstall && !xamlThemeService.EnabledThemes.Contains(themeId))
                {
                    xamlThemeService.EnabledThemes.Add(themeId);
                }
            });

            return JsonSerializer.SerializeToElement(new
            {
                requested = true,
                themeId
            });
        }

        throw new ArgumentException("theme.install 需要提供 themeId 或 packageUrl。");
    }

    private async Task<JsonElement> SetEnabledThemesAsync(JsonElement payload)
    {
        if (!payload.TryGetProperty("enabledThemes", out var arrProp) || arrProp.ValueKind != JsonValueKind.Array)
        {
            throw new ArgumentException("theme.set_enabled 需要提供 enabledThemes 字符串数组。");
        }

        var desiredIds = arrProp.EnumerateArray()
            .Select(x => x.GetString())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            xamlThemeService.EnabledThemes.Clear();
            foreach (var id in desiredIds)
            {
                xamlThemeService.EnabledThemes.Add(id);
            }

            xamlThemeService.LoadAllThemes();
            HostRuntimeBridge.SaveSettings("集控服务器更新已启用主题列表");

            logger.LogInformation("集控已更新启用主题并在运行时重载：{Themes}", string.Join(", ", desiredIds));
            return JsonSerializer.SerializeToElement(new
            {
                enabledThemes = xamlThemeService.EnabledThemes.ToList()
            });
        });
    }

    private static async Task<JsonElement> SetAppearanceSettingsAsync(JsonElement payload)
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (payload.TryGetProperty("themeMode", out var modeProp) && modeProp.TryGetInt32(out var mode))
            {
                HostRuntimeBridge.SetSettingValue("Theme", mode);
            }
            if (payload.TryGetProperty("colorSource", out var csProp) && csProp.TryGetInt32(out var cs))
            {
                HostRuntimeBridge.SetSettingValue("ColorSource", cs);
            }
            HostRuntimeBridge.SaveSettings("集控服务器修改主题外观设置");

            return JsonSerializer.SerializeToElement(new
            {
                themeMode = HostRuntimeBridge.GetSettingValue("Theme", 0),
                colorSource = HostRuntimeBridge.GetSettingValue("ColorSource", 0)
            });
        });
    }

    private async Task<JsonElement> UninstallThemeAsync(JsonElement payload)
    {
        var themeId = payload.TryGetProperty("themeId", out var idProp) ? idProp.GetString()?.Trim() : null;
        if (string.IsNullOrWhiteSpace(themeId))
        {
            throw new ArgumentException("必须指定 themeId。");
        }

        var cleanId = Path.GetFileName(themeId);
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            xamlThemeService.EnabledThemes.Remove(cleanId);
            var targetDir = Path.Combine(ThemesDirectoryPath, cleanId);
            if (Directory.Exists(targetDir))
            {
                Directory.Delete(targetDir, true);
            }

            xamlThemeService.LoadAllThemes();
            HostRuntimeBridge.SaveSettings($"集控服务器卸载主题 {cleanId}");

            return JsonSerializer.SerializeToElement(new
            {
                uninstalled = true,
                themeId = cleanId
            });
        });
    }

    private async Task<JsonElement> ReloadThemesAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            xamlThemeService.LoadAllThemes();
            return JsonSerializer.SerializeToElement(new
            {
                reloaded = true,
                enabledThemes = xamlThemeService.EnabledThemes.ToList()
            });
        });
    }
}
