using System.Collections.ObjectModel;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services;
using ClassIsland.Core.Models.Automation;
using ClassIsland.Shared.Helpers;
using Microsoft.Extensions.Logging;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// [第一级受控能力] 自动化工作流配置管理处理器（automation.*）。
/// </summary>
public sealed class AutomationCommandHandler(
    ILogger<AutomationCommandHandler> logger,
    IAutomationService automationService)
{
    public string AutomationsDirectoryPath => Path.Combine(CommonDirectories.AppConfigPath, "Automations");

    private static string GetCurrentAutomationConfigName() =>
        HostRuntimeBridge.GetSettingValue("CurrentAutomationConfig", "Default") ?? "Default";

    private static bool GetIsAutomationEnabled() =>
        HostRuntimeBridge.GetSettingValue("IsAutomationEnabled", true);

    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        Directory.CreateDirectory(AutomationsDirectoryPath);
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "automation.list" => await ListAutomationConfigsAsync(),
            "automation.get" => await GetAutomationWorkflowsAsync(payload),
            "automation.put" or "automation.save" => await SaveAutomationWorkflowsAsync(payload),
            "automation.switch" => await SwitchAutomationConfigAsync(payload),
            "automation.delete" => DeleteAutomationConfig(payload),
            _ => throw new NotSupportedException($"不支持的自动化指令：{action}")
        };
    }

    private async Task<JsonElement> ListAutomationConfigsAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            automationService.RefreshConfigs();
            var currentConfig = GetCurrentAutomationConfigName();
            return JsonSerializer.SerializeToElement(new
            {
                currentConfig,
                isAutomationEnabled = GetIsAutomationEnabled(),
                configs = automationService.Configs,
                activeWorkflowCount = automationService.Workflows.Count
            });
        });
    }

    private async Task<JsonElement> GetAutomationWorkflowsAsync(JsonElement payload)
    {
        var configName = TryGetConfigName(payload, fallbackToCurrent: true);
        var currentName = GetCurrentAutomationConfigName();

        if (string.Equals(configName, currentName, StringComparison.OrdinalIgnoreCase))
        {
            return await Dispatcher.UIThread.InvokeAsync(() =>
                JsonSerializer.SerializeToElement(new
                {
                    configName = currentName,
                    isActive = true,
                    isAutomationEnabled = GetIsAutomationEnabled(),
                    workflows = automationService.Workflows
                }));
        }

        var fullPath = GetSafeAutomationFilePath(configName);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"自动化配置文件不存在：{configName}");
        }

        var list = ConfigureFileHelper.LoadConfig<ObservableCollection<Workflow>>(fullPath);
        return JsonSerializer.SerializeToElement(new
        {
            configName,
            isActive = false,
            workflows = list
        });
    }

    private async Task<JsonElement> SaveAutomationWorkflowsAsync(JsonElement payload)
    {
        var configName = TryGetConfigName(payload, fallbackToCurrent: true);
        if (!payload.TryGetProperty("workflows", out var wfElem) || wfElem.ValueKind != JsonValueKind.Array)
        {
            throw new ArgumentException("automation.put 需要包含 workflows 数组。");
        }

        var workflows = wfElem.Deserialize<ObservableCollection<Workflow>>()
                        ?? throw new InvalidOperationException("无法反序列化 Workflows 列表。");

        var isActive = string.Equals(configName, GetCurrentAutomationConfigName(), StringComparison.OrdinalIgnoreCase);
        var fullPath = GetSafeAutomationFilePath(configName);

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (payload.TryGetProperty("isAutomationEnabled", out var enProp) &&
                enProp.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                HostRuntimeBridge.SetSettingValue("IsAutomationEnabled", enProp.GetBoolean());
                HostRuntimeBridge.SaveSettings("集控变更自动化启用状态");
            }

            ConfigureFileHelper.SaveConfig(fullPath, workflows);
            automationService.RefreshConfigs();

            if (isActive)
            {
                automationService.Workflows.Clear();
                foreach (var wf in workflows)
                {
                    automationService.Workflows.Add(wf);
                }
                automationService.SaveConfig("集控服务器远程更新自动化配置");
            }

            logger.LogInformation("集控已更新自动化配置方案 {Config}（共 {Count} 条工作流）。", configName, workflows.Count);
            return JsonSerializer.SerializeToElement(new
            {
                configName,
                isActive,
                workflowCount = workflows.Count
            });
        });
    }

    private async Task<JsonElement> SwitchAutomationConfigAsync(JsonElement payload)
    {
        var targetName = TryGetConfigName(payload, fallbackToCurrent: false);
        var fullPath = GetSafeAutomationFilePath(targetName);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"目标自动化配置方案不存在：{targetName}");
        }

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            automationService.SaveConfig("切换自动化配置前保存");
            HostRuntimeBridge.SetSettingValue("CurrentAutomationConfig", targetName);
            HostRuntimeBridge.SaveSettings($"集控切换自动化方案至 {targetName}");
            automationService.RefreshConfigs();

            return JsonSerializer.SerializeToElement(new
            {
                currentConfig = GetCurrentAutomationConfigName(),
                workflowCount = automationService.Workflows.Count
            });
        });
    }

    private JsonElement DeleteAutomationConfig(JsonElement payload)
    {
        var targetName = TryGetConfigName(payload, fallbackToCurrent: false);
        if (string.Equals(targetName, GetCurrentAutomationConfigName(), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("不能删除当前激活的自动化配置方案。");
        }

        var fullPath = GetSafeAutomationFilePath(targetName);
        if (!File.Exists(fullPath))
        {
            return JsonSerializer.SerializeToElement(new { deleted = false, configName = targetName });
        }

        File.Delete(fullPath);
        Dispatcher.UIThread.Post(() => automationService.RefreshConfigs());
        return JsonSerializer.SerializeToElement(new { deleted = true, configName = targetName });
    }

    private static string TryGetConfigName(JsonElement payload, bool fallbackToCurrent)
    {
        string? name = null;
        if (payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty("configName", out var cProp))
        {
            name = cProp.GetString();
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            if (fallbackToCurrent)
            {
                return GetCurrentAutomationConfigName();
            }
            throw new ArgumentException("必须指定自动化方案名称 configName。");
        }

        return Path.GetFileNameWithoutExtension(name.Trim());
    }

    private string GetSafeAutomationFilePath(string configName)
    {
        var clean = Path.GetFileNameWithoutExtension(configName);
        var fullPath = Path.GetFullPath(Path.Combine(AutomationsDirectoryPath, clean + ".json"));
        var rootFull = Path.GetFullPath(AutomationsDirectoryPath);
        if (!fullPath.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("非法的自动化配置路径。");
        }
        return fullPath;
    }
}
