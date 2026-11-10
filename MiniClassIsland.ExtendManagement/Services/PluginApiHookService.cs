using System.Collections;
using System.Collections.Specialized;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services;
using ClassIsland.Core.Attributes;
using ClassIsland.Core.Models.Components;
using ClassIsland.Core.Models.Plugin;
using ClassIsland.Core.Services.Registry;
using ClassIsland.Shared;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Security;

namespace MiniClassIsland.ExtendManagement.Services;

/// <summary>
/// 插件标准 API 安全 Hook 与内省服务。
/// 1. 监听并拦截通过标准接口 ISettingsWindowRegistryService 注册的设置页（SettingsPageInfo）及插件设置文件/对象；
/// 2. 监听并拦截通过标准接口 IComponentRegistryService 注册的主界面组件（ComponentInfo）及其 SettingsType 默认设置 Schema；
/// 3. 支持读取和热更新当前主界面布局（IComponentsService.CurrentComponents）中各个已放置组件实例（含嵌套容器子组件）的专属组件设置（ComponentSettings.Settings）；
/// 4. 支持读取和热更新任意已安装插件暴露在 PluginConfigFolder 下的 JSON 配置文件及 DI 容器中的插件设置服务属性。
/// </summary>
public sealed class PluginApiHookService : IDisposable
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);

    private readonly ILogger<PluginApiHookService> _logger;
    private readonly IComponentsService _componentsService;
    private readonly TamperEvidentConfigStore _configStore;
    private bool _hooksAttached;
    private bool _disposed;

    public PluginApiHookService(
        ILogger<PluginApiHookService> logger,
        IComponentsService componentsService,
        TamperEvidentConfigStore configStore)
    {
        _logger = logger;
        _componentsService = componentsService;
        _configStore = configStore;

        if (_configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            AttachRegistryHooks();
            AppBase.Current.AppStarted += OnAppStarted;
        }
    }

    private void OnAppStarted(object? sender, EventArgs e)
    {
        AttachRegistryHooks();
    }

    public void AttachRegistryHooks()
    {
        if (_hooksAttached)
        {
            return;
        }

        try
        {
            ComponentRegistryService.Registered.CollectionChanged += OnComponentRegistryChanged;
            SettingsWindowRegistryService.Registered.CollectionChanged += OnSettingsRegistryChanged;
            _hooksAttached = true;

            _logger.LogInformation(
                "已挂载插件标准 API Hook：当前已捕获注册组件 {ComponentCount} 个，注册设置页 {SettingsPageCount} 个。",
                ComponentRegistryService.Registered.Count,
                SettingsWindowRegistryService.Registered.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "挂载插件标准 API Hook 时发生异常。");
        }
    }

    private void OnComponentRegistryChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems == null)
        {
            return;
        }

        foreach (var item in e.NewItems.OfType<ComponentInfo>())
        {
            _logger.LogDebug(
                "插件 API Hook 捕获新注册主界面组件：{Name} ({Guid}), SettingsType={SettingsType}",
                item.Name,
                item.Guid,
                item.SettingsType?.FullName ?? "none");
        }
    }

    private void OnSettingsRegistryChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems == null)
        {
            return;
        }

        foreach (var item in e.NewItems.OfType<SettingsPageInfo>())
        {
            _logger.LogDebug(
                "插件 API Hook 捕获新注册设置页面：{Name} ({Id})",
                item.Name,
                item.Id);
        }
    }

    /// <summary>
    /// 聚合导出所有通过标准接口暴露的插件设置页、插件配置文件、注册主界面组件及当前活跃组件实例设置。
    /// </summary>
    public async Task<JsonElement> GetFullApiSnapshotAsync(string? filterPluginId = null)
    {
        var settingsCatalog = await GetPluginSettingsCatalogAsync(filterPluginId);
        var registeredComponents = await GetRegisteredComponentsAsync(includeBuiltIn: string.IsNullOrWhiteSpace(filterPluginId), filterPluginId: filterPluginId);
        var activeInstances = await GetActiveComponentInstancesSettingsAsync(filterPluginId);

        return JsonSerializer.SerializeToElement(new
        {
            capturedAtUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            filterPluginId,
            settingsCatalog,
            registeredComponents,
            activeComponentInstances = activeInstances
        });
    }

    /// <summary>
    /// 获取所有插件（或指定插件）通过标准接口注册的设置页面、PluginConfigFolder 配置文件及可读写设置属性。
    /// </summary>
    public async Task<JsonElement> GetPluginSettingsCatalogAsync(string? filterPluginId = null)
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var plugins = IPluginService.LoadedPlugins
                .Where(p => string.IsNullOrWhiteSpace(filterPluginId) ||
                            string.Equals(p.Manifest.Id, filterPluginId, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var allSettingsPages = SettingsWindowRegistryService.Registered.ToList();
            var pluginSettingsList = new List<object>();

            foreach (var p in plugins)
            {
                var pluginId = p.Manifest.Id;
                var configDir = Path.Combine(CommonDirectories.AppConfigPath, "Plugins", pluginId);

                // 1. 匹配归属该插件的注册设置页面（通过程序集或命名空间匹配）
                var matchedPages = MatchSettingsPagesForPlugin(p, allSettingsPages);

                // 2. 扫描该插件配置目录下的所有 JSON 配置文件并解析内容
                var configFiles = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
                if (Directory.Exists(configDir))
                {
                    foreach (var file in Directory.GetFiles(configDir, "*.json", SearchOption.AllDirectories))
                    {
                        try
                        {
                            var relName = Path.GetRelativePath(configDir, file).Replace('\\', '/');
                            var rawJson = File.ReadAllText(file, Encoding.UTF8);
                            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(rawJson) ? "{}" : rawJson);
                            configFiles[relName] = doc.RootElement.Clone();
                        }
                        catch
                        {
                            // Ignore unreadable or non-JSON file
                        }
                    }
                }

                // 3. 反射探测该插件程序集内定义的 Settings / Config 模型类与默认属性 Schema
                var discoveredSettingsModels = DiscoverPluginSettingsModels(p);

                pluginSettingsList.Add(new
                {
                    pluginId,
                    name = p.Manifest.Name,
                    version = p.Manifest.Version,
                    isEnabled = p.IsEnabled,
                    loadStatus = p.LoadStatus.ToString(),
                    configFolderPath = configDir,
                    registeredSettingsPages = matchedPages,
                    configFiles,
                    settingsModels = discoveredSettingsModels
                });
            }

            // 同时列出全部已注册的设置页（含宿主与插件）
            var allRegisteredPagesSummary = allSettingsPages.Select(sp => new
            {
                id = sp.Id,
                name = sp.Name,
                groupId = TryGetStringProperty(sp, "GroupId"),
                category = sp.Category.ToString(),
                useFullWidth = sp.UseFullWidth,
                hideDefault = sp.HideDefault,
                ownerPluginId = ResolveSettingsPageOwnerPluginId(sp)
            }).ToList();

            return JsonSerializer.SerializeToElement(new
            {
                totalPlugins = pluginSettingsList.Count,
                totalRegisteredSettingsPages = allRegisteredPagesSummary.Count,
                plugins = pluginSettingsList,
                registeredSettingsPages = allRegisteredPagesSummary
            });
        });
    }

    /// <summary>
    /// 更新指定插件的设置项（支持直接更新 PluginConfigFolder 下的 JSON 配置文件或合并键值）。
    /// </summary>
    public async Task<JsonElement> SetPluginSettingsAsync(JsonElement payload)
    {
        var pluginId = payload.TryGetProperty("pluginId", out var idProp) ? idProp.GetString()?.Trim() : null;
        if (string.IsNullOrWhiteSpace(pluginId))
        {
            throw new ArgumentException("必须提供 pluginId。");
        }

        if (string.Equals(pluginId, SelfProtectionService.PluginId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("集控增强组件自身配置受防篡改签名保护，不支持通过通用插件配置接口直接覆写。");
        }

        var fileName = payload.TryGetProperty("fileName", out var fProp) && !string.IsNullOrWhiteSpace(fProp.GetString())
            ? fProp.GetString()!.Trim()
            : "Config.json";
        if (!fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            fileName += ".json";
        }

        var safeRelPath = fileName.Replace('\\', '/').TrimStart('/');
        if (safeRelPath.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("非法的配置文件路径。");
        }

        var configDir = Path.Combine(CommonDirectories.AppConfigPath, "Plugins", pluginId);
        Directory.CreateDirectory(configDir);
        var fullPath = Path.GetFullPath(Path.Combine(configDir, safeRelPath));
        if (!fullPath.StartsWith(Path.GetFullPath(configDir), StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("配置文件路径越界。");
        }

        var merge = !payload.TryGetProperty("merge", out var mProp) || mProp.ValueKind != JsonValueKind.False;
        if (!payload.TryGetProperty("settings", out var settingsElem) &&
            !payload.TryGetProperty("values", out settingsElem) &&
            !payload.TryGetProperty("content", out settingsElem))
        {
            throw new ArgumentException("需要提供 settings / values / content 对象。");
        }

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var targetDict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            if (merge && File.Exists(fullPath))
            {
                try
                {
                    var existingRaw = File.ReadAllText(fullPath, Encoding.UTF8);
                    var existingDict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(existingRaw);
                    if (existingDict != null)
                    {
                        foreach (var (k, v) in existingDict)
                        {
                            targetDict[k] = v;
                        }
                    }
                }
                catch
                {
                    // Ignore
                }
            }

            if (settingsElem.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in settingsElem.EnumerateObject())
                {
                    targetDict[prop.Name] = prop.Value.Clone();
                }
            }

            var outDir = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(outDir))
            {
                Directory.CreateDirectory(outDir);
            }

            var serialized = JsonSerializer.Serialize(targetDict, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(fullPath, serialized, Utf8NoBom);

            // 尝试同步更新内存中已加载的插件对象属性（如果插件在 DI 容器或 PluginBase 实例上持有同名属性）
            var updatedLiveProperties = TryApplySettingsToLivePluginInstances(pluginId, settingsElem);

            return JsonSerializer.SerializeToElement(new
            {
                updated = true,
                pluginId,
                fileName = safeRelPath,
                fullPath,
                updatedLiveProperties,
                settings = JsonDocument.Parse(serialized).RootElement.Clone()
            });
        });
    }

    /// <summary>
    /// 获取通过 IComponentRegistryService 注册的所有主界面组件及默认组件设置 Schema。
    /// </summary>
    public async Task<JsonElement> GetRegisteredComponentsAsync(bool includeBuiltIn = true, string? filterPluginId = null)
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var registered = ComponentRegistryService.Registered.ToList();
            var items = new List<object>();

            foreach (var comp in registered)
            {
                var ownerPlugin = ResolveComponentOwnerPlugin(comp);
                var ownerPluginId = ownerPlugin?.Manifest?.Id;
                var isBuiltIn = string.IsNullOrWhiteSpace(ownerPluginId) && (TryGetBoolProperty(comp, "IsBuiltIn") ?? true);

                if (!includeBuiltIn && isBuiltIn)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(filterPluginId) &&
                    !string.Equals(ownerPluginId, filterPluginId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var settingsSchema = ExtractTypePropertiesSchema(comp.SettingsType);
                var defaultSettings = CreateDefaultSettingsElement(comp.SettingsType);
                var compType = TryGetTypeProperty(comp, "ComponentBaseType") ?? TryGetTypeProperty(comp, "ComponentType");

                items.Add(new
                {
                    id = comp.Guid.ToString(),
                    name = comp.Name,
                    description = comp.Description,
                    isBuiltIn,
                    isComponentContainer = comp.IsComponentContainer,
                    ownerPluginId,
                    ownerPluginName = ownerPlugin?.Manifest?.Name,
                    componentType = compType?.FullName,
                    settingsType = comp.SettingsType?.FullName,
                    hasSettings = comp.SettingsType != null,
                    defaultSettings,
                    settingsSchema
                });
            }

            return JsonSerializer.SerializeToElement(new
            {
                totalCount = items.Count,
                components = items
            });
        });
    }

    /// <summary>
    /// 获取当前主界面布局（IComponentsService.CurrentComponents）中所有已放置组件实例（含容器内子组件）及其关联的专属设置。
    /// </summary>
    public async Task<JsonElement> GetActiveComponentInstancesSettingsAsync(
        string? filterPluginId = null,
        string? filterComponentId = null)
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var profile = _componentsService.CurrentComponents;
            var instances = new List<object>();

            for (var lineIdx = 0; lineIdx < profile.Lines.Count; lineIdx++)
            {
                var line = profile.Lines[lineIdx];
                CollectComponentInstancesRecursive(
                    line.Children,
                    lineIdx,
                    parentPath: $"lines[{lineIdx}]",
                    filterPluginId,
                    filterComponentId,
                    instances);
            }

            return JsonSerializer.SerializeToElement(new
            {
                currentComponentConfig = HostRuntimeBridge.GetSettingValue("CurrentComponentConfig", "Default") ?? "Default",
                isManagementMode = _componentsService.IsManagementMode,
                lineCount = profile.Lines.Count,
                instanceCount = instances.Count,
                instances
            });
        });
    }

    /// <summary>
    /// 修改当前主界面布局中指定组件实例的专属设置（ComponentSettings.Settings）及视觉外观属性，并立即热重载生效。
    /// </summary>
    public async Task<JsonElement> UpdateActiveComponentInstanceSettingsAsync(JsonElement payload)
    {
        var targetComponentId = payload.TryGetProperty("componentId", out var cidProp)
            ? cidProp.GetString()?.Trim()
            : payload.TryGetProperty("id", out var idProp)
                ? idProp.GetString()?.Trim()
                : null;
        var targetInstancePath = payload.TryGetProperty("instancePath", out var pathProp)
            ? pathProp.GetString()?.Trim()
            : null;
        var targetLineIndex = payload.TryGetProperty("lineIndex", out var lProp) && lProp.TryGetInt32(out var lVal)
            ? (int?)lVal
            : null;
        var targetChildIndex = payload.TryGetProperty("childIndex", out var cProp) && cProp.TryGetInt32(out var cVal)
            ? (int?)cVal
            : null;

        if (!payload.TryGetProperty("settings", out var settingsPatch) &&
            !payload.TryGetProperty("componentSettings", out settingsPatch))
        {
            throw new ArgumentException("需要提供 settings 对象以更新组件实例设置。");
        }

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var profile = _componentsService.CurrentComponents;
            var matched = new List<(ComponentSettings Item, string Path)>();

            for (var lineIdx = 0; lineIdx < profile.Lines.Count; lineIdx++)
            {
                if (targetLineIndex.HasValue && targetLineIndex.Value != lineIdx)
                {
                    continue;
                }

                FindMatchingComponentInstancesRecursive(
                    profile.Lines[lineIdx].Children,
                    lineIdx,
                    parentPath: $"lines[{lineIdx}]",
                    targetComponentId,
                    targetInstancePath,
                    targetChildIndex,
                    matched);
            }

            if (matched.Count == 0)
            {
                throw new KeyNotFoundException("未在当前主界面组件布局中找到匹配的组件实例。");
            }

            var updatedRecords = new List<object>();
            foreach (var (compItem, path) in matched)
            {
                ApplySettingsPatchToComponentInstance(compItem, settingsPatch);

                // 如果同时提供了外观覆盖属性（如 HideOnRule, Opacity, IsCustomForegroundColorEnabled 等）也一并应用
                if (payload.TryGetProperty("appearance", out var appearanceElem) &&
                    appearanceElem.ValueKind == JsonValueKind.Object)
                {
                    ApplyPropertiesToClrObject(compItem, appearanceElem);
                }

                updatedRecords.Add(new
                {
                    instancePath = path,
                    componentId = compItem.Id,
                    name = compItem.AssociatedComponentInfo?.Name ?? compItem.NameCache,
                    settings = SerializeObjectToElement(compItem.Settings)
                });
            }

            // 持久化当前组件布局并触发热重载
            SaveCurrentComponentProfileAndRefresh();

            return JsonSerializer.SerializeToElement(new
            {
                updatedCount = updatedRecords.Count,
                instances = updatedRecords
            });
        });
    }

    private void SaveCurrentComponentProfileAndRefresh()
    {
        try
        {
            var saveMethod = _componentsService.GetType().GetMethod(
                "SaveConfig",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            saveMethod?.Invoke(_componentsService, null);

            if (_componentsService.IsManagementMode)
            {
                Directory.CreateDirectory(HostRuntimeBridge.ManagementConfigureFolderPath);
                ClassIsland.Shared.Helpers.ConfigureFileHelper.SaveConfig(
                    HostRuntimeBridge.ManagementComponentsPath,
                    _componentsService.CurrentComponents);
            }

            var loadConfigMethod = _componentsService.GetType().GetMethod(
                "LoadConfig",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            loadConfigMethod?.Invoke(_componentsService, null);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "保存并刷新主界面组件实例设置异常。");
        }
    }

    private static void ApplySettingsPatchToComponentInstance(ComponentSettings compItem, JsonElement settingsPatch)
    {
        if (settingsPatch.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var settingsType = compItem.AssociatedComponentInfo?.SettingsType ?? compItem.Settings?.GetType();
        if (settingsType != null)
        {
            var currentObj = compItem.Settings;
            if (currentObj == null)
            {
                try
                {
                    currentObj = Activator.CreateInstance(settingsType);
                }
                catch
                {
                    currentObj = null;
                }
            }
            else if (currentObj is JsonElement je)
            {
                try
                {
                    currentObj = je.Deserialize(settingsType);
                }
                catch
                {
                    currentObj = Activator.CreateInstance(settingsType);
                }
            }

            if (currentObj != null && currentObj is not JsonElement)
            {
                ApplyPropertiesToClrObject(currentObj, settingsPatch);
                compItem.Settings = currentObj;
                return;
            }
        }

        // Fallback: merge as JsonElement dictionary
        var dict = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        if (compItem.Settings != null)
        {
            try
            {
                var existingElem = SerializeObjectToElement(compItem.Settings);
                if (existingElem.ValueKind == JsonValueKind.Object)
                {
                    foreach (var p in existingElem.EnumerateObject())
                    {
                        dict[p.Name] = p.Value.Clone();
                    }
                }
            }
            catch
            {
                // Ignore
            }
        }

        foreach (var p in settingsPatch.EnumerateObject())
        {
            dict[p.Name] = p.Value.Clone();
        }

        compItem.Settings = JsonSerializer.SerializeToElement(dict);
    }

    private static void CollectComponentInstancesRecursive(
        IList<ComponentSettings>? children,
        int lineIndex,
        string parentPath,
        string? filterPluginId,
        string? filterComponentId,
        List<object> output)
    {
        if (children == null)
        {
            return;
        }

        for (var idx = 0; idx < children.Count; idx++)
        {
            var item = children[idx];
            var path = $"{parentPath}.children[{idx}]";
            var info = item.AssociatedComponentInfo;
            var ownerPlugin = info != null ? ResolveComponentOwnerPlugin(info) : null;
            var ownerPluginId = ownerPlugin?.Manifest?.Id;

            var matchPlugin = string.IsNullOrWhiteSpace(filterPluginId) ||
                              string.Equals(ownerPluginId, filterPluginId, StringComparison.OrdinalIgnoreCase);
            var matchComp = string.IsNullOrWhiteSpace(filterComponentId) ||
                            string.Equals(item.Id, filterComponentId, StringComparison.OrdinalIgnoreCase);

            if (matchPlugin && matchComp)
            {
                output.Add(new
                {
                    instancePath = path,
                    lineIndex,
                    childIndex = idx,
                    componentId = item.Id,
                    name = info?.Name ?? item.NameCache,
                    isBuiltIn = string.IsNullOrWhiteSpace(ownerPluginId) && (info != null ? (TryGetBoolProperty(info, "IsBuiltIn") ?? true) : true),
                    isContainer = info?.IsComponentContainer ?? false,
                    ownerPluginId,
                    ownerPluginName = ownerPlugin?.Manifest?.Name,
                    settingsType = info?.SettingsType?.FullName ?? item.Settings?.GetType().FullName,
                    settings = SerializeObjectToElement(item.Settings),
                    settingsSchema = ExtractTypePropertiesSchema(info?.SettingsType ?? item.Settings?.GetType()),
                    appearance = new
                    {
                        item.HideOnRule,
                        item.IsResourceOverridingEnabled,
                        item.MainWindowSecondaryFontSize,
                        item.MainWindowBodyFontSize,
                        item.MainWindowEmphasizedFontSize,
                        item.MainWindowLargeFontSize,
                        item.IsCustomForegroundColorEnabled,
                        ForegroundColor = item.ForegroundColor.ToString(),
                        item.IsCustomBackgroundColorEnabled,
                        BackgroundColor = item.BackgroundColor.ToString(),
                        item.IsCustomBackgroundOpacityEnabled,
                        item.BackgroundOpacity,
                        item.IsCustomCornerRadiusEnabled,
                        item.CustomCornerRadius,
                        item.Opacity,
                        HorizontalAlignment = (int)item.HorizontalAlignment,
                        item.IsMinWidthEnabled,
                        item.MinWidth,
                        item.IsMaxWidthEnabled,
                        item.MaxWidth,
                        item.IsFixedWidthEnabled,
                        item.FixedWidth
                    }
                });
            }

            // 如果该组件是容器组件（如分组容器、轮播容器、堆叠容器等），递归遍历其内部 Children
            var nestedChildren = TryGetContainerChildren(item);
            if (nestedChildren != null && nestedChildren.Count > 0)
            {
                CollectComponentInstancesRecursive(
                    nestedChildren,
                    lineIndex,
                    path,
                    filterPluginId,
                    filterComponentId,
                    output);
            }
        }
    }

    private static void FindMatchingComponentInstancesRecursive(
        IList<ComponentSettings>? children,
        int lineIndex,
        string parentPath,
        string? targetComponentId,
        string? targetInstancePath,
        int? targetChildIndex,
        List<(ComponentSettings Item, string Path)> matched)
    {
        if (children == null)
        {
            return;
        }

        for (var idx = 0; idx < children.Count; idx++)
        {
            var item = children[idx];
            var path = $"{parentPath}.children[{idx}]";

            var pathMatch = !string.IsNullOrWhiteSpace(targetInstancePath) &&
                            string.Equals(path, targetInstancePath, StringComparison.OrdinalIgnoreCase);
            var idMatch = !string.IsNullOrWhiteSpace(targetComponentId) &&
                          string.Equals(item.Id, targetComponentId, StringComparison.OrdinalIgnoreCase) &&
                          (!targetChildIndex.HasValue || targetChildIndex.Value == idx);

            if (pathMatch || (string.IsNullOrWhiteSpace(targetInstancePath) && idMatch))
            {
                matched.Add((item, path));
            }

            var nestedChildren = TryGetContainerChildren(item);
            if (nestedChildren != null && nestedChildren.Count > 0)
            {
                FindMatchingComponentInstancesRecursive(
                    nestedChildren,
                    lineIndex,
                    path,
                    targetComponentId,
                    targetInstancePath,
                    targetChildIndex: null,
                    matched);
            }
        }
    }

    private static IList<ComponentSettings>? TryGetContainerChildren(ComponentSettings item)
    {
        if (item.Settings == null)
        {
            return null;
        }

        try
        {
            var prop = item.Settings.GetType().GetProperty(
                "Children",
                BindingFlags.Instance | BindingFlags.Public);
            if (prop?.GetValue(item.Settings) is IList<ComponentSettings> list)
            {
                return list;
            }
        }
        catch
        {
            // Ignore
        }
        return null;
    }

    private static PluginInfo? ResolveComponentOwnerPlugin(ComponentInfo comp)
    {
        try
        {
            var srcProp = comp.GetType().GetProperty("SourcePlugin", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (srcProp?.GetValue(comp) is PluginInfo pInfo)
            {
                return pInfo;
            }
        }
        catch
        {
            // Ignore
        }

        var compType = TryGetTypeProperty(comp, "ComponentBaseType") ?? TryGetTypeProperty(comp, "ComponentType") ?? comp.SettingsType;
        var pid = ResolvePluginIdByAssembly(compType?.Assembly);
        if (!string.IsNullOrWhiteSpace(pid))
        {
            return IPluginService.LoadedPlugins.FirstOrDefault(
                p => string.Equals(p.Manifest.Id, pid, StringComparison.OrdinalIgnoreCase));
        }

        return null;
    }

    private static string? TryGetStringProperty(object target, string propName)
    {
        try
        {
            var p = target.GetType().GetProperty(propName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            return p?.GetValue(target)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static bool? TryGetBoolProperty(object target, string propName)
    {
        try
        {
            var p = target.GetType().GetProperty(propName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            return p?.GetValue(target) is bool b ? b : null;
        }
        catch
        {
            return null;
        }
    }

    private static Type? TryGetTypeProperty(object target, string propName)
    {
        try
        {
            var p = target.GetType().GetProperty(propName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            return p?.GetValue(target) as Type;
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveSettingsPageOwnerPluginId(SettingsPageInfo page)
    {
        try
        {
            // 尝试通过 SettingsPageInfo 内部的创建委托或类型推断归属插件
            var fields = page.GetType().GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
            foreach (var f in fields)
            {
                var val = f.GetValue(page);
                if (val is Type t)
                {
                    var pid = ResolvePluginIdByAssembly(t.Assembly);
                    if (!string.IsNullOrWhiteSpace(pid))
                    {
                        return pid;
                    }
                }
                else if (val is Delegate del)
                {
                    var pid = ResolvePluginIdByAssembly(del.Method.DeclaringType?.Assembly);
                    if (!string.IsNullOrWhiteSpace(pid))
                    {
                        return pid;
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }
        return null;
    }

    private static string? ResolvePluginIdByAssembly(Assembly? assembly)
    {
        if (assembly == null)
        {
            return null;
        }

        var asmName = assembly.GetName().Name ?? string.Empty;
        if (asmName.StartsWith("ClassIsland", StringComparison.OrdinalIgnoreCase) ||
            asmName.StartsWith("System", StringComparison.OrdinalIgnoreCase) ||
            asmName.StartsWith("Avalonia", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var asmLocation = string.Empty;
        try
        {
            asmLocation = assembly.Location;
        }
        catch
        {
            // Ignore
        }

        foreach (var p in IPluginService.LoadedPlugins)
        {
            if (!string.IsNullOrWhiteSpace(asmLocation) &&
                !string.IsNullOrWhiteSpace(p.PluginFolderPath) &&
                asmLocation.StartsWith(Path.GetFullPath(p.PluginFolderPath), StringComparison.OrdinalIgnoreCase))
            {
                return p.Manifest.Id;
            }

            if (!string.IsNullOrWhiteSpace(p.Manifest.EntranceAssembly) &&
                string.Equals(
                    Path.GetFileNameWithoutExtension(p.Manifest.EntranceAssembly),
                    asmName,
                    StringComparison.OrdinalIgnoreCase))
            {
                return p.Manifest.Id;
            }
        }

        return null;
    }

    private static List<object> MatchSettingsPagesForPlugin(PluginInfo plugin, List<SettingsPageInfo> allPages)
    {
        var result = new List<object>();
        foreach (var page in allPages)
        {
            var ownerId = ResolveSettingsPageOwnerPluginId(page);
            if (string.Equals(ownerId, plugin.Manifest.Id, StringComparison.OrdinalIgnoreCase))
            {
                result.Add(new
                {
                    id = page.Id,
                    name = page.Name,
                    groupId = TryGetStringProperty(page, "GroupId"),
                    category = page.Category.ToString(),
                    useFullWidth = page.UseFullWidth
                });
            }
        }
        return result;
    }

    private static List<object> DiscoverPluginSettingsModels(PluginInfo plugin)
    {
        var models = new List<object>();
        try
        {
            var asm = FindLoadedPluginAssembly(plugin);
            if (asm == null)
            {
                return models;
            }

            foreach (var type in GetSafeExportedTypes(asm))
            {
                if (type.IsAbstract || type.IsInterface || !type.IsClass)
                {
                    continue;
                }

                var isSettingsCandidate =
                    type.Name.EndsWith("Settings", StringComparison.OrdinalIgnoreCase) ||
                    type.Name.EndsWith("Config", StringComparison.OrdinalIgnoreCase) ||
                    type.Name.EndsWith("Configuration", StringComparison.OrdinalIgnoreCase) ||
                    type.Name.EndsWith("Options", StringComparison.OrdinalIgnoreCase);

                if (!isSettingsCandidate)
                {
                    continue;
                }

                // 排除控件和窗口
                if (typeof(Avalonia.AvaloniaObject).IsAssignableFrom(type))
                {
                    continue;
                }

                var schema = ExtractTypePropertiesSchema(type);
                if (schema.Count == 0)
                {
                    continue;
                }

                models.Add(new
                {
                    typeName = type.FullName,
                    defaultValues = CreateDefaultSettingsElement(type),
                    properties = schema
                });
            }
        }
        catch
        {
            // Ignore reflection errors
        }
        return models;
    }

    private static int TryApplySettingsToLivePluginInstances(string pluginId, JsonElement settingsPatch)
    {
        if (settingsPatch.ValueKind != JsonValueKind.Object)
        {
            return 0;
        }

        var updatedCount = 0;
        try
        {
            var plugin = IPluginService.LoadedPlugins.FirstOrDefault(
                p => string.Equals(p.Manifest.Id, pluginId, StringComparison.OrdinalIgnoreCase));
            if (plugin == null)
            {
                return 0;
            }

            var asm = FindLoadedPluginAssembly(plugin);
            if (asm == null)
            {
                return 0;
            }

            foreach (var type in GetSafeExportedTypes(asm))
            {
                if (type.IsAbstract || type.IsInterface)
                {
                    continue;
                }

                var serviceInstance = IAppHost.Host?.Services.GetService(type);
                if (serviceInstance == null)
                {
                    continue;
                }

                updatedCount += ApplyPropertiesToClrObject(serviceInstance, settingsPatch);

                // 同时检查该服务是否有名为 Settings / Config / CurrentConfig 的子属性对象
                foreach (var subPropName in new[] { "Settings", "Config", "CurrentConfig", "Options" })
                {
                    var subProp = type.GetProperty(subPropName, BindingFlags.Instance | BindingFlags.Public);
                    var subObj = subProp?.GetValue(serviceInstance);
                    if (subObj != null)
                    {
                        updatedCount += ApplyPropertiesToClrObject(subObj, settingsPatch);
                    }
                }
            }
        }
        catch
        {
            // Ignore
        }
        return updatedCount;
    }

    private static Assembly? FindLoadedPluginAssembly(PluginInfo plugin)
    {
        var entranceName = Path.GetFileNameWithoutExtension(plugin.Manifest.EntranceAssembly ?? string.Empty);
        var folder = string.IsNullOrWhiteSpace(plugin.PluginFolderPath)
            ? string.Empty
            : Path.GetFullPath(plugin.PluginFolderPath);

        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(entranceName) &&
                    string.Equals(asm.GetName().Name, entranceName, StringComparison.OrdinalIgnoreCase))
                {
                    return asm;
                }

                if (!string.IsNullOrWhiteSpace(folder) &&
                    !asm.IsDynamic &&
                    !string.IsNullOrWhiteSpace(asm.Location) &&
                    asm.Location.StartsWith(folder, StringComparison.OrdinalIgnoreCase))
                {
                    return asm;
                }
            }
            catch
            {
                // Ignore
            }
        }

        return null;
    }

    private static IEnumerable<Type> GetSafeExportedTypes(Assembly asm)
    {
        try
        {
            return asm.GetExportedTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types.Where(t => t != null)!;
        }
        catch
        {
            return [];
        }
    }

    private static List<object> ExtractTypePropertiesSchema(Type? type)
    {
        var list = new List<object>();
        if (type == null || type == typeof(object) || type == typeof(JsonElement))
        {
            return list;
        }

        try
        {
            object? sampleInstance = null;
            try
            {
                if (type.GetConstructor(Type.EmptyTypes) != null)
                {
                    sampleInstance = Activator.CreateInstance(type);
                }
            }
            catch
            {
                sampleInstance = null;
            }

            var props = type.GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Where(p => p.CanRead && p.GetIndexParameters().Length == 0);

            foreach (var p in props)
            {
                var propType = Nullable.GetUnderlyingType(p.PropertyType) ?? p.PropertyType;
                object? defaultVal = null;
                if (sampleInstance != null)
                {
                    try
                    {
                        defaultVal = p.GetValue(sampleInstance);
                    }
                    catch
                    {
                        defaultVal = null;
                    }
                }

                string[]? enumNames = null;
                if (propType.IsEnum)
                {
                    try
                    {
                        enumNames = Enum.GetNames(propType);
                    }
                    catch
                    {
                        enumNames = null;
                    }
                }

                list.Add(new
                {
                    name = p.Name,
                    type = propType.Name,
                    fullType = propType.FullName,
                    canWrite = p.CanWrite,
                    isEnum = propType.IsEnum,
                    enumNames,
                    defaultValue = SerializeObjectToElement(defaultVal)
                });
            }
        }
        catch
        {
            // Ignore
        }
        return list;
    }

    private static JsonElement CreateDefaultSettingsElement(Type? settingsType)
    {
        if (settingsType == null || settingsType == typeof(object))
        {
            return JsonSerializer.SerializeToElement<object?>(null);
        }

        try
        {
            if (settingsType.GetConstructor(Type.EmptyTypes) != null)
            {
                var instance = Activator.CreateInstance(settingsType);
                return SerializeObjectToElement(instance);
            }
        }
        catch
        {
            // Ignore
        }

        return JsonSerializer.SerializeToElement<object?>(null);
    }

    private static JsonElement SerializeObjectToElement(object? obj)
    {
        if (obj == null)
        {
            return JsonSerializer.SerializeToElement<object?>(null);
        }
        if (obj is JsonElement je)
        {
            return je.Clone();
        }
        try
        {
            return JsonSerializer.SerializeToElement(obj, obj.GetType());
        }
        catch
        {
            return JsonSerializer.SerializeToElement(obj.ToString());
        }
    }

    private static int ApplyPropertiesToClrObject(object target, JsonElement patchObject)
    {
        if (patchObject.ValueKind != JsonValueKind.Object)
        {
            return 0;
        }

        var count = 0;
        var targetType = target.GetType();
        foreach (var jsonProp in patchObject.EnumerateObject())
        {
            try
            {
                var clrProp = targetType.GetProperty(
                    jsonProp.Name,
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
                if (clrProp == null || !clrProp.CanWrite)
                {
                    continue;
                }

                var val = DeserializeJsonElementToType(jsonProp.Value, clrProp.PropertyType);
                clrProp.SetValue(target, val);
                count++;
            }
            catch
            {
                // Ignore incompatible property
            }
        }
        return count;
    }

    private static object? DeserializeJsonElementToType(JsonElement element, Type targetType)
    {
        var underlying = Nullable.GetUnderlyingType(targetType) ?? targetType;
        if (element.ValueKind == JsonValueKind.Null)
        {
            return targetType.IsValueType && Nullable.GetUnderlyingType(targetType) == null
                ? Activator.CreateInstance(targetType)
                : null;
        }

        if (underlying.IsEnum)
        {
            if (element.ValueKind == JsonValueKind.String &&
                Enum.TryParse(underlying, element.GetString(), ignoreCase: true, out var parsedEnum))
            {
                return parsedEnum;
            }
            if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var enumInt))
            {
                return Enum.ToObject(underlying, enumInt);
            }
        }

        return element.Deserialize(targetType, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        AppBase.Current.AppStarted -= OnAppStarted;
        if (_hooksAttached)
        {
            ComponentRegistryService.Registered.CollectionChanged -= OnComponentRegistryChanged;
            SettingsWindowRegistryService.Registered.CollectionChanged -= OnSettingsRegistryChanged;
        }
    }
}
