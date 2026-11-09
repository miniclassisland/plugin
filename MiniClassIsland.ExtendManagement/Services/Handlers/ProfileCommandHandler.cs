using System.Reflection;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services;
using ClassIsland.Shared.Helpers;
using ClassIsland.Shared.Models.Profile;
using Microsoft.Extensions.Logging;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// 运行时档案热更新与多套档案管理处理器（profile.*）。
/// </summary>
public sealed class ProfileCommandHandler(
    ILogger<ProfileCommandHandler> logger,
    IProfileService profileService,
    ILessonsService lessonsService,
    IComponentsService componentsService)
{
    public string ProfilesDirectoryPath => Path.Combine(CommonDirectories.AppRootFolderPath, "Profiles");
    public string ComponentLayoutsDirectoryPath => Path.Combine(CommonDirectories.AppConfigPath, "ComponentLayouts");

    private static string GetSelectedProfileName() =>
        HostRuntimeBridge.GetSettingValue("SelectedProfile", "Default.json") ?? "Default.json";

    private static string GetCurrentComponentConfigName() =>
        HostRuntimeBridge.GetSettingValue("CurrentComponentConfig", "Default") ?? "Default";

    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        Directory.CreateDirectory(ProfilesDirectoryPath);
        Directory.CreateDirectory(ComponentLayoutsDirectoryPath);
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "profile.list" => await ListProfilesAsync(),
            "profile.get" => await GetProfileAsync(payload),
            "profile.put" or "profile.save" => await SaveProfileAsync(payload),
            "profile.patch" => await PatchProfileAsync(payload),
            "profile.switch" => await SwitchActiveProfileAsync(payload),
            "profile.delete" => DeleteProfile(payload),
            "profile.reload" => await ReloadActiveProfileAtRuntimeAsync(),
            "profile.temp_classplan" => await ManageTempClassPlanAsync(payload),
            "profile.components.list" or "components.list" => ListComponentConfigs(),
            "profile.components.get" or "components.get" => await GetComponentConfigAsync(payload),
            "profile.components.put" or "profile.components.save" or "components.put" or "components.save" => await SaveComponentConfigAsync(payload),
            "profile.components.switch" or "components.switch" => await SwitchComponentConfigAsync(payload),
            "profile.components.reload" or "components.reload" => await ReloadComponentsAtRuntimeAsync(),
            _ => throw new NotSupportedException($"不支持的档案指令：{action}")
        };
    }

    private static void RefreshProfileTimeLayouts(Profile profile)
    {
        var method = typeof(Profile).GetMethod(
            "RefreshTimeLayouts",
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        method?.Invoke(profile, null);
    }

    public async Task<JsonElement> ReloadActiveProfileAtRuntimeAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            lessonsService.StopMainTimer();
            try
            {
                var loadMethod = profileService.GetType().GetMethod(
                    "LoadProfileAsync",
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                if (loadMethod != null && loadMethod.Invoke(profileService, null) is Task loadTask)
                {
                    await loadTask;
                }

                RefreshProfileTimeLayouts(profileService.Profile);
                profileService.CleanExpiredTempClassPlan();
                profileService.ClearExpiredTempClassPlanGroup();
            }
            finally
            {
                lessonsService.StartMainTimer();
            }

            await ReloadComponentsInUiThreadAsync();

            var activeProfile = GetSelectedProfileName();
            var activeComponentConfig = GetCurrentComponentConfigName();
            logger.LogInformation("已在运行时热重载当前档案：{Profile} 与组件布局：{ComponentConfig}", profileService.CurrentProfilePath, activeComponentConfig);
            return JsonSerializer.SerializeToElement(new
            {
                reloaded = true,
                activeProfile,
                activeComponentConfig,
                classPlanCount = profileService.Profile.ClassPlans.Count,
                timeLayoutCount = profileService.Profile.TimeLayouts.Count,
                subjectCount = profileService.Profile.Subjects.Count,
                componentLineCount = componentsService.CurrentComponents.Lines.Count
            });
        });
    }

    public async Task<JsonElement> ReloadComponentsAtRuntimeAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(async () =>
        {
            await ReloadComponentsInUiThreadAsync();
            return JsonSerializer.SerializeToElement(new
            {
                reloaded = true,
                activeComponentConfig = GetCurrentComponentConfigName(),
                isManagementMode = componentsService.IsManagementMode,
                lineCount = componentsService.CurrentComponents.Lines.Count
            });
        });
    }

    private async Task ReloadComponentsInUiThreadAsync()
    {
        try
        {
            componentsService.RefreshConfigs();
            var loadMgmtMethod = componentsService.GetType().GetMethod(
                "LoadManagementConfig",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (loadMgmtMethod != null && loadMgmtMethod.Invoke(componentsService, null) is Task mgmtTask)
            {
                await mgmtTask;
            }

            var loadConfigMethod = componentsService.GetType().GetMethod(
                "LoadConfig",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            loadConfigMethod?.Invoke(componentsService, null);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "运行时热重载组件布局配置异常。");
        }
    }

    private JsonElement ListComponentConfigs()
    {
        componentsService.RefreshConfigs();
        var activeName = GetCurrentComponentConfigName();
        var configs = componentsService.ComponentConfigs;
        return JsonSerializer.SerializeToElement(new
        {
            currentComponentConfig = activeName,
            isManagementMode = componentsService.IsManagementMode,
            configs,
            lineCount = componentsService.CurrentComponents.Lines.Count
        });
    }

    private async Task<JsonElement> GetComponentConfigAsync(JsonElement payload)
    {
        var requestedName = payload.ValueKind == JsonValueKind.Object &&
                            payload.TryGetProperty("configName", out var cProp) &&
                            !string.IsNullOrWhiteSpace(cProp.GetString())
            ? Path.GetFileNameWithoutExtension(cProp.GetString()!.Trim())
            : GetCurrentComponentConfigName();

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var isCurrent = string.Equals(requestedName, GetCurrentComponentConfigName(), StringComparison.OrdinalIgnoreCase);
            if (isCurrent)
            {
                return JsonSerializer.SerializeToElement(new
                {
                    configName = requestedName,
                    isActive = true,
                    isManagementMode = componentsService.IsManagementMode,
                    components = componentsService.CurrentComponents
                });
            }

            var fullPath = Path.GetFullPath(Path.Combine(ComponentLayoutsDirectoryPath, requestedName + ".json"));
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException($"未找到组件布局配置：{requestedName}");
            }

            var loaded = ConfigureFileHelper.LoadConfig<ClassIsland.Core.Models.Components.ComponentProfile>(fullPath);
            return JsonSerializer.SerializeToElement(new
            {
                configName = requestedName,
                isActive = false,
                isManagementMode = componentsService.IsManagementMode,
                components = loaded
            });
        });
    }

    private async Task<JsonElement> SaveComponentConfigAsync(JsonElement payload)
    {
        var targetName = payload.ValueKind == JsonValueKind.Object &&
                         payload.TryGetProperty("configName", out var cProp) &&
                         !string.IsNullOrWhiteSpace(cProp.GetString())
            ? Path.GetFileNameWithoutExtension(cProp.GetString()!.Trim())
            : GetCurrentComponentConfigName();

        if (!payload.TryGetProperty("components", out var compElem) || compElem.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("需要提供有效的 components 布局对象。");
        }

        var profile = compElem.Deserialize<ClassIsland.Core.Models.Components.ComponentProfile>()
                      ?? throw new InvalidOperationException("无法反序列化组件布局配置。");

        var fullPath = Path.GetFullPath(Path.Combine(ComponentLayoutsDirectoryPath, targetName + ".json"));
        Directory.CreateDirectory(ComponentLayoutsDirectoryPath);
        ConfigureFileHelper.SaveConfig(fullPath, profile);

        var activate = !payload.TryGetProperty("activate", out var actProp) || actProp.ValueKind != JsonValueKind.False;
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            componentsService.RefreshConfigs();
            var isCurrent = string.Equals(targetName, GetCurrentComponentConfigName(), StringComparison.OrdinalIgnoreCase);
            if (activate || isCurrent)
            {
                if (componentsService.IsManagementMode)
                {
                    Directory.CreateDirectory(HostRuntimeBridge.ManagementConfigureFolderPath);
                    ConfigureFileHelper.SaveConfig(HostRuntimeBridge.ManagementComponentsPath, profile);
                }

                if (!isCurrent)
                {
                    HostRuntimeBridge.SetSettingValue("CurrentComponentConfig", targetName);
                    HostRuntimeBridge.SaveSettings("集控切换组件布局配置");
                }

                componentsService.CurrentComponents = profile;
                var loadConfigMethod = componentsService.GetType().GetMethod(
                    "LoadConfig",
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                loadConfigMethod?.Invoke(componentsService, null);
                isCurrent = true;
            }

            return JsonSerializer.SerializeToElement(new
            {
                configName = targetName,
                isActive = isCurrent,
                lineCount = profile.Lines.Count
            });
        });
    }

    private async Task<JsonElement> SwitchComponentConfigAsync(JsonElement payload)
    {
        if (!payload.TryGetProperty("configName", out var cProp) || string.IsNullOrWhiteSpace(cProp.GetString()))
        {
            throw new ArgumentException("需要提供要切换的组件布局名称 configName。");
        }

        var targetName = Path.GetFileNameWithoutExtension(cProp.GetString()!.Trim());
        var fullPath = Path.GetFullPath(Path.Combine(ComponentLayoutsDirectoryPath, targetName + ".json"));
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"未找到组件布局配置：{targetName}");
        }

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var loaded = ConfigureFileHelper.LoadConfig<ClassIsland.Core.Models.Components.ComponentProfile>(fullPath);
            if (componentsService.IsManagementMode)
            {
                ConfigureFileHelper.SaveConfig(HostRuntimeBridge.ManagementComponentsPath, loaded);
            }

            HostRuntimeBridge.SetSettingValue("CurrentComponentConfig", targetName);
            HostRuntimeBridge.SaveSettings($"集控切换组件布局配置至 {targetName}");
            componentsService.CurrentComponents = loaded;
            var loadConfigMethod = componentsService.GetType().GetMethod(
                "LoadConfig",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            loadConfigMethod?.Invoke(componentsService, null);

            return JsonSerializer.SerializeToElement(new
            {
                configName = targetName,
                isActive = true,
                lineCount = componentsService.CurrentComponents.Lines.Count
            });
        });
    }

    private async Task<JsonElement> ListProfilesAsync()
    {
        return await Task.Run(() =>
        {
            var activeFileName = GetSelectedProfileName();
            var files = Directory.GetFiles(ProfilesDirectoryPath, "*.json", SearchOption.TopDirectoryOnly)
                .OrderBy(f => Path.GetFileName(f), StringComparer.OrdinalIgnoreCase)
                .ToList();

            var items = new List<object>();
            foreach (var file in files)
            {
                var fileName = Path.GetFileName(file);
                var fi = new FileInfo(file);
                var isActive = string.Equals(fileName, activeFileName, StringComparison.OrdinalIgnoreCase);

                int subjects = 0, timeLayouts = 0, classPlans = 0;
                try
                {
                    var p = isActive
                        ? profileService.Profile
                        : ConfigureFileHelper.LoadConfig<Profile>(file);
                    subjects = p.Subjects.Count;
                    timeLayouts = p.TimeLayouts.Count;
                    classPlans = p.ClassPlans.Count;
                }
                catch
                {
                    // Ignore parse failure for summary
                }

                items.Add(new
                {
                    fileName,
                    isActive,
                    sizeBytes = fi.Length,
                    lastModifiedUtc = fi.LastWriteTimeUtc,
                    subjectCount = subjects,
                    timeLayoutCount = timeLayouts,
                    classPlanCount = classPlans
                });
            }

            return JsonSerializer.SerializeToElement(new
            {
                activeProfile = activeFileName,
                totalCount = items.Count,
                profiles = items
            });
        });
    }

    private async Task<JsonElement> GetProfileAsync(JsonElement payload)
    {
        var requestedName = TryGetProfileFileName(payload, fallbackToActive: true);
        var activeName = GetSelectedProfileName();

        if (string.Equals(requestedName, activeName, StringComparison.OrdinalIgnoreCase))
        {
            return await Dispatcher.UIThread.InvokeAsync(() =>
                JsonSerializer.SerializeToElement(new
                {
                    fileName = activeName,
                    isActive = true,
                    profile = profileService.Profile
                }));
        }

        var fullPath = GetSafeProfilePath(requestedName);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"未找到档案文件：{requestedName}");
        }

        var profile = ConfigureFileHelper.LoadConfig<Profile>(fullPath);
        return JsonSerializer.SerializeToElement(new
        {
            fileName = requestedName,
            isActive = false,
            profile
        });
    }

    private async Task<JsonElement> SaveProfileAsync(JsonElement payload)
    {
        var targetName = TryGetProfileFileName(payload, fallbackToActive: true);
        if (!payload.TryGetProperty("profile", out var profileElem) || profileElem.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("profile.put 需要包含完整的 profile 对象。");
        }

        var newProfile = profileElem.Deserialize<Profile>()
                         ?? throw new InvalidOperationException("无法反序列化 Profile 数据。");

        var fullPath = GetSafeProfilePath(targetName);
        ConfigureFileHelper.SaveConfig(fullPath, newProfile);

        var activate = payload.TryGetProperty("activate", out var actProp) && actProp.ValueKind == JsonValueKind.True;
        var isActive = string.Equals(targetName, GetSelectedProfileName(), StringComparison.OrdinalIgnoreCase);

        if (activate && !isActive)
        {
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                HostRuntimeBridge.SetSettingValue("SelectedProfile", targetName);
                HostRuntimeBridge.SaveSettings("集控切换激活档案");
            });
            isActive = true;
        }

        if (isActive)
        {
            await ApplyProfileToRuntimeMemoryAsync(newProfile);
        }

        return JsonSerializer.SerializeToElement(new
        {
            fileName = targetName,
            isActive,
            classPlanCount = newProfile.ClassPlans.Count,
            timeLayoutCount = newProfile.TimeLayouts.Count,
            subjectCount = newProfile.Subjects.Count
        });
    }

    private async Task<JsonElement> PatchProfileAsync(JsonElement payload)
    {
        var targetName = TryGetProfileFileName(payload, fallbackToActive: true);
        var isActive = string.Equals(targetName, GetSelectedProfileName(), StringComparison.OrdinalIgnoreCase);
        var fullPath = GetSafeProfilePath(targetName);

        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var targetProfile = isActive
                ? profileService.Profile
                : File.Exists(fullPath)
                    ? ConfigureFileHelper.LoadConfig<Profile>(fullPath)
                    : new Profile();

            if (payload.TryGetProperty("subjects", out var subsElem) && subsElem.ValueKind == JsonValueKind.Object)
            {
                var replaceAll = payload.TryGetProperty("replaceSubjects", out var rSub) && rSub.ValueKind == JsonValueKind.True;
                if (replaceAll)
                {
                    targetProfile.Subjects.Clear();
                }

                var dict = subsElem.Deserialize<Dictionary<Guid, Subject>>();
                if (dict != null)
                {
                    foreach (var (k, v) in dict)
                    {
                        targetProfile.Subjects[k] = v;
                    }
                }
            }

            if (payload.TryGetProperty("timeLayouts", out var tlElem) && tlElem.ValueKind == JsonValueKind.Object)
            {
                var replaceAll = payload.TryGetProperty("replaceTimeLayouts", out var rTl) && rTl.ValueKind == JsonValueKind.True;
                if (replaceAll)
                {
                    targetProfile.TimeLayouts.Clear();
                }

                var dict = tlElem.Deserialize<Dictionary<Guid, TimeLayout>>();
                if (dict != null)
                {
                    foreach (var (k, v) in dict)
                    {
                        targetProfile.TimeLayouts[k] = v;
                    }
                }
            }

            if (payload.TryGetProperty("classPlans", out var cpElem) && cpElem.ValueKind == JsonValueKind.Object)
            {
                var replaceAll = payload.TryGetProperty("replaceClassPlans", out var rCp) && rCp.ValueKind == JsonValueKind.True;
                if (replaceAll)
                {
                    targetProfile.ClassPlans.Clear();
                }

                var dict = cpElem.Deserialize<Dictionary<Guid, ClassPlan>>();
                if (dict != null)
                {
                    foreach (var (k, v) in dict)
                    {
                        targetProfile.ClassPlans[k] = v;
                    }
                }
            }

            if (payload.TryGetProperty("orderedSchedules", out var osElem) && osElem.ValueKind == JsonValueKind.Object)
            {
                var dict = osElem.Deserialize<Dictionary<DateTime, OrderedSchedule>>();
                if (dict != null)
                {
                    foreach (var (k, v) in dict)
                    {
                        targetProfile.OrderedSchedules[k] = v;
                    }
                }
            }

            if (payload.TryGetProperty("selectedClassPlanGroupId", out var groupProp) &&
                Guid.TryParse(groupProp.GetString(), out var groupGuid))
            {
                targetProfile.SelectedClassPlanGroupId = groupGuid;
            }

            RefreshProfileTimeLayouts(targetProfile);
            ConfigureFileHelper.SaveConfig(fullPath, targetProfile);

            if (isActive)
            {
                lessonsService.StopMainTimer();
                profileService.SaveProfile();
                lessonsService.StartMainTimer();
            }

            return JsonSerializer.SerializeToElement(new
            {
                fileName = targetName,
                isActive,
                subjectCount = targetProfile.Subjects.Count,
                timeLayoutCount = targetProfile.TimeLayouts.Count,
                classPlanCount = targetProfile.ClassPlans.Count
            });
        });
    }

    private async Task<JsonElement> SwitchActiveProfileAsync(JsonElement payload)
    {
        var targetName = TryGetProfileFileName(payload, fallbackToActive: false);
        var fullPath = GetSafeProfilePath(targetName);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"目标档案不存在：{targetName}");
        }

        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            profileService.SaveProfile();
            HostRuntimeBridge.SetSettingValue("SelectedProfile", targetName);
            HostRuntimeBridge.SaveSettings($"集控切换当前使用档案至 {targetName}");
        });

        return await ReloadActiveProfileAtRuntimeAsync();
    }

    private JsonElement DeleteProfile(JsonElement payload)
    {
        var targetName = TryGetProfileFileName(payload, fallbackToActive: false);
        if (string.Equals(targetName, GetSelectedProfileName(), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("不能直接删除当前正在使用的激活档案，请先切换到其他档案。");
        }

        var fullPath = GetSafeProfilePath(targetName);
        if (!File.Exists(fullPath))
        {
            return JsonSerializer.SerializeToElement(new { deleted = false, fileName = targetName, reason = "文件不存在" });
        }

        File.Delete(fullPath);
        return JsonSerializer.SerializeToElement(new { deleted = true, fileName = targetName });
    }

    private async Task<JsonElement> ManageTempClassPlanAsync(JsonElement payload)
    {
        var mode = payload.TryGetProperty("mode", out var mProp) ? mProp.GetString()?.ToLowerInvariant() : "set";
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (mode == "clear")
            {
                profileService.ClearTempClassPlan();
                profileService.ClearTempClassPlanGroup();
                return JsonSerializer.SerializeToElement(new { cleared = true });
            }

            if (!payload.TryGetProperty("classPlanId", out var idProp) || !Guid.TryParse(idProp.GetString(), out var cpGuid))
            {
                throw new ArgumentException("需要提供有效的 classPlanId GUID。");
            }

            if (mode == "overlay")
            {
                Guid? tlId = payload.TryGetProperty("timeLayoutId", out var tlProp) && Guid.TryParse(tlProp.GetString(), out var parsedTl)
                    ? parsedTl
                    : null;
                var overlayId = profileService.CreateTempClassPlan(cpGuid, tlId);
                return JsonSerializer.SerializeToElement(new { mode = "overlay", overlayClassPlanId = overlayId });
            }

            if (mode == "group")
            {
                profileService.SetupTempClassPlanGroup(cpGuid);
                return JsonSerializer.SerializeToElement(new { mode = "group", tempClassPlanGroupId = cpGuid });
            }

            profileService.Profile.TempClassPlanId = cpGuid;
            profileService.Profile.TempClassPlanSetupTime = DateTime.Now;
            profileService.SaveProfile();
            return JsonSerializer.SerializeToElement(new { mode = "temp", tempClassPlanId = cpGuid });
        });
    }

    private async Task ApplyProfileToRuntimeMemoryAsync(Profile updatedProfile)
    {
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            lessonsService.StopMainTimer();
            try
            {
                var current = profileService.Profile;
                current.Subjects.Clear();
                foreach (var (k, v) in updatedProfile.Subjects)
                {
                    current.Subjects[k] = v;
                }

                current.TimeLayouts.Clear();
                foreach (var (k, v) in updatedProfile.TimeLayouts)
                {
                    current.TimeLayouts[k] = v;
                }

                current.ClassPlans.Clear();
                foreach (var (k, v) in updatedProfile.ClassPlans)
                {
                    current.ClassPlans[k] = v;
                }

                current.ClassPlanGroups.Clear();
                foreach (var (k, v) in updatedProfile.ClassPlanGroups)
                {
                    current.ClassPlanGroups[k] = v;
                }

                current.OrderedSchedules.Clear();
                foreach (var (k, v) in updatedProfile.OrderedSchedules)
                {
                    current.OrderedSchedules[k] = v;
                }

                current.SelectedClassPlanGroupId = updatedProfile.SelectedClassPlanGroupId;
                current.TempClassPlanId = updatedProfile.TempClassPlanId;
                current.OverlayClassPlanId = updatedProfile.OverlayClassPlanId;
                current.IsOverlayClassPlanEnabled = updatedProfile.IsOverlayClassPlanEnabled;

                RefreshProfileTimeLayouts(current);
                profileService.SaveProfile();
            }
            finally
            {
                lessonsService.StartMainTimer();
            }
        });
    }

    private static string TryGetProfileFileName(JsonElement payload, bool fallbackToActive)
    {
        string? name = null;
        if (payload.ValueKind == JsonValueKind.Object)
        {
            if (payload.TryGetProperty("fileName", out var fProp))
            {
                name = fProp.GetString();
            }
            else if (payload.TryGetProperty("name", out var nProp))
            {
                name = nProp.GetString();
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            if (fallbackToActive)
            {
                return GetSelectedProfileName();
            }
            throw new ArgumentException("必须指定档案文件名 fileName。");
        }

        name = Path.GetFileName(name.Trim());
        if (!name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            name += ".json";
        }
        return name;
    }

    private string GetSafeProfilePath(string fileName)
    {
        var cleanName = Path.GetFileName(fileName);
        var fullPath = Path.GetFullPath(Path.Combine(ProfilesDirectoryPath, cleanName));
        var rootFull = Path.GetFullPath(ProfilesDirectoryPath);
        if (!fullPath.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("非法的档案路径。");
        }
        return fullPath;
    }
}
