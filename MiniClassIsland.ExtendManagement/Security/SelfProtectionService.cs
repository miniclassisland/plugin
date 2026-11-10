using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.LogicalTree;
using Avalonia.Threading;
using Avalonia.VisualTree;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Core.Models.Plugin;
using ClassIsland.Shared;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Services;

namespace MiniClassIsland.ExtendManagement.Security;

/// <summary>
/// 插件自我保护与 MINI 集控隐藏服务：
/// 仅保护插件本体文件与启用状态（移除应用重启保护与应用退出保护）：
/// 1. 对插件核心文件持有只读共享文件句柄锁并保存内存镜像，防止外部运行期删除或覆盖；
/// 2. 拦截并清除未经授权的 `.disabled` 与 `.uninstall` 标记，并同步重置内存中的 `PluginInfo.RestartRequired` / `IsEnabled` / `IsUninstalling`；
/// 3. 在设置窗口（`PluginsSettingsPage`）视觉树中，当选择本插件时直接禁用「已启用」复选框与「移除」按钮，引导用户前往「集控」设置页操作；
/// 4. 进程正常退出时仅释放文件句柄锁并校验插件本体文件完整性，不干预或拦截宿主应用的退出与重启。
/// </summary>
public sealed class SelfProtectionService : IDisposable
{
    public const string PluginId = "org.miniopensource.miniclassisland.extendmanagement";

    private readonly ILogger<SelfProtectionService> _logger;
    private readonly IManagementService _managementService;
    private readonly TamperEvidentConfigStore _configStore;
    private readonly string _pluginFolderPath;
    private readonly List<FileStream> _lockedStreams = [];
    private readonly Dictionary<string, byte[]> _pluginFileMirrors = new(StringComparer.OrdinalIgnoreCase);
    private FileSystemWatcher? _pluginFolderWatcher;
    private readonly Timer _guardTimer;
    private bool _authorizedSelfUninstallRequested;

    public bool IsSelfUninstallPending => _authorizedSelfUninstallRequested;

    public SelfProtectionService(
        ILogger<SelfProtectionService> logger,
        IManagementService managementService,
        TamperEvidentConfigStore configStore,
        string pluginFolderPath)
    {
        _logger = logger;
        _managementService = managementService;
        _configStore = configStore;
        _pluginFolderPath = pluginFolderPath;

        if (_configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            InitializePluginSelfProtection();
        }

        AppBase.Current.AppStarted += (_, _) =>
        {
            if (_configStore.CurrentConfig.HasAcceptedSecurityWarning)
            {
                ApplyMiniServerPluginListStealth();
            }
        };

        _guardTimer = new Timer(_ => PeriodicGuardTick(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }

    /// <summary>
    /// 兼容保留的退出授权方法（已移除应用退出/重启拦截，无需额外操作）。
    /// </summary>
    public void GrantAuthorizedExit()
    {
    }

    /// <summary>
    /// 由“集控选项”页面中的“移除集控增强”触发的合法卸载流程。
    /// </summary>
    public bool RequestUninstallSelfFromManagementPage()
    {
        try
        {
            _authorizedSelfUninstallRequested = true;
            ReleaseFileLocks();
            _configStore.ResetSecurityWarningAcceptanceForUninstall();

            if (!string.IsNullOrWhiteSpace(_pluginFolderPath) && Directory.Exists(_pluginFolderPath))
            {
                var uninstallMarker = Path.Combine(_pluginFolderPath, ".uninstall");
                File.WriteAllText(uninstallMarker, "", Encoding.UTF8);
            }

            var selfInfo = GetSelfPluginInfo();
            if (selfInfo != null)
            {
                selfInfo.IsUninstalling = true;
            }

            _logger.LogInformation("用户已在集控选项页请求移除集控增强组件，将在下次应用启动时完成卸载。");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "标记移除集控增强组件失败。");
            return false;
        }
    }

    private static PluginInfo? GetSelfPluginInfo()
    {
        return IPluginService.LoadedPlugins.FirstOrDefault(
            p => string.Equals(p.Manifest.Id, PluginId, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// 当加入具有 MINI ClassIsland 特征的集控服务器时，从插件列表中隐藏本组件，仅保留集控设置页中的选项。
    /// </summary>
    public void ApplyMiniServerPluginListStealth()
    {
        if (!HostRuntimeBridge.IsJoinedMiniClassIslandServer(_managementService))
        {
            return;
        }

        Dispatcher.UIThread.Post(() =>
        {
            try
            {
                var loadedProp = typeof(IPluginService).GetProperty(
                    "LoadedPluginsInternal",
                    BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                if (loadedProp?.GetValue(null) is IList loadedList)
                {
                    for (var i = loadedList.Count - 1; i >= 0; i--)
                    {
                        var item = loadedList[i];
                        var id = item?.GetType().GetProperty("Manifest")?.GetValue(item)
                            ?.GetType().GetProperty("Id")?.GetValue(item.GetType().GetProperty("Manifest")!.GetValue(item));
                        if (string.Equals(id as string, PluginId, StringComparison.OrdinalIgnoreCase))
                        {
                            loadedList.RemoveAt(i);
                        }
                    }
                }

                var marketSvc = IAppHost.TryGetService<IPluginMarketService>();
                if (marketSvc != null && marketSvc.MergedPlugins.ContainsKey(PluginId))
                {
                    marketSvc.MergedPlugins.Remove(PluginId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "隐藏插件列表项时发生异常。");
            }
        });
    }

    private void InitializePluginSelfProtection()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_pluginFolderPath) || !Directory.Exists(_pluginFolderPath))
            {
                return;
            }

            foreach (var file in Directory.GetFiles(_pluginFolderPath, "*", SearchOption.AllDirectories))
            {
                var fileName = Path.GetFileName(file);
                if (fileName is ".disabled" or ".uninstall")
                {
                    continue;
                }
                try
                {
                    _pluginFileMirrors[file] = File.ReadAllBytes(file);
                }
                catch
                {
                    // Ignore transient read error
                }
            }

            RemoveDisableAndUninstallMarkers();
            AcquireFileLocks();

            var selfInfo = GetSelfPluginInfo();
            if (selfInfo != null)
            {
                selfInfo.PropertyChanged += (_, args) =>
                {
                    if (_authorizedSelfUninstallRequested)
                    {
                        return;
                    }

                    if (args.PropertyName is nameof(PluginInfo.IsEnabled) or nameof(PluginInfo.IsUninstalling) or nameof(PluginInfo.RestartRequired))
                    {
                        var disabledMarker = Path.Combine(_pluginFolderPath, ".disabled");
                        var uninstallMarker = Path.Combine(_pluginFolderPath, ".uninstall");
                        if (File.Exists(disabledMarker) || File.Exists(uninstallMarker) || selfInfo.RestartRequired)
                        {
                            Dispatcher.UIThread.Post(RemoveDisableAndUninstallMarkers);
                        }
                    }
                };
            }

            _pluginFolderWatcher = new FileSystemWatcher(_pluginFolderPath)
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            _pluginFolderWatcher.Created += OnPluginDirectoryFileChanged;
            _pluginFolderWatcher.Changed += OnPluginDirectoryFileChanged;
            _pluginFolderWatcher.Renamed += OnPluginDirectoryFileChanged;

            AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
            Window.WindowOpenedEvent.AddClassHandler<Window>(OnWindowOpenedForPluginGuard);
            Control.LoadedEvent.AddClassHandler<Control>(OnControlLoadedForPluginGuard);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "初始化插件自我保护时发生异常。");
        }
    }

    private void OnControlLoadedForPluginGuard(Control control, RoutedEventArgs e)
    {
        var fullName = control.GetType().FullName;
        if (fullName == "ClassIsland.Views.SettingPages.PluginsSettingsPage")
        {
            ApplyMiniServerPluginListStealth();
            AttachPluginsSettingsPageUiGuard(control);
        }
    }

    /// <summary>
    /// 在插件管理页面（PluginsSettingsPage）中挂载 UI 级保护：
    /// 直接在插件详情区锁定对本插件的“已启用”勾选取消与“移除”按钮点击，
    /// 彻底避免在插件页产生无效的“重启以应用更改”提示，并引导用户在“集控”页面操作。
    /// </summary>
    private void AttachPluginsSettingsPageUiGuard(Control pluginsPage)
    {
        void EnforceSelfPluginControlsState()
        {
            if (_authorizedSelfUninstallRequested)
            {
                return;
            }

            foreach (var checkBox in pluginsPage.GetVisualDescendants().OfType<CheckBox>())
            {
                if (checkBox.DataContext is PluginInfo info &&
                    string.Equals(info.Manifest.Id, PluginId, StringComparison.OrdinalIgnoreCase) &&
                    checkBox.Content as string == "已启用")
                {
                    checkBox.IsEnabled = false;
                    if (checkBox.IsChecked != true)
                    {
                        checkBox.IsChecked = true;
                    }
                    ToolTip.SetTip(checkBox, "插件自我保护已开启，请前往【集控】设置页面管理或移除本组件。");
                }
            }

            foreach (var button in pluginsPage.GetVisualDescendants().OfType<Button>())
            {
                if (button.DataContext is PluginInfo info &&
                    string.Equals(info.Manifest.Id, PluginId, StringComparison.OrdinalIgnoreCase))
                {
                    var text = button.GetVisualDescendants().OfType<TextBlock>().FirstOrDefault()?.Text
                               ?? button.GetLogicalDescendants().OfType<TextBlock>().FirstOrDefault()?.Text
                               ?? string.Empty;
                    if (text.Contains("移除", StringComparison.Ordinal) || button.Content?.ToString()?.Contains("移除") == true)
                    {
                        button.IsEnabled = false;
                        ToolTip.SetTip(button, "插件自我保护已开启，请前往【集控】设置页面点击【移除集控增强】。");
                    }
                }
            }
        }

        pluginsPage.AddHandler(InputElement.PointerPressedEvent, (_, _) =>
        {
            Dispatcher.UIThread.Post(EnforceSelfPluginControlsState, DispatcherPriority.Loaded);
        }, RoutingStrategies.Tunnel | RoutingStrategies.Bubble, true);

        pluginsPage.AddHandler(InputElement.PointerReleasedEvent, (_, _) =>
        {
            if (!_authorizedSelfUninstallRequested)
            {
                RemoveDisableAndUninstallMarkers();
                Dispatcher.UIThread.Post(EnforceSelfPluginControlsState, DispatcherPriority.Loaded);
            }
        }, RoutingStrategies.Tunnel | RoutingStrategies.Bubble, true);

        Dispatcher.UIThread.Post(EnforceSelfPluginControlsState, DispatcherPriority.Loaded);
    }

    private void OnPluginDirectoryFileChanged(object sender, FileSystemEventArgs e)
    {
        if (_authorizedSelfUninstallRequested)
        {
            return;
        }

        var name = Path.GetFileName(e.FullPath);
        if (string.Equals(name, ".disabled", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(name, ".uninstall", StringComparison.OrdinalIgnoreCase))
        {
            RemoveDisableAndUninstallMarkers();
        }
    }

    private void RemoveDisableAndUninstallMarkers()
    {
        if (_authorizedSelfUninstallRequested || string.IsNullOrWhiteSpace(_pluginFolderPath) || !Directory.Exists(_pluginFolderPath))
        {
            return;
        }

        try
        {
            var disabledMarker = Path.Combine(_pluginFolderPath, ".disabled");
            var hadDisabled = File.Exists(disabledMarker);
            if (hadDisabled)
            {
                File.SetAttributes(disabledMarker, FileAttributes.Normal);
                File.Delete(disabledMarker);
                _logger.LogInformation("插件自我保护：已拦截并清除 .disabled 禁用标记。");
            }

            var uninstallMarker = Path.Combine(_pluginFolderPath, ".uninstall");
            var hadUninstall = File.Exists(uninstallMarker);
            if (hadUninstall)
            {
                File.SetAttributes(uninstallMarker, FileAttributes.Normal);
                File.Delete(uninstallMarker);
                _logger.LogInformation("插件自我保护：已拦截并清除非授权的 .uninstall 卸载标记。");
            }

            var selfInfo = GetSelfPluginInfo();
            if (selfInfo != null && (hadDisabled || hadUninstall || selfInfo.RestartRequired))
            {
                Dispatcher.UIThread.Post(() =>
                {
                    try
                    {
                        if (selfInfo.RestartRequired)
                        {
                            selfInfo.RestartRequired = false;
                        }
                        if (hadDisabled || hadUninstall)
                        {
                            var notifyMethod = typeof(PluginInfo).GetMethod("OnPropertyChanged", BindingFlags.Instance | BindingFlags.NonPublic, null, [typeof(string)], null);
                            if (hadDisabled)
                            {
                                notifyMethod?.Invoke(selfInfo, [nameof(PluginInfo.IsEnabled)]);
                            }
                            if (hadUninstall)
                            {
                                notifyMethod?.Invoke(selfInfo, [nameof(PluginInfo.IsUninstalling)]);
                            }
                        }
                    }
                    catch
                    {
                        // Ignore
                    }
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "清除插件禁用/卸载标记时发生异常。");
        }
    }

    private void AcquireFileLocks()
    {
        if (_authorizedSelfUninstallRequested || _lockedStreams.Count > 0 || string.IsNullOrWhiteSpace(_pluginFolderPath))
        {
            return;
        }

        var criticalFiles = new[]
        {
            Path.Combine(_pluginFolderPath, "MiniClassIsland.ExtendManagement.dll"),
            Path.Combine(_pluginFolderPath, "manifest.yml"),
            Path.Combine(_pluginFolderPath, "icon.png"),
            Path.Combine(_pluginFolderPath, TamperEvidentConfigStore.SecurityAcceptedMarkerFileName)
        };

        foreach (var filePath in criticalFiles)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    _lockedStreams.Add(stream);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "锁定插件文件 {File} 失败。", filePath);
            }
        }
    }

    private void ReleaseFileLocks()
    {
        foreach (var s in _lockedStreams)
        {
            try
            {
                s.Dispose();
            }
            catch
            {
                // Ignore
            }
        }
        _lockedStreams.Clear();
    }

    private void HealPluginFilesIfMissing()
    {
        if (_authorizedSelfUninstallRequested)
        {
            return;
        }

        foreach (var (filePath, bytes) in _pluginFileMirrors)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
                    File.WriteAllBytes(filePath, bytes);
                    _logger.LogWarning("插件自我保护：已自动修复缺失的插件文件 {File}。", Path.GetFileName(filePath));
                }
            }
            catch
            {
                // Ignore if locked by us
            }
        }
    }

    private void OnWindowOpenedForPluginGuard(Window window, RoutedEventArgs e)
    {
        if (_authorizedSelfUninstallRequested)
        {
            return;
        }

        window.AddHandler(InputElement.PointerReleasedEvent, (_, _) =>
        {
            if (!_authorizedSelfUninstallRequested)
            {
                RemoveDisableAndUninstallMarkers();
            }
        }, RoutingStrategies.Tunnel | RoutingStrategies.Bubble, true);
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        ReleaseFileLocks();
        if (!_authorizedSelfUninstallRequested)
        {
            RemoveDisableAndUninstallMarkers();
            HealPluginFilesIfMissing();
        }
    }

    private void PeriodicGuardTick()
    {
        if (!_configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            return;
        }

        _configStore.VerifyAndHealDiskFile();

        if (!_authorizedSelfUninstallRequested)
        {
            RemoveDisableAndUninstallMarkers();
            HealPluginFilesIfMissing();
        }
    }

    public void Dispose()
    {
        _guardTimer.Dispose();
        _pluginFolderWatcher?.Dispose();
        ReleaseFileLocks();
    }
}
