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
    private FileSystemWatcher? _packagesStagingWatcher;
    private readonly Timer _guardTimer;
    private bool _authorizedSelfUninstallRequested;
    private bool _authorizedSignedSelfUpdatePending;

    public bool IsSelfUninstallPending => _authorizedSelfUninstallRequested;
    public bool IsSignedSelfUpdatePending => _authorizedSignedSelfUpdatePending;

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
                if (fileName is ".disabled" or ".uninstall" or ".old" || fileName.EndsWith(".old", StringComparison.OrdinalIgnoreCase))
                {
                    if (fileName.EndsWith(".old", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            File.SetAttributes(file, FileAttributes.Normal);
                            File.Delete(file);
                        }
                        catch
                        {
                            // Ignore
                        }
                    }
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

            InitializePackagesStagingGuard();

            var (installedSigOk, installedSigReason, installedSigVer) =
                CipxPackageSshVerifier.VerifyInstalledPluginDirectory(_pluginFolderPath);
            if (installedSigOk)
            {
                _logger.LogInformation("插件本体 SSH-Ed25519 数字签名校验通过（版本：{Version}）。", installedSigVer);
            }
            else
            {
                _logger.LogDebug("当前插件安装目录签名状态：{Reason}", installedSigReason);
            }

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
            Path.Combine(_pluginFolderPath, CipxPackageSshVerifier.SignatureManifestEntryName),
            Path.Combine(_pluginFolderPath, CipxPackageSshVerifier.SignatureSshSigEntryName),
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

    private void InitializePackagesStagingGuard()
    {
        try
        {
            var pkgDir = HostRuntimeBridge.PluginsPkgRootPath;
            Directory.CreateDirectory(pkgDir);

            VerifyAndPurgeTamperedStagedPackages();

            _packagesStagingWatcher = new FileSystemWatcher(pkgDir, "*.cipx")
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            _packagesStagingWatcher.Created += OnPackagesStagingChanged;
            _packagesStagingWatcher.Changed += OnPackagesStagingChanged;
            _packagesStagingWatcher.Renamed += OnPackagesStagingChanged;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "初始化插件安装暂存目录签名守卫时发生异常。");
        }
    }

    private void OnPackagesStagingChanged(object sender, FileSystemEventArgs e)
    {
        VerifyAndPurgeTamperedStagedPackages();
    }

    /// <summary>
    /// 扫描插件安装暂存目录（Cache/PluginPackages/*.cipx），拦截任何试图通过插件市场安装服务或“从文件安装”服务覆盖本插件但未携带合法开发者 SSH-Ed25519 签名的包；
    /// 若检测到通过开发者 SSH-Ed25519 签名的正版更新包，则自动标记允许热替换更新并在退出时释放旧文件句柄。
    /// </summary>
    public void VerifyAndPurgeTamperedStagedPackages()
    {
        try
        {
            var pkgDir = HostRuntimeBridge.PluginsPkgRootPath;
            if (!Directory.Exists(pkgDir))
            {
                return;
            }

            foreach (var cipxFile in Directory.GetFiles(pkgDir, "*.cipx", SearchOption.TopDirectoryOnly))
            {
                var (isSelfPkg, isSigValid, reason, version) = CipxPackageSshVerifier.InspectAndVerifyCipxPackage(cipxFile);
                if (!isSelfPkg)
                {
                    continue;
                }

                if (isSigValid)
                {
                    if (!_authorizedSignedSelfUpdatePending)
                    {
                        _authorizedSignedSelfUpdatePending = true;
                        _logger.LogInformation(
                            "插件更新保护：检测到经过开发者 SSH-Ed25519 签名认证的正版更新包 ({File}, 版本={Version})，已授权热替换更新。",
                            Path.GetFileName(cipxFile),
                            version ?? "unknown");
                    }
                }
                else
                {
                    try
                    {
                        File.SetAttributes(cipxFile, FileAttributes.Normal);
                        File.Delete(cipxFile);
                        _logger.LogWarning(
                            "插件更新保护：已拦截并删除未通过开发者 SSH-Ed25519 签名校验的覆盖安装包 [{File}]，原因：{Reason}",
                            Path.GetFileName(cipxFile),
                            reason);
                    }
                    catch (Exception delEx)
                    {
                        _logger.LogDebug(delEx, "删除未授权覆盖安装包 {File} 失败。", cipxFile);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "巡检插件安装暂存区签名时发生异常。");
        }
    }

    /// <summary>
    /// 对外部或远程传入的本插件更新包执行 SSH-Ed25519 签名校验并执行就地原子热替换（将旧版 DLL 重命名为 .old 供进程退出清理，立即写入新版文件）。
    /// </summary>
    public (bool Success, string Message, string? Version) ApplySignedHotReplaceUpdate(string signedCipxFilePath, bool alsoStageForHostInstaller = true)
    {
        var (isSelfPkg, isSigValid, reason, version) = CipxPackageSshVerifier.InspectAndVerifyCipxPackage(signedCipxFilePath);
        if (!isSelfPkg)
        {
            return (false, "目标 .cipx 包不是 MINI ClassIsland 集控增强组件安装包。", null);
        }

        if (!isSigValid)
        {
            try
            {
                if (File.Exists(signedCipxFilePath))
                {
                    File.Delete(signedCipxFilePath);
                }
            }
            catch
            {
                // Ignore
            }
            return (false, $"拒绝热替换更新：{reason}", version);
        }

        try
        {
            _authorizedSignedSelfUpdatePending = true;
            ReleaseFileLocks();

            if (!string.IsNullOrWhiteSpace(_pluginFolderPath) && Directory.Exists(_pluginFolderPath))
            {
                // 清理旧的 .old 残留文件
                foreach (var oldFile in Directory.GetFiles(_pluginFolderPath, "*.old", SearchOption.AllDirectories))
                {
                    try
                    {
                        File.SetAttributes(oldFile, FileAttributes.Normal);
                        File.Delete(oldFile);
                    }
                    catch
                    {
                        // Ignore
                    }
                }

                using var fs = new FileStream(signedCipxFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var archive = new System.IO.Compression.ZipArchive(fs, System.IO.Compression.ZipArchiveMode.Read);

                foreach (var entry in archive.Entries)
                {
                    if (string.IsNullOrEmpty(entry.Name) && entry.FullName.EndsWith('/'))
                    {
                        continue;
                    }

                    var targetPath = Path.Combine(_pluginFolderPath, entry.FullName.Replace('/', Path.DirectorySeparatorChar));
                    var targetDir = Path.GetDirectoryName(targetPath);
                    if (!string.IsNullOrWhiteSpace(targetDir))
                    {
                        Directory.CreateDirectory(targetDir);
                    }

                    using var entryStream = entry.Open();
                    using var ms = new MemoryStream();
                    entryStream.CopyTo(ms);
                    var newBytes = ms.ToArray();

                    // 如果目标文件正在被 CLR 映射占用（如 .dll），Windows 允许在运行时将其 Move 重命名为 .old，然后再创建同名新文件！
                    if (File.Exists(targetPath))
                    {
                        try
                        {
                            File.SetAttributes(targetPath, FileAttributes.Normal);
                            File.WriteAllBytes(targetPath, newBytes);
                        }
                        catch
                        {
                            var backupOldPath = $"{targetPath}.{Guid.NewGuid():N}.old";
                            File.Move(targetPath, backupOldPath, overwrite: true);
                            File.WriteAllBytes(targetPath, newBytes);
                        }
                    }
                    else
                    {
                        File.WriteAllBytes(targetPath, newBytes);
                    }

                    _pluginFileMirrors[targetPath] = newBytes;
                }
            }

            if (alsoStageForHostInstaller)
            {
                Directory.CreateDirectory(HostRuntimeBridge.PluginsPkgRootPath);
                var stagedPath = Path.Combine(HostRuntimeBridge.PluginsPkgRootPath, $"{PluginId}.cipx");
                if (!string.Equals(Path.GetFullPath(signedCipxFilePath), Path.GetFullPath(stagedPath), StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(signedCipxFilePath, stagedPath, overwrite: true);
                }
            }

            AcquireFileLocks();
            _logger.LogInformation("已完成经 SSH-Ed25519 签名验证的插件本体热替换更新（版本：{Version}）。", version);
            return (true, "SSH-Ed25519 签名验证通过，已完成插件本体热替换更新。", version);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "执行签名插件热替换更新失败。");
            AcquireFileLocks();
            return (false, $"执行热替换更新异常：{ex.Message}", version);
        }
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        ReleaseFileLocks();
        VerifyAndPurgeTamperedStagedPackages();
        if (!_authorizedSelfUninstallRequested && !_authorizedSignedSelfUpdatePending)
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
        VerifyAndPurgeTamperedStagedPackages();

        if (!_authorizedSelfUninstallRequested)
        {
            RemoveDisableAndUninstallMarkers();
            if (!_authorizedSignedSelfUpdatePending)
            {
                HealPluginFilesIfMissing();
            }
        }
    }

    public void Dispose()
    {
        _guardTimer.Dispose();
        _pluginFolderWatcher?.Dispose();
        _packagesStagingWatcher?.Dispose();
        ReleaseFileLocks();
    }
}
