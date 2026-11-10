using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Controls;
using ClassIsland.Core.Abstractions.Services;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Core.Attributes;
using ClassIsland.Core.Commands;
using ClassIsland.Core.Models.UriNavigation;
using ClassIsland.Core.Services.Registry;
using ClassIsland.Shared;
using ClassIsland.Shared.Models.Management;
using Microsoft.Extensions.Logging;

namespace MiniClassIsland.ExtendManagement.Security;

/// <summary>
/// 服务端受控应用锁定服务（AppLockService）。
/// 当集控服务器开启应用锁定时：
/// 1. 捕获并静默丢弃所有 classisland:// 协议与命令导航事件；
/// 2. Hook 并静默移除所有设置页面与各类编辑器窗口/视图，仅保留主界面（及提醒特效层）与必要的异常报错弹窗；
/// 3. Hook 系统托盘菜单，仅保留“应用标题”与“重启”两个选项，其余菜单项与托盘左键打开设置/档案行为全部静默移除；
/// 4. 采用纯事件驱动 + 严格重入锁（Re-entrancy Guard）+ 软状态备份恢复机制，彻底杜绝启动阶段“加载主题”卡死与集合变更死循环内存溢出问题。
/// </summary>
public sealed class AppLockService : IDisposable
{
    private static readonly HashSet<string> AllowedWindowTypeNames = new(StringComparer.Ordinal)
    {
        "ClassIsland.MainWindow",
        "ClassIsland.Views.TopmostEffectWindow",
        "ClassIsland.Views.SplashWindow",
        "ClassIsland.Views.CrashWindow",
        "ClassIsland.Views.RecoveryWindow"
    };

    private static readonly HashSet<string> AllowedViewBaseTypeNames = new(StringComparer.Ordinal)
    {
        "ClassIsland.Views.MainView",
        "ClassIsland.Views.SplashView",
        "ClassIsland.Views.CrashWindow",
        "ClassIsland.Views.RecoveryWindow"
    };

    private static readonly HashSet<string> ExplicitlyBlockedTypeNames = new(StringComparer.Ordinal)
    {
        "ClassIsland.Views.SettingsWindowNew",
        "ClassIsland.Views.ProfileSettingsWindow",
        "ClassIsland.Views.ClassChangingWindow",
        "ClassIsland.Views.ClassPlanDetailsWindow",
        "ClassIsland.Views.DataTransferWindow",
        "ClassIsland.Views.DevPortalWindow",
        "ClassIsland.Views.TimeAdjustmentWindow",
        "ClassIsland.Views.TutorialCenterWindow",
        "ClassIsland.Views.TutorialControllerWindow",
        "ClassIsland.Views.TutorialEditorWindow",
        "ClassIsland.Views.TutorialScriptEditWindow",
        "ClassIsland.Views.WelcomeWindow",
        "ClassIsland.Views.WindowRuleDebugWindow",
        "ClassIsland.Views.AppLogsWindow",
        "ClassIsland.Views.AuthorizeWindow",
        "ClassIsland.Views.ScreenshotHelperWindow",
        "ClassIsland.Controls.JoinManagementDialog"
    };

    private readonly ILogger<AppLockService> _logger;
    private readonly IManagementService _managementService;
    private readonly TamperEvidentConfigStore _configStore;

    // ---- 严格重入保护锁（防止任何集合/属性/窗口回调引发递归或内存溢出） ----
    private bool _appHasStarted;
    private bool _isTransitioningLockState;
    private bool _isMutatingSettingsRegistry;
    private bool _isMutatingTrayMenu;
    private bool _isSuppressingEditMode;
    private bool _lastAppliedEffectiveLockState;
    private bool _disposed;

    // ---- 备份状态（支持服务端运行时动态解锁无损还原） ----
    private readonly List<SettingsPageInfo> _backedUpSettingsPages = [];
    private sealed record TrayMenuItemSavedState(bool IsVisible, bool IsEnabled);
    private readonly Dictionary<NativeMenuItemBase, TrayMenuItemSavedState> _savedTrayItemStates = [];
    private readonly HashSet<NativeMenuItemBase> _hookedTrayMenuItems = [];
    private NativeMenuItem? _hookedRestartMenuItem;
    private INotifyCollectionChanged? _hookedTrayItemsObservable;
    private TrayIcon? _hookedTrayIcon;
    private Delegate? _removedMainWindowTrayClickedHandler;
    private bool _lockedTrayClickHookAttached;

    // ---- URI 导航拦截与命令包装 ----
    private readonly ConditionalWeakTable<object, Action<UriNavigationEventArgs>?> _wrappedUriNodes = new();
    private ICommand? _originalUriNavigationCommand;
    private LockedUriNavigationCommandWrapper? _wrappedUriNavigationCommand;

    // ---- 窗口/视图去重抑制跟踪 ----
    private readonly HashSet<Window> _suppressingWindows = [];
    private readonly HashSet<Control> _suppressingViews = [];
    private INotifyPropertyChanged? _hookedMainWindowViewModel;

    public bool IsEffectiveAppLocked =>
        _configStore.CurrentConfig.HasAcceptedSecurityWarning &&
        _managementService.IsManagementEnabled &&
        _managementService.Settings.IsManagementEnabled &&
        _configStore.CurrentConfig.IsAppLocked;

    public AppLockService(
        ILogger<AppLockService> logger,
        IManagementService managementService,
        TamperEvidentConfigStore configStore)
    {
        _logger = logger;
        _managementService = managementService;
        _configStore = configStore;

        _configStore.ConfigChanged += OnConfigStoreChanged;
        if (_managementService.Settings is INotifyPropertyChanged mgtNpc)
        {
            mgtNpc.PropertyChanged += OnManagementSettingsPropertyChanged;
        }

        // 注册全局路由事件监听（仅在实际锁定时生效，且绝不触碰 SplashWindow）
        Window.WindowOpenedEvent.AddClassHandler<Window>(OnWindowOpened);
        Control.LoadedEvent.AddClassHandler<Control>(OnControlLoaded);

        AppBase.Current.AppStarted += OnAppStarted;

        // 若插件在应用启动阶段已被构造且处于锁定状态，可提前包裹静态命令与设置页注册表（非 UI 阻塞）
        if (IsEffectiveAppLocked)
        {
            EnsureUriNavigationCommandHooked();
            Dispatcher.UIThread.Post(ApplySettingsRegistryLockState, DispatcherPriority.Normal);
        }
    }

    public void SetAppLockedFromServer(bool isLocked, string sourceReason = "集控服务器远程指令")
    {
        _logger.LogInformation("应用锁定状态变更请求：{IsLocked}（来源：{Reason}）", isLocked, sourceReason);
        _configStore.SetAppLockState(isLocked);
        RefreshEffectiveLockState();
    }

    private void OnAppStarted(object? sender, EventArgs e)
    {
        _appHasStarted = true;
        Dispatcher.UIThread.Post(RefreshEffectiveLockState, DispatcherPriority.Loaded);
        Dispatcher.UIThread.Post(RefreshEffectiveLockState, DispatcherPriority.ApplicationIdle);
        Dispatcher.UIThread.Post(RefreshEffectiveLockState, DispatcherPriority.Background);
    }

    private void OnConfigStoreChanged(object? sender, EventArgs e)
    {
        Dispatcher.UIThread.Post(RefreshEffectiveLockState, DispatcherPriority.Normal);
    }

    private void OnManagementSettingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.Equals(e.PropertyName, nameof(ManagementSettings.IsManagementEnabled), StringComparison.OrdinalIgnoreCase))
        {
            Dispatcher.UIThread.Post(RefreshEffectiveLockState, DispatcherPriority.Normal);
        }
    }

    public void RefreshEffectiveLockState()
    {
        if (_disposed || _isTransitioningLockState)
        {
            return;
        }

        if (!Dispatcher.UIThread.CheckAccess())
        {
            Dispatcher.UIThread.Post(RefreshEffectiveLockState, DispatcherPriority.Normal);
            return;
        }

        _isTransitioningLockState = true;
        try
        {
            var isLocked = IsEffectiveAppLocked;

            // 1. 无论是否已完成 AppStarted，均可安全包裹 URI 导航与设置页注册表
            EnsureUriNavigationCommandHooked();
            WrapAllRegisteredUriNavigationHandlers();
            ApplySettingsRegistryLockState();

            // 2. 涉及 MainWindow、TrayIcon 及桌面窗口的操作，必须在 AppStarted 之后执行，彻底避免干扰 SplashWindow 加载主题！
            if (!_appHasStarted && AppBase.Current.MainWindow is not { IsLoaded: true })
            {
                return;
            }
            _appHasStarted = true;

            ApplyMainWindowEditModeGuard();
            ApplyTrayIconLockState();

            if (isLocked)
            {
                CloseAllCurrentlyOpenForbiddenWindows();
            }

            if (_lastAppliedEffectiveLockState != isLocked)
            {
                _lastAppliedEffectiveLockState = isLocked;
                _logger.LogInformation("应用锁定状态已生效：{State}", isLocked ? "已锁定 (Locked)" : "已解除锁定 (Unlocked)");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "刷新应用锁定状态时发生非致命异常。");
        }
        finally
        {
            _isTransitioningLockState = false;
        }
    }

    #region 1. 捕获并静默丢弃所有 classisland:// 事件

    private void EnsureUriNavigationCommandHooked()
    {
        try
        {
            var field = typeof(UriNavigationCommands).GetField(
                nameof(UriNavigationCommands.UriNavigationCommand),
                BindingFlags.Static | BindingFlags.Public);
            if (field == null)
            {
                return;
            }

            var currentCmd = field.GetValue(null) as ICommand;
            if (currentCmd is LockedUriNavigationCommandWrapper)
            {
                return;
            }

            _originalUriNavigationCommand = currentCmd;
            _wrappedUriNavigationCommand = new LockedUriNavigationCommandWrapper(this, _originalUriNavigationCommand);

            if (!field.IsInitOnly)
            {
                field.SetValue(null, _wrappedUriNavigationCommand);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "挂载 UriNavigationCommand 包装器时跳过。");
        }
    }

    private void WrapAllRegisteredUriNavigationHandlers()
    {
        try
        {
            var uriSvc = IAppHost.TryGetService<IUriNavigationService>();
            if (uriSvc == null)
            {
                return;
            }

            var handlersProp = uriSvc.GetType().GetProperty(
                "NavigationHandlers",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            var rootNode = handlersProp?.GetValue(uriSvc);
            if (rootNode != null)
            {
                WrapUriNodeRecursively(rootNode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "挂载 UriNavigationService 节点拦截器时发生异常。");
        }
    }

    private void WrapUriNodeRecursively(object? node)
    {
        if (node == null)
        {
            return;
        }

        var nodeType = node.GetType();
        var actionProp = nodeType.GetProperty("NavigatedAction", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (actionProp?.GetValue(node) is Action<UriNavigationEventArgs> originalAction &&
            !_wrappedUriNodes.TryGetValue(node, out _))
        {
            _wrappedUriNodes.Add(node, originalAction);

            Action<UriNavigationEventArgs> wrappedAction = args =>
            {
                if (IsEffectiveAppLocked)
                {
                    _logger.LogInformation("应用锁定中：已静默捕获并丢弃 classisland:// 导航事件 ({Uri})。", args?.Uri);
                    return;
                }
                originalAction(args!);
            };

            actionProp.SetValue(node, wrappedAction);
        }

        var childrenProp = nodeType.GetProperty("Children", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (childrenProp?.GetValue(node) is IDictionary childrenDict)
        {
            foreach (var child in childrenDict.Values.Cast<object?>().ToList())
            {
                WrapUriNodeRecursively(child);
            }
        }
    }

    private sealed class LockedUriNavigationCommandWrapper(AppLockService owner, ICommand? inner) : ICommand
    {
        public event EventHandler? CanExecuteChanged
        {
            add
            {
                if (inner != null) inner.CanExecuteChanged += value;
            }
            remove
            {
                if (inner != null) inner.CanExecuteChanged -= value;
            }
        }

        public bool CanExecute(object? parameter)
        {
            if (owner.IsEffectiveAppLocked)
            {
                return true; // 保持按钮不抛异常但点击静默丢弃
            }
            return inner?.CanExecute(parameter) ?? true;
        }

        public void Execute(object? parameter)
        {
            if (owner.IsEffectiveAppLocked)
            {
                owner._logger.LogInformation("应用锁定中：已静默丢弃 UriNavigationCommand 调用 ({Param})。", parameter);
                return;
            }
            owner.WrapAllRegisteredUriNavigationHandlers();
            inner?.Execute(parameter);
        }
    }

    #endregion

    #region 2. Hook 并静默移除所有设置页面与编辑器（仅保留异常报错弹窗和主界面）

    private void ApplySettingsRegistryLockState()
    {
        if (_isMutatingSettingsRegistry)
        {
            return;
        }

        _isMutatingSettingsRegistry = true;
        try
        {
            var registered = SettingsWindowRegistryService.Registered;
            registered.CollectionChanged -= OnSettingsRegistryCollectionChanged;
            registered.CollectionChanged += OnSettingsRegistryCollectionChanged;

            if (IsEffectiveAppLocked)
            {
                if (registered.Count > 0)
                {
                    foreach (var page in registered)
                    {
                        if (page != null && !_backedUpSettingsPages.Contains(page))
                        {
                            _backedUpSettingsPages.Add(page);
                        }
                    }
                    registered.Clear();
                }
            }
            else
            {
                if (_backedUpSettingsPages.Count > 0)
                {
                    foreach (var page in _backedUpSettingsPages)
                    {
                        if (page != null && !registered.Contains(page))
                        {
                            registered.Add(page);
                        }
                    }
                    _backedUpSettingsPages.Clear();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "同步 SettingsWindowRegistryService 锁定状态异常。");
        }
        finally
        {
            _isMutatingSettingsRegistry = false;
        }
    }

    private void OnSettingsRegistryCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (_isMutatingSettingsRegistry || !IsEffectiveAppLocked)
        {
            return;
        }

        _isMutatingSettingsRegistry = true;
        try
        {
            var registered = SettingsWindowRegistryService.Registered;
            if (registered.Count > 0)
            {
                foreach (var page in registered)
                {
                    if (page != null && !_backedUpSettingsPages.Contains(page))
                    {
                        _backedUpSettingsPages.Add(page);
                    }
                }
                registered.Clear();
            }
        }
        catch
        {
            // Ignore
        }
        finally
        {
            _isMutatingSettingsRegistry = false;
        }
    }

    private void ApplyMainWindowEditModeGuard()
    {
        try
        {
            var mainWin = AppBase.Current.MainWindow;
            if (mainWin == null)
            {
                return;
            }

            var vmProp = mainWin.GetType().GetProperty("ViewModel", BindingFlags.Instance | BindingFlags.Public);
            var vm = vmProp?.GetValue(mainWin);
            if (vm is INotifyPropertyChanged npc && !ReferenceEquals(_hookedMainWindowViewModel, npc))
            {
                if (_hookedMainWindowViewModel != null)
                {
                    _hookedMainWindowViewModel.PropertyChanged -= OnMainWindowViewModelPropertyChanged;
                }
                _hookedMainWindowViewModel = npc;
                _hookedMainWindowViewModel.PropertyChanged += OnMainWindowViewModelPropertyChanged;
            }

            if (IsEffectiveAppLocked)
            {
                ForceExitMainWindowEditMode(mainWin, vm);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "挂载主界面编辑模式拦截器异常。");
        }
    }

    private void OnMainWindowViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_isSuppressingEditMode || !IsEffectiveAppLocked)
        {
            return;
        }

        if (string.Equals(e.PropertyName, "IsEditMode", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(e.PropertyName, "IsOverlayOpened", StringComparison.OrdinalIgnoreCase))
        {
            var mainWin = AppBase.Current.MainWindow;
            if (mainWin != null)
            {
                ForceExitMainWindowEditMode(mainWin, sender);
            }
        }
    }

    private void ForceExitMainWindowEditMode(Window mainWin, object? viewModel)
    {
        if (_isSuppressingEditMode)
        {
            return;
        }

        _isSuppressingEditMode = true;
        try
        {
            var isEditProp = viewModel?.GetType().GetProperty("IsEditMode", BindingFlags.Instance | BindingFlags.Public);
            if (isEditProp?.GetValue(viewModel) is true)
            {
                var exitMethod = mainWin.GetType().GetMethod("ExitEditMode", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                if (exitMethod != null)
                {
                    exitMethod.Invoke(mainWin, null);
                }
                else
                {
                    isEditProp.SetValue(viewModel, false);
                }
                _logger.LogInformation("应用锁定中：已静默阻止主界面进入组件视图编辑模式。");
            }
        }
        catch
        {
            // Ignore
        }
        finally
        {
            _isSuppressingEditMode = false;
        }
    }

    private static bool InheritsFromTypeName(Type? type, string baseTypeFullName)
    {
        var current = type;
        while (current != null)
        {
            if (string.Equals(current.FullName, baseTypeFullName, StringComparison.Ordinal))
            {
                return true;
            }
            current = current.BaseType;
        }
        return false;
    }

    private void OnControlLoaded(Control control, RoutedEventArgs e)
    {
        if (!IsEffectiveAppLocked || control == null)
        {
            return;
        }

        var controlType = control.GetType();
        var typeName = controlType.FullName ?? string.Empty;

        // 若是受控的 ViewBase 或 SettingsPageBase，检查是否允许
        if (InheritsFromTypeName(controlType, "ClassIsland.Core.Abstractions.Controls.ViewBase"))
        {
            if (IsViewBaseAllowedWhenLocked(typeName))
            {
                return;
            }

            SuppressForbiddenViewBase(control, typeName);
            return;
        }

        if (control is SettingsPageBase || ExplicitlyBlockedTypeNames.Contains(typeName))
        {
            SuppressForbiddenControl(control, typeName);
        }
    }

    private void OnWindowOpened(Window window, RoutedEventArgs e)
    {
        if (!IsEffectiveAppLocked || window == null)
        {
            return;
        }

        // 每次有窗口尝试打开时，顺带确保动态新增的 URI 节点已被包裹
        WrapAllRegisteredUriNavigationHandlers();

        EvaluateAndSuppressWindowIfNeeded(window);
    }

    private void CloseAllCurrentlyOpenForbiddenWindows()
    {
        try
        {
            if (AppBase.Current.DesktopLifetime is not IClassicDesktopStyleApplicationLifetime desktop)
            {
                return;
            }

            foreach (var window in desktop.Windows.ToList())
            {
                EvaluateAndSuppressWindowIfNeeded(window);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "巡检并关闭已打开的受限窗口时发生异常。");
        }
    }

    private void EvaluateAndSuppressWindowIfNeeded(Window window)
    {
        if (window == null || _suppressingWindows.Contains(window))
        {
            return;
        }

        var winTypeName = window.GetType().FullName ?? string.Empty;

        // 1. 显式允许的核心窗口（主界面、特效层、启动 SplashWindow、崩溃/恢复窗口、首次安全确认弹窗）
        if (AllowedWindowTypeNames.Contains(winTypeName))
        {
            return;
        }

        if (string.Equals(window.Title, "安全风险警告 — MINI ClassIsland 集控增强组件", StringComparison.Ordinal))
        {
            return;
        }

        // 2. WindowViewHost 宿主窗口：检查其承载的 CurrentView / 视觉树子视图
        if (winTypeName == "ClassIsland.Controls.UI.WindowViewHost")
        {
            var currentViewProp = window.GetType().GetProperty("CurrentView", BindingFlags.Instance | BindingFlags.Public);
            var currentView = currentViewProp?.GetValue(window) as Control;
            if (currentView != null)
            {
                var viewTypeName = currentView.GetType().FullName ?? string.Empty;
                if (IsViewBaseAllowedWhenLocked(viewTypeName))
                {
                    return;
                }
                SuppressForbiddenWindow(window, $"{winTypeName}({viewTypeName})");
                return;
            }

            // 如果 CurrentView 尚未赋值，先检查视觉树中是否已有禁止的 ViewBase
            var descendantView = window.GetVisualDescendants()
                .OfType<Control>()
                .FirstOrDefault(c => InheritsFromTypeName(c.GetType(), "ClassIsland.Core.Abstractions.Controls.ViewBase"));
            if (descendantView != null)
            {
                var viewTypeName = descendantView.GetType().FullName ?? string.Empty;
                if (IsViewBaseAllowedWhenLocked(viewTypeName))
                {
                    return;
                }
                SuppressForbiddenWindow(window, $"{winTypeName}({viewTypeName})");
                return;
            }

            // 监听 WindowViewHost 加载完成后的 CurrentView
            Dispatcher.UIThread.Post(() =>
            {
                if (!IsEffectiveAppLocked || _suppressingWindows.Contains(window))
                {
                    return;
                }
                var delayedView = currentViewProp?.GetValue(window) as Control
                                  ?? window.GetVisualDescendants()
                                      .OfType<Control>()
                                      .FirstOrDefault(c => InheritsFromTypeName(c.GetType(), "ClassIsland.Core.Abstractions.Controls.ViewBase"));
                if (delayedView != null)
                {
                    var delayedTypeName = delayedView.GetType().FullName ?? string.Empty;
                    if (!IsViewBaseAllowedWhenLocked(delayedTypeName))
                    {
                        SuppressForbiddenWindow(window, $"{winTypeName}({delayedTypeName})");
                    }
                }
            }, DispatcherPriority.Loaded);
            return;
        }

        // 3. 显式禁止的窗口类型（或任何包含设置/档案/换课/编辑器/调试的窗口）
        if (ExplicitlyBlockedTypeNames.Contains(winTypeName) || !IsEssentialErrorOrSystemDialog(window, winTypeName))
        {
            SuppressForbiddenWindow(window, winTypeName);
        }
    }

    private static bool IsViewBaseAllowedWhenLocked(string viewTypeName)
    {
        if (AllowedViewBaseTypeNames.Contains(viewTypeName))
        {
            return true;
        }

        if (ExplicitlyBlockedTypeNames.Contains(viewTypeName))
        {
            return false;
        }

        // 仅允许名称中含有 Crash / Recovery / Exception / Error 的异常报错视图
        return viewTypeName.Contains("Crash", StringComparison.OrdinalIgnoreCase) ||
               viewTypeName.Contains("Recovery", StringComparison.OrdinalIgnoreCase) ||
               viewTypeName.Contains("Exception", StringComparison.OrdinalIgnoreCase) ||
               viewTypeName.Contains("Error", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsEssentialErrorOrSystemDialog(Window window, string winTypeName)
    {
        if (winTypeName.Contains("Crash", StringComparison.OrdinalIgnoreCase) ||
            winTypeName.Contains("Recovery", StringComparison.OrdinalIgnoreCase) ||
            winTypeName.Contains("Exception", StringComparison.OrdinalIgnoreCase) ||
            winTypeName.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
            winTypeName.Contains("TaskDialog", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var title = window.Title ?? string.Empty;
        if (title.Contains("崩溃", StringComparison.OrdinalIgnoreCase) ||
            title.Contains("异常", StringComparison.OrdinalIgnoreCase) ||
            title.Contains("错误", StringComparison.OrdinalIgnoreCase) ||
            title.Contains("恢复", StringComparison.OrdinalIgnoreCase) ||
            title.Contains("Crash", StringComparison.OrdinalIgnoreCase) ||
            title.Contains("Error", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private void SuppressForbiddenViewBase(Control viewBase, string viewTypeName)
    {
        if (!_suppressingViews.Add(viewBase))
        {
            return;
        }

        try
        {
            viewBase.Opacity = 0;
            viewBase.IsVisible = false;
            viewBase.IsHitTestVisible = false;

            var topWindow = TopLevel.GetTopLevel(viewBase) as Window;
            if (topWindow != null && !AllowedWindowTypeNames.Contains(topWindow.GetType().FullName ?? string.Empty))
            {
                SuppressForbiddenWindow(topWindow, $"{topWindow.GetType().Name}({viewTypeName})");
            }

            Dispatcher.UIThread.Post(() =>
            {
                try
                {
                    var closeMethod = viewBase.GetType().GetMethod("Close", BindingFlags.Instance | BindingFlags.Public, null, Type.EmptyTypes, null);
                    closeMethod?.Invoke(viewBase, null);
                }
                catch
                {
                    // Ignore
                }
                finally
                {
                    _suppressingViews.Remove(viewBase);
                }
            }, DispatcherPriority.Loaded);
        }
        catch
        {
            _suppressingViews.Remove(viewBase);
        }
    }

    private void SuppressForbiddenControl(Control control, string typeName)
    {
        if (!_suppressingViews.Add(control))
        {
            return;
        }

        try
        {
            control.Opacity = 0;
            control.IsVisible = false;
            control.IsHitTestVisible = false;

            var topWindow = TopLevel.GetTopLevel(control) as Window;
            if (topWindow != null && !AllowedWindowTypeNames.Contains(topWindow.GetType().FullName ?? string.Empty))
            {
                SuppressForbiddenWindow(topWindow, $"{topWindow.GetType().Name}({typeName})");
            }
        }
        finally
        {
            Dispatcher.UIThread.Post(() => _suppressingViews.Remove(control), DispatcherPriority.Background);
        }
    }

    private void SuppressForbiddenWindow(Window window, string reasonLabel)
    {
        if (!_suppressingWindows.Add(window))
        {
            return;
        }

        try
        {
            _logger.LogInformation("应用锁定中：已静默拦截并移除窗口 [{WindowType}]。", reasonLabel);
            window.Opacity = 0;
            window.ShowInTaskbar = false;
            window.IsEnabled = false;

            Dispatcher.UIThread.Post(() =>
            {
                try
                {
                    window.Hide();
                    window.Close();
                }
                catch
                {
                    // Ignore
                }
                finally
                {
                    _suppressingWindows.Remove(window);
                }
            }, DispatcherPriority.Loaded);
        }
        catch
        {
            _suppressingWindows.Remove(window);
        }
    }

    #endregion

    #region 3. Hook 托盘菜单（除标题和重启以外的选项全部隐藏且禁用）

    private void ApplyTrayIconLockState()
    {
        if (_isMutatingTrayMenu)
        {
            return;
        }

        _isMutatingTrayMenu = true;
        try
        {
            var taskBarSvc = IAppHost.TryGetService<ITaskBarIconService>();
            var trayIcon = taskBarSvc?.MainTaskBarIcon;
            if (trayIcon == null)
            {
                return;
            }

            if (!ReferenceEquals(_hookedTrayIcon, trayIcon))
            {
                if (_hookedTrayIcon != null)
                {
                    _hookedTrayIcon.PropertyChanged -= OnTrayIconPropertyChanged;
                }
                _hookedTrayIcon = trayIcon;
                _hookedTrayIcon.PropertyChanged += OnTrayIconPropertyChanged;
            }

            // 挂载托盘左键点击拦截
            HookTrayIconClick(trayIcon, IsEffectiveAppLocked);

            var menu = trayIcon.Menu ?? TryGetAppMenuFromMainWindow();
            if (menu == null)
            {
                return;
            }

            // 若当前处于锁定状态且 trayIcon.Menu 尚未赋值或被置空，确保菜单挂载到托盘图标
            if (IsEffectiveAppLocked && trayIcon.Menu == null)
            {
                trayIcon.Menu = menu;
            }

            if (menu.Items is INotifyCollectionChanged itemsNpc && !ReferenceEquals(_hookedTrayItemsObservable, itemsNpc))
            {
                if (_hookedTrayItemsObservable != null)
                {
                    _hookedTrayItemsObservable.CollectionChanged -= OnTrayMenuItemsCollectionChanged;
                }
                _hookedTrayItemsObservable = itemsNpc;
                _hookedTrayItemsObservable.CollectionChanged += OnTrayMenuItemsCollectionChanged;
            }

            if (IsEffectiveAppLocked)
            {
                EnforceLockedTrayMenuItems(menu);
            }
            else
            {
                RestoreOriginalTrayMenuItems(menu);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "同步系统托盘锁定状态异常。");
        }
        finally
        {
            _isMutatingTrayMenu = false;
        }
    }

    private static NativeMenu? TryGetAppMenuFromMainWindow()
    {
        try
        {
            var mainWin = AppBase.Current.MainWindow;
            if (mainWin != null && mainWin.TryFindResource("AppMenu", out var res) && res is NativeMenu appMenu)
            {
                return appMenu;
            }
        }
        catch
        {
            // Ignore
        }
        return null;
    }

    private void OnTrayIconPropertyChanged(object? sender, Avalonia.AvaloniaPropertyChangedEventArgs e)
    {
        if (_isMutatingTrayMenu || _disposed)
        {
            return;
        }

        if (string.Equals(e.Property.Name, nameof(TrayIcon.Menu), StringComparison.Ordinal))
        {
            Dispatcher.UIThread.Post(ApplyTrayIconLockState, DispatcherPriority.Normal);
        }
    }

    private void HookTrayIconClick(TrayIcon trayIcon, bool isLocked)
    {
        try
        {
            var mainWin = AppBase.Current.MainWindow;
            if (mainWin == null)
            {
                return;
            }

            var eventField = typeof(TrayIcon).GetField("Clicked", BindingFlags.Instance | BindingFlags.NonPublic);
            var mainWinClickMethod = mainWin.GetType().GetMethod(
                "MainTaskBarIconOnClicked",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

            if (isLocked)
            {
                if (eventField?.GetValue(trayIcon) is EventHandler currentDelegate && mainWinClickMethod != null)
                {
                    foreach (var d in currentDelegate.GetInvocationList())
                    {
                        if (d.Method == mainWinClickMethod && ReferenceEquals(d.Target, mainWin))
                        {
                            _removedMainWindowTrayClickedHandler = d;
                            trayIcon.Clicked -= (EventHandler)d;
                            break;
                        }
                    }
                }

                if (!_lockedTrayClickHookAttached)
                {
                    trayIcon.Clicked -= OnLockedTrayIconClicked;
                    trayIcon.Clicked += OnLockedTrayIconClicked;
                    _lockedTrayClickHookAttached = true;
                }
            }
            else
            {
                if (_lockedTrayClickHookAttached)
                {
                    trayIcon.Clicked -= OnLockedTrayIconClicked;
                    _lockedTrayClickHookAttached = false;
                }

                if (_removedMainWindowTrayClickedHandler is EventHandler savedHandler)
                {
                    trayIcon.Clicked -= savedHandler;
                    trayIcon.Clicked += savedHandler;
                    _removedMainWindowTrayClickedHandler = null;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "调整托盘图标左键点击处理异常。");
        }
    }

    private void OnLockedTrayIconClicked(object? sender, EventArgs e)
    {
        if (!IsEffectiveAppLocked || sender is not TrayIcon trayIcon)
        {
            return;
        }

        try
        {
            if (trayIcon.Menu == null)
            {
                var appMenu = TryGetAppMenuFromMainWindow();
                if (appMenu != null)
                {
                    trayIcon.Menu = appMenu;
                    EnforceLockedTrayMenuItems(appMenu);
                }
            }

            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            var impl = typeof(TrayIcon)
                .GetProperty("Impl", BindingFlags.NonPublic | BindingFlags.Instance)?
                .GetValue(trayIcon);
            var type = AppDomain.CurrentDomain.GetAssemblies()
                .Where(a => a.FullName?.StartsWith("Avalonia.Win32", StringComparison.Ordinal) ?? false)
                .SelectMany(a => a.GetTypes())
                .FirstOrDefault(t => t.Name == "TrayIconImpl");
            if (impl != null && type != null)
            {
                var methodInfo = type.GetMethod("OnRightClicked", BindingFlags.NonPublic | BindingFlags.Instance);
                methodInfo?.Invoke(impl, null);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "锁定状态下左键弹出托盘菜单异常。");
        }
    }

    private static bool IsTitleTrayMenuItem(NativeMenuItemBase item, int index)
    {
        if (item is not NativeMenuItem menuItem)
        {
            return false;
        }

        var header = menuItem.Header?.Trim() ?? string.Empty;
        return index == 0 || header.StartsWith("ClassIsland", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRestartTrayMenuItem(NativeMenuItemBase item)
    {
        if (item is not NativeMenuItem menuItem)
        {
            return false;
        }

        var header = menuItem.Header?.Trim() ?? string.Empty;
        return string.Equals(header, "重启", StringComparison.OrdinalIgnoreCase);
    }

    private static bool GetNativeMenuItemVisible(NativeMenuItemBase item)
    {
        if (item is NativeMenuItem mi)
        {
            return mi.IsVisible;
        }

        var prop = item.GetType().GetProperty("IsVisible", BindingFlags.Instance | BindingFlags.Public);
        return prop?.GetValue(item) as bool? ?? true;
    }

    private static void SetNativeMenuItemVisible(NativeMenuItemBase item, bool isVisible)
    {
        if (item is NativeMenuItem mi)
        {
            mi.IsVisible = isVisible;
            return;
        }

        var prop = item.GetType().GetProperty("IsVisible", BindingFlags.Instance | BindingFlags.Public);
        if (prop is { CanWrite: true })
        {
            prop.SetValue(item, isVisible);
        }
    }

    private void EnforceLockedTrayMenuItems(NativeMenu menu)
    {
        for (var i = 0; i < menu.Items.Count; i++)
        {
            var item = menu.Items[i];
            if (item == null)
            {
                continue;
            }

            if (!_savedTrayItemStates.ContainsKey(item))
            {
                var origEnabled = item is not NativeMenuItem mi || mi.IsEnabled;
                _savedTrayItemStates[item] = new TrayMenuItemSavedState(GetNativeMenuItemVisible(item), origEnabled);
            }

            if (_hookedTrayMenuItems.Add(item))
            {
                item.PropertyChanged += OnTrayMenuItemPropertyChanged;
            }

            ApplyLockedStateToSingleTrayItem(item, i);
        }
    }

    private void ApplyLockedStateToSingleTrayItem(NativeMenuItemBase item, int index)
    {
        if (IsTitleTrayMenuItem(item, index))
        {
            SetNativeMenuItemVisible(item, true);
            if (item is NativeMenuItem titleItem)
            {
                titleItem.IsEnabled = false;
            }
        }
        else if (IsRestartTrayMenuItem(item))
        {
            SetNativeMenuItemVisible(item, true);
            if (item is NativeMenuItem restartItem)
            {
                restartItem.IsEnabled = true;
                if (!ReferenceEquals(_hookedRestartMenuItem, restartItem))
                {
                    if (_hookedRestartMenuItem != null)
                    {
                        _hookedRestartMenuItem.Click -= OnLockedTrayRestartClicked;
                    }
                    _hookedRestartMenuItem = restartItem;
                    _hookedRestartMenuItem.Click += OnLockedTrayRestartClicked;
                }
            }
        }
        else
        {
            SetNativeMenuItemVisible(item, false);
            if (item is NativeMenuItem otherItem)
            {
                otherItem.IsEnabled = false;
            }
        }
    }

    private void OnTrayMenuItemPropertyChanged(object? sender, Avalonia.AvaloniaPropertyChangedEventArgs e)
    {
        if (_isMutatingTrayMenu || !IsEffectiveAppLocked || sender is not NativeMenuItemBase item)
        {
            return;
        }

        var propName = e.Property.Name;
        if (!string.Equals(propName, nameof(NativeMenuItem.IsVisible), StringComparison.Ordinal) &&
            !string.Equals(propName, nameof(NativeMenuItem.IsEnabled), StringComparison.Ordinal))
        {
            return;
        }

        _isMutatingTrayMenu = true;
        try
        {
            var menu = _hookedTrayIcon?.Menu ?? TryGetAppMenuFromMainWindow();
            var idx = menu?.Items.IndexOf(item) ?? -1;
            ApplyLockedStateToSingleTrayItem(item, idx);
        }
        catch
        {
            // Ignore
        }
        finally
        {
            _isMutatingTrayMenu = false;
        }
    }

    private void RestoreOriginalTrayMenuItems(NativeMenu menu)
    {
        foreach (var item in _hookedTrayMenuItems.ToList())
        {
            item.PropertyChanged -= OnTrayMenuItemPropertyChanged;
        }
        _hookedTrayMenuItems.Clear();

        if (_hookedRestartMenuItem != null)
        {
            _hookedRestartMenuItem.Click -= OnLockedTrayRestartClicked;
            _hookedRestartMenuItem = null;
        }

        foreach (var item in menu.Items)
        {
            if (item != null && _savedTrayItemStates.TryGetValue(item, out var saved))
            {
                SetNativeMenuItemVisible(item, saved.IsVisible);
                if (item is NativeMenuItem mi)
                {
                    mi.IsEnabled = saved.IsEnabled;
                }
            }
        }
        _savedTrayItemStates.Clear();
    }

    private void OnTrayMenuItemsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (_isMutatingTrayMenu || !IsEffectiveAppLocked)
        {
            return;
        }

        _isMutatingTrayMenu = true;
        try
        {
            var menu = _hookedTrayIcon?.Menu ?? TryGetAppMenuFromMainWindow();
            if (menu != null)
            {
                EnforceLockedTrayMenuItems(menu);
            }
        }
        catch
        {
            // Ignore
        }
        finally
        {
            _isMutatingTrayMenu = false;
        }
    }

    private static void OnLockedTrayRestartClicked(object? sender, EventArgs e)
    {
        try
        {
            var sp = IAppHost.TryGetService<SelfProtectionService>();
            sp?.GrantAuthorizedExit();
        }
        catch
        {
            // Ignore
        }

        Dispatcher.UIThread.Post(() =>
        {
            try
            {
                AppBase.Current.Restart();
            }
            catch
            {
                // Ignore
            }
        });
    }

    #endregion

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        _configStore.ConfigChanged -= OnConfigStoreChanged;
        if (_managementService.Settings is INotifyPropertyChanged mgtNpc)
        {
            mgtNpc.PropertyChanged -= OnManagementSettingsPropertyChanged;
        }
        if (_hookedMainWindowViewModel != null)
        {
            _hookedMainWindowViewModel.PropertyChanged -= OnMainWindowViewModelPropertyChanged;
        }
        if (_hookedTrayIcon != null)
        {
            _hookedTrayIcon.PropertyChanged -= OnTrayIconPropertyChanged;
            if (_lockedTrayClickHookAttached)
            {
                _hookedTrayIcon.Clicked -= OnLockedTrayIconClicked;
                _lockedTrayClickHookAttached = false;
            }
        }
        if (_hookedTrayItemsObservable != null)
        {
            _hookedTrayItemsObservable.CollectionChanged -= OnTrayMenuItemsCollectionChanged;
        }
        foreach (var item in _hookedTrayMenuItems.ToList())
        {
            item.PropertyChanged -= OnTrayMenuItemPropertyChanged;
        }
        _hookedTrayMenuItems.Clear();
        if (_hookedRestartMenuItem != null)
        {
            _hookedRestartMenuItem.Click -= OnLockedTrayRestartClicked;
            _hookedRestartMenuItem = null;
        }
        SettingsWindowRegistryService.Registered.CollectionChanged -= OnSettingsRegistryCollectionChanged;
    }
}
