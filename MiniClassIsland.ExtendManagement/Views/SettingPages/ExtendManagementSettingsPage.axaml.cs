using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services.Management;
using MiniClassIsland.ExtendManagement.Models;
using MiniClassIsland.ExtendManagement.Networking;
using MiniClassIsland.ExtendManagement.Security;
using MiniClassIsland.ExtendManagement.Services;

namespace MiniClassIsland.ExtendManagement.Views.SettingPages;

/// <summary>
/// 直接内嵌注入到应用“集控选项”页面（ManagementSettingsPage）中的集控增强面板。
/// 仅保留状态信息横幅、近期指令执行记录与（未加入受控集控服务器时的）移除集控增强控件。
/// </summary>
public partial class ExtendManagementSettingsPage : UserControl, INotifyPropertyChanged
{
    private bool _isUninstallPending;

    private Control? _statusInfoBar;
    private Control? _uninstallPendingInfoBar;
    private Control? _removeEnhanceItem;
    private Control? _removeCardContainer;
    private readonly StackPanel RootPanel;

    public IManagementService ManagementService { get; }
    public SelfProtectionService SelfProtectionService { get; }
    public ObservableCollection<AuditLogEntry> RecentAuditLogs { get; }

    public bool IsUninstallPending
    {
        get => _isUninstallPending;
        set
        {
            if (_isUninstallPending == value) return;
            _isUninstallPending = value;
            UpdateVisualState();
            OnPropertyChanged();
        }
    }

    public new event PropertyChangedEventHandler? PropertyChanged;

    public ExtendManagementSettingsPage() : this(
        ClassIsland.Shared.IAppHost.GetService<IManagementService>(),
        ClassIsland.Shared.IAppHost.GetService<SelfProtectionService>(),
        ClassIsland.Shared.IAppHost.GetService<ExtendManagementHostService>().RecentAuditLogs)
    {
    }

    public ExtendManagementSettingsPage(
        IManagementService managementService,
        SelfProtectionService selfProtectionService,
        ObservableCollection<AuditLogEntry> recentAuditLogs)
    {
        ManagementService = managementService;
        SelfProtectionService = selfProtectionService;
        RecentAuditLogs = recentAuditLogs;
        _isUninstallPending = selfProtectionService.IsSelfUninstallPending;
        DataContext = this;
        RootPanel = new StackPanel
        {
            Spacing = 6,
            Margin = new Thickness(0, 8, 0, 0)
        };
        Content = RootPanel;
        Loaded += ExtendManagementSettingsPage_OnLoaded;
        BuildAdaptiveVisualTree();
    }

    private void BuildAdaptiveVisualTree()
    {
        RootPanel.Children.Clear();

        RootPanel.Children.Add(new Separator { Margin = new Thickness(0, 4, 0, 8) });

        var isJoinedMiniServer = HostRuntimeBridge.IsJoinedMiniClassIslandServer(ManagementService);

        // 1. 状态信息横幅
        _statusInfoBar = FluentAvaloniaBridge.CreateInfoBar(
            message: GetStatusBannerMessage(isJoinedMiniServer),
            severity: "Informational",
            isClosable: false,
            isOpen: true);
        RootPanel.Children.Add(_statusInfoBar);

        // 2. 待卸载重启提示栏
        var restartNowBtn = new Button
        {
            Content = FluentAvaloniaBridge.CreateIconTextContent("\uE0BD", "立即重启", fontSize: 13)
        };
        restartNowBtn.Click += ButtonRestartNow_OnClick;

        _uninstallPendingInfoBar = FluentAvaloniaBridge.CreateInfoBar(
            message: "已标记移除集控增强组件，重启应用后生效。",
            severity: "Success",
            isClosable: false,
            isOpen: IsUninstallPending && !isJoinedMiniServer,
            actionButton: restartNowBtn);
        RootPanel.Children.Add(_uninstallPendingInfoBar);

        // 3. 近期指令执行记录
        var openAuditBtn = new Button
        {
            Content = FluentAvaloniaBridge.CreateIconTextContent("\uE510", "查看执行记录", fontSize: 13)
        };
        openAuditBtn.Click += ButtonOpenAuditLogDialog_OnClick;

        var auditExpander = FluentAvaloniaBridge.CreateSettingsExpander(
            "\uE699",
            "近期指令执行记录",
            "在独立窗口中查看当前会话接收到的集控扩展指令与权限校验详情。",
            footer: openAuditBtn);
        RootPanel.Children.Add(auditExpander);

        // 4. 移除集控增强控件（加入受 MINI ClassIsland 控制的服务器后隐藏/移除）
        var removeCardContent = new StackPanel
        {
            Spacing = 4,
            Children =
            {
                new TextBlock { Text = "移除集控增强", FontWeight = FontWeight.SemiBold },
                new TextBlock
                {
                    Text = "从当前客户端卸载 MINI ClassIsland 集控增强组件，重启应用后生效。",
                    Opacity = 0.75,
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap
                }
            }
        };

        _removeEnhanceItem = FluentAvaloniaBridge.CreateSettingsExpanderItem(
            removeCardContent,
            isClickEnabled: true,
            actionGlyph: "\uE61D",
            onClick: ButtonRemoveEnhance_OnClick);
        _removeEnhanceItem.IsEnabled = !IsUninstallPending;

        _removeCardContainer = new StackPanel
        {
            Classes = { "cardContainer" },
            Margin = new Thickness(0, 2, 0, 0),
            IsVisible = !isJoinedMiniServer,
            Children = { _removeEnhanceItem }
        };
        RootPanel.Children.Add(_removeCardContainer);
    }

    private static string GetStatusBannerMessage(bool isJoinedMiniServer)
    {
        return isJoinedMiniServer
            ? "集控增强已启用，集控服务器可能拥有意料之外的权限。"
            : "集控增强已启用";
    }

    private void UpdateVisualState()
    {
        var isJoinedMiniServer = HostRuntimeBridge.IsJoinedMiniClassIslandServer(ManagementService);

        if (_statusInfoBar != null)
        {
            FluentAvaloniaBridge.SetInfoBarMessage(_statusInfoBar, GetStatusBannerMessage(isJoinedMiniServer));
        }

        if (_uninstallPendingInfoBar != null)
        {
            FluentAvaloniaBridge.SetInfoBarOpen(_uninstallPendingInfoBar, _isUninstallPending && !isJoinedMiniServer);
        }

        if (_removeEnhanceItem != null)
        {
            _removeEnhanceItem.IsEnabled = !_isUninstallPending;
        }

        if (_removeCardContainer != null)
        {
            _removeCardContainer.IsVisible = !isJoinedMiniServer;
        }
    }

    private async void ExtendManagementSettingsPage_OnLoaded(object? sender, RoutedEventArgs e)
    {
        _isUninstallPending = SelfProtectionService.IsSelfUninstallPending;
        UpdateVisualState();

        if (ManagementService.IsManagementEnabled)
        {
            var coordinator = ClassIsland.Shared.IAppHost.TryGetService<NetworkRoamingCoordinator>();
            if (coordinator != null && await coordinator.ProbeCurrentManagementServerFlavorAsync())
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(UpdateVisualState);
            }
        }
    }

    private async Task<bool> TryAuthorizeAsync()
    {
        try
        {
            var level = ManagementService.CredentialConfig.EditPolicyAuthorizeLevel;
            if (level == ClassIsland.Shared.Enums.AuthorizeLevel.None)
            {
                return true;
            }

            return await ManagementService.AuthorizeByLevel(level);
        }
        catch
        {
            return true;
        }
    }

    private async void ButtonRemoveEnhance_OnClick(object? sender, RoutedEventArgs e)
    {
        if (HostRuntimeBridge.IsJoinedMiniClassIslandServer(ManagementService))
        {
            UpdateVisualState();
            return;
        }

        var unlocked = await TryAuthorizeAsync();
        if (!unlocked)
        {
            return;
        }

        var confirmed = await FluentAvaloniaBridge.ShowConfirmationDialogAsync(
            this,
            "移除集控增强",
            "确定要从当前客户端移除 MINI ClassIsland 集控增强组件吗？移除操作将在应用重启后生效。",
            positiveText: "确认移除",
            negativeText: "取消");

        if (!confirmed)
        {
            return;
        }

        if (SelfProtectionService.RequestUninstallSelfFromManagementPage())
        {
            IsUninstallPending = true;
        }
    }

    private void ButtonOpenAuditLogDialog_OnClick(object? sender, RoutedEventArgs e)
    {
        var dialogWindow = new Window
        {
            Title = "近期指令执行记录",
            Width = 620,
            Height = 440,
            MinWidth = 480,
            MinHeight = 320,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };

        var emptyHint = new TextBlock
        {
            Text = "当前会话暂无集控扩展指令执行记录。",
            Opacity = 0.65,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 48, 0, 0),
            IsVisible = RecentAuditLogs.Count == 0
        };

        var itemsControl = new ItemsControl
        {
            ItemsSource = RecentAuditLogs,
            ItemTemplate = new FuncDataTemplate<AuditLogEntry>((entry, _) =>
            {
                if (entry == null)
                {
                    return new Control();
                }

                var cardGrid = new Grid
                {
                    ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"),
                    RowDefinitions = new RowDefinitions("Auto,Auto"),
                    ColumnSpacing = 12,
                    RowSpacing = 4
                };

                var timeText = new TextBlock
                {
                    Text = entry.TimestampUtc.ToLocalTime().ToString("HH:mm:ss"),
                    FontFamily = new FontFamily("Consolas, Monospace"),
                    Opacity = 0.7,
                    FontSize = 12,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetRow(timeText, 0);
                Grid.SetColumn(timeText, 0);
                cardGrid.Children.Add(timeText);

                var actionText = new TextBlock
                {
                    Text = entry.Action,
                    FontWeight = FontWeight.SemiBold,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetRow(actionText, 0);
                Grid.SetColumn(actionText, 1);
                cardGrid.Children.Add(actionText);

                var statusBadge = new TextBlock
                {
                    Text = $"{entry.Tier} · {(entry.Allowed ? "已执行" : "已拦截")}",
                    FontSize = 12,
                    Foreground = entry.Allowed
                        ? new SolidColorBrush(Color.FromRgb(46, 160, 67))
                        : new SolidColorBrush(Color.FromRgb(218, 54, 51)),
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetRow(statusBadge, 0);
                Grid.SetColumn(statusBadge, 2);
                cardGrid.Children.Add(statusBadge);

                var summaryText = new TextBlock
                {
                    Text = entry.Summary,
                    FontSize = 12,
                    Opacity = 0.82,
                    TextWrapping = TextWrapping.Wrap
                };
                Grid.SetRow(summaryText, 1);
                Grid.SetColumn(summaryText, 0);
                Grid.SetColumnSpan(summaryText, 3);
                cardGrid.Children.Add(summaryText);

                return new Border
                {
                    Padding = new Thickness(12, 8),
                    Margin = new Thickness(0, 0, 0, 6),
                    CornerRadius = new CornerRadius(6),
                    Background = new SolidColorBrush(Color.FromArgb(16, 128, 128, 128)),
                    BorderBrush = new SolidColorBrush(Color.FromArgb(40, 128, 128, 128)),
                    BorderThickness = new Thickness(1),
                    Child = cardGrid
                };
            })
        };

        var closeBtn = new Button
        {
            Content = "关闭",
            HorizontalAlignment = HorizontalAlignment.Right,
            Padding = new Thickness(18, 6),
            IsCancel = true,
            IsDefault = true
        };
        closeBtn.Click += (_, _) => dialogWindow.Close();

        var rootGrid = new Grid
        {
            RowDefinitions = new RowDefinitions("Auto,*,Auto"),
            Margin = new Thickness(16),
            RowSpacing = 12
        };

        var headerBar = FluentAvaloniaBridge.CreateIconTextContent("\uE699", "近期指令执行记录", fontSize: 16, spacing: 8);
        Grid.SetRow(headerBar, 0);
        rootGrid.Children.Add(headerBar);

        var scrollViewer = new ScrollViewer
        {
            Content = new StackPanel
            {
                Children =
                {
                    emptyHint,
                    itemsControl
                }
            }
        };
        Grid.SetRow(scrollViewer, 1);
        rootGrid.Children.Add(scrollViewer);

        Grid.SetRow(closeBtn, 2);
        rootGrid.Children.Add(closeBtn);

        dialogWindow.Content = rootGrid;

        var parentWindow = FluentAvaloniaBridge.GetSafeOwnerWindow(this);
        if (parentWindow != null)
        {
            dialogWindow.ShowDialog(parentWindow);
        }
        else
        {
            dialogWindow.Show();
        }
    }

    private void ButtonRestartNow_OnClick(object? sender, RoutedEventArgs e)
    {
        SelfProtectionService.GrantAuthorizedExit();
        AppBase.Current.Restart();
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
