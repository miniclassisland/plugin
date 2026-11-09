using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Shared;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Security;
using MiniClassIsland.ExtendManagement.Services;

namespace MiniClassIsland.ExtendManagement.Views.SettingPages;

/// <summary>
/// 集控设置页注入器。
/// 不使用独立插件设置菜单，而是监听应用原生“集控”设置页面（ManagementSettingsPage）加载事件，
/// 将集控增强选项面板无缝注入到该页面内，并在接入 MINI ClassIsland 时增强客户端信息与服务端类型显示。
/// </summary>
public sealed class ManagementPageInjector
{
    private const string InjectedControlName = "MciExtendManagementInjectedPanel";
    private const string ServerDeviceNameItemName = "MciServerDeviceNameExpanderItem";

    private readonly ILogger<ManagementPageInjector> _logger;
    private readonly IManagementService _managementService;
    private readonly TamperEvidentConfigStore _configStore;
    private readonly SelfProtectionService _selfProtectionService;
    private WeakReference<StackPanel>? _lastContainerStackRef;

    public ManagementPageInjector(
        ILogger<ManagementPageInjector> logger,
        IManagementService managementService,
        TamperEvidentConfigStore configStore,
        SelfProtectionService selfProtectionService)
    {
        _logger = logger;
        _managementService = managementService;
        _configStore = configStore;
        _selfProtectionService = selfProtectionService;

        Control.LoadedEvent.AddClassHandler<Control>(OnControlLoaded);
        HostRuntimeBridge.ServerMetadataUpdated += OnServerMetadataUpdated;
    }

    private void OnServerMetadataUpdated(object? sender, EventArgs e)
    {
        Dispatcher.UIThread.Post(() =>
        {
            if (_lastContainerStackRef != null &&
                _lastContainerStackRef.TryGetTarget(out var containerStack))
            {
                try
                {
                    EnhanceNativeManagementCards(containerStack);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "刷新集控设置页客户端信息与服务端类型显示异常。");
                }
            }
        });
    }

    private void OnControlLoaded(Control control, RoutedEventArgs e)
    {
        if (!_configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            return;
        }

        if (control.GetType().FullName == "ClassIsland.Views.SettingPages.ManagementSettingsPage")
        {
            try
            {
                InjectOptionsPanelIntoManagementPage(control);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "向集控设置页面注入集控增强选项时发生异常。");
            }
        }
    }

    private void InjectOptionsPanelIntoManagementPage(Control managementPage)
    {
        var containerStack = managementPage.GetVisualDescendants()
            .OfType<StackPanel>()
            .FirstOrDefault(sp => sp.Classes.Contains("settings-container"));

        if (containerStack == null)
        {
            return;
        }

        _lastContainerStackRef = new WeakReference<StackPanel>(containerStack);
        EnhanceNativeManagementCards(containerStack);

        if (containerStack.Children.Any(c => c.Name == InjectedControlName))
        {
            return;
        }

        var hostSvc = IAppHost.TryGetService<ExtendManagementHostService>();
        var auditLogs = hostSvc?.RecentAuditLogs ?? [];

        var panel = new ExtendManagementSettingsPage(
            _managementService,
            _selfProtectionService,
            auditLogs)
        {
            Name = InjectedControlName
        };

        containerStack.Children.Add(panel);
    }

    private void EnhanceNativeManagementCards(StackPanel containerStack)
    {
        var isMiniServer = HostRuntimeBridge.IsJoinedMiniClassIslandServer(_managementService) &&
                           _managementService.IsManagementEnabled;

        foreach (var card in containerStack.Children.OfType<StackPanel>().Where(sp => sp.Classes.Contains("cardContainer")))
        {
            var headerTexts = card.GetVisualDescendants()
                .OfType<TextBlock>()
                .Select(tb => tb.Text?.Trim() ?? string.Empty)
                .ToList();

            if (headerTexts.Contains("客户端信息"))
            {
                EnhanceClientInfoCard(card, isMiniServer);
            }
            else if (headerTexts.Contains("服务端信息"))
            {
                EnhanceServerInfoCard(card, isMiniServer);
            }
        }
    }

    private void EnhanceClientInfoCard(StackPanel clientCard, bool isMiniServer)
    {
        var existingDeviceNameItem = clientCard.Children
            .FirstOrDefault(c => c.Name == ServerDeviceNameItemName);

        if (isMiniServer)
        {
            var deviceName = HostRuntimeBridge.GetServerClientDisplayName();
            if (existingDeviceNameItem == null)
            {
                var nameTb = new TextBlock
                {
                    TextWrapping = TextWrapping.Wrap
                };
                nameTb.Inlines?.Add(new Run("设备名称："));
                nameTb.Inlines?.Add(new Run(deviceName));

                var item = FluentAvaloniaBridge.CreateSettingsExpanderItem(nameTb);
                item.Name = ServerDeviceNameItemName;
                clientCard.Children.Add(item);
            }
            else
            {
                var tb = existingDeviceNameItem.GetVisualDescendants().OfType<TextBlock>().FirstOrDefault()
                         ?? (existingDeviceNameItem as ContentControl)?.Content as TextBlock;
                if (tb?.Inlines is { Count: >= 2 } && tb.Inlines[1] is Run valueRun)
                {
                    valueRun.Text = deviceName;
                }
                else if (tb != null)
                {
                    tb.Inlines?.Clear();
                    tb.Inlines?.Add(new Run("设备名称："));
                    tb.Inlines?.Add(new Run(deviceName));
                }
                existingDeviceNameItem.IsVisible = true;
            }
        }
        else if (existingDeviceNameItem != null)
        {
            existingDeviceNameItem.IsVisible = false;
        }

        // 当 ID 为空时显示占位符
        foreach (var tb in clientCard.GetVisualDescendants().OfType<TextBlock>())
        {
            if (tb.Inlines is { Count: >= 2 } &&
                tb.Inlines[0] is Run labelRun &&
                string.Equals(labelRun.Text?.Trim(), "ID：", StringComparison.Ordinal) &&
                tb.Inlines[1] is Run idValueRun)
            {
                var effectiveId = HostRuntimeBridge.GetEffectiveClientIdentity(_managementService);
                var rawLocalId = _managementService.Settings.ClassIdentity?.Trim();
                if (string.IsNullOrWhiteSpace(rawLocalId))
                {
                    idValueRun.Text = string.IsNullOrWhiteSpace(effectiveId) ? "未设置" : effectiveId;
                    idValueRun.Foreground = new SolidColorBrush(Color.FromArgb(150, 128, 128, 128));
                }
                else
                {
                    idValueRun.Text = rawLocalId;
                    idValueRun.ClearValue(TextElement.ForegroundProperty);
                }
            }
        }
    }

    private void EnhanceServerInfoCard(StackPanel serverCard, bool isMiniServer)
    {
        if (!isMiniServer)
        {
            return;
        }

        var displayServerKind = HostRuntimeBridge.GetMiniServerDisplayKind(_managementService);
        foreach (var tb in serverCard.GetVisualDescendants().OfType<TextBlock>())
        {
            if (tb.Inlines is { Count: >= 2 } &&
                tb.Inlines[0] is Run labelRun &&
                string.Equals(labelRun.Text?.Trim(), "服务端类型：", StringComparison.Ordinal) &&
                tb.Inlines[1] is Run kindValueRun)
            {
                kindValueRun.Text = displayServerKind;
            }
        }
    }
}
