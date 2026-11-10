using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Shared;
using ClassIsland.Shared.Enums;
using ClassIsland.Shared.Helpers;
using ClassIsland.Shared.Models.Management;
using ClassIsland.Shared.Protobuf.Client;
using ClassIsland.Shared.Protobuf.Enum;
using ClassIsland.Shared.Protobuf.Service;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Security;
using MiniClassIsland.ExtendManagement.Services;

namespace MiniClassIsland.ExtendManagement.Networking;

/// <summary>
/// 加入集控窗口增强器：
/// 1. 在 JoinManagementDialog 中注入 MINI ClassIsland 品牌图标按钮（“快速加入”），点击后原地切换卡片 UI 为租户标识与班级标识表单；
/// 2. 直接接管加入集控工作流（直接发起 gRPC ClientRegister.RegisterAsync 或拉取清单并保存配置），不再构造临时 JSON 配置文件，彻底避免 URI Empty 异常；
/// 3. 当服务端处于配对模式返回配对码时，直接将配对码卡片内嵌显示在 JoinManagementDialog 窗口内；
/// 4. 等待配对期间使用新开的轻量级 HTTP API（/api/v1/client/{cuid}/pairing-status）轮询审批状态，不使用标准 gRPC 握手流，大幅降低服务器开销。
/// </summary>
public sealed partial class PairingDialogEnhancer : IDisposable
{
    private const string ProtocolName = "Cyrene_MSP";
    private const string ProtocolVersion = "2.0.0.0";
    private static readonly UTF8Encoding Utf8NoBom = new(false);

    [GeneratedRegex(@"Pairing\s*Code\s*[:：]\s*([A-Z0-9]{4,16})", RegexOptions.IgnoreCase)]
    private static partial Regex PairingCodeRegex();

    private readonly ILogger<PairingDialogEnhancer> _logger;
    private readonly IManagementService _managementService;
    private readonly TamperEvidentConfigStore _configStore;
    private readonly NetworkRoamingCoordinator _roamingCoordinator;
    private readonly HttpClient _pollingHttpClient;

    public PairingDialogEnhancer(
        ILogger<PairingDialogEnhancer> logger,
        IManagementService managementService,
        TamperEvidentConfigStore configStore,
        NetworkRoamingCoordinator roamingCoordinator)
    {
        _logger = logger;
        _managementService = managementService;
        _configStore = configStore;
        _roamingCoordinator = roamingCoordinator;
        _pollingHttpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(8)
        };

        Control.LoadedEvent.AddClassHandler<Control>(OnControlLoaded);
        Window.WindowOpenedEvent.AddClassHandler<Window>(OnWindowOpened);
    }

    private void OnControlLoaded(Control control, RoutedEventArgs e)
    {
        if (!_configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            return;
        }

        if (control.GetType().FullName == "ClassIsland.Controls.JoinManagementDialog")
        {
            TryAttachWithRetry(control);
        }
    }

    private void OnWindowOpened(Window window, RoutedEventArgs e)
    {
        if (!_configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            return;
        }

        if (window.GetType().FullName == "ClassIsland.Controls.JoinManagementDialog")
        {
            TryAttachWithRetry(window);
        }
    }

    private void TryAttachWithRetry(Control dialog)
    {
        try
        {
            if (AttachToJoinManagementDialog(dialog))
            {
                return;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "向加入集控弹窗注入 MINI ClassIsland 增强组件时发生异常。");
        }

        foreach (var priority in new[] { DispatcherPriority.Loaded, DispatcherPriority.Render, DispatcherPriority.Background })
        {
            Dispatcher.UIThread.Post(() =>
            {
                try
                {
                    AttachToJoinManagementDialog(dialog);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "延迟向加入集控弹窗注入 MINI ClassIsland 增强组件重试异常。");
                }
            }, priority);
        }
    }

    private static StackPanel? ResolveJoinDialogStackPanel(Control dialog)
    {
        var contentObj = dialog.GetType().GetProperty("Content", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public)?.GetValue(dialog);
        if (contentObj is StackPanel directSp)
        {
            return directSp;
        }
        if (contentObj is Control contentCtrl)
        {
            var fromContentLogical = Avalonia.LogicalTree.LogicalExtensions.GetLogicalDescendants(contentCtrl).OfType<StackPanel>().FirstOrDefault();
            if (fromContentLogical != null)
            {
                return fromContentLogical;
            }
            var fromContentVisual = Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(contentCtrl).OfType<StackPanel>().FirstOrDefault();
            if (fromContentVisual != null)
            {
                return fromContentVisual;
            }
        }

        return Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(dialog)
                   .OfType<StackPanel>()
                   .FirstOrDefault(sp => sp.Children.Count >= 2)
               ?? Avalonia.LogicalTree.LogicalExtensions.GetLogicalDescendants(dialog)
                   .OfType<StackPanel>()
                   .FirstOrDefault(sp => sp.Children.Count >= 2);
    }

    private bool AttachToJoinManagementDialog(Control dialog)
    {
        var rootStack = ResolveJoinDialogStackPanel(dialog);
        if (rootStack == null)
        {
            return false;
        }

        if (rootStack.Children.Any(c => c.Name == "MciEnhancedMarker"))
        {
            return true;
        }

        var vm = dialog.GetType().GetProperty("ViewModel", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public)?.GetValue(dialog);
        if (vm == null)
        {
            return false;
        }

        // 查找原生元素，做到 100% 保持原项目视觉风格与结构：
        // 原生 JoinManagementDialog 的 rootStack 包含：
        // [0] TextBlock ("加入管理", SubtitleTextBlockStyle)
        // [1] TextBlock ("将当前ClassIsland实例连接到管理组织。")
        // [2] Grid ("配置文件：" + FileBrowserButton)
        // [3] Field (Label="ID（可选）", Content=TextBox 绑定 ViewModel.ManagementSettings.ClassIdentity)
        // [4] TextBlock (ErrorMessage, Foreground=IndianRed)
        // [5] ProgressBar (IsWorking)
        // [6] Bottom Grid -> Inner Grid -> [Button("取消"), Button("连接", Classes={"accent"})]
        var nativeChildren = rootStack.Children.ToList();

        TextBlock? nativeTitleBlock = nativeChildren.OfType<TextBlock>()
            .FirstOrDefault(tb => string.Equals(tb.Text?.Trim(), "加入管理", StringComparison.Ordinal))
            ?? nativeChildren.FirstOrDefault() as TextBlock;

        TextBlock? nativeSubtitleBlock = nativeChildren.OfType<TextBlock>()
            .FirstOrDefault(tb => tb != nativeTitleBlock && (tb.Text?.Contains("连接", StringComparison.Ordinal) == true || tb.Text?.Contains("管理", StringComparison.Ordinal) == true));

        Grid? nativeConfigFileRow = nativeChildren.OfType<Grid>()
            .FirstOrDefault(g => g.ColumnDefinitions.Count == 2 &&
                                 Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(g)
                                     .OfType<TextBlock>()
                                     .Any(tb => tb.Text?.Contains("配置文件", StringComparison.Ordinal) == true || tb.Inlines?.Count > 0));

        Control? nativeIdField = nativeChildren
            .FirstOrDefault(c => c.GetType().FullName == "ClassIsland.Core.Controls.Field");
        TextBox? nativeIdTextBox = (nativeIdField?.GetType().GetProperty("Content")?.GetValue(nativeIdField) as TextBox)
            ?? (nativeIdField != null ? Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(nativeIdField).OfType<TextBox>().FirstOrDefault() : null);

        var errorTextBlock = rootStack.Children
            .OfType<TextBlock>()
            .FirstOrDefault(tb => tb.Foreground is ISolidColorBrush brush && brush.Color == Colors.IndianRed);

        var nativeProgressBar = rootStack.Children.OfType<ProgressBar>().FirstOrDefault();

        Button? nativeConnectButton = Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(rootStack)
            .OfType<Button>()
            .FirstOrDefault(b => b.Classes.Contains("accent") || string.Equals(b.Content as string, "连接", StringComparison.Ordinal));

        CancellationTokenSource? pollingCts = null;
        void StopPolling()
        {
            try
            {
                pollingCts?.Cancel();
                pollingCts?.Dispose();
            }
            catch
            {
                // Ignore
            }
            pollingCts = null;
        }

        // 构建与原版 FluentAvalonia 视觉主题一致的内嵌配对码展示面板
        var pairingCodeText = new TextBlock
        {
            FontFamily = new FontFamily("Consolas, Monospace"),
            FontSize = 22,
            FontWeight = FontWeight.SemiBold,
            LetterSpacing = 2,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };

        var copyStatusText = new TextBlock
        {
            FontSize = 12,
            Opacity = 0.78,
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            Text = "请将上方配对码提供给集控管理员进行审批"
        };

        var currentRawPairingCode = string.Empty;
        var copyButton = new Button
        {
            HorizontalAlignment = HorizontalAlignment.Right,
            Padding = new Thickness(10, 4),
            Content = FluentAvaloniaBridge.CreateIconTextContent("\uE58C", "复制", fontSize: 12, spacing: 6)
        };

        copyButton.Click += async (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(currentRawPairingCode))
            {
                return;
            }
            var top = TopLevel.GetTopLevel(dialog);
            if (top?.Clipboard != null)
            {
                await top.Clipboard.SetTextAsync(currentRawPairingCode);
                copyStatusText.Text = "配对码已复制到剪贴板，等待管理员批准…";
            }
        };

        var codeDisplayBox = new Border
        {
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(12, 8),
            Margin = new Thickness(0, 4, 0, 4),
            BorderThickness = new Thickness(1),
            Child = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("*,Auto"),
                Children =
                {
                    pairingCodeText,
                    copyButton
                }
            }
        };
        if (Application.Current != null && Application.Current.TryFindResource("SubtleFillColorSecondaryBrush", out var subtleBg) && subtleBg is IBrush bgBrush)
        {
            codeDisplayBox.Background = bgBrush;
        }
        else
        {
            codeDisplayBox.Background = new SolidColorBrush(Color.FromArgb(20, 128, 128, 128));
        }
        if (Application.Current != null && Application.Current.TryFindResource("ControlStrokeColorDefaultBrush", out var strokeRes) && strokeRes is IBrush strokeBrush)
        {
            codeDisplayBox.BorderBrush = strokeBrush;
        }
        else
        {
            codeDisplayBox.BorderBrush = new SolidColorBrush(Color.FromArgb(50, 128, 128, 128));
        }
        Grid.SetColumn(pairingCodeText, 0);
        Grid.SetColumn(copyButton, 1);

        var pollingProgress = new ProgressBar
        {
            IsIndeterminate = true,
            Height = 3,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 2, 0, 0)
        };

        var inlinePairingPanel = new Border
        {
            Name = "MciInlinePairingPanel",
            IsVisible = false,
            Margin = new Thickness(0, 8, 0, 4),
            Padding = new Thickness(12, 10),
            CornerRadius = new CornerRadius(6),
            BorderThickness = new Thickness(1),
            Child = new StackPanel
            {
                Spacing = 6,
                Children =
                {
                    new StackPanel
                    {
                        Orientation = Orientation.Horizontal,
                        Spacing = 6,
                        Children =
                        {
                            FluentAvaloniaBridge.CreateGlyphIcon("\uE9D5", 14),
                            new TextBlock
                            {
                                Text = "等待集控管理员审批配对",
                                FontSize = 13,
                                FontWeight = FontWeight.SemiBold,
                                VerticalAlignment = VerticalAlignment.Center
                            }
                        }
                    },
                    codeDisplayBox,
                    copyStatusText,
                    pollingProgress
                }
            }
        };
        if (Application.Current != null && Application.Current.TryFindResource("CardBackgroundFillColorDefaultBrush", out var cardBg) && cardBg is IBrush cardBgBrush)
        {
            inlinePairingPanel.Background = cardBgBrush;
        }
        else
        {
            inlinePairingPanel.Background = new SolidColorBrush(Color.FromArgb(16, 128, 128, 128));
        }
        if (Application.Current != null && Application.Current.TryFindResource("CardStrokeColorDefaultBrush", out var cardStroke) && cardStroke is IBrush cardStrokeBrush)
        {
            inlinePairingPanel.BorderBrush = cardStrokeBrush;
        }
        else
        {
            inlinePairingPanel.BorderBrush = new SolidColorBrush(Color.FromArgb(45, 128, 128, 128));
        }

        void ShowInlinePairingPanel(ManagementSettings activeSettings, string rawCode)
        {
            var code = rawCode.Trim().ToUpperInvariant();
            currentRawPairingCode = code;
            var formatted = code.Length == 8
                ? $"{code[..4]} - {code[4..]}"
                : code;

            if (errorTextBlock != null)
            {
                errorTextBlock.IsVisible = false;
            }
            SetVmProperty(vm, "IsErrorMessageOpen", false);

            pairingCodeText.Text = formatted;
            copyStatusText.Text = "请将上方配对码提供给集控管理员进行审批";
            inlinePairingPanel.IsVisible = true;

            StartLightweightPairingPoll(
                dialog,
                activeSettings,
                code,
                copyStatusText,
                inlinePairingPanel,
                ref pollingCts);
        }

        // 构建与原版 JoinManagementDialog 100% 视觉同构的“租户或地址”原生 Field 控件
        var currentSettings = GetVmProperty<ManagementSettings>(vm, "ManagementSettings") ?? new ManagementSettings();
        var slugBox = new TextBox
        {
            Watermark = "租户标识或集控服务器地址",
            Text = _configStore.CurrentConfig.LastTenantSlug
        };

        var quickTenantField = FluentAvaloniaBridge.CreateNativeField(
            label: "租户或地址",
            content: slugBox,
            margin: new Thickness(0, 12, 0, 0));
        quickTenantField.Name = "MciInPlaceQuickJoinField";
        quickTenantField.IsVisible = false;

        // 兜底：若万一未找到原生 ID Field 或底部连接按钮，则提供备用控件
        var fallbackClassIdBox = new TextBox
        {
            Text = currentSettings.ClassIdentity ?? string.Empty
        };
        var fallbackErrorText = errorTextBlock ?? new TextBlock
        {
            Foreground = Brushes.IndianRed,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0),
            IsVisible = false
        };
        var fallbackProgress = nativeProgressBar ?? new ProgressBar
        {
            IsIndeterminate = true,
            IsVisible = false,
            Margin = new Thickness(0, 8, 0, 0)
        };
        var fallbackButton = nativeConnectButton ?? new Button
        {
            Content = "连接",
            Classes = { "accent" },
            HorizontalAlignment = HorizontalAlignment.Right,
            IsDefault = true
        };

        var isQuickJoinMode = false;
        var modeButtonText = new TextBlock
        {
            Text = "快速加入",
            FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center
        };

        var miniButton = BuildMiniBrandToggleButton(modeButtonText);

        void UpdateConnectButtonState()
        {
            if (isQuickJoinMode)
            {
                var hasSlug = !string.IsNullOrWhiteSpace(slugBox.Text);
                SetVmProperty(vm, "IsConfigLoaded", hasSlug);
                if (nativeConnectButton != null)
                {
                    nativeConnectButton.IsEnabled = hasSlug;
                }
            }
            else
            {
                var configPath = GetVmProperty<string>(vm, "ConfigFilePath");
                var loaded = !string.IsNullOrWhiteSpace(configPath) && File.Exists(configPath);
                SetVmProperty(vm, "IsConfigLoaded", loaded);
                if (nativeConnectButton != null)
                {
                    nativeConnectButton.IsEnabled = loaded;
                }
            }
        }

        slugBox.TextChanged += (_, _) =>
        {
            if (isQuickJoinMode)
            {
                UpdateConnectButtonState();
            }
        };

        void SetQuickJoinMode(bool enableQuickJoin)
        {
            isQuickJoinMode = enableQuickJoin;
            modeButtonText.Text = enableQuickJoin ? "配置文件" : "快速加入";
            ToolTip.SetTip(miniButton, enableQuickJoin ? "切换回使用配置文件导入加入集控" : "使用租户标识或服务器地址快速加入集控");

            SetVmProperty(vm, "IsErrorMessageOpen", false);
            if (errorTextBlock != null)
            {
                errorTextBlock.IsVisible = false;
            }

            if (nativeSubtitleBlock != null)
            {
                nativeSubtitleBlock.Text = enableQuickJoin
                    ? "输入租户标识或服务器地址，将当前ClassIsland实例连接到管理组织。"
                    : "将当前ClassIsland实例连接到管理组织。";
            }

            if (nativeConfigFileRow != null)
            {
                nativeConfigFileRow.IsVisible = !enableQuickJoin;
            }

            quickTenantField.IsVisible = enableQuickJoin;
            UpdateConnectButtonState();

            if (enableQuickJoin)
            {
                Dispatcher.UIThread.Post(() => slugBox.Focus(), DispatcherPriority.Input);
            }
        }

        miniButton.Click += (_, _) =>
        {
            SetQuickJoinMode(!isQuickJoinMode);
        };

        // 拦截原生右下角“连接”按钮（Tunnel 路由），当处于快速加入模式时直接执行快速加入工作流
        if (nativeConnectButton != null)
        {
            nativeConnectButton.AddHandler(
                Button.ClickEvent,
                async (_, e) =>
                {
                    if (!isQuickJoinMode)
                    {
                        return;
                    }
                    e.Handled = true;
                    var idBox = nativeIdTextBox ?? fallbackClassIdBox;
                    await ExecuteDirectQuickJoinWorkflowAsync(
                        dialog,
                        vm,
                        slugBox,
                        idBox,
                        fallbackErrorText,
                        fallbackProgress,
                        nativeConnectButton,
                        ShowInlinePairingPanel);
                },
                RoutingStrategies.Tunnel);
        }

        // 组装顶部标题栏：保持原生 "加入管理" SubtitleTextBlockStyle 标题，右侧放置轻量化切换按钮
        if (nativeTitleBlock != null)
        {
            var headerIndex = rootStack.Children.IndexOf(nativeTitleBlock);
            rootStack.Children.RemoveAt(headerIndex);

            var headerGrid = new Grid
            {
                Name = "MciEnhancedMarker",
                ColumnDefinitions = new ColumnDefinitions("*,Auto"),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(nativeTitleBlock, 0);
            nativeTitleBlock.VerticalAlignment = VerticalAlignment.Center;
            headerGrid.Children.Add(nativeTitleBlock);

            Grid.SetColumn(miniButton, 1);
            headerGrid.Children.Add(miniButton);

            rootStack.Children.Insert(headerIndex, headerGrid);
        }
        else
        {
            miniButton.Name = "MciEnhancedMarker";
            miniButton.HorizontalAlignment = HorizontalAlignment.Right;
            rootStack.Children.Insert(0, miniButton);
        }

        // 将“租户或地址”原生 Field 精确插入到“配置文件：”行所在的位置
        if (nativeConfigFileRow != null)
        {
            var configRowIdx = rootStack.Children.IndexOf(nativeConfigFileRow);
            rootStack.Children.Insert(configRowIdx + 1, quickTenantField);
        }
        else
        {
            var insertIdx = Math.Min(2, rootStack.Children.Count);
            rootStack.Children.Insert(insertIdx, quickTenantField);
        }

        // 将内嵌配对码面板放置在进度条之后、底部“取消/连接”按钮栏之前
        if (nativeProgressBar != null)
        {
            var progIdx = rootStack.Children.IndexOf(nativeProgressBar);
            rootStack.Children.Insert(progIdx + 1, inlinePairingPanel);
        }
        else
        {
            rootStack.Children.Add(inlinePairingPanel);
        }

        // 监听原生模式下的配对码报错并自动转为内嵌配对码卡片
        if (vm is System.ComponentModel.INotifyPropertyChanged vmNotify)
        {
            vmNotify.PropertyChanged += (_, args) =>
            {
                if (args.PropertyName is not ("ErrorMessage" or "IsErrorMessageOpen"))
                {
                    return;
                }

                var msg = GetVmProperty<string>(vm, "ErrorMessage") ?? string.Empty;
                var match = PairingCodeRegex().Match(msg);
                if (!match.Success)
                {
                    return;
                }

                var code = match.Groups[1].Value;
                var activeSettings = GetVmProperty<ManagementSettings>(vm, "ManagementSettings") ?? new ManagementSettings();
                Dispatcher.UIThread.Post(() => ShowInlinePairingPanel(activeSettings, code));
            };
        }

        dialog.Unloaded += (_, _) => StopPolling();
        if (dialog is Window win)
        {
            win.Closed += (_, _) => StopPolling();
        }

        _logger.LogInformation("已成功向加入集控弹窗注入 MINI ClassIsland 快速加入原地卡片与配对增强组件。");
        return true;
    }

    private Button BuildMiniBrandToggleButton(TextBlock buttonTextBlock)
    {
        Control iconVisual;
        try
        {
            var iconPath = Path.Combine(
                CommonDirectories.AppRootFolderPath,
                "Plugins",
                SelfProtectionService.PluginId,
                "icon.png");
            if (File.Exists(iconPath))
            {
                using var stream = new FileStream(iconPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var bitmap = new Bitmap(stream);
                iconVisual = new Image
                {
                    Source = bitmap,
                    Width = 18,
                    Height = 18,
                    Stretch = Stretch.Uniform
                };
            }
            else
            {
                iconVisual = FluentAvaloniaBridge.CreateGlyphIcon("\uE4C3", 16);
            }
        }
        catch
        {
            iconVisual = FluentAvaloniaBridge.CreateGlyphIcon("\uE4C3", 16);
        }

        var btn = new Button
        {
            Padding = new Thickness(8, 5),
            VerticalAlignment = VerticalAlignment.Center,
            Content = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 6,
                Children =
                {
                    iconVisual,
                    buttonTextBlock
                }
            }
        };
        ToolTip.SetTip(btn, "使用租户标识快速加入 MINI ClassIsland 集控");
        return btn;
    }

    /// <summary>
    /// 直接接管加入集控工作流（不生成临时 JSON 预设文件，直接执行 gRPC 实例注册、清单拉取、确认与配置保存）。
    /// </summary>
    private async Task ExecuteDirectQuickJoinWorkflowAsync(
        Control dialog,
        object vm,
        TextBox slugBox,
        TextBox classIdBox,
        TextBlock errorText,
        ProgressBar progressBar,
        Button joinButton,
        Action<ManagementSettings, string> onPairingCodeReceived)
    {
        void ShowError(string msg)
        {
            SetVmProperty(vm, "ErrorMessage", msg);
            SetVmProperty(vm, "IsErrorMessageOpen", true);
            errorText.Text = msg;
            errorText.IsVisible = true;
        }

        SetVmProperty(vm, "IsErrorMessageOpen", false);
        errorText.IsVisible = false;

        if (_managementService.IsManagementEnabled)
        {
            ShowError("当前客户端已加入集控管理，无法重复加入。");
            return;
        }

        var rawSlug = (slugBox.Text ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(rawSlug))
        {
            ShowError("请输入租户标识或集控服务器地址。");
            return;
        }

        var serverUrl = ResolveTenantServerUrl(rawSlug, _configStore.CurrentConfig.DefaultBaseDomain);
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            ShowError("租户标识或服务器地址格式无效，请检查后重试。");
            return;
        }

        var classId = (classIdBox.Text ?? string.Empty).Trim();
        _configStore.UpdateNetworkMetadata(lastTenantSlug: rawSlug);

        // 构造完整的 ManagementServer 模式配置，同时填充 ManifestUrlTemplate 防止任何代码路径触发空 URI
        var settings = new ManagementSettings
        {
            IsManagementEnabled = true,
            ManagementServerKind = ManagementServerKind.ManagementServer,
            ManagementServer = serverUrl,
            ManagementServerGrpc = serverUrl,
            ManifestUrlTemplate = $"{serverUrl}/api/v1/client/{{cuid}}/manifest",
            ClassIdentity = string.IsNullOrWhiteSpace(classId) ? string.Empty : classId
        };

        SetVmProperty(vm, "ManagementSettings", settings);
        SetVmProperty(vm, "IsErrorMessageOpen", false);
        SetVmProperty(vm, "IsWorking", true);

        progressBar.IsVisible = true;
        joinButton.IsEnabled = false;
        slugBox.IsEnabled = false;
        classIdBox.IsEnabled = false;

        try
        {
            var clientUid = _managementService.Persist.ClientUniqueId;
            var mac = _roamingCoordinator.EnsureAnchoredPhysicalMac();
            var tenantSlug = ExtractTenantSlugFromInput(rawSlug);

            // 1. 直接发起 gRPC ClientRegister.RegisterAsync
            using var channel = GrpcChannel.ForAddress(settings.ManagementServerGrpc);
            var registerClient = new ClientRegister.ClientRegisterClient(channel);
            var metadata = new Metadata
            {
                { "cuid", clientUid.ToString() },
                { "protocol_name", ProtocolName },
                { "protocol_version", ProtocolVersion },
                { "session", string.Empty },
                { "x-extend-management-enabled", "1" },
                { "x-extend-management-version", "2.0.0.1" }
            };
            if (!string.IsNullOrWhiteSpace(tenantSlug))
            {
                metadata.Add("tenant-slug", tenantSlug);
            }

            var regRsp = await registerClient.RegisterAsync(new ClientRegisterCsReq
            {
                ClientUid = clientUid.ToString(),
                ClientId = settings.ClassIdentity ?? string.Empty,
                ClientMac = mac
            }, metadata, deadline: DateTime.UtcNow.AddSeconds(12));

            // 检查是否需要配对码审批（10003 为 MINI ClassIsland PairingRequired 状态码）
            var pairingMatch = PairingCodeRegex().Match(regRsp.Message ?? string.Empty);
            if ((int)regRsp.Retcode == 10003 || pairingMatch.Success)
            {
                var code = pairingMatch.Success ? pairingMatch.Groups[1].Value : (regRsp.Message ?? string.Empty);
                onPairingCodeReceived(settings, code);
                return;
            }

            if (regRsp.Retcode != Retcode.Registered && regRsp.Retcode != Retcode.Success)
            {
                ShowError($"无法注册实例：{regRsp.Message}");
                return;
            }

            // 2. 保存服务端公钥并拉取集控清单
            Directory.CreateDirectory(HostRuntimeBridge.ManagementConfigureFolderPath);
            if (!string.IsNullOrWhiteSpace(regRsp.ServerPublicKey))
            {
                await File.WriteAllTextAsync(HostRuntimeBridge.ServerPublicKeyPath, regRsp.ServerPublicKey.TrimStart('\uFEFF'), Utf8NoBom);
            }

            var manifestUrl = $"{serverUrl}/api/v1/client/{clientUid}/manifest";
            var manifest = await _roamingCoordinator.GetJsonWithSessionAsync<ManagementManifest>(manifestUrl)
                           ?? new ManagementManifest { OrganizationName = tenantSlug ?? serverUrl };

            if (manifest.CoreVersion.Major != IAppHost.CoreVersion.Major)
            {
                ShowError($"集控服务核心版本（{manifest.CoreVersion}）与当前客户端核心版本（{IAppHost.CoreVersion}）不兼容。");
                return;
            }

            // 3. 弹出跨版本兼容的加入集控确认弹窗
            var orgDisplayName = string.IsNullOrWhiteSpace(manifest.OrganizationName) ? (tenantSlug ?? serverUrl) : manifest.OrganizationName;
            var confirmed = await FluentAvaloniaBridge.ShowConfirmationDialogAsync(
                dialog,
                "加入集控",
                $"确定要加入组织「{orgDisplayName}」的集控管理吗？",
                positiveText: "加入",
                negativeText: "取消");

            if (!confirmed)
            {
                return;
            }

            // 4. 清理旧的集控缓存配置并持久化新集控设置
            HostRuntimeBridge.MarkServerAsVerifiedMiniServer(serverUrl, true);
            PersistJoinedManagementConfiguration(settings, manifest);

            await FluentAvaloniaBridge.ShowMessageDialogAsync(
                dialog,
                "已加入集控",
                $"已成功加入组织「{orgDisplayName}」的管理，应用将立即重启以应用更改。");

            CloseDialogInstance(dialog);
            AppBase.Current.Restart();
        }
        catch (Exception ex)
        {
            var match = PairingCodeRegex().Match(ex.Message);
            if (match.Success)
            {
                onPairingCodeReceived(settings, match.Groups[1].Value);
                return;
            }

            _logger.LogWarning(ex, "MINI ClassIsland 快速加入集控失败。");
            ShowError($"连接集控服务器失败：{ex.Message}");
        }
        finally
        {
            SetVmProperty(vm, "IsWorking", false);
            progressBar.IsVisible = false;
            joinButton.IsEnabled = !string.IsNullOrWhiteSpace(slugBox.Text);
            slugBox.IsEnabled = true;
            classIdBox.IsEnabled = true;
        }
    }

    private static void PersistJoinedManagementConfiguration(ManagementSettings settings, ManagementManifest manifest)
    {
        Directory.CreateDirectory(HostRuntimeBridge.ManagementConfigureFolderPath);

        var staleFiles = new[]
        {
            HostRuntimeBridge.ManagementManifestPath,
            HostRuntimeBridge.ManagementPolicyPath,
            Path.Combine(HostRuntimeBridge.ManagementConfigureFolderPath, "Versions.json"),
            HostRuntimeBridge.ManagementCredentialsPath,
            Path.Combine(CommonDirectories.AppDataFolderPath, "Management", "ClassPlans.json"),
            Path.Combine(CommonDirectories.AppDataFolderPath, "Management", "Subjects.json"),
            Path.Combine(CommonDirectories.AppDataFolderPath, "Management", "TimeLayouts.json"),
            Path.Combine(CommonDirectories.AppRootFolderPath, "Profiles", "_management-profile.json")
        };

        foreach (var file in staleFiles)
        {
            try
            {
                if (File.Exists(file))
                {
                    File.Delete(file);
                }
                if (File.Exists(file + ".bak"))
                {
                    File.Delete(file + ".bak");
                }
            }
            catch
            {
                // Ignore cleanup failure
            }
        }

        settings.IsManagementEnabled = true;
        ConfigureFileHelper.SaveConfig(HostRuntimeBridge.ManagementManifestPath, manifest);
        ConfigureFileHelper.SaveConfig(HostRuntimeBridge.ManagementSettingsPath, settings);
    }

    private void StartLightweightPairingPoll(
        Control dialog,
        ManagementSettings settings,
        string pairingCode,
        TextBlock statusTextBlock,
        Control inlinePanel,
        ref CancellationTokenSource? pollingCts)
    {
        pollingCts?.Cancel();
        pollingCts?.Dispose();
        pollingCts = new CancellationTokenSource();
        var token = pollingCts.Token;

        var baseUrl = (settings.ManagementServer ?? string.Empty).TrimEnd('/');
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            return;
        }

        var clientUid = _managementService.Persist.ClientUniqueId.ToString();
        var classId = settings.ClassIdentity ?? string.Empty;
        var mac = _roamingCoordinator.EnsureAnchoredPhysicalMac();

        _ = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(3));
            while (await timer.WaitForNextTickAsync(token))
            {
                try
                {
                    var pollResult = await PollPairingStatusViaHttpApiAsync(baseUrl, clientUid, pairingCode, classId, mac, token);
                    if (pollResult.Status == PairingPollStatus.Rejected)
                    {
                        await Dispatcher.UIThread.InvokeAsync(() =>
                        {
                            statusTextBlock.Text = "配对请求已被管理员拒绝，请重新发起连接。";
                        });
                        return;
                    }

                    if (pollResult.Status == PairingPollStatus.Approved)
                    {
                        await Dispatcher.UIThread.InvokeAsync(async () =>
                        {
                            statusTextBlock.Text = "管理员已批准配对，正在完成接入…";
                            inlinePanel.IsVisible = false;

                            var completed = await TryCompleteApprovedPairingAsync(dialog, settings, pollResult.ServerPublicKey);
                            if (completed)
                            {
                                CloseDialogInstance(dialog);
                            }
                        });
                        return;
                    }
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "轻量轮询配对状态异常。");
                }
            }
        }, token);
    }

    private enum PairingPollStatus
    {
        Pending,
        Approved,
        Rejected
    }

    private readonly record struct PairingPollResult(PairingPollStatus Status, string? ServerPublicKey);

    private async Task<PairingPollResult> PollPairingStatusViaHttpApiAsync(
        string baseUrl,
        string clientUid,
        string pairingCode,
        string classId,
        string mac,
        CancellationToken cancellationToken)
    {
        var queryUrl = $"{baseUrl}/api/v1/client/{Uri.EscapeDataString(clientUid)}/pairing-status" +
                       $"?code={Uri.EscapeDataString(pairingCode)}" +
                       $"&class_id={Uri.EscapeDataString(classId)}" +
                       $"&mac={Uri.EscapeDataString(mac)}";

        using var req = new HttpRequestMessage(HttpMethod.Get, queryUrl);
        req.Headers.TryAddWithoutValidation("x-client-uid", clientUid);
        req.Headers.TryAddWithoutValidation("x-pairing-code", pairingCode);

        using var resp = await _pollingHttpClient.SendAsync(req, cancellationToken);
        if (resp.IsSuccessStatusCode)
        {
            var json = await resp.Content.ReadAsStringAsync(cancellationToken);
            if (HostRuntimeBridge.InspectHttpResponseForMiniMarker(resp, json))
            {
                HostRuntimeBridge.MarkServerAsVerifiedMiniServer(baseUrl, true);
            }
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var statusStr = root.TryGetProperty("status", out var sProp) ? sProp.GetString()?.ToLowerInvariant() : null;
            var approved = (root.TryGetProperty("approved", out var aProp) && aProp.ValueKind == JsonValueKind.True) ||
                           (root.TryGetProperty("registered", out var rProp) && rProp.ValueKind == JsonValueKind.True) ||
                           statusStr is "approved" or "registered";

            if (statusStr is "rejected" or "denied" or "expired")
            {
                return new PairingPollResult(PairingPollStatus.Rejected, null);
            }

            if (approved)
            {
                var pubKey = root.TryGetProperty("serverPublicKey", out var kProp)
                    ? kProp.GetString()
                    : root.TryGetProperty("server_public_key", out var k2Prop)
                        ? k2Prop.GetString()
                        : null;
                return new PairingPollResult(PairingPollStatus.Approved, pubKey);
            }
        }

        return new PairingPollResult(PairingPollStatus.Pending, null);
    }

    private async Task<bool> TryCompleteApprovedPairingAsync(Control dialog, ManagementSettings settings, string? serverPublicKey)
    {
        try
        {
            Directory.CreateDirectory(HostRuntimeBridge.ManagementConfigureFolderPath);

            // 若轻量轮询未直接携带公钥，则再调用一次 RegisterAsync 完成注册落库并获取公钥
            if (string.IsNullOrWhiteSpace(serverPublicKey))
            {
                var clientUid = _managementService.Persist.ClientUniqueId;
                var mac = _roamingCoordinator.EnsureAnchoredPhysicalMac();
                using var channel = GrpcChannel.ForAddress(settings.ManagementServerGrpc);
                var registerClient = new ClientRegister.ClientRegisterClient(channel);
                var metadata = new Metadata
                {
                    { "cuid", clientUid.ToString() },
                    { "protocol_name", ProtocolName },
                    { "protocol_version", ProtocolVersion },
                    { "session", string.Empty }
                };
                var regRsp = await registerClient.RegisterAsync(new ClientRegisterCsReq
                {
                    ClientUid = clientUid.ToString(),
                    ClientId = settings.ClassIdentity ?? string.Empty,
                    ClientMac = mac
                }, metadata, deadline: DateTime.UtcNow.AddSeconds(12));

                if (!string.IsNullOrWhiteSpace(regRsp.ServerPublicKey))
                {
                    serverPublicKey = regRsp.ServerPublicKey;
                }
            }

            if (!string.IsNullOrWhiteSpace(serverPublicKey))
            {
                await File.WriteAllTextAsync(HostRuntimeBridge.ServerPublicKeyPath, serverPublicKey.TrimStart('\uFEFF'), Utf8NoBom);
            }

            var manifestUrl = $"{settings.ManagementServer.TrimEnd('/')}/api/v1/client/{_managementService.Persist.ClientUniqueId}/manifest";
            var manifest = await _roamingCoordinator.GetJsonWithSessionAsync<ManagementManifest>(manifestUrl) ?? new ManagementManifest();

            HostRuntimeBridge.MarkServerAsVerifiedMiniServer(settings.ManagementServer, true);
            PersistJoinedManagementConfiguration(settings, manifest);

            await FluentAvaloniaBridge.ShowMessageDialogAsync(
                dialog,
                "加入集控",
                $"已成功加入组织「{manifest.OrganizationName}」的管理，应用将立即重启以应用更改。");
            AppBase.Current.Restart();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "配对批准后完成加入集控流程时发生异常。");
            return false;
        }
    }

    private static void CloseDialogInstance(Control dialog)
    {
        if (dialog is Window win)
        {
            win.Close();
            return;
        }

        var hideMethod = dialog.GetType().GetMethod("Hide", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public, Type.DefaultBinder, Type.EmptyTypes, null);
        hideMethod?.Invoke(dialog, null);
    }

    private static T? GetVmProperty<T>(object vm, string propName)
    {
        var prop = vm.GetType().GetProperty(propName, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public);
        if (prop == null)
        {
            return default;
        }
        var val = prop.GetValue(vm);
        return val is T typed ? typed : default;
    }

    private static void SetVmProperty(object vm, string propName, object? value)
    {
        var prop = vm.GetType().GetProperty(propName, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public);
        if (prop is { CanWrite: true })
        {
            prop.SetValue(vm, value);
        }
    }

    private static string? ExtractTenantSlugFromInput(string rawSlugOrUrl)
    {
        var input = rawSlugOrUrl.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }

        if (!input.Contains('.', StringComparison.Ordinal) &&
            !input.Contains(':', StringComparison.Ordinal) &&
            !input.Contains('/', StringComparison.Ordinal))
        {
            return input.ToLowerInvariant();
        }

        if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
        {
            var hostParts = uri.Host.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (hostParts.Length >= 3)
            {
                return hostParts[0].ToLowerInvariant();
            }
        }

        return null;
    }

    public static string ResolveTenantServerUrl(string rawSlugOrUrl, string defaultBaseDomain)
    {
        var input = rawSlugOrUrl.Trim().TrimEnd('/');
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        if (input.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            input.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            return Uri.TryCreate(input, UriKind.Absolute, out var uri) ? uri.ToString().TrimEnd('/') : string.Empty;
        }

        var domain = string.IsNullOrWhiteSpace(defaultBaseDomain) ? "miniclassisland.com" : defaultBaseDomain.Trim().TrimStart('.');
        if (input.Contains('.', StringComparison.Ordinal) || input.Contains(':', StringComparison.Ordinal))
        {
            var scheme = input.StartsWith("localhost", StringComparison.OrdinalIgnoreCase) ||
                         input.StartsWith("127.", StringComparison.OrdinalIgnoreCase)
                ? "http://"
                : "https://";
            var candidate = $"{scheme}{input}";
            return Uri.TryCreate(candidate, UriKind.Absolute, out var uri) ? uri.ToString().TrimEnd('/') : string.Empty;
        }

        foreach (var ch in input)
        {
            if (!char.IsLetterOrDigit(ch) && ch != '-' && ch != '_')
            {
                return string.Empty;
            }
        }

        return $"https://{input.ToLowerInvariant()}.{domain}";
    }

    public void Dispose()
    {
        _pollingHttpClient.Dispose();
    }
}
