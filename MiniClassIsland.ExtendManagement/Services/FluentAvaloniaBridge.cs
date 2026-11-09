using System.Collections;
using System.Reflection;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using ClassIsland.Core;

namespace MiniClassIsland.ExtendManagement.Services;

/// <summary>
/// 跨 FluentAvalonia 2.x (ClassIsland 2.0) 与 FluentAvalonia 3.0 (ClassIsland 2.1.x) 的运行时 UI 控件桥接器。
/// 彻底消除因 FluentAvalonia 3.0 将 InfoBar / SettingsExpander / FontIcon 重命名为 FAInfoBar / FASettingsExpander / FAFontIcon 导致的 TypeLoadException。
/// </summary>
public static class FluentAvaloniaBridge
{
    private static Assembly? _faAssembly;
    private static Type? _settingsExpanderType;
    private static Type? _settingsExpanderItemType;
    private static Type? _infoBarType;
    private static Type? _infoBarSeverityType;

    private static Assembly? FluentAvaloniaAssembly =>
        _faAssembly ??= AppDomain.CurrentDomain.GetAssemblies()
            .FirstOrDefault(a => string.Equals(a.GetName().Name, "FluentAvalonia", StringComparison.OrdinalIgnoreCase));

    private static Type? SettingsExpanderType =>
        _settingsExpanderType ??= ResolveFluentType("FluentAvalonia.UI.Controls.FASettingsExpander", "FluentAvalonia.UI.Controls.SettingsExpander");

    private static Type? SettingsExpanderItemType =>
        _settingsExpanderItemType ??= ResolveFluentType("FluentAvalonia.UI.Controls.FASettingsExpanderItem", "FluentAvalonia.UI.Controls.SettingsExpanderItem");

    private static Type? InfoBarType =>
        _infoBarType ??= ResolveFluentType("FluentAvalonia.UI.Controls.FAInfoBar", "FluentAvalonia.UI.Controls.InfoBar");

    private static Type? InfoBarSeverityType =>
        _infoBarSeverityType ??= ResolveFluentType("FluentAvalonia.UI.Controls.FAInfoBarSeverity", "FluentAvalonia.UI.Controls.InfoBarSeverity");

    private static Type? ResolveFluentType(string fa3Name, string fa2Name)
    {
        var asm = FluentAvaloniaAssembly;
        if (asm == null)
        {
            return null;
        }
        return asm.GetType(fa3Name, throwOnError: false) ?? asm.GetType(fa2Name, throwOnError: false);
    }

    /// <summary>
    /// 创建跨版本兼容的 Fluent 字体图标控件（不触发 FluentAvalonia.UI.Controls.FontIcon 类型加载）。
    /// </summary>
    public static Control CreateGlyphIcon(string glyph, double fontSize = 16, IBrush? foreground = null)
    {
        var tb = new TextBlock
        {
            Text = glyph,
            FontFamily = AppBase.FluentIconsFontFamily,
            FontSize = fontSize,
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Center
        };
        if (foreground != null)
        {
            tb.Foreground = foreground;
        }
        return tb;
    }

    /// <summary>
    /// 创建带图标和文字的水平组合内容。
    /// </summary>
    public static Control CreateIconTextContent(string glyph, string text, double fontSize = 14, double spacing = 6)
    {
        return new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = spacing,
            VerticalAlignment = VerticalAlignment.Center,
            Children =
            {
                CreateGlyphIcon(glyph, fontSize),
                new TextBlock
                {
                    Text = text,
                    FontSize = fontSize,
                    VerticalAlignment = VerticalAlignment.Center
                }
            }
        };
    }

    /// <summary>
    /// 创建跨版本兼容的 FontIconSource（FAFontIconSource / FontIconSource）。
    /// </summary>
    public static object? CreateFluentIconSource(string glyph)
    {
        var iconSourceType = ResolveFluentType("FluentAvalonia.UI.Controls.FAFontIconSource", "FluentAvalonia.UI.Controls.FontIconSource");
        if (iconSourceType == null)
        {
            return null;
        }

        try
        {
            var instance = Activator.CreateInstance(iconSourceType);
            if (instance != null)
            {
                iconSourceType.GetProperty("FontFamily")?.SetValue(instance, AppBase.FluentIconsFontFamily);
                iconSourceType.GetProperty("Glyph")?.SetValue(instance, glyph);
            }
            return instance;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 创建跨版本兼容的 InfoBar（FAInfoBar / InfoBar）。
    /// </summary>
    public static Control CreateInfoBar(
        string message,
        string severity = "Informational",
        bool isClosable = false,
        bool isOpen = true,
        Control? actionButton = null)
    {
        var type = InfoBarType;
        if (type != null && Activator.CreateInstance(type) is Control infoBar)
        {
            SetProperty(infoBar, "Message", message);
            SetProperty(infoBar, "IsClosable", isClosable);
            SetProperty(infoBar, "IsOpen", isOpen);

            if (InfoBarSeverityType != null && Enum.TryParse(InfoBarSeverityType, severity, ignoreCase: true, out var sevVal))
            {
                SetProperty(infoBar, "Severity", sevVal);
            }

            if (actionButton != null)
            {
                SetProperty(infoBar, "ActionButton", actionButton);
            }

            return infoBar;
        }

        // Fallback Border if InfoBar type is unavailable
        var grid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("*,Auto"),
            Children =
            {
                new TextBlock
                {
                    Text = message,
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Center
                }
            }
        };
        if (actionButton != null)
        {
            Grid.SetColumn(actionButton, 1);
            grid.Children.Add(actionButton);
        }

        return new Border
        {
            Padding = new Thickness(12, 10),
            CornerRadius = new CornerRadius(6),
            Background = new SolidColorBrush(Color.FromArgb(24, 0, 120, 215)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(70, 0, 120, 215)),
            BorderThickness = new Thickness(1),
            IsVisible = isOpen,
            Child = grid
        };
    }

    public static void SetInfoBarOpen(Control infoBar, bool isOpen)
    {
        if (InfoBarType != null && InfoBarType.IsInstanceOfType(infoBar))
        {
            SetProperty(infoBar, "IsOpen", isOpen);
        }
        else
        {
            infoBar.IsVisible = isOpen;
        }
    }

    public static void SetInfoBarMessage(Control infoBar, string message)
    {
        if (InfoBarType != null && InfoBarType.IsInstanceOfType(infoBar))
        {
            SetProperty(infoBar, "Message", message);
        }
        else if (infoBar is Border { Child: Grid grid })
        {
            var tb = grid.Children.OfType<TextBlock>().FirstOrDefault();
            if (tb != null)
            {
                tb.Text = message;
            }
        }
    }

    /// <summary>
    /// 创建跨版本兼容的 SettingsExpander（FASettingsExpander / SettingsExpander）。
    /// </summary>
    public static Control CreateSettingsExpander(
        string glyph,
        string header,
        string description,
        Control? footer = null,
        IEnumerable<Control>? items = null)
    {
        var type = SettingsExpanderType;
        if (type != null && Activator.CreateInstance(type) is Control expander)
        {
            SetProperty(expander, "Header", header);
            SetProperty(expander, "Description", description);

            var iconSource = CreateFluentIconSource(glyph);
            if (iconSource != null)
            {
                SetProperty(expander, "IconSource", iconSource);
            }

            if (footer != null)
            {
                SetProperty(expander, "Footer", footer);
            }

            if (items != null)
            {
                var itemsProp = type.GetProperty("Items", BindingFlags.Instance | BindingFlags.Public);
                if (itemsProp?.GetValue(expander) is IList list)
                {
                    foreach (var item in items)
                    {
                        list.Add(item);
                    }
                }
            }

            return expander;
        }

        // Fallback card
        var rowGrid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"),
            ColumnSpacing = 12
        };
        var icon = CreateGlyphIcon(glyph, 20);
        Grid.SetColumn(icon, 0);
        rowGrid.Children.Add(icon);

        var textStack = new StackPanel
        {
            Spacing = 2,
            VerticalAlignment = VerticalAlignment.Center,
            Children =
            {
                new TextBlock { Text = header, FontWeight = FontWeight.SemiBold },
                new TextBlock { Text = description, FontSize = 12, Opacity = 0.75, TextWrapping = TextWrapping.Wrap }
            }
        };
        Grid.SetColumn(textStack, 1);
        rowGrid.Children.Add(textStack);

        if (footer != null)
        {
            Grid.SetColumn(footer, 2);
            rowGrid.Children.Add(footer);
        }

        return new Border
        {
            Padding = new Thickness(14, 12),
            CornerRadius = new CornerRadius(6),
            Background = new SolidColorBrush(Color.FromArgb(16, 128, 128, 128)),
            Child = rowGrid
        };
    }

    /// <summary>
    /// 创建跨版本兼容的 SettingsExpanderItem（FASettingsExpanderItem / SettingsExpanderItem）。
    /// </summary>
    public static Control CreateSettingsExpanderItem(
        Control content,
        bool isClickEnabled = false,
        string? actionGlyph = null,
        EventHandler<RoutedEventArgs>? onClick = null)
    {
        var type = SettingsExpanderItemType;
        if (type != null && Activator.CreateInstance(type) is Control item)
        {
            SetProperty(item, "Content", content);
            SetProperty(item, "IsClickEnabled", isClickEnabled);

            if (!string.IsNullOrWhiteSpace(actionGlyph))
            {
                var iconSource = CreateFluentIconSource(actionGlyph);
                if (iconSource != null)
                {
                    SetProperty(item, "ActionIconSource", iconSource);
                }
            }

            if (onClick != null)
            {
                var clickEvent = type.GetEvent("Click", BindingFlags.Instance | BindingFlags.Public);
                clickEvent?.AddEventHandler(item, onClick);
            }

            return item;
        }

        var btn = new Button
        {
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Padding = new Thickness(12, 10),
            Content = content
        };
        if (onClick != null)
        {
            btn.Click += onClick;
        }
        return btn;
    }

    /// <summary>
    /// 安全获取当前激活或主窗口（避免直接调用在 ClassIsland 2.1.x 中已被移除的 AppBase.GetRootWindow()）。
    /// </summary>
    public static Window? GetSafeOwnerWindow(Visual? visual = null)
    {
        if (visual != null && TopLevel.GetTopLevel(visual) is Window topWin)
        {
            return topWin;
        }

        try
        {
            var windows = AppBase.Current.DesktopLifetime?.Windows;
            if (windows != null)
            {
                var active = windows.FirstOrDefault(w => w is { IsActive: true, IsVisible: true } && w.GetType().Name != "TrayPopupRoot")
                             ?? windows.FirstOrDefault(w => w.IsVisible && w.GetType().Name != "TrayPopupRoot");
                if (active != null)
                {
                    return active;
                }
            }
        }
        catch
        {
            // Ignore
        }

        return AppBase.Current.MainWindow;
    }

    /// <summary>
    /// 显示跨版本兼容的模态确认弹窗（不依赖 AppBase.GetRootWindow 或 ContentDialog 重命名类型）。
    /// </summary>
    public static async Task<bool> ShowConfirmationDialogAsync(
        Visual? callerVisual,
        string title,
        string message,
        string positiveText = "确认",
        string negativeText = "取消")
    {
        var result = false;
        var dialogWindow = new Window
        {
            Title = title,
            Width = 420,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };

        var cancelBtn = new Button
        {
            Content = negativeText,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 6, 0),
            Padding = new Thickness(12, 8),
            IsCancel = true
        };
        cancelBtn.Click += (_, _) =>
        {
            result = false;
            dialogWindow.Close();
        };

        var confirmBtn = new Button
        {
            Content = positiveText,
            Classes = { "accent" },
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(6, 0, 0, 0),
            Padding = new Thickness(12, 8),
            IsDefault = true
        };
        confirmBtn.Click += (_, _) =>
        {
            result = true;
            dialogWindow.Close();
        };

        var btnGrid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("*,*"),
            Margin = new Thickness(0, 12, 0, 0),
            Children = { cancelBtn, confirmBtn }
        };
        Grid.SetColumn(cancelBtn, 0);
        Grid.SetColumn(confirmBtn, 1);

        dialogWindow.Content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 12,
            Children =
            {
                new TextBlock
                {
                    Text = title,
                    FontSize = 16,
                    FontWeight = FontWeight.Bold
                },
                new TextBlock
                {
                    Text = message,
                    TextWrapping = TextWrapping.Wrap,
                    LineHeight = 20,
                    Opacity = 0.9
                },
                btnGrid
            }
        };

        var owner = GetSafeOwnerWindow(callerVisual);
        if (owner is { IsVisible: true })
        {
            await dialogWindow.ShowDialog(owner);
        }
        else
        {
            var tcs = new TaskCompletionSource();
            dialogWindow.Closed += (_, _) => tcs.TrySetResult();
            dialogWindow.Show();
            await tcs.Task;
        }

        return result;
    }

    /// <summary>
    /// 显示跨版本兼容的模态信息提示弹窗。
    /// </summary>
    public static async Task ShowMessageDialogAsync(
        Visual? callerVisual,
        string title,
        string message,
        string buttonText = "确定")
    {
        var dialogWindow = new Window
        {
            Title = title,
            Width = 400,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };

        var okBtn = new Button
        {
            Content = buttonText,
            Classes = { "accent" },
            HorizontalAlignment = HorizontalAlignment.Right,
            MinWidth = 96,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            Padding = new Thickness(14, 8),
            IsDefault = true
        };
        okBtn.Click += (_, _) => dialogWindow.Close();

        dialogWindow.Content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 12,
            Children =
            {
                new TextBlock
                {
                    Text = title,
                    FontSize = 16,
                    FontWeight = FontWeight.Bold
                },
                new TextBlock
                {
                    Text = message,
                    TextWrapping = TextWrapping.Wrap,
                    LineHeight = 20,
                    Opacity = 0.9
                },
                okBtn
            }
        };

        var owner = GetSafeOwnerWindow(callerVisual);
        if (owner is { IsVisible: true })
        {
            await dialogWindow.ShowDialog(owner);
        }
        else
        {
            var tcs = new TaskCompletionSource();
            dialogWindow.Closed += (_, _) => tcs.TrySetResult();
            dialogWindow.Show();
            await tcs.Task;
        }
    }

    private static void SetProperty(object target, string propertyName, object? value)
    {
        try
        {
            var prop = target.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public);
            if (prop is { CanWrite: true })
            {
                prop.SetValue(target, value);
            }
        }
        catch
        {
            // Ignore reflection setter failure
        }
    }
}
