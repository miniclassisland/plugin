using System.Collections.ObjectModel;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Shared.Abstraction.Services;
using ClassIsland.Shared.Models.Management;
using ClassIsland.Shared.Protobuf.Client;
using ClassIsland.Shared.Protobuf.Enum;
using ClassIsland.Shared.Protobuf.Service;
using Grpc.Net.Client;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Models;
using MiniClassIsland.ExtendManagement.Networking;
using MiniClassIsland.ExtendManagement.Security;
using MiniClassIsland.ExtendManagement.Services.Handlers;
using MiniClassIsland.ExtendManagement.Views.SettingPages;

namespace MiniClassIsland.ExtendManagement.Services;

/// <summary>
/// 扩展集控核心调度与宿主服务。
/// </summary>
public sealed class ExtendManagementHostService(
    ILogger<ExtendManagementHostService> logger,
    IManagementService managementService,
    TamperEvidentConfigStore configStore,
    CommandSignatureVerifier signatureVerifier,
    PolicyIntegrityMonitor policyMonitor,
    SelfProtectionService selfProtectionService,
    AppLockService appLockService,
    NetworkRoamingCoordinator roamingCoordinator,
    PairingDialogEnhancer pairingDialogEnhancer,
    ManagementPageInjector managementPageInjector,
    PluginApiHookService pluginApiHookService,
    HardwareCommandHandler hardwareHandler,
    SettingsCommandHandler settingsHandler,
    ProfileCommandHandler profileHandler,
    AutomationCommandHandler automationHandler,
    UpdateCommandHandler updateHandler,
    PluginManageCommandHandler pluginManageHandler,
    ThemeManageCommandHandler themeManageHandler,
    RemoteControlCommandHandler remoteControlHandler) : IHostedService
{
    private bool _securityDialogShown;

    public ObservableCollection<AuditLogEntry> RecentAuditLogs { get; } = [];

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            logger.LogWarning("MINI ClassIsland 集控增强组件尚未完成首次安装安全警告确认，本次会话暂不加载功能，等待用户确认。");
            AppBase.Current.AppStarted += (_, _) => PromptFirstRunSecurityWarning();
            Avalonia.Controls.Window.WindowOpenedEvent.AddClassHandler<Avalonia.Controls.Window>((w, _) =>
            {
                if (w != null && !string.Equals(w.Title, "安全风险警告 — MINI ClassIsland 集控增强组件", StringComparison.Ordinal))
                {
                    PromptFirstRunSecurityWarning();
                }
            });
            Dispatcher.UIThread.Post(PromptFirstRunSecurityWarning, DispatcherPriority.ApplicationIdle);
            return Task.CompletedTask;
        }

        _ = roamingCoordinator;
        _ = pairingDialogEnhancer;
        _ = selfProtectionService;
        _ = appLockService;
        _ = managementPageInjector;
        _ = pluginApiHookService;

        AttachManagementHooks();
        AppBase.Current.AppStarted += (_, _) =>
        {
            AttachManagementHooks();
            _ = Task.Run(SyncClientHookAndHardwareSnapshotToServerAsync);
        };
        _ = Task.Run(SyncClientHookAndHardwareSnapshotToServerAsync);

        return Task.CompletedTask;
    }

    private void PromptFirstRunSecurityWarning()
    {
        if (_securityDialogShown || configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            return;
        }
        _securityDialogShown = true;

        Dispatcher.UIThread.Post(async () =>
        {
            await Task.Delay(500);
            var accepted = await ShowFirstRunSecurityWarningDialogAsync();
            if (accepted)
            {
                logger.LogInformation("用户已同意安全风险警告，正在保存确认状态并重启应用以加载插件功能。");
                configStore.MarkSecurityWarningAccepted();
                selfProtectionService.GrantAuthorizedExit();
                AppBase.Current.Restart();
            }
            else
            {
                logger.LogWarning("用户已拒绝安全风险警告，正在就地标记卸载插件并重启应用。");
                selfProtectionService.RequestUninstallSelfFromManagementPage();
                AppBase.Current.Restart();
            }
        });
    }

    private static async Task<bool> ShowFirstRunSecurityWarningDialogAsync()
    {
        var tcs = new TaskCompletionSource<bool>();
        var resultAccepted = false;

        var dialogWindow = new Avalonia.Controls.Window
        {
            Title = "安全风险警告 — MINI ClassIsland 集控增强组件",
            Width = 520,
            SizeToContent = Avalonia.Controls.SizeToContent.Height,
            CanResize = false,
            Topmost = true,
            WindowStartupLocation = Avalonia.Controls.WindowStartupLocation.CenterScreen
        };

        var warningBanner = FluentAvaloniaBridge.CreateInfoBar(
            message: "检测到您首次安装了 MINI ClassIsland 集控增强组件。在启用前，请仔细确认以下高权限与安全风险说明：",
            severity: "Warning",
            isClosable: false,
            isOpen: true);

        var detailBlock = new Avalonia.Controls.TextBlock
        {
            Text = "1. 同级运行与深层控制：本组件运行在 ClassIsland 应用本体同级上下文中，允许受信任的集控服务器采集本机详细硬件信息、修改应用设置、在运行时热更新与切换多套档案。\n" +
                   "2. 插件自我保护：启用后组件将开启插件本体保护，防止插件文件被外部篡改、非授权禁用或移除（需在【集控】设置页面移除集控增强）。\n" +
                   "3. 高敏扩展与远程运维：本组件启用后，受信任的集控服务器将能够编辑自动化、控制更新、管理插件与主题，以及执行经加密签名校验的外部指令、捕获屏幕截图、发送模拟点击及读取进程清单。\n\n" +
                   "是否确认信任所接入的集控环境并同意启用本组件？\n" +
                   "• 点击【同意并重启加载】：保存确认状态并立即重启应用以正式加载组件。\n" +
                   "• 点击【拒绝并卸载重启】：立即卸载本组件并重启应用。",
            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
            FontSize = 13,
            LineHeight = 21,
            Margin = new Avalonia.Thickness(2, 6, 2, 8)
        };

        var rejectBtn = new Avalonia.Controls.Button
        {
            Content = FluentAvaloniaBridge.CreateIconTextContent("\uE61D", "拒绝并卸载重启", fontSize: 13),
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Stretch,
            HorizontalContentAlignment = Avalonia.Layout.HorizontalAlignment.Center,
            Padding = new Avalonia.Thickness(12, 8),
            Margin = new Avalonia.Thickness(0, 0, 6, 0),
            IsCancel = true
        };
        rejectBtn.Click += (_, _) =>
        {
            resultAccepted = false;
            dialogWindow.Close();
        };

        var acceptBtn = new Avalonia.Controls.Button
        {
            Content = FluentAvaloniaBridge.CreateIconTextContent("\uE9D5", "同意并重启加载", fontSize: 13),
            Classes = { "accent" },
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Stretch,
            HorizontalContentAlignment = Avalonia.Layout.HorizontalAlignment.Center,
            Padding = new Avalonia.Thickness(12, 8),
            Margin = new Avalonia.Thickness(6, 0, 0, 0),
            IsDefault = true
        };
        acceptBtn.Click += (_, _) =>
        {
            resultAccepted = true;
            dialogWindow.Close();
        };

        var buttonGrid = new Avalonia.Controls.Grid
        {
            ColumnDefinitions = new Avalonia.Controls.ColumnDefinitions("*,*"),
            Margin = new Avalonia.Thickness(0, 8, 0, 0),
            Children = { rejectBtn, acceptBtn }
        };
        Avalonia.Controls.Grid.SetColumn(rejectBtn, 0);
        Avalonia.Controls.Grid.SetColumn(acceptBtn, 1);

        dialogWindow.Content = new Avalonia.Controls.StackPanel
        {
            Margin = new Avalonia.Thickness(20),
            Spacing = 10,
            Children =
            {
                FluentAvaloniaBridge.CreateIconTextContent("\uEEBD", "MINI ClassIsland 集控增强组件 — 安全风险警告", fontSize: 16, spacing: 8),
                warningBanner,
                detailBlock,
                buttonGrid
            }
        };

        dialogWindow.Closed += (_, _) => tcs.TrySetResult(resultAccepted);

        var owner = AppBase.Current.MainWindow;
        if (owner is { IsVisible: true })
        {
            await dialogWindow.ShowDialog(owner);
        }
        else
        {
            dialogWindow.Show();
        }

        return await tcs.Task;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (managementService.Connection != null)
        {
            managementService.Connection.CommandReceived -= OnManagementCommandReceived;
        }
        return Task.CompletedTask;
    }

    private void AttachManagementHooks()
    {
        if (managementService.Connection == null)
        {
            return;
        }

        PreemptGetClientConfigForSignedEnvelopes(managementService.Connection);
        managementService.Connection.CommandReceived -= OnManagementCommandReceived;
        managementService.Connection.CommandReceived += OnManagementCommandReceived;
        policyMonitor.CaptureGoldenSnapshot();
    }

    private static void PreemptGetClientConfigForSignedEnvelopes(IManagementServerConnection conn)
    {
        try
        {
            var connType = conn.GetType();
            var eventField = connType.GetField("CommandReceived", BindingFlags.Instance | BindingFlags.NonPublic);
            var origMethod = connType.GetMethod("OnCommandReceived", BindingFlags.Instance | BindingFlags.NonPublic);
            if (eventField == null || origMethod == null)
            {
                return;
            }

            if (eventField.GetValue(conn) is not EventHandler<ClientCommandEventArgs> currentDelegate)
            {
                return;
            }

            foreach (var d in currentDelegate.GetInvocationList())
            {
                if (d.Method == origMethod && ReferenceEquals(d.Target, conn))
                {
                    conn.CommandReceived -= (EventHandler<ClientCommandEventArgs>)d;
                    conn.CommandReceived += (_, args) =>
                    {
                        if (args.Type == CommandTypes.GetClientConfig && TryExtractSignedEnvelope(args, out SignedCommandEnvelope? _))
                        {
                            return;
                        }
                        origMethod.Invoke(conn, [conn, args]);
                    };
                    break;
                }
            }
        }
        catch
        {
            // Ignore reflection differences
        }
    }

    private async void OnManagementCommandReceived(object? sender, ClientCommandEventArgs e)
    {
        try
        {
            if (TryExtractSignedEnvelope(e, out var envelope) && envelope != null)
            {
                await ProcessSignedCommandEnvelopeAsync(envelope);
                return;
            }

            if (e.Type == CommandTypes.DataUpdated)
            {
                await HandleEnhancedDataUpdatedAsync();
            }
            else if (e.Type == CommandTypes.RestartApp)
            {
                selfProtectionService.GrantAuthorizedExit();
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "处理集控指令事件异常。");
        }
    }

    private async Task HandleEnhancedDataUpdatedAsync()
    {
        await policyMonitor.RunWithAuthorizedPolicyUpdateAsync(async () =>
        {
            await Task.Delay(500);

            try
            {
                await roamingCoordinator.ProbeCurrentManagementServerFlavorAsync();
            }
            catch
            {
                // Ignore
            }

            try
            {
                await settingsHandler.SyncDefaultSettingsFromServerAsync(force: false);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "同步集控默认设置跳过或异常。");
            }

            try
            {
                await profileHandler.ReloadActiveProfileAtRuntimeAsync();
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "运行时热重载集控档案异常。");
            }

            await SyncClientHookAndHardwareSnapshotToServerAsync();
        });
    }

    private async Task SyncClientHookAndHardwareSnapshotToServerAsync()
    {
        try
        {
            await Task.Delay(1500);
            if (!managementService.IsManagementEnabled)
            {
                return;
            }

            var settingsCatalog = await pluginApiHookService.GetPluginSettingsCatalogAsync();
            var registeredComponents = await pluginApiHookService.GetRegisteredComponentsAsync(includeBuiltIn: true);
            using var emptyDoc = JsonDocument.Parse("{}");
            var hardwareInfo = await hardwareHandler.ExecuteAsync("hardware.get_info", emptyDoc.RootElement);

            await roamingCoordinator.ReportHookSnapshotAsync(new
            {
                extend_management_version = "2.0.0.3",
                is_app_locked = appLockService.IsEffectiveAppLocked,
                plugin_settings = settingsCatalog,
                plugin_components = registeredComponents,
                hardware_info = hardwareInfo
            });
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "同步客户端 Hook 清单与硬件信息快照跳过或异常。");
        }
    }

    private static bool TryExtractSignedEnvelope(ClientCommandEventArgs e, out SignedCommandEnvelope? envelope)
    {
        envelope = null;
        if (e.Payload == null || e.Payload.IsEmpty)
        {
            return false;
        }

        try
        {
            var rawText = e.Payload.ToStringUtf8().Trim();
            var jsonStart = rawText.IndexOf('{');
            var jsonEnd = rawText.LastIndexOf('}');
            if (jsonStart < 0 || jsonEnd <= jsonStart)
            {
                return false;
            }

            var candidateJson = rawText[jsonStart..(jsonEnd + 1)];
            if (!candidateJson.Contains("\"requestGuid\"", StringComparison.OrdinalIgnoreCase) ||
                !candidateJson.Contains("\"action\"", StringComparison.OrdinalIgnoreCase) ||
                !candidateJson.Contains("\"signature\"", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            envelope = JsonSerializer.Deserialize<SignedCommandEnvelope>(candidateJson, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            return envelope != null && !string.IsNullOrWhiteSpace(envelope.Action);
        }
        catch
        {
            return false;
        }
    }

    public async Task<CommandExecutionResponse> ProcessSignedCommandEnvelopeAsync(SignedCommandEnvelope envelope)
    {
        var action = envelope.Action.Trim().ToLowerInvariant();
        var clientUid = managementService.Persist.ClientUniqueId.ToString();

        var (isValid, errCode, errMsg) = await signatureVerifier.VerifyEnvelopeAsync(envelope);
        if (!isValid)
        {
            RecordAuditLog(envelope.RequestGuid, action, GetActionTierName(action), false, $"签名校验未通过：{errMsg}");
            var rejectResp = BuildResponse(envelope.RequestGuid, clientUid, action, false, errCode, errMsg, null);
            await UploadExecutionResponseAsync(rejectResp);
            return rejectResp;
        }

        try
        {
            using var payloadDoc = JsonDocument.Parse(string.IsNullOrWhiteSpace(envelope.PayloadJson) ? "{}" : envelope.PayloadJson);
            var payloadRoot = payloadDoc.RootElement;

            var resultData = await DispatchActionAsync(action, payloadRoot);
            RecordAuditLog(envelope.RequestGuid, action, GetActionTierName(action), true, "指令执行成功");

            var okResp = BuildResponse(envelope.RequestGuid, clientUid, action, true, "OK", "Success", resultData);
            await UploadExecutionResponseAsync(okResp);
            return okResp;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "执行扩展集控指令 {Action} ({RequestGuid}) 失败。", action, envelope.RequestGuid);
            RecordAuditLog(envelope.RequestGuid, action, GetActionTierName(action), false, ex.Message);

            var failResp = BuildResponse(envelope.RequestGuid, clientUid, action, false, "ERR_EXECUTION_FAILED", ex.Message, null);
            await UploadExecutionResponseAsync(failResp);
            return failResp;
        }
    }

    private async Task<JsonElement> DispatchActionAsync(string action, JsonElement payload)
    {
        if (action.StartsWith("hardware.", StringComparison.Ordinal))
        {
            return await hardwareHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("settings.", StringComparison.Ordinal))
        {
            return await settingsHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("profile.", StringComparison.Ordinal) ||
            action.StartsWith("components.", StringComparison.Ordinal))
        {
            return await profileHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("automation.", StringComparison.Ordinal))
        {
            return await automationHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("update.", StringComparison.Ordinal))
        {
            return await updateHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("plugin.", StringComparison.Ordinal))
        {
            return await pluginManageHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("theme.", StringComparison.Ordinal))
        {
            return await themeManageHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("remote.", StringComparison.Ordinal))
        {
            return await remoteControlHandler.ExecuteAsync(action, payload);
        }
        if (action.StartsWith("lock.", StringComparison.Ordinal) ||
            action.StartsWith("app.lock", StringComparison.Ordinal) ||
            action.StartsWith("app.unlock", StringComparison.Ordinal))
        {
            return settingsHandler.ExecuteAppLockCommand(action, payload);
        }
        if (action is "extend.status" or "extend.ping" or "system.status" or "extend.info")
        {
            return JsonSerializer.SerializeToElement(new
            {
                extendManagementEnabled = true,
                pluginId = SelfProtectionService.PluginId,
                version = "2.0.0.3",
                serverFlavor = HostRuntimeBridge.GetMiniServerDisplayKind(managementService),
                isAppLocked = appLockService.IsEffectiveAppLocked,
                features = new[]
                {
                    "hardware", "settings", "profile", "components",
                    "automation", "update", "plugin", "plugin.api_hook",
                    "theme", "remote", "management.exit", "lock"
                },
                timestampUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            });
        }
        if (action is "management.exit" or "client.exit_management" or "client.unregister")
        {
            var reason = "集控服务器远程移除了此设备";
            if (payload.ValueKind == JsonValueKind.Object &&
                payload.TryGetProperty("reason", out var rProp) &&
                rProp.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(rProp.GetString()))
            {
                reason = rProp.GetString()!;
            }

            _ = Task.Run(async () =>
            {
                await Task.Delay(350);
                roamingCoordinator.ExecuteLocalExitManagementAndRestart(reason);
            });

            return JsonSerializer.SerializeToElement(new
            {
                exiting = true,
                reason
            });
        }

        throw new NotSupportedException($"不支持的指令动作：{action}");
    }

    private static string GetActionTierName(string action)
    {
        if (action.StartsWith("remote.", StringComparison.Ordinal)) return "远程协助";
        if (action.StartsWith("automation.", StringComparison.Ordinal) ||
            action.StartsWith("update.", StringComparison.Ordinal) ||
            action.StartsWith("plugin.", StringComparison.Ordinal) ||
            action.StartsWith("theme.", StringComparison.Ordinal)) return "扩展运维";
        return "基础集控";
    }

    private static CommandExecutionResponse BuildResponse(
        string requestGuid,
        string clientUid,
        string action,
        bool success,
        string code,
        string message,
        JsonElement? data)
    {
        var resp = new CommandExecutionResponse
        {
            RequestGuid = requestGuid,
            ClientUid = clientUid,
            Action = action,
            Success = success,
            Code = code,
            Message = message,
            RespondedAtUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Data = data
        };

        var rawDataJson = data.HasValue ? data.Value.GetRawText() : "null";
        var integrityMaterial = $"{resp.RequestGuid}|{resp.ClientUid}|{resp.Action}|{resp.Success}|{resp.Code}|{resp.RespondedAtUtc}|{rawDataJson}";
        resp.IntegritySha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(integrityMaterial))).ToLowerInvariant();
        return resp;
    }

    private async Task UploadExecutionResponseAsync(CommandExecutionResponse response)
    {
        try
        {
            var conn = managementService.Connection;
            if (conn == null)
            {
                return;
            }

            var connType = conn.GetType();
            var channelProp = connType.GetProperty(
                "Channel",
                BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
            var getMetadataMethod = connType.GetMethod(
                "GetMetadata",
                BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);

            var channel = channelProp?.GetValue(conn) as GrpcChannel;
            if (channel == null)
            {
                return;
            }

            var metadata = getMetadataMethod?.Invoke(conn, [false]) as Grpc.Core.Metadata ?? [];
            metadata.Add("x-extend-management-enabled", "1");
            metadata.Add("x-extend-management-version", "2.0.0.3");
            var payloadJson = JsonSerializer.Serialize(response);

            var uploadClient = new ConfigUpload.ConfigUploadClient(channel);
            await uploadClient.UploadConfigAsync(new ConfigUploadScReq
            {
                RequestGuidId = response.RequestGuid,
                Payload = payloadJson
            }, metadata);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "回传扩展指令执行结果 ({RequestGuid}) 失败。", response.RequestGuid);
        }
    }

    private void RecordAuditLog(string requestGuid, string action, string tier, bool allowed, string summary)
    {
        Dispatcher.UIThread.Post(() =>
        {
            RecentAuditLogs.Insert(0, new AuditLogEntry
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                RequestGuid = requestGuid,
                Action = action,
                Tier = tier,
                Allowed = allowed,
                Summary = summary
            });

            while (RecentAuditLogs.Count > 100)
            {
                RecentAuditLogs.RemoveAt(RecentAuditLogs.Count - 1);
            }
        });
    }
}
