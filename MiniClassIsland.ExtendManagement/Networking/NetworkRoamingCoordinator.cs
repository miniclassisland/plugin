using System.ComponentModel;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Shared.Helpers;
using ClassIsland.Shared.Models.Management;
using ClassIsland.Shared.Protobuf.Client;
using ClassIsland.Shared.Protobuf.Service;
using Grpc.Net.Client;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Security;
using MiniClassIsland.ExtendManagement.Services;

namespace MiniClassIsland.ExtendManagement.Networking;

/// <summary>
/// 网络漫游与连接可靠性协调器。
/// 1. 物理网卡 MAC 锚定：排除虚拟/VPN/隧道网卡，固定注册使用的物理网卡 MAC，防止多网卡切换引发握手拒绝；
/// 2. IP 与网卡跳变快速自愈：监听系统网络地址变更事件，以指数退避（300ms -> 1.2s -> 2.5s -> 5s）立即重建 gRPC 会话并刷新服务端绑定 IP，消除上游 30 秒重连盲区；
/// 3. 会话凭证注入：为 HTTP 配置与资源请求自动注入 x-client-session 头，避免 IP 跳变期间触发服务端 403 拦截。
/// </summary>
public sealed class NetworkRoamingCoordinator : IDisposable
{
    private static readonly string[] VirtualAdapterKeywords =
    [
        "virtual", "vmware", "vbox", "hyper-v", "vethernet", "tap-", "tun", "wireguard",
        "tailscale", "zerotier", "wintun", "wan miniport", "loopback", "bluetooth",
        "teredo", "isatap", "docker", "wsl", "clash", "sing-box", " meta", "npcap"
    ];

    private readonly ILogger<NetworkRoamingCoordinator> _logger;
    private readonly IManagementService _managementService;
    private readonly TamperEvidentConfigStore _configStore;
    private readonly HttpClient _httpClient;
    private CancellationTokenSource? _roamingReconnectCts;
    private string _lastNetworkFingerprint = string.Empty;
    private string _cachedServerUrl = string.Empty;
    private string _cachedGrpcUrl = string.Empty;
    private string _cachedClientUid = string.Empty;
    private bool _wasManagementEnabled;
    private bool _remoteExitInProgress;
    private bool _disposed;

    public NetworkRoamingCoordinator(
        ILogger<NetworkRoamingCoordinator> logger,
        IManagementService managementService,
        TamperEvidentConfigStore configStore)
    {
        _logger = logger;
        _managementService = managementService;
        _configStore = configStore;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };

        if (_configStore.CurrentConfig.HasAcceptedSecurityWarning)
        {
            EnsureAnchoredPhysicalMac();
            _lastNetworkFingerprint = ComputeActiveNetworkFingerprint();

            CacheCurrentManagementEndpoints();
            _wasManagementEnabled = _managementService.IsManagementEnabled && _managementService.Settings.IsManagementEnabled;

            if (_managementService.Settings is INotifyPropertyChanged npc)
            {
                npc.PropertyChanged += OnManagementSettingsPropertyChanged;
            }

            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;

            if (_managementService.IsManagementEnabled)
            {
                _ = Task.Run(() => ProbeCurrentManagementServerFlavorAsync());
            }
        }
    }

    private void CacheCurrentManagementEndpoints()
    {
        try
        {
            var server = (_managementService.Settings.ManagementServer ?? string.Empty).Trim().TrimEnd('/');
            var grpc = (_managementService.Settings.ManagementServerGrpc ?? string.Empty).Trim().TrimEnd('/');
            var cuid = _managementService.Persist.ClientUniqueId.ToString();
            if (!string.IsNullOrWhiteSpace(server))
            {
                _cachedServerUrl = server;
            }
            if (!string.IsNullOrWhiteSpace(grpc))
            {
                _cachedGrpcUrl = grpc;
            }
            if (!string.IsNullOrWhiteSpace(cuid))
            {
                _cachedClientUid = cuid;
            }
        }
        catch
        {
            // Ignore
        }
    }

    private void OnManagementSettingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_remoteExitInProgress)
        {
            return;
        }

        if (string.Equals(e.PropertyName, nameof(ManagementSettings.IsManagementEnabled), StringComparison.OrdinalIgnoreCase))
        {
            var currentEnabled = _managementService.Settings.IsManagementEnabled;
            if (_wasManagementEnabled && !currentEnabled)
            {
                _wasManagementEnabled = false;
                _configStore.SetAppLockState(false);
                _logger.LogInformation("检测到客户端主动退出集控，正在通知集控服务器同步解绑设备...");
                _ = Task.Run(() => NotifyServerUnregisterAsync(_cachedServerUrl, _cachedGrpcUrl, _cachedClientUid));
            }
            else if (currentEnabled)
            {
                _wasManagementEnabled = true;
                CacheCurrentManagementEndpoints();
            }
        }
        else
        {
            CacheCurrentManagementEndpoints();
        }
    }

    public async Task<bool> ProbeCurrentManagementServerFlavorAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            if (!_managementService.IsManagementEnabled)
            {
                return false;
            }

            var server = (_managementService.Settings.ManagementServer ?? string.Empty).Trim().TrimEnd('/');
            if (string.IsNullOrWhiteSpace(server))
            {
                return HostRuntimeBridge.IsJoinedMiniClassIslandServer(_managementService);
            }

            var cuid = _managementService.Persist.ClientUniqueId.ToString();
            var manifestUrl = server.Contains("/manifest", StringComparison.OrdinalIgnoreCase)
                ? DecorateManagementUrl(server)
                : $"{server}/api/v1/client/{Uri.EscapeDataString(cuid)}/manifest";
            using var req = new HttpRequestMessage(HttpMethod.Get, manifestUrl);
            AttachSessionHeaders(req);
            using var resp = await _httpClient.SendAsync(req, cancellationToken);
            var rawBody = await resp.Content.ReadAsStringAsync(cancellationToken);

            if (resp.Headers.TryGetValues("X-Client-Registration-Status", out var regStatusValues))
            {
                var status = regStatusValues.FirstOrDefault()?.Trim();
                if (string.Equals(status, "unregistered", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("探测到当前设备已在集控服务器端被移除（unregistered），正在自动同步退出集控并重启应用...");
                    ExecuteLocalExitManagementAndRestart("集控服务器已远程移除此设备");
                    return false;
                }
            }

            if (HostRuntimeBridge.InspectHttpResponseForMiniMarker(resp, rawBody))
            {
                HostRuntimeBridge.MarkServerAsVerifiedMiniServer(server, true);
                TryApplyAppLockFromManifestOrPolicyJson(rawBody);
                return true;
            }
            TryApplyAppLockFromManifestOrPolicyJson(rawBody);
        }
        catch
        {
            // Ignore probe failure
        }
        return HostRuntimeBridge.IsJoinedMiniClassIslandServer(_managementService);
    }

    private void TryApplyAppLockFromManifestOrPolicyJson(string rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
        {
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (string.Equals(prop.Name, "IsAppLocked", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(prop.Name, "AppLockEnabled", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(prop.Name, "app_locked", StringComparison.OrdinalIgnoreCase))
                {
                    if (prop.Value.ValueKind == JsonValueKind.True || prop.Value.ValueKind == JsonValueKind.False)
                    {
                        _configStore.SetAppLockState(prop.Value.GetBoolean());
                        return;
                    }
                }
            }
        }
        catch
        {
            // Ignore non-JSON or unrelated payload
        }
    }

    public string EnsureAnchoredPhysicalMac()
    {
        var existing = _configStore.CurrentConfig.AnchoredMacAddress;
        if (!string.IsNullOrWhiteSpace(existing) && existing.Length >= 12)
        {
            return existing;
        }

        var selectedMac = SelectBestPhysicalMacAddress();
        if (!string.IsNullOrWhiteSpace(selectedMac))
        {
            _configStore.UpdateNetworkMetadata(anchoredMac: selectedMac);
            _logger.LogInformation("已锚定主物理网卡 MAC 地址：{Mac}", selectedMac);
        }
        return selectedMac;
    }

    public static string SelectBestPhysicalMacAddress()
    {
        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                            n.GetPhysicalAddress().GetAddressBytes().Length >= 6)
                .ToList();

            var candidates = interfaces
                .Select(nic =>
                {
                    var mac = nic.GetPhysicalAddress().ToString().ToUpperInvariant();
                    var desc = $"{nic.Name} {nic.Description}".ToLowerInvariant();
                    var isVirtual = VirtualAdapterKeywords.Any(k => desc.Contains(k, StringComparison.Ordinal));
                    var isUp = nic.OperationalStatus == OperationalStatus.Up;
                    var props = nic.GetIPProperties();
                    var hasIpv4 = props.UnicastAddresses.Any(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);
                    var hasGateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any));
                    var isEthernetOrWifi = nic.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.GigabitEthernet;

                    var score = 0;
                    if (!isVirtual) score += 100;
                    if (isEthernetOrWifi) score += 50;
                    if (isUp) score += 30;
                    if (hasGateway) score += 20;
                    if (hasIpv4) score += 10;

                    return (Nic: nic, Mac: mac, Score: score);
                })
                .Where(x => !string.IsNullOrWhiteSpace(x.Mac) && x.Mac != "000000000000")
                .OrderByDescending(x => x.Score)
                .ToList();

            return candidates.FirstOrDefault().Mac ?? "000000000000";
        }
        catch
        {
            return "000000000000";
        }
    }

    public string? TryGetCurrentSessionId()
    {
        try
        {
            var conn = _managementService.Connection;
            if (conn == null)
            {
                return null;
            }

            var prop = conn.GetType().GetProperty(
                "CurrentSessionId",
                BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
            return prop?.GetValue(conn) as string;
        }
        catch
        {
            return null;
        }
    }

    public async Task<T?> GetJsonWithSessionAsync<T>(string url, CancellationToken cancellationToken = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, DecorateManagementUrl(url));
        AttachSessionHeaders(req);
        using var resp = await _httpClient.SendAsync(req, cancellationToken);
        resp.EnsureSuccessStatusCode();
        var rawJson = await resp.Content.ReadAsStringAsync(cancellationToken);
        if (HostRuntimeBridge.InspectHttpResponseForMiniMarker(resp, rawJson))
        {
            var server = (_managementService.Settings.ManagementServer ?? string.Empty).Trim().TrimEnd('/');
            if (string.IsNullOrWhiteSpace(server) && req.RequestUri != null)
            {
                server = $"{req.RequestUri.Scheme}://{req.RequestUri.Authority}";
            }
            HostRuntimeBridge.MarkServerAsVerifiedMiniServer(server, true);
        }
        return JsonSerializer.Deserialize<T>(rawJson);
    }

    public async Task DownloadFileWithSessionAsync(string url, string destinationPath, CancellationToken cancellationToken = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, DecorateManagementUrl(url));
        AttachSessionHeaders(req);
        using var resp = await _httpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        resp.EnsureSuccessStatusCode();
        if (HostRuntimeBridge.InspectHttpResponseForMiniMarker(resp))
        {
            var server = (_managementService.Settings.ManagementServer ?? string.Empty).Trim().TrimEnd('/');
            HostRuntimeBridge.MarkServerAsVerifiedMiniServer(server, true);
        }

        var dir = Path.GetDirectoryName(destinationPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var tempPath = destinationPath + ".tmp";
        await using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await resp.Content.CopyToAsync(fs, cancellationToken);
        }
        File.Move(tempPath, destinationPath, true);
    }

    private void AttachSessionHeaders(HttpRequestMessage request)
    {
        var sessionId = TryGetCurrentSessionId();
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            request.Headers.TryAddWithoutValidation("x-client-session", sessionId);
            request.Headers.TryAddWithoutValidation("session", sessionId);
        }

        var cuid = _managementService.Persist.ClientUniqueId.ToString();
        var mac = EnsureAnchoredPhysicalMac();
        request.Headers.TryAddWithoutValidation("x-client-uid", cuid);
        if (!string.IsNullOrWhiteSpace(mac))
        {
            request.Headers.TryAddWithoutValidation("x-client-mac", mac);
        }
        request.Headers.TryAddWithoutValidation("x-extend-management-enabled", "1");
        request.Headers.TryAddWithoutValidation("x-extend-management-version", "2.0.0.3");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public async Task ReportHookSnapshotAsync(object snapshotPayload, CancellationToken cancellationToken = default)
    {
        try
        {
            if (!_managementService.IsManagementEnabled)
            {
                return;
            }

            var server = (_managementService.Settings.ManagementServer ?? string.Empty).Trim().TrimEnd('/');
            var grpc = (_managementService.Settings.ManagementServerGrpc ?? string.Empty).Trim().TrimEnd('/');
            var cuid = _managementService.Persist.ClientUniqueId.ToString().Trim();
            var baseUrl = ExtractBaseHttpOrigin(server, grpc);
            if (string.IsNullOrWhiteSpace(baseUrl) || string.IsNullOrWhiteSpace(cuid))
            {
                return;
            }

            var snapshotUrl = $"{baseUrl}/api/v1/client/{Uri.EscapeDataString(cuid)}/hook-snapshot";
            var jsonBody = JsonSerializer.Serialize(snapshotPayload);
            using var req = new HttpRequestMessage(HttpMethod.Post, snapshotUrl)
            {
                Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
            };
            AttachSessionHeaders(req);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            using var resp = await _httpClient.SendAsync(req, cts.Token);
            _logger.LogDebug("已向集控服务器同步 Hook 快照 ({StatusCode})。", (int)resp.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "向集控服务器同步 Hook 快照未完成。");
        }
    }

    public async Task NotifyServerUnregisterAsync(
        string? serverUrlOverride = null,
        string? grpcUrlOverride = null,
        string? clientUidOverride = null)
    {
        try
        {
            var server = (serverUrlOverride ?? _cachedServerUrl ?? _managementService.Settings.ManagementServer ?? string.Empty).Trim().TrimEnd('/');
            var grpc = (grpcUrlOverride ?? _cachedGrpcUrl ?? _managementService.Settings.ManagementServerGrpc ?? string.Empty).Trim().TrimEnd('/');
            var cuid = (clientUidOverride ?? _cachedClientUid ?? _managementService.Persist.ClientUniqueId.ToString()).Trim();
            var mac = EnsureAnchoredPhysicalMac();
            var sessionId = TryGetCurrentSessionId();

            if (string.IsNullOrWhiteSpace(cuid))
            {
                return;
            }

            // 1. 尝试通过 HTTP POST /api/v1/client/{cuid}/unregister 通知服务器解绑
            var baseUrl = ExtractBaseHttpOrigin(server, grpc);
            if (!string.IsNullOrWhiteSpace(baseUrl))
            {
                try
                {
                    var unregisterUrl = $"{baseUrl}/api/v1/client/{Uri.EscapeDataString(cuid)}/unregister";
                    using var req = new HttpRequestMessage(HttpMethod.Post, unregisterUrl)
                    {
                        Content = new StringContent("{}", Encoding.UTF8, "application/json")
                    };
                    if (!string.IsNullOrWhiteSpace(sessionId))
                    {
                        req.Headers.TryAddWithoutValidation("x-client-session", sessionId);
                        req.Headers.TryAddWithoutValidation("session", sessionId);
                    }
                    req.Headers.TryAddWithoutValidation("x-client-uid", cuid);
                    if (!string.IsNullOrWhiteSpace(mac))
                    {
                        req.Headers.TryAddWithoutValidation("x-client-mac", mac);
                    }
                    req.Headers.TryAddWithoutValidation("x-extend-management-enabled", "1");
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                    using var resp = await _httpClient.SendAsync(req, cts.Token);
                    _logger.LogInformation("已向集控服务器发送 HTTP 解绑请求 ({StatusCode})。", (int)resp.StatusCode);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "HTTP 解绑通知发送未完成。");
                }
            }

            // 2. 尝试通过 gRPC ClientRegister.UnRegisterAsync 通知服务器解绑
            var grpcTarget = !string.IsNullOrWhiteSpace(grpc) ? grpc : baseUrl;
            if (!string.IsNullOrWhiteSpace(grpcTarget))
            {
                try
                {
                    using var channel = GrpcChannel.ForAddress(grpcTarget, new GrpcChannelOptions
                    {
                        HttpHandler = new SocketsHttpHandler
                        {
                            EnableMultipleHttp2Connections = true,
                            ConnectTimeout = TimeSpan.FromSeconds(3)
                        }
                    });
                    var client = new ClientRegister.ClientRegisterClient(channel);
                    var metadata = new Grpc.Core.Metadata
                    {
                        { "cuid", cuid },
                        { "x-extend-management-enabled", "1" }
                    };
                    if (!string.IsNullOrWhiteSpace(sessionId))
                    {
                        metadata.Add("session", sessionId);
                    }
                    await client.UnRegisterAsync(
                        new ClientRegisterCsReq
                        {
                            ClientUid = cuid,
                            ClientMac = mac ?? string.Empty
                        },
                        headers: metadata,
                        deadline: DateTime.UtcNow.AddSeconds(3));
                    _logger.LogInformation("已向集控服务器发送 gRPC UnRegister 解绑请求。");
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "gRPC UnRegister 解绑通知发送未完成。");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "通知服务器解绑异常。");
        }
    }

    private static string ExtractBaseHttpOrigin(string serverUrl, string grpcUrl)
    {
        foreach (var candidate in new[] { grpcUrl, serverUrl })
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }
            if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
            {
                return $"{uri.Scheme}://{uri.Authority}";
            }
        }
        return string.Empty;
    }

    public void ExecuteLocalExitManagementAndRestart(string reason)
    {
        if (_remoteExitInProgress)
        {
            return;
        }
        _remoteExitInProgress = true;

        try
        {
            _logger.LogWarning("正在执行远程集控解绑退出并重启（原因：{Reason}）...", reason);

            _managementService.Settings.IsManagementEnabled = false;
            _managementService.Settings.ManagementServer = string.Empty;
            _managementService.Settings.ManagementServerGrpc = string.Empty;
            _managementService.Settings.ManifestUrlTemplate = string.Empty;

            ConfigureFileHelper.SaveConfig(HostRuntimeBridge.ManagementSettingsPath, _managementService.Settings);

            string[] filesToClean =
            [
                HostRuntimeBridge.ManagementManifestPath,
                HostRuntimeBridge.ManagementPolicyPath,
                HostRuntimeBridge.ManagementCredentialsPath,
                HostRuntimeBridge.ManagementComponentsPath,
                HostRuntimeBridge.ServerPublicKeyPath,
                Path.Combine(HostRuntimeBridge.ManagementConfigureFolderPath, "Versions.json"),
                Path.Combine(HostRuntimeBridge.ManagementConfigureFolderPath, "DefaultSettings.json"),
                Path.Combine(CommonDirectories.AppDataFolderPath, "Profiles", "_management-profile.json")
            ];

            foreach (var file in filesToClean)
            {
                try
                {
                    if (File.Exists(file))
                    {
                        File.Delete(file);
                    }
                }
                catch
                {
                    // Ignore
                }
            }

            HostRuntimeBridge.MarkServerAsVerifiedMiniServer(
                serverUrl: string.Empty,
                verified: false,
                serverFlavor: string.Empty,
                clientDisplayName: string.Empty,
                clientIdentity: string.Empty);

            _configStore.SetAppLockState(false);

            Dispatcher.UIThread.Post(() =>
            {
                try
                {
                    AppBase.Current.Restart();
                }
                catch
                {
                    Environment.Exit(0);
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "执行远程退出集控并重启时发生异常。");
            Dispatcher.UIThread.Post(() => AppBase.Current.Restart());
        }
    }

    private string DecorateManagementUrl(string templateUrl)
    {
        var host = _managementService.Settings.ManagementServer?.TrimEnd('/') ?? string.Empty;
        var cuid = _managementService.Persist.ClientUniqueId.ToString();
        var id = _managementService.Settings.ClassIdentity ?? string.Empty;
        return templateUrl
            .Replace("{cuid}", cuid, StringComparison.OrdinalIgnoreCase)
            .Replace("{id}", id, StringComparison.OrdinalIgnoreCase)
            .Replace("{host}", host, StringComparison.OrdinalIgnoreCase);
    }

    private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
    {
        if (e.IsAvailable)
        {
            TriggerFastRoamingReconnect("网络可用性恢复");
        }
    }

    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        var currentFingerprint = ComputeActiveNetworkFingerprint();
        if (string.Equals(currentFingerprint, _lastNetworkFingerprint, StringComparison.Ordinal))
        {
            return;
        }

        _lastNetworkFingerprint = currentFingerprint;
        TriggerFastRoamingReconnect("检测到网卡或 IP 地址跳变");
    }

    public void TriggerFastRoamingReconnect(string reason)
    {
        if (!_managementService.IsManagementEnabled)
        {
            return;
        }

        var conn = _managementService.Connection;
        if (conn == null)
        {
            return;
        }

        _roamingReconnectCts?.Cancel();
        _roamingReconnectCts = new CancellationTokenSource();
        var token = _roamingReconnectCts.Token;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(600, token);
                _logger.LogInformation("网络漫游优化：{Reason}，正在主动重建集控会话。", reason);

                var delaysMs = new[] { 300, 1200, 2500, 5000 };
                foreach (var delay in delaysMs)
                {
                    token.ThrowIfCancellationRequested();
                    if (await TryForceReconnectOnceAsync(conn, token))
                    {
                        _logger.LogInformation("网络漫游优化：集控命令流与会话已快速恢复。");
                        return;
                    }
                    await Task.Delay(delay, token);
                }
            }
            catch (OperationCanceledException)
            {
                // 被更新的网络事件取代
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "网络漫游快速重连执行异常。");
            }
        }, token);
    }

    private async Task<bool> TryForceReconnectOnceAsync(object conn, CancellationToken cancellationToken)
    {
        try
        {
            var connType = conn.GetType();
            var callProp = connType.GetProperty("CommandListeningCall", BindingFlags.Instance | BindingFlags.NonPublic);
            var ctsProp = connType.GetProperty("CommandListeningCallCancellationTokenSource", BindingFlags.Instance | BindingFlags.NonPublic);
            var timerProp = connType.GetProperty("CommandConnectionAliveTimer", BindingFlags.Instance | BindingFlags.NonPublic);
            var listenMethod = connType.GetMethod("ListenCommands", BindingFlags.Instance | BindingFlags.NonPublic);

            if (listenMethod == null)
            {
                return false;
            }

            if (ctsProp?.GetValue(conn) is CancellationTokenSource oldCts)
            {
                try
                {
                    await oldCts.CancelAsync();
                }
                catch
                {
                    // Ignore
                }
            }
            ctsProp?.SetValue(conn, new CancellationTokenSource());

            if (timerProp?.GetValue(conn) is DispatcherTimer aliveTimer)
            {
                await Dispatcher.UIThread.InvokeAsync(() => aliveTimer.Stop());
            }

            if (callProp?.GetValue(conn) is IDisposable oldCall)
            {
                try
                {
                    oldCall.Dispose();
                }
                catch
                {
                    // Ignore
                }
                callProp.SetValue(conn, null);
            }

            cancellationToken.ThrowIfCancellationRequested();

            if (listenMethod.Invoke(conn, null) is Task listenTask)
            {
                var waitStart = DateTime.UtcNow;
                while ((DateTime.UtcNow - waitStart).TotalMilliseconds < 2500 && !cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(250, cancellationToken);
                    var sessionId = TryGetCurrentSessionId();
                    var activeCall = callProp?.GetValue(conn);
                    if (!string.IsNullOrWhiteSpace(sessionId) && activeCall != null)
                    {
                        return true;
                    }
                    if (listenTask.IsCompleted)
                    {
                        break;
                    }
                }
            }

            return !string.IsNullOrWhiteSpace(TryGetCurrentSessionId());
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "单次快速重握手尝试未完成。");
            return false;
        }
    }

    private static string ComputeActiveNetworkFingerprint()
    {
        try
        {
            var parts = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .OrderBy(n => n.Id)
                .Select(n =>
                {
                    var ips = n.GetIPProperties().UnicastAddresses
                        .Where(a => a.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        .Select(a => a.Address.ToString())
                        .OrderBy(x => x);
                    return $"{n.Id}:{string.Join(",", ips)}";
                });
            return string.Join("|", parts);
        }
        catch
        {
            return string.Empty;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (_managementService.Settings is INotifyPropertyChanged npc)
        {
            npc.PropertyChanged -= OnManagementSettingsPropertyChanged;
        }
        NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
        _roamingReconnectCts?.Cancel();
        _roamingReconnectCts?.Dispose();
        _httpClient.Dispose();
    }
}
