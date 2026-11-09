using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core.Abstractions.Services.Management;
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

            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;

            if (_managementService.IsManagementEnabled)
            {
                _ = Task.Run(() => ProbeCurrentManagementServerFlavorAsync());
            }
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

            if (HostRuntimeBridge.InspectHttpResponseForMiniMarker(resp, rawBody))
            {
                HostRuntimeBridge.MarkServerAsVerifiedMiniServer(server, true);
                return true;
            }
        }
        catch
        {
            // Ignore probe failure
        }
        return HostRuntimeBridge.IsJoinedMiniClassIslandServer(_managementService);
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
        request.Headers.TryAddWithoutValidation("x-client-uid", cuid);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
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
        NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
        _roamingReconnectCts?.Cancel();
        _roamingReconnectCts?.Dispose();
        _httpClient.Dispose();
    }
}
