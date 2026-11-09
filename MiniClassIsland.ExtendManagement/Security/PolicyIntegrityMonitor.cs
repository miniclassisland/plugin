using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Avalonia.Threading;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Shared.Models.Management;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Services;

namespace MiniClassIsland.ExtendManagement.Security;

/// <summary>
/// 集控策略捕获与完整性守护器。
/// 1. 捕获服务端下发的权威 ManagementPolicy、Manifest.json 与 ServerKey.asc 黄金快照；
/// 2. 防止运行时通过内存修改器或第三方插件篡改 Policy 属性；
/// 3. 防止离线状态下手动删改本地集控配置文件绕过集控限制。
/// </summary>
public sealed class PolicyIntegrityMonitor : IDisposable
{
    private readonly ILogger<PolicyIntegrityMonitor> _logger;
    private readonly IManagementService _managementService;
    private readonly Dictionary<string, byte[]> _protectedFilesSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private readonly Timer _integrityTimer;
    private string _goldenPolicyJson = string.Empty;
    private byte[] _goldenPolicyHash = [];
    private bool _isApplyingSnapshot;
    private bool _isAuthorizedPolicyUpdateInProgress;

    public PolicyIntegrityMonitor(
        ILogger<PolicyIntegrityMonitor> logger,
        IManagementService managementService)
    {
        _logger = logger;
        _managementService = managementService;

        CaptureGoldenSnapshot();

        if (_managementService.Policy is INotifyPropertyChanged notifyPolicy)
        {
            notifyPolicy.PropertyChanged += OnPolicyPropertyChanged;
        }

        _integrityTimer = new Timer(_ => InspectIntegrity(), null, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3));
    }

    public async Task RunWithAuthorizedPolicyUpdateAsync(Func<Task> action)
    {
        _isAuthorizedPolicyUpdateInProgress = true;
        try
        {
            await action();
            CaptureGoldenSnapshot();
        }
        finally
        {
            _isAuthorizedPolicyUpdateInProgress = false;
        }
    }

    public void CaptureGoldenSnapshot()
    {
        if (!_managementService.IsManagementEnabled)
        {
            return;
        }

        try
        {
            var policyJson = JsonSerializer.Serialize(_managementService.Policy);
            _goldenPolicyJson = policyJson;
            _goldenPolicyHash = SHA256.HashData(Encoding.UTF8.GetBytes(policyJson));

            CaptureProtectedFile(HostRuntimeBridge.ManagementManifestPath);
            CaptureProtectedFile(HostRuntimeBridge.ManagementPolicyPath);
            CaptureProtectedFile(HostRuntimeBridge.ManagementSettingsPath);
            CaptureProtectedFile(HostRuntimeBridge.ManagementCredentialsPath);
            CaptureProtectedFile(HostRuntimeBridge.ManagementComponentsPath);
            CaptureProtectedFile(HostRuntimeBridge.ServerPublicKeyPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "捕获集控策略黄金快照失败。");
        }
    }

    private void CaptureProtectedFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                _protectedFilesSnapshot[path] = File.ReadAllBytes(path);
            }
        }
        catch
        {
            // Ignore read conflicts
        }
    }

    private void OnPolicyPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_isApplyingSnapshot || _isAuthorizedPolicyUpdateInProgress || !_managementService.IsManagementEnabled)
        {
            return;
        }

        VerifyAndRestoreMemoryPolicy();
    }

    private void InspectIntegrity()
    {
        if (!_managementService.IsManagementEnabled || _isAuthorizedPolicyUpdateInProgress)
        {
            return;
        }

        VerifyAndRestoreMemoryPolicy();
        VerifyAndRestoreDiskFiles();
    }

    private void VerifyAndRestoreMemoryPolicy()
    {
        if (string.IsNullOrEmpty(_goldenPolicyJson) || _goldenPolicyHash.Length == 0)
        {
            CaptureGoldenSnapshot();
            return;
        }

        try
        {
            var currentJson = JsonSerializer.Serialize(_managementService.Policy);
            var currentHash = SHA256.HashData(Encoding.UTF8.GetBytes(currentJson));
            if (CryptographicOperations.FixedTimeEquals(currentHash, _goldenPolicyHash))
            {
                return;
            }

            var golden = JsonSerializer.Deserialize<ManagementPolicy>(_goldenPolicyJson);
            if (golden == null)
            {
                return;
            }

            _logger.LogWarning("检测到内存中的集控策略被非授权修改，正在从权威快照强制恢复。");
            Dispatcher.UIThread.Post(() =>
            {
                _isApplyingSnapshot = true;
                try
                {
                    CopyPolicyProperties(golden, _managementService.Policy);
                }
                finally
                {
                    _isApplyingSnapshot = false;
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "校验内存集控策略时发生异常。");
        }
    }

    private void VerifyAndRestoreDiskFiles()
    {
        foreach (var (filePath, expectedBytes) in _protectedFilesSnapshot)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("检测到集控核心文件 {Path} 被移除，正在从内存快照自动恢复。", filePath);
                    Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
                    File.WriteAllBytes(filePath, expectedBytes);
                    continue;
                }

                var currentBytes = File.ReadAllBytes(filePath);
                if (!CryptographicOperations.FixedTimeEquals(currentBytes, expectedBytes))
                {
                    _logger.LogWarning("检测到集控核心文件 {Path} 被非授权修改，正在从内存快照自动恢复。", filePath);
                    File.WriteAllBytes(filePath, expectedBytes);
                }
            }
            catch
            {
                // Ignore transient file locks during legitimate reload
            }
        }
    }

    private static void CopyPolicyProperties(ManagementPolicy source, ManagementPolicy target)
    {
        target.DisableProfileClassPlanEditing = source.DisableProfileClassPlanEditing;
        target.DisableProfileTimeLayoutEditing = source.DisableProfileTimeLayoutEditing;
        target.DisableProfileSubjectsEditing = source.DisableProfileSubjectsEditing;
        target.DisableProfileEditing = source.DisableProfileEditing;
        target.DisableSettingsEditing = source.DisableSettingsEditing;
        target.DisableSplashCustomize = source.DisableSplashCustomize;
        target.DisableDebugMenu = source.DisableDebugMenu;
        target.AllowExitManagement = source.AllowExitManagement;
        target.DisableEasterEggs = source.DisableEasterEggs;
    }

    public void Dispose()
    {
        _integrityTimer.Dispose();
        if (_managementService.Policy is INotifyPropertyChanged notifyPolicy)
        {
            notifyPolicy.PropertyChanged -= OnPolicyPropertyChanged;
        }
    }
}
