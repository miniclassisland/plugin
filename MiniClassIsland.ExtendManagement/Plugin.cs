using ClassIsland.Core.Abstractions;
using ClassIsland.Core.Abstractions.Services.Management;
using ClassIsland.Core.Attributes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Networking;
using MiniClassIsland.ExtendManagement.Security;
using MiniClassIsland.ExtendManagement.Services;
using MiniClassIsland.ExtendManagement.Services.Handlers;
using MiniClassIsland.ExtendManagement.Views.SettingPages;

namespace MiniClassIsland.ExtendManagement;

/// <summary>
/// MINI ClassIsland 集控增强组件入口。
/// 包名：org.miniopensource.miniclassisland.extendmanagement
/// </summary>
[PluginEntrance]
public class Plugin : PluginBase
{
    public override void Initialize(HostBuilderContext context, IServiceCollection services)
    {
        var configFolder = PluginConfigFolder;
        var pluginFolder = Info.PluginFolderPath;

        // 1. 注册防篡改权限开关存储、端到端签名验证器、策略完整性监控与自我保护服务
        services.AddSingleton(sp => new TamperEvidentConfigStore(
            sp.GetRequiredService<ILogger<TamperEvidentConfigStore>>(),
            configFolder));

        services.AddSingleton(sp => new CommandSignatureVerifier(
            sp.GetRequiredService<ILogger<CommandSignatureVerifier>>(),
            sp.GetRequiredService<IManagementService>(),
            configFolder));

        services.AddSingleton<PolicyIntegrityMonitor>();

        services.AddSingleton(sp => new SelfProtectionService(
            sp.GetRequiredService<ILogger<SelfProtectionService>>(),
            sp.GetRequiredService<IManagementService>(),
            sp.GetRequiredService<TamperEvidentConfigStore>(),
            pluginFolder));

        // 2. 注册网卡切换/IP 跳变漫游优化协调器、加入集控窗口增强器与集控设置页注入器
        services.AddSingleton<NetworkRoamingCoordinator>();
        services.AddSingleton<PairingDialogEnhancer>();
        services.AddSingleton<ManagementPageInjector>();

        // 3. 注册三级集控业务指令处理器
        services.AddSingleton<HardwareCommandHandler>();
        services.AddSingleton<SettingsCommandHandler>();
        services.AddSingleton<ProfileCommandHandler>();
        services.AddSingleton<AutomationCommandHandler>();
        services.AddSingleton<UpdateCommandHandler>();
        services.AddSingleton<PluginManageCommandHandler>();
        services.AddSingleton<ThemeManageCommandHandler>();
        services.AddSingleton<RemoteControlCommandHandler>();

        // 4. 注册核心调度服务与 HostedService
        services.AddSingleton<ExtendManagementHostService>();
        services.AddHostedService(sp => sp.GetRequiredService<ExtendManagementHostService>());
    }
}
