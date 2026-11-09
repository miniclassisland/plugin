using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Threading;
using ClassIsland.Core;
using Microsoft.Extensions.Logging;
using MiniClassIsland.ExtendManagement.Models;
using MiniClassIsland.ExtendManagement.Networking;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// 详细硬件与系统信息采集处理器（hardware.get_info）。
/// </summary>
public sealed class HardwareCommandHandler(ILogger<HardwareCommandHandler> logger)
{
    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        return await Task.Run(async () =>
        {
            var report = new HardwareInfoReport
            {
                CollectedAtUtc = DateTimeOffset.UtcNow,
                System = CollectSystemBoardInfo(),
                Cpus = CollectCpuInfo(),
                Memory = CollectMemoryInfo(),
                Disks = CollectPhysicalDisks(),
                Partitions = CollectPartitions(),
                Gpus = CollectGpuInfo(),
                Displays = await CollectDisplaysAsync(),
                NetworkInterfaces = CollectNetworkInterfaces()
            };

            return JsonSerializer.SerializeToElement(report);
        });
    }

    private SystemBoardInfo CollectSystemBoardInfo()
    {
        var info = new SystemBoardInfo
        {
            MachineName = Environment.MachineName,
            UserName = Environment.UserName,
            OsDescription = RuntimeInformation.OSDescription,
            OsVersion = Environment.OSVersion.VersionString,
            OsArchitecture = RuntimeInformation.OSArchitecture.ToString(),
            ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            UptimeSeconds = Environment.TickCount64 / 1000,
            AppVersion = AppBase.AppVersion,
            DotnetVersion = Environment.Version.ToString()
        };

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var boardSearcher = new ManagementObjectSearcher("SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard");
                foreach (var obj in boardSearcher.Get().OfType<ManagementObject>())
                {
                    info.MotherboardManufacturer = Convert.ToString(obj["Manufacturer"])?.Trim() ?? string.Empty;
                    info.MotherboardProduct = Convert.ToString(obj["Product"])?.Trim() ?? string.Empty;
                    info.MotherboardSerialNumber = Convert.ToString(obj["SerialNumber"])?.Trim() ?? string.Empty;
                    break;
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "采集主板信息异常。");
            }

            try
            {
                using var biosSearcher = new ManagementObjectSearcher("SELECT Manufacturer, SMBIOSBIOSVersion FROM Win32_BIOS");
                foreach (var obj in biosSearcher.Get().OfType<ManagementObject>())
                {
                    info.BiosVendor = Convert.ToString(obj["Manufacturer"])?.Trim() ?? string.Empty;
                    info.BiosVersion = Convert.ToString(obj["SMBIOSBIOSVersion"])?.Trim() ?? string.Empty;
                    break;
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "采集 BIOS 信息异常。");
            }

            try
            {
                using var csProductSearcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
                foreach (var obj in csProductSearcher.Get().OfType<ManagementObject>())
                {
                    info.SystemUuid = Convert.ToString(obj["UUID"])?.Trim() ?? string.Empty;
                    break;
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "采集系统 UUID 异常。");
            }
        }

        return info;
    }

    private List<CpuDeviceInfo> CollectCpuInfo()
    {
        var list = new List<CpuDeviceInfo>();
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, Manufacturer, ProcessorId, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, CurrentClockSpeed FROM Win32_Processor");
                foreach (var obj in searcher.Get().OfType<ManagementObject>())
                {
                    list.Add(new CpuDeviceInfo
                    {
                        Name = Convert.ToString(obj["Name"])?.Trim() ?? string.Empty,
                        Manufacturer = Convert.ToString(obj["Manufacturer"])?.Trim() ?? string.Empty,
                        ProcessorId = Convert.ToString(obj["ProcessorId"])?.Trim() ?? string.Empty,
                        PhysicalCores = Convert.ToInt32(obj["NumberOfCores"] ?? Environment.ProcessorCount),
                        LogicalProcessors = Convert.ToInt32(obj["NumberOfLogicalProcessors"] ?? Environment.ProcessorCount),
                        MaxClockSpeedMhz = Convert.ToUInt32(obj["MaxClockSpeed"] ?? 0u),
                        CurrentClockSpeedMhz = Convert.ToUInt32(obj["CurrentClockSpeed"] ?? 0u)
                    });
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "WMI 采集处理器信息失败，使用基础回退。");
            }
        }

        if (list.Count == 0)
        {
            list.Add(new CpuDeviceInfo
            {
                Name = RuntimeInformation.ProcessArchitecture.ToString(),
                PhysicalCores = Environment.ProcessorCount,
                LogicalProcessors = Environment.ProcessorCount
            });
        }

        return list;
    }

    private MemoryStatusInfo CollectMemoryInfo()
    {
        var mem = new MemoryStatusInfo();
        if (OperatingSystem.IsWindows())
        {
            var status = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref status))
            {
                mem.TotalPhysicalBytes = status.ullTotalPhys;
                mem.AvailablePhysicalBytes = status.ullAvailPhys;
                mem.UsedPercentage = status.dwMemoryLoad;
                mem.TotalPageFileBytes = status.ullTotalPageFile;
                mem.AvailablePageFileBytes = status.ullAvailPageFile;
            }

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT BankLabel, Manufacturer, PartNumber, Capacity, Speed FROM Win32_PhysicalMemory");
                foreach (var obj in searcher.Get().OfType<ManagementObject>())
                {
                    mem.Modules.Add(new MemoryModuleStickInfo
                    {
                        BankLabel = Convert.ToString(obj["BankLabel"])?.Trim() ?? string.Empty,
                        Manufacturer = Convert.ToString(obj["Manufacturer"])?.Trim() ?? string.Empty,
                        PartNumber = Convert.ToString(obj["PartNumber"])?.Trim() ?? string.Empty,
                        CapacityBytes = Convert.ToUInt64(obj["Capacity"] ?? 0UL),
                        SpeedMhz = Convert.ToUInt32(obj["Speed"] ?? 0u)
                    });
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "采集物理内存条详情异常。");
            }
        }
        else
        {
            var gcInfo = GC.GetGCMemoryInfo();
            mem.TotalPhysicalBytes = (ulong)Math.Max(0, gcInfo.TotalAvailableMemoryBytes);
        }

        return mem;
    }

    private List<DiskDeviceInfo> CollectPhysicalDisks()
    {
        var list = new List<DiskDeviceInfo>();
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Model, InterfaceType, MediaType, SerialNumber, Size FROM Win32_DiskDrive");
                foreach (var obj in searcher.Get().OfType<ManagementObject>())
                {
                    list.Add(new DiskDeviceInfo
                    {
                        Model = Convert.ToString(obj["Model"])?.Trim() ?? string.Empty,
                        InterfaceType = Convert.ToString(obj["InterfaceType"])?.Trim() ?? string.Empty,
                        MediaType = Convert.ToString(obj["MediaType"])?.Trim() ?? string.Empty,
                        SerialNumber = Convert.ToString(obj["SerialNumber"])?.Trim() ?? string.Empty,
                        SizeBytes = Convert.ToUInt64(obj["Size"] ?? 0UL)
                    });
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "采集物理磁盘信息异常。");
            }
        }
        return list;
    }

    private List<PartitionVolumeInfo> CollectPartitions()
    {
        var list = new List<PartitionVolumeInfo>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady)
                {
                    continue;
                }
                list.Add(new PartitionVolumeInfo
                {
                    Name = drive.Name,
                    VolumeLabel = drive.VolumeLabel,
                    DriveFormat = drive.DriveFormat,
                    DriveType = drive.DriveType.ToString(),
                    TotalSizeBytes = drive.TotalSize,
                    AvailableFreeBytes = drive.AvailableFreeSpace
                });
            }
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "采集磁盘分区信息异常。");
        }
        return list;
    }

    private List<GpuDeviceInfo> CollectGpuInfo()
    {
        var list = new List<GpuDeviceInfo>();
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, DriverVersion, AdapterRAM, VideoProcessor, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate FROM Win32_VideoController");
                foreach (var obj in searcher.Get().OfType<ManagementObject>())
                {
                    list.Add(new GpuDeviceInfo
                    {
                        Name = Convert.ToString(obj["Name"])?.Trim() ?? string.Empty,
                        DriverVersion = Convert.ToString(obj["DriverVersion"])?.Trim() ?? string.Empty,
                        AdapterRamBytes = Convert.ToUInt64(obj["AdapterRAM"] ?? 0UL),
                        VideoProcessor = Convert.ToString(obj["VideoProcessor"])?.Trim() ?? string.Empty,
                        CurrentHorizontalResolution = Convert.ToUInt32(obj["CurrentHorizontalResolution"] ?? 0u),
                        CurrentVerticalResolution = Convert.ToUInt32(obj["CurrentVerticalResolution"] ?? 0u),
                        CurrentRefreshRate = Convert.ToUInt32(obj["CurrentRefreshRate"] ?? 0u)
                    });
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "采集 GPU 信息异常。");
            }
        }
        return list;
    }

    private static async Task<List<DisplayMonitorInfo>> CollectDisplaysAsync()
    {
        return await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var result = new List<DisplayMonitorInfo>();
            var screens = AppBase.Current.MainWindow?.Screens ?? AppBase.Current.GetRootWindow()?.Screens;
            if (screens == null)
            {
                return result;
            }

            var idx = 0;
            foreach (var s in screens.All)
            {
                result.Add(new DisplayMonitorInfo
                {
                    Index = idx++,
                    DisplayName = s.DisplayName ?? $"Display {idx}",
                    IsPrimary = s.IsPrimary,
                    BoundsX = s.Bounds.X,
                    BoundsY = s.Bounds.Y,
                    WidthPixels = s.Bounds.Width,
                    HeightPixels = s.Bounds.Height,
                    Scaling = s.Scaling
                });
            }
            return result;
        });
    }

    private List<NetworkAdapterInfo> CollectNetworkInterfaces()
    {
        var list = new List<NetworkAdapterInfo>();
        try
        {
            var bestMac = NetworkRoamingCoordinator.SelectBestPhysicalMacAddress();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                var mac = nic.GetPhysicalAddress().ToString().ToUpperInvariant();
                var props = nic.GetIPProperties();

                var ipv4 = props.UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString())
                    .ToList();

                var ipv6 = props.UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6)
                    .Select(a => a.Address.ToString())
                    .ToList();

                var gateways = props.GatewayAddresses
                    .Select(g => g.Address.ToString())
                    .ToList();

                var dns = props.DnsAddresses
                    .Select(d => d.ToString())
                    .ToList();

                list.Add(new NetworkAdapterInfo
                {
                    Id = nic.Id,
                    Name = nic.Name,
                    Description = nic.Description,
                    InterfaceType = nic.NetworkInterfaceType.ToString(),
                    OperationalStatus = nic.OperationalStatus.ToString(),
                    MacAddress = mac,
                    IsPhysicalCandidate = !string.IsNullOrEmpty(mac) && string.Equals(mac, bestMac, StringComparison.OrdinalIgnoreCase),
                    SpeedBitsPerSecond = nic.Speed,
                    Ipv4Addresses = ipv4,
                    Ipv6Addresses = ipv6,
                    Gateways = gateways,
                    DnsAddresses = dns
                });
            }
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "采集网络接口信息异常。");
        }
        return list;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
}
