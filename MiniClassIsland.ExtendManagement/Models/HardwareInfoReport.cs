using System.Text.Json.Serialization;

namespace MiniClassIsland.ExtendManagement.Models;

/// <summary>
/// 客户端详细硬件与系统信息报告。
/// </summary>
public sealed class HardwareInfoReport
{
    [JsonPropertyName("collectedAtUtc")]
    public DateTimeOffset CollectedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("system")]
    public SystemBoardInfo System { get; set; } = new();

    [JsonPropertyName("cpu")]
    public List<CpuDeviceInfo>Cpus { get; set; } = [];

    [JsonPropertyName("memory")]
    public MemoryStatusInfo Memory { get; set; } = new();

    [JsonPropertyName("disks")]
    public List<DiskDeviceInfo> Disks { get; set; } = [];

    [JsonPropertyName("partitions")]
    public List<PartitionVolumeInfo> Partitions { get; set; } = [];

    [JsonPropertyName("gpus")]
    public List<GpuDeviceInfo> Gpus { get; set; } = [];

    [JsonPropertyName("displays")]
    public List<DisplayMonitorInfo> Displays { get; set; } = [];

    [JsonPropertyName("networkInterfaces")]
    public List<NetworkAdapterInfo> NetworkInterfaces { get; set; } = [];
}

public sealed class SystemBoardInfo
{
    [JsonPropertyName("machineName")]
    public string MachineName { get; set; } = string.Empty;

    [JsonPropertyName("userName")]
    public string UserName { get; set; } = string.Empty;

    [JsonPropertyName("osDescription")]
    public string OsDescription { get; set; } = string.Empty;

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("osArchitecture")]
    public string OsArchitecture { get; set; } = string.Empty;

    [JsonPropertyName("processArchitecture")]
    public string ProcessArchitecture { get; set; } = string.Empty;

    [JsonPropertyName("uptimeSeconds")]
    public long UptimeSeconds { get; set; }

    [JsonPropertyName("motherboardManufacturer")]
    public string MotherboardManufacturer { get; set; } = string.Empty;

    [JsonPropertyName("motherboardProduct")]
    public string MotherboardProduct { get; set; } = string.Empty;

    [JsonPropertyName("motherboardSerialNumber")]
    public string MotherboardSerialNumber { get; set; } = string.Empty;

    [JsonPropertyName("biosVendor")]
    public string BiosVendor { get; set; } = string.Empty;

    [JsonPropertyName("biosVersion")]
    public string BiosVersion { get; set; } = string.Empty;

    [JsonPropertyName("systemUuid")]
    public string SystemUuid { get; set; } = string.Empty;

    [JsonPropertyName("appVersion")]
    public string AppVersion { get; set; } = string.Empty;

    [JsonPropertyName("dotnetVersion")]
    public string DotnetVersion { get; set; } = string.Empty;
}

public sealed class CpuDeviceInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("manufacturer")]
    public string Manufacturer { get; set; } = string.Empty;

    [JsonPropertyName("processorId")]
    public string ProcessorId { get; set; } = string.Empty;

    [JsonPropertyName("physicalCores")]
    public int PhysicalCores { get; set; }

    [JsonPropertyName("logicalProcessors")]
    public int LogicalProcessors { get; set; }

    [JsonPropertyName("maxClockSpeedMhz")]
    public uint MaxClockSpeedMhz { get; set; }

    [JsonPropertyName("currentClockSpeedMhz")]
    public uint CurrentClockSpeedMhz { get; set; }
}

public sealed class MemoryStatusInfo
{
    [JsonPropertyName("totalPhysicalBytes")]
    public ulong TotalPhysicalBytes { get; set; }

    [JsonPropertyName("availablePhysicalBytes")]
    public ulong AvailablePhysicalBytes { get; set; }

    [JsonPropertyName("usedPercentage")]
    public double UsedPercentage { get; set; }

    [JsonPropertyName("totalPageFileBytes")]
    public ulong TotalPageFileBytes { get; set; }

    [JsonPropertyName("availablePageFileBytes")]
    public ulong AvailablePageFileBytes { get; set; }

    [JsonPropertyName("modules")]
    public List<MemoryModuleStickInfo> Modules { get; set; } = [];
}

public sealed class MemoryModuleStickInfo
{
    [JsonPropertyName("bankLabel")]
    public string BankLabel { get; set; } = string.Empty;

    [JsonPropertyName("manufacturer")]
    public string Manufacturer { get; set; } = string.Empty;

    [JsonPropertyName("partNumber")]
    public string PartNumber { get; set; } = string.Empty;

    [JsonPropertyName("capacityBytes")]
    public ulong CapacityBytes { get; set; }

    [JsonPropertyName("speedMhz")]
    public uint SpeedMhz { get; set; }
}

public sealed class DiskDeviceInfo
{
    [JsonPropertyName("model")]
    public string Model { get; set; } = string.Empty;

    [JsonPropertyName("interfaceType")]
    public string InterfaceType { get; set; } = string.Empty;

    [JsonPropertyName("mediaType")]
    public string MediaType { get; set; } = string.Empty;

    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; set; } = string.Empty;

    [JsonPropertyName("sizeBytes")]
    public ulong SizeBytes { get; set; }
}

public sealed class PartitionVolumeInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("volumeLabel")]
    public string VolumeLabel { get; set; } = string.Empty;

    [JsonPropertyName("driveFormat")]
    public string DriveFormat { get; set; } = string.Empty;

    [JsonPropertyName("driveType")]
    public string DriveType { get; set; } = string.Empty;

    [JsonPropertyName("totalSizeBytes")]
    public long TotalSizeBytes { get; set; }

    [JsonPropertyName("availableFreeBytes")]
    public long AvailableFreeBytes { get; set; }
}

public sealed class GpuDeviceInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("driverVersion")]
    public string DriverVersion { get; set; } = string.Empty;

    [JsonPropertyName("adapterRamBytes")]
    public ulong AdapterRamBytes { get; set; }

    [JsonPropertyName("videoProcessor")]
    public string VideoProcessor { get; set; } = string.Empty;

    [JsonPropertyName("currentHorizontalResolution")]
    public uint CurrentHorizontalResolution { get; set; }

    [JsonPropertyName("currentVerticalResolution")]
    public uint CurrentVerticalResolution { get; set; }

    [JsonPropertyName("currentRefreshRate")]
    public uint CurrentRefreshRate { get; set; }
}

public sealed class DisplayMonitorInfo
{
    [JsonPropertyName("index")]
    public int Index { get; set; }

    [JsonPropertyName("displayName")]
    public string DisplayName { get; set; } = string.Empty;

    [JsonPropertyName("isPrimary")]
    public bool IsPrimary { get; set; }

    [JsonPropertyName("boundsX")]
    public int BoundsX { get; set; }

    [JsonPropertyName("boundsY")]
    public int BoundsY { get; set; }

    [JsonPropertyName("widthPixels")]
    public int WidthPixels { get; set; }

    [JsonPropertyName("heightPixels")]
    public int HeightPixels { get; set; }

    [JsonPropertyName("scaling")]
    public double Scaling { get; set; }
}

public sealed class NetworkAdapterInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("interfaceType")]
    public string InterfaceType { get; set; } = string.Empty;

    [JsonPropertyName("operationalStatus")]
    public string OperationalStatus { get; set; } = string.Empty;

    [JsonPropertyName("macAddress")]
    public string MacAddress { get; set; } = string.Empty;

    [JsonPropertyName("isPhysicalCandidate")]
    public bool IsPhysicalCandidate { get; set; }

    [JsonPropertyName("speedBitsPerSecond")]
    public long SpeedBitsPerSecond { get; set; }

    [JsonPropertyName("ipv4Addresses")]
    public List<string> Ipv4Addresses { get; set; } = [];

    [JsonPropertyName("ipv6Addresses")]
    public List<string> Ipv6Addresses { get; set; } = [];

    [JsonPropertyName("gateways")]
    public List<string> Gateways { get; set; } = [];

    [JsonPropertyName("dnsAddresses")]
    public List<string> DnsAddresses { get; set; } = [];
}
