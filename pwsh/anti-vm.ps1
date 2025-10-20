function Check-CpuidHypervisor {
    try {
        $cpuid = Get-WmiObject -Query "SELECT * FROM Win32_Processor"
        $hypervisorPresent = $cpuid.HypervisorPresent
        return $hypervisorPresent
    } catch {
        return $false
    }
}

function Check-MemorySize {
    try {
        $memory = Get-WmiObject -Class "Win32_ComputerSystem"
        $totalMemoryGB = [Math]::Round($memory.TotalPhysicalMemory / 1GB)
        $commonVmSizes = @(1, 2, 4)
        return $commonVmSizes -contains $totalMemoryGB
    } catch {
        return $false
    }
}

function Check-MacAddress {
    try {
        $macs = (Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" | Where-Object { $_.IPEnabled }).MACAddress
        $vmMacPrefixes = @("00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27", "00:1C:42", "52:54:00")
        foreach ($mac in $macs) {
            foreach ($prefix in $vmMacPrefixes) {
                if ($mac -like "$prefix*") {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Check-Bios {
    try {
        $bios = Get-WmiObject -Class "Win32_BIOS"
        $vmBiosStrings = @("VMware", "VirtualBox", "QEMU", "Hyper-V", "Parallels", "Xen")
        foreach ($str in $vmBiosStrings) {
            if (($bios.SerialNumber -match $str) -or ($bios.Manufacturer -match $str)) {
                return $true
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Check-CpuCores {
    try {
        $cpu = Get-WmiObject -Class "Win32_Processor"
        $coreCount = $cpu.NumberOfCores
        return $coreCount -le 2
    } catch {
        return $false
    }
}

function Check-DiskSize {
    try {
        $disk = Get-WmiObject -Class "Win32_LogicalDisk" | Where-Object { $_.DeviceID -eq "C:" }
        $diskSizeGB = [Math]::Round($disk.Size / 1GB)
        $commonVmSizes = @(60, 80, 100)
        return $commonVmSizes -contains $diskSizeGB
    } catch {
        return $false
    }
}

function Check-DisplayAdapter {
    try {
        $adapters = Get-WmiObject -Class "Win32_VideoController"
        $vmAdapters = @("VMware SVGA", "VirtualBox Graphics Adapter", "Hyper-V Video", "QEMU Standard VGA", "Parallels Display Adapter")
        foreach ($adapter in $adapters) {
            foreach ($vmAdapter in $vmAdapters) {
                if ($adapter.Name -match $vmAdapter) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Check-PciDevices {
    try {
        $devices = Get-WmiObject -Class "Win32_PnPEntity"
        $vmPciDevices = @("VMware VMCI", "VirtualBox Guest Service", "Red Hat VirtIO")
        foreach ($device in $devices) {
            foreach ($vmDevice in $vmPciDevices) {
                if ($device.Name -match $vmDevice) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Check-Drivers {
    try {
        $drivers = Get-WmiObject -Class "Win32_SystemDriver"
        $vmDrivers = @("virtio", "vmxnet", "pvscsi", "vboxguest", "vmware", "vmusb", "vmx86")
        foreach ($driver in $drivers) {
            foreach ($vmDriver in $vmDrivers) {
                if ($driver.Name -match $vmDriver) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Check-VmRegistryKeys {
    $vmKeys = @(
        "HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxVideo"
    )
    foreach ($key in $vmKeys) {
        if (Test-Path $key) {
            return $true
        }
    }
    return $false
}

function Check-VmProcesses {
    $vmProcesses = @(
        "vmtoolsd",
        "VMwareService",
        "VMwareTray",
        "VBoxService",
        "VBoxTray",
        "qemu-ga",
        "prl_tools_service"
    )
    $processes = Get-Process
    foreach ($process in $processes) {
        foreach ($vmProcess in $vmProcesses) {
            if ($process.ProcessName -eq $vmProcess) {
                return $true
            }
        }
    }
    return $false
}

function Check-FileSystemArtifacts {
    $vmDirs = @(
        "C:\\Program Files\\VMware",
        "C:\\Program Files\\Oracle",
        "C:\\Program Files\\VirtualBox",
        "C:\\Program Files\\Parallels",
        "C:\\Program Files\\QEMU"
    )
    foreach ($dir in $vmDirs) {
        if (Test-Path $dir) {
            return $true
        }
    }
    return $false
}

function Is-Virtualized {
    if (Check-CpuidHypervisor) { return $true }
    if (Check-MemorySize) { return $true }
    if (Check-MacAddress) { return $true }
    if (Check-Bios) { return $true }
    if (Check-CpuCores) { return $true }
    if (Check-DiskSize) { return $true }
    if (Check-DisplayAdapter) { return $true }
    if (Check-PciDevices) { return $true }
    if (Check-Drivers) { return $true }
    if (Check-VmRegistryKeys) { return $true }
    if (Check-VmProcesses) { return $true }
    if (Check-FileSystemArtifacts) { return $true }
    return $false
}

if (Is-Virtualized) {
    Write-Output "A virtual machine has been detected."
} else {
    Write-Output "No virtual machine has been detected."
}
