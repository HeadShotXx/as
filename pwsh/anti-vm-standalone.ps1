function a {
    try {
        $b = Get-WmiObject -Query ("SE" + "LECT * FROM Win32_Processor")
        $c = $b.HypervisorPresent
        return $c
    } catch {
        return $false
    }
}

function b {
    try {
        $c = Get-WmiObject -Class ("Win32_Computer" + "System")
        $d = [Math]::Round($c.TotalPhysicalMemory / 1GB)
        $e = @(1, 2, 4)
        return $e -contains $d
    } catch {
        return $false
    }
}

function c {
    try {
        $d = (Get-WmiObject -Class ("Win32_NetworkAdapter" + "Configuration") | Where-Object { $_.IPEnabled }).MACAddress
        $e = @("00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27", "00:1C:42", "52:54:00")
        foreach ($f in $d) {
            foreach ($g in $e) {
                if ($f -like "$g*") {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function d {
    try {
        $e = Get-WmiObject -Class ("Win32" + "_BIOS")
        $f = @("VMware", "VirtualBox", "QEMU", "Hyper-V", "Parallels", "Xen")
        foreach ($g in $f) {
            if (($e.SerialNumber -match $g) -or ($e.Manufacturer -match $g)) {
                return $true
            }
        }
        return $false
    } catch {
        return $false
    }
}

function e {
    try {
        $f = Get-WmiObject -Class ("Win32_Pro" + "cessor")
        $g = $f.NumberOfCores
        return $g -le 2
    } catch {
        return $false
    }
}

function f {
    try {
        $g = Get-WmiObject -Class ("Win32_Logical" + "Disk") | Where-Object { $_.DeviceID -eq "C:" }
        $h = [Math]::Round($g.Size / 1GB)
        $i = @(60, 80, 100)
        return $i -contains $h
    } catch {
        return $false
    }
}

function g {
    try {
        $h = Get-WmiObject -Class ("Win32_Video" + "Controller")
        $i = @("VMware SVGA", "VirtualBox Graphics Adapter", "Hyper-V Video", "QEMU Standard VGA", "Parallels Display Adapter")
        foreach ($j in $h) {
            foreach ($k in $i) {
                if ($j.Name -match $k) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function h {
    try {
        $i = Get-WmiObject -Class ("Win32_PnPE" + "ntity")
        $j = @("VMware VMCI", "VirtualBox Guest Service", "Red Hat VirtIO")
        foreach ($k in $i) {
            foreach ($l in $j) {
                if ($k.Name -match $l) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function i {
    try {
        $j = Get-WmiObject -Class ("Win32_System" + "Driver")
        $k = @("virtio", "vmxnet", "pvscsi", "vboxguest", "vmware", "vmusb", "vmx86")
        foreach ($l in $j) {
            foreach ($m in $k) {
                if ($l.Name -match $m) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function j {
    $k = @(
        ("HKLM:\\SOFT" + "WARE\\VMware, Inc.\\VMware Tools"),
        ("HKLM:\\SYSTEM\\Current" + "ControlSet\\Services\\VBoxGuest"),
        ("HKLM:\\SYSTEM\\Current" + "ControlSet\\Services\\VBoxMouse"),
        ("HKLM:\\SYSTEM\\Current" + "ControlSet\\Services\\VBoxSF"),
        ("HKLM:\\SYSTEM\\Current" + "ControlSet\\Services\\VBoxVideo")
    )
    foreach ($l in $k) {
        if (Test-Path $l) {
            return $true
        }
    }
    return $false
}

function k {
    $l = @(
        "vmtoolsd",
        "VMwareService",
        "VMwareTray",
        "VBoxService",
        "VBoxTray",
        "qemu-ga",
        "prl_tools_service"
    )
    $m = Get-Process
    foreach ($n in $m) {
        foreach ($o in $l) {
            if ($n.ProcessName -eq $o) {
                return $true
            }
        }
    }
    return $false
}

function l {
    $m = @(
        ("C:\\Program Files\\" + "VMware"),
        ("C:\\Program Files\\" + "Oracle"),
        ("C:\\Program Files\\" + "VirtualBox"),
        ("C:\\Program Files\\" + "Parallels"),
        ("C:\\Program Files\\" + "QEMU")
    )
    foreach ($n in $m) {
        if (Test-Path $n) {
            return $true
        }
    }
    return $false
}

function m {
    try {
        $n = Get-WmiObject -Class ("Win32_Video" + "Controller")
        return $n.Name -eq ("VMware SVGA " + "II")
    } catch {
        return $false
    }
}

function n {
    try {
        $o = Get-WmiObject -Class ("Win32_SCSI" + "Controller")
        return $o.Name -eq ("Red Hat VirtIO SCSI " + "Controller")
    } catch {
        return $false
    }
}

function o {
    if (a) { return $true }
    if (b) { return $true }
    if (c) { return $true }
    if (d) { return $true }
    if (e) { return $true }
    if (f) { return $true }
    if (g) { return $true }
    if (h) { return $true }
    if (i) { return $true }
    if (j) { return $true }
    if (k) { return $true }
    if (l) { return $true }
    if (m) { return $true }
    if (n) { return $true }
    return $false
}

if (o) {
    Write-Output ("A virtual machine has " + "been detected.")
} else {
    Write-Output ("No virtual machine has " + "been detected.")
}

# Decoy code
$p = 1
while ($p -lt 10) {
    $p++
}
