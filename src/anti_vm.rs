use sysinfo::{System, SystemExt, DiskExt, NetworkExt, ProcessExt};
use raw_cpuid::CpuId;
use std::path::Path;
use std::time::Instant;

// Obfuscation function
fn deobfuscate(s: &str) -> String {
    s.chars().map(|c| (c as u8 ^ 0x1A) as char).collect()
}

// Analysis function A
fn analysis_a() -> Option<String> {
    let cpuid = CpuId::new();
    if let Some(hypervisor_info) = cpuid.get_hypervisor_info() {
        return Some(format!("Flag A: {:?}", hypervisor_info.identify()));
    }
    None
}

// Analysis function B
fn analysis_b(sys: &System) -> Vec<String> {
    let mut findings = Vec::new();
    if sys.total_memory() < 2 * 1024 * 1024 * 1024 {
        findings.push(deobfuscate("T{ik(E1"));
    }
    if sys.cpus().len() <= 1 {
        findings.push(deobfuscate("T{ik(E2"));
    }
    if let Some(disk) = sys.disks().iter().next() {
        if disk.total_space() < 100 * 1024 * 1024 * 1024 {
            findings.push(deobfuscate("T{ik(E3"));
        }
    }
    findings
}

// Analysis function C
fn analysis_c(sys: &System) -> Vec<String> {
    let mut findings = Vec::new();
    let vm_processes = vec![
        deobfuscate("r`gq|`w+`{`"),
        deobfuscate("r`gq|`w+q`w"),
        deobfuscate("r`qgg{w+`{`"),
        deobfuscate("r`qgg{w+m`w`"),
        deobfuscate("r`qgg{w+m`w`"),
    ];
    for process in sys.processes().values() {
        for vm_process in &vm_processes {
            if process.name().to_lowercase() == *vm_process {
                findings.push(format!("Flag C: {}", process.name()));
            }
        }
    }
    findings
}

// Analysis function D
fn analysis_d(sys: &System) -> Vec<String> {
    let mut findings = Vec::new();
    let vm_mac_prefixes = vec![
        deobfuscate("5A15515:"),
        deobfuscate("5515616;"),
        deobfuscate("5515S15;"),
        deobfuscate("5512S126"),
        deobfuscate("55165168"),
    ];
    for (iface_name, network_data) in sys.networks() {
        let mac_address = network_data.mac_address().to_string().to_uppercase();
        for prefix in &vm_mac_prefixes {
            if mac_address.starts_with(prefix) {
                findings.push(format!("Flag D: {} -> {}", iface_name, mac_address));
            }
        }
    }
    findings
}

// Analysis function E
#[cfg(target_os = "windows")]
fn analysis_e() -> Vec<String> {
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
                    if manufacturer.contains(&deobfuscate("r`gq|`{gq")) {
                        findings.push(deobfuscate("T{ik(T2"));
                    }
                    if manufacturer.contains(&deobfuscate("r`qg{`")) {
                        findings.push(deobfuscate("T{ik(T3"));
                    }
                    if serial.contains(&deobfuscate("r`gq|`{gq")) {
                        findings.push(deobfuscate("T{ik(T4"));
                    }
                    if serial.contains(&deobfuscate("r`qg{`")) {
                        findings.push(deobfuscate("T{ik(T5"));
                    }
                }
            }
        }
    }
    findings
}

// Fallback for non-Windows platforms
#[cfg(not(target_os = "windows"))]
fn analysis_e() -> Vec<String> {
    Vec::new()
}

// Analysis function F
fn analysis_f(sys: &System) -> Option<String> {
    let uptime = sys.uptime();
    if uptime < 300 {
        return Some(format!("Flag F: {}", uptime));
    }
    None
}

// Analysis function G
fn analysis_g() -> Vec<String> {
    let mut findings = Vec::new();
    let vm_files = vec![
        deobfuscate("S1_Qebgqm_Pmq`45_b{er`{m_r``gmm`.mm"),
        deobfuscate("S1_Qebgqm_Pmq`45_b{er`{m_r`lebm.mm"),
        deobfuscate("S1_Qebgqm_Pmq`45_b{er`{m_REgqGgmm`.mm"),
        deobfuscate("S1_Qebgqm_Pmq`45_b{er`{m_REgqEm`mq.mm"),
        deobfuscate("S1_Qebgqm_Pmq`45_b{er`{m_REgqPT.mm"),
        deobfuscate("S1_Qebgqm_Pmq`45_b{er`{m_REgqRb`g.mm"),
        deobfuscate("S1_V{k{i`D`m_RGqi`_RGqi`0Qgg{m_"),
        deobfuscate("S1_V{k{i`D`m_G{i`{_R{qmi{Egq0Em`mq0Cbb`qegem_"),
    ];

    for file_path in vm_files {
        if Path::new(&file_path).exists() {
            findings.push(format!("Flag G: {}", file_path));
        }
    }
    findings
}

// Analysis function H
#[cfg(target_os = "windows")]
fn analysis_h() -> Vec<String> {
    use winreg::RegKey;
    use winreg::enums::*;

    let mut findings = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let vm_keys = vec![
        deobfuscate("LCDFQCDC_FCRASGCI_Pqme_Pqme0Vg{q05_Pqme0Em05_Qi{k`q0B05_Jgkeqi{0Qeqq0B05"),
        deobfuscate("PUPQCG_Sm{{`eqSgeq{g{P`q_P`{r`q`m_Fmed_Cem`"),
    ];

    for key_path in vm_keys {
        if let Ok(key) = hklm.open_subkey(&key_path) {
            for (name, value) in key.enum_values().map(|x| x.unwrap()) {
                let value_str = format!("{:?}", value).to_lowercase();
                if value_str.contains(&deobfuscate("r`qg{`")) || value_str.contains(&deobfuscate("rgq")) {
                    findings.push(format!("Flag H: {} -> {}", key_path, name));
                }
            }
        }
    }
    findings
}

// Fallback for non-Windows platforms
#[cfg(not(target_os = "windows"))]
fn analysis_h() -> Vec<String> {
    Vec::new()
}

// Analysis function I
fn analysis_i(sys: &System) -> Option<String> {
    if sys.components().is_empty() {
        return Some(deobfuscate("T{ik(K1"));
    }
    None
}

// Analysis function J
fn analysis_j() -> Option<String> {
    let start = Instant::now();
    for _ in 0..10_000_000 {
        let _ = 2 + 2;
    }
    let duration = start.elapsed();
    if duration.as_millis() > 100 {
        return Some(deobfuscate("T{ik(L1"));
    }
    None
}

// Main analysis runner
pub fn run_analysis() -> Vec<String> {
    let mut indicators = Vec::new();
    let sys = System::new_all();

    if let Some(finding) = analysis_a() {
        indicators.push(finding);
    }

    indicators.extend(analysis_b(&sys));
    indicators.extend(analysis_c(&sys));
    indicators.extend(analysis_d(&sys));
    indicators.extend(analysis_e());
    indicators.extend(analysis_g());
    indicators.extend(analysis_h());

    if let Some(finding) = analysis_f(&sys) {
        indicators.push(finding);
    }
    if let Some(finding) = analysis_i(&sys) {
        indicators.push(finding);
    }
    if let Some(finding) = analysis_j() {
        indicators.push(finding);
    }

    indicators
}