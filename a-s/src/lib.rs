
use std::path::Path;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, HMODULE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{EnumProcessModulesEx, GetModuleBaseNameA, LIST_MODULES_ALL},
            SystemInformation::GetTickCount64,
            Threading::GetCurrentProcess,
            Registry::{RegCloseKey, RegOpenKeyExA, HKEY_LOCAL_MACHINE, KEY_READ},
        },
        UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
    },
};

/// Checks for user activity by querying the last input time.
pub fn check_user_activity() -> bool {
    let mut last_input_info: LASTINPUTINFO = unsafe { std::mem::zeroed() };
    last_input_info.cbSize = std::mem::size_of::<LASTINPUTINFO>() as u32;
    let result = unsafe { GetLastInputInfo(&mut last_input_info) };
    if result.as_bool() {
        let last_input_tick = last_input_info.dwTime as u64;
        let current_tick = unsafe { GetTickCount64() };
        // If the last input was more than 2 minutes ago, we assume no user activity.
        if current_tick - last_input_tick > 120000 {
            return true;
        }
    }
    false
}

/// Checks for common API hooking/sandboxing modules.
pub fn check_for_hooking() -> bool {
    let mut modules = [HMODULE::default(); 1024];
    let mut needed = 0;
    let process_handle = unsafe { GetCurrentProcess() };

    if unsafe { EnumProcessModulesEx(process_handle, modules.as_mut_ptr(), std::mem::size_of_val(&modules) as u32, &mut needed, LIST_MODULES_ALL) }.is_ok() {
        let module_count = needed as usize / std::mem::size_of::<HMODULE>();
        for i in 0..module_count {
            let mut module_name = [0u8; 256];
            if unsafe { GetModuleBaseNameA(process_handle, modules[i], &mut module_name) } > 0 {
                let name_len = module_name.iter().position(|&c| c == 0).unwrap_or(module_name.len());
                let name = String::from_utf8_lossy(&module_name[..name_len]).to_lowercase();

                let suspicious_modules = [
                    "sbiedll.dll", // Sandboxie
                    "api_log.dll", // API Logger
                    "dir_watch.dll", // Directory Watcher
                    "pstorec.dll", // PStoreC
                    "vmcheck.dll", // VM Check
                    "wpespy.dll", // WPE Spy
                ];

                for suspicious in suspicious_modules {
                    if name.contains(suspicious) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Checks for the presence of common analysis tools and sandbox-related processes.
pub fn check_processes() -> bool {
    let suspicious_processes = [
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "procmon.exe",
        "regmon.exe",
        "wireshark.exe",
        "x32dbg.exe",
        "x64dbg.exe",
    ];

    if let Ok(snapshot) = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        if snapshot.is_invalid() {
            return false;
        }

        let mut process_entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if unsafe { Process32First(snapshot, &mut process_entry) }.is_ok() {
            loop {
                let process_name = unsafe { std::ffi::CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const i8) }.to_string_lossy().to_lowercase();
                for suspicious in suspicious_processes {
                    if process_name.contains(suspicious) {
                        unsafe { let _ = CloseHandle(snapshot); };
                        return true;
                    }
                }
                if unsafe { Process32Next(snapshot, &mut process_entry) }.is_err() {
                    break;
                }
            }
        }

        unsafe { let _ = CloseHandle(snapshot); };
    }

    false
}

/// Checks for registry and file artifacts that indicate a sandbox environment.
pub fn check_artifacts() -> bool {
    let suspicious_registry_keys = [
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    ];

    for key in suspicious_registry_keys {
        let mut hkey = HKEY_LOCAL_MACHINE;
        if unsafe { RegOpenKeyExA(HKEY_LOCAL_MACHINE, PCSTR(key.as_ptr()), 0, KEY_READ, &mut hkey) }.is_ok() {
            unsafe { let _ = RegCloseKey(hkey); };
            return true;
        }
    }

    let suspicious_files = [
        "C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys",
        "C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys",
    ];

    for file in suspicious_files {
        if Path::new(file).exists() {
            return true;
        }
    }

    false
}

/// Checks the system uptime to detect freshly started sandboxes.
pub fn check_uptime() -> bool {
    let uptime_ms = unsafe { GetTickCount64() };
    // If uptime is less than 5 minutes, it might be a sandbox.
    if uptime_ms < 300000 {
        return true;
    }
    false
}
