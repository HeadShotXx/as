use std::ffi::{CString};
use std::mem;
use std::process::Command;
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        System::{
            Diagnostics::Debug::*,
            ProcessStatus::*,
            SystemInformation::*,
            Threading::*,
            LibraryLoader::*,
        },
        UI::WindowsAndMessaging::*,
        Security::*,
    },
};
// Additional imports to fix compilation errors
use windows::Win32::System::Threading::PROCESS_NAME_FORMAT;
use windows::Win32::UI::WindowsAndMessaging::{SM_CXSCREEN, SM_CYSCREEN};


// ============================================================================
// TOP-LEVEL PUBLIC API
// ============================================================================

/// Run comprehensive checks with admin privilege escalation.
/// This will attempt to elevate the process if not already running as an administrator.
pub fn run_all_checks_with_admin() -> bool {
    // Only run on Windows
    if !runtime_detector::is_windows() {
        return false;
    }

    // Check if we're admin, try to elevate if not
    if !admin_check::is_admin() {
        if let Err(_) = admin_check::elevate_process() {
            // Continue without admin privileges if elevation fails
        }
    }

    // Enable all available tokens if we have admin privileges
    if admin_check::is_admin() {
        let _ = all_tokens::enable();
        
        // Note: Setting process as critical is commented out as it can cause BSOD
        // if the process is terminated. Use with extreme caution.
        // let _ = critical_process::set_process_critical();
    }

    // Run all standard checks
    run_all_checks()
}

/// Windows-specific comprehensive anti-analysis check.
/// Runs checks in logical categories.
pub fn run_windows_specific_checks() -> bool {
    if !runtime_detector::is_windows() {
        return false;
    }

    // Core debugging detection
    if run_debug_checks() {
        return true;
    }

    // VM/Sandbox detection
    if run_vm_checks() {
        return true;
    }

    // Environment analysis
    if run_environment_checks() {
        return true;
    }

    // Process detection
    if run_process_checks() {
        return true;
    }

    false
}


/// The main detection function that runs a comprehensive suite of checks.
/// Returns `true` if a debugger, VM, sandbox, or other analysis tool is detected.
pub fn run_all_checks() -> bool {
    // Core anti-debug checks
    if debugger_detection::is_debugger_present() { return true; }
    if debugger_detection::check_remote_debugger().unwrap_or(false) { return true; }
    if parent_anti_debug::parent_anti_debug() { return true; }
    if pc_uptime::check_uptime(600).unwrap_or(false) { return true; }
    if bad_processes::detect().unwrap_or(false) { return true; }
    if running_processes::check_running_processes_count(50).unwrap_or(false) { return true; }
    if blacklisted_windows::check_blacklisted_windows() { return true; }
    if hooks_detection::detect_hooks_on_common_winapi_functions(None, None) { return true; }

    // Sandbox/VM detection checks
    if shadow_defender_detection::detect_shadow_defender() { return true; }
    if anyrun_detection::anyrun_detection().unwrap_or(false) { return true; }
    if !clean_environment_detection::detect_clean_environment() { return true; }
    if comodo_antivirus_detection::detect_comodo_antivirus() { return true; }
    if deep_freeze_detection::detect_deep_freeze() { return true; }
    if hyperv_check::detect_hyperv().unwrap_or(false) { return true; }
    if kvm_check::check_for_kvm().unwrap_or(false) { return true; }
    if monitor_metrics::is_screen_small().unwrap_or(false) { return true; }
    if parallels_check::check_for_parallels().unwrap_or(false) { return true; }
    if qemu_check::check_for_qemu().unwrap_or(false) { return true; }
    if recent_file_activity::recent_file_activity_check().unwrap_or(false) { return true; }
    if repetitive_process::check().unwrap_or(false) { return true; }
    if sandboxie_detection::detect_sandboxie() { return true; }
    if triage_detection::triage_check().unwrap_or(false) { return true; }
    if usb_check::plugged_in().unwrap_or(true) == false { return true; } // No USB devices is suspicious
    if username_check::check_for_blacklisted_names() { return true; }
    if virtualbox_detection::graphics_card_check().unwrap_or(false) { return true; }
    if vm_artifacts::vm_artifacts_detect() { return true; }
    if vm_platform_check::detect_vm_platform().unwrap_or(false) { return true; }
    if vmware_detection::graphics_card_check().unwrap_or(false) { return true; }
    if internet_check::check_connection().unwrap_or(true) == false { return true; }

    false
}

/// Run only core debugging detection checks.
pub fn run_debug_checks() -> bool {
    debugger_detection::is_debugger_present() ||
    debugger_detection::check_remote_debugger().unwrap_or(false) ||
    parent_anti_debug::parent_anti_debug() ||
    hooks_detection::detect_hooks_on_common_winapi_functions(None, None)
}

/// Run only sandbox/VM detection checks.
pub fn run_vm_checks() -> bool {
    shadow_defender_detection::detect_shadow_defender() ||
    anyrun_detection::anyrun_detection().unwrap_or(false) ||
    comodo_antivirus_detection::detect_comodo_antivirus() ||
    deep_freeze_detection::detect_deep_freeze() ||
    hyperv_check::detect_hyperv().unwrap_or(false) ||
    kvm_check::check_for_kvm().unwrap_or(false) ||
    parallels_check::check_for_parallels().unwrap_or(false) ||
    qemu_check::check_for_qemu().unwrap_or(false) ||
    sandboxie_detection::detect_sandboxie() ||
    virtualbox_detection::graphics_card_check().unwrap_or(false) ||
    vm_artifacts::vm_artifacts_detect() ||
    vm_platform_check::detect_vm_platform().unwrap_or(false) ||
    vmware_detection::graphics_card_check().unwrap_or(false)
}

/// Run only environment analysis checks.
pub fn run_environment_checks() -> bool {
    !clean_environment_detection::detect_clean_environment() ||
    pc_uptime::check_uptime(600).unwrap_or(false) ||
    running_processes::check_running_processes_count(50).unwrap_or(false) ||
    monitor_metrics::is_screen_small().unwrap_or(false) ||
    recent_file_activity::recent_file_activity_check().unwrap_or(false) ||
    repetitive_process::check().unwrap_or(false) ||
    username_check::check_for_blacklisted_names() ||
    triage_detection::triage_check().unwrap_or(false)
}

/// Run only process/service detection checks.
pub fn run_process_checks() -> bool {
    bad_processes::detect().unwrap_or(false) ||
    blacklisted_windows::check_blacklisted_windows()
}

// ============================================================================
// CONFIGURATION AND CUSTOMIZATION
// ============================================================================

pub struct AntiAnalysisConfig {
    pub enable_debug_checks: bool,
    pub enable_vm_checks: bool,
    pub enable_environment_checks: bool,
    pub enable_process_checks: bool,
    pub min_uptime_seconds: u32,
    pub min_process_count: usize,
    pub min_installed_programs: usize,
    pub enable_internet_check: bool,
    pub enable_usb_check: bool,
    pub enable_admin_escalation: bool,
    pub enable_privilege_escalation: bool,
    pub enable_critical_process: bool,
}

impl Default for AntiAnalysisConfig {
    fn default() -> Self {
        Self {
            enable_debug_checks: true,
            enable_vm_checks: true,
            enable_environment_checks: true,
            enable_process_checks: true,
            min_uptime_seconds: 600,    // 10 minutes
            min_process_count: 50,
            min_installed_programs: 10,
            enable_internet_check: true,
            enable_usb_check: true,
            enable_admin_escalation: true, // Disabled by default for safety
            enable_privilege_escalation: true, // Disabled by default
            enable_critical_process: true, // Disabled by default (can cause BSOD)
        }
    }
}


// ============================================================================
// UTILITY FUNCTIONS FOR COMMON OPERATIONS
// ============================================================================

pub mod utils {
    use std::process::Command;

    /// Execute a command and return whether it succeeded
    pub fn execute_command(cmd: &str, args: &[&str]) -> bool {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Execute a command and return its output as a string
    pub fn get_command_output(cmd: &str, args: &[&str]) -> Result<String, String> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute command: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Check if a file or directory exists
    pub fn path_exists(path: &str) -> bool {
        std::fs::metadata(path).is_ok()
    }

    /// Check if a registry key exists using reg command
    pub fn registry_key_exists(hive: &str, key_path: &str) -> bool {
        execute_command("reg", &["query", &format!("{}\\{}", hive, key_path)])
    }

    /// Check if a registry value exists using reg command
    pub fn registry_value_exists(hive: &str, key_path: &str, value_name: &str) -> bool {
        execute_command("reg", &["query", &format!("{}\\{}", hive, key_path), "/v", value_name])
    }

    /// Check if a service exists and is running
    pub fn service_is_running(service_name: &str) -> bool {
        if let Ok(output) = get_command_output("sc", &["query", service_name]) {
            output.contains("RUNNING")
        } else {
            false
        }
    }

    /// Check if a service exists (regardless of state)
    pub fn service_exists(service_name: &str) -> bool {
        execute_command("sc", &["query", service_name])
    }

    /// Get environment variable safely
    pub fn get_env_var(var_name: &str) -> Option<String> {
        std::env::var(var_name).ok()
    }

    /// Check if a process is running by name
    pub fn process_is_running(process_name: &str) -> bool {
        if let Ok(output) = get_command_output("tasklist", &["/fi", &format!("imagename eq {}", process_name)]) {
            output.to_lowercase().contains(&process_name.to_lowercase())
        } else {
            false
        }
    }
}

// ============================================================================
// DETECTION MODULES
// ============================================================================

pub mod internet_check {
    use std::net::TcpStream;
    use std::time::Duration;

    pub fn check_connection() -> Result<bool, String> {
        match TcpStream::connect_timeout(
            &"8.8.8.8:53".parse().unwrap(),
            Duration::from_secs(5)
        ) {
            Ok(_) => Ok(true),
            Err(e) => Err(format!("Error checking internet connection: {}", e)),
        }
    }
}

pub mod debugger_detection {
    use super::*;

    pub fn is_debugger_present() -> bool {
        unsafe { IsDebuggerPresent().as_bool() }
    }

    pub fn check_remote_debugger() -> std::result::Result<bool, String> {
        unsafe {
            let mut is_remote_debug_present = FALSE;
            CheckRemoteDebuggerPresent(
                GetCurrentProcess(),
                &mut is_remote_debug_present
            ).map(|_| is_remote_debug_present.as_bool()).map_err(|e| e.to_string())
        }
    }
}

pub mod parent_anti_debug {
    use super::*;
    use std::path::Path;

    #[repr(C)]
    struct ProcessBasicInformation {
        _exit_status: *mut std::ffi::c_void,
        _peb_base_address: *mut std::ffi::c_void,
        _affinity_mask: usize,
        _base_priority: i32,
        _unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    pub fn parent_anti_debug() -> bool {
        unsafe {
            let current_process = GetCurrentProcess();
            let mut pbi: ProcessBasicInformation = mem::zeroed();
            let mut return_length = 0u32;

            let ntdll = match GetModuleHandleA(s!("ntdll.dll")) {
                Ok(handle) => handle,
                Err(_) => return false,
            };

            let nt_query_proc = match GetProcAddress(ntdll, s!("NtQueryInformationProcess")) {
                Some(proc_addr) => proc_addr,
                None => return false,
            };

            type NtQueryInformationProcessFn = unsafe extern "system" fn(
                HANDLE,
                u32,
                *mut std::ffi::c_void,
                u32,
                *mut u32,
            ) -> i32;

            let nt_query: NtQueryInformationProcessFn = mem::transmute(nt_query_proc);
            
            if nt_query(
                current_process,
                0, // ProcessBasicInformation
                &mut pbi as *mut _ as *mut std::ffi::c_void,
                mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            ) != 0 {
                return false;
            }

            let parent_pid = pbi.inherited_from_unique_process_id as u32;
            if parent_pid == 0 {
                return false;
            }

            let parent_handle = match OpenProcess(
                PROCESS_QUERY_INFORMATION,
                false,
                parent_pid,
            ) {
                Ok(handle) => handle,
                Err(_) => return false,
            };

            let mut buffer = [0u16; 260]; // MAX_PATH
            let mut size = buffer.len() as u32;
            
            let result = match QueryFullProcessImageNameW(parent_handle, PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr()), &mut size) {
                Ok(_) => {
                    let parent_name = String::from_utf16_lossy(&buffer[..size as usize]);
                    let parent_exe = Path::new(&parent_name)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase();
                    
                    parent_exe != "explorer.exe" && parent_exe != "cmd.exe"
                }
                Err(_) => false,
            };
            
            let _ = CloseHandle(parent_handle);
            result
        }
    }
}

pub mod pc_uptime {

    use super::*;
    pub fn get_uptime_in_seconds() -> std::result::Result<u32, String> {
        unsafe {
            let uptime_ms = GetTickCount();
            Ok(uptime_ms / 1000)
        }
    }

    pub fn check_uptime(duration_in_seconds: u32) -> std::result::Result<bool, String> {
        let uptime = get_uptime_in_seconds()?;
        Ok(uptime < duration_in_seconds)
    }
}

pub mod bad_processes {
    use super::*;

    const BANNED_PROCESSES: &[&str] = &[
        // Analysis & Debugging Tools
        "taskmgr.exe", "process.exe", "processhacker.exe", "procexp.exe", "procexp64.exe",
        "procmon.exe", "procmon64.exe", "processmonitor.exe", "systemexplorer.exe",
        "ksdumper.exe", "ksdumperclient.exe", "fiddler.exe", "httpdebuggerui.exe",
        "wireshark.exe", "httpanalyzerv7.exe", "decoder.exe", "regedit.exe", "dnspy.exe",
        "burpsuite.exe", "DbgX.Shell.exe", "ILSpy.exe", "ollydbg.exe", "x32dbg.exe",
        "x64dbg.exe", "x96dbg.exe", "gdb.exe", "idaq.exe", "idag.exe", "idaw.exe",
        "ida64.exe", "idag64.exe", "idaw64.exe", "idaq64.exe", "windbg.exe",
        "immunitydebugger.exe", "windasm.exe", "HTTP Toolkit.exe", "pestudio.exe",
        "pe-bear.exe", "detectiteasy.exe", "die.exe", "hex.exe", "hxd.exe",
        "010editor.exe", "binaryninja.exe", "radare2.exe", "r2.exe", "cutter.exe",
        "ghidra.exe", "cheatengine.exe", "cheatengine-x86_64.exe", "apimonitor.exe",
        "apimonitor-x64.exe", "apispypp.exe", "regshot.exe", "regshot-x64-ansi.exe",
        "regshot-x64-unicode.exe", "perfview.exe", "vmmap.exe", "rammap.exe",
        "pslist.exe", "pskill.exe", "psexec.exe", "autoruns.exe", "autoruns64.exe",
        "tcpview.exe", "strings.exe", "strings64.exe", "handle.exe", "handle64.exe",
        "listdlls.exe", "listdlls64.exe", "portmon.exe", "filemon.exe", "regmon.exe",
        "sysmon.exe", "sysmon64.exe",
        
        // VM/Sandbox Specific Processes
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vgauthservice.exe",
        "vmacthlp.exe", "vmsrvc.exe", "vmusrvc.exe", "prl_cc.exe", "prl_tools.exe",
        "xenservice.exe", "qemu-ga.exe", "joeboxcontrol.exe", "joeboxserver.exe",
        "df5serv.exe", // Deep Freeze
    ];

    pub fn detect() -> std::result::Result<bool, String> {
        unsafe {
            let mut processes = [0u32; 1024];
            let mut bytes_returned = 0u32;

            if !K32EnumProcesses(
                processes.as_mut_ptr(),
                (processes.len() * mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            ).as_bool() {
                return Err(format!("Failed to enumerate processes: {:?}", GetLastError()));
            }

            let process_count = bytes_returned as usize / mem::size_of::<u32>();
            
            for &pid in &processes[..process_count] {
                if let Ok(handle) = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    pid,
                ) {
                    let mut buffer = [0u16; 260];
                    let mut size = buffer.len() as u32;
                    if QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr()), &mut size).is_ok() {
                        let process_name = String::from_utf16_lossy(&buffer);
                        let exe_name = std::path::Path::new(process_name.trim_end_matches('\0'))
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();

                        if BANNED_PROCESSES.contains(&exe_name.as_str()) {
                            let _ = CloseHandle(handle);
                            return Ok(true);
                        }
                    }
                    let _ = CloseHandle(handle);
                }
            }
            Ok(false)
        }
    }
}

pub mod running_processes {
    use super::*;

    pub fn get_running_processes_count() -> std::result::Result<usize, String> {
        unsafe {
            let mut processes = [0u32; 1024];
            let mut bytes_returned = 0u32;

            if K32EnumProcesses(
                processes.as_mut_ptr(),
                (processes.len() * mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            ).as_bool() {
                Ok(bytes_returned as usize / mem::size_of::<u32>())
            } else {
                Err(format!("Failed to enumerate processes: {:?}", GetLastError()))
            }
        }
    }

    pub fn check_running_processes_count(threshold: usize) -> std::result::Result<bool, String> {
        let count = get_running_processes_count()?;
        Ok(count < threshold)
    }
}

pub mod blacklisted_windows {
    use super::*;
    
    const BANNED_UUIDS: &[&str] = &[ "7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009", "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "00000000-0000-0000-0000-000000000000", "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022", "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65", "B1112042-52E8-E25B-3655-6A4F54155DBF", "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C", "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670", "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A", "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27", "79AF5279-16CF-4094-9758-F88A616D81B4", ];
    const BANNED_COMPUTER_NAMES: &[&str] = &[ "WDAGUtilityAccount", "Abby", "Peter Wilson", "hmarc", "patex", "JOHN-PC", "RDhJ0CNFevzX", "kEecfMwgj", "Frank", "8Nl0ColNQ5bq", "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl", "BEE7370C-8C0C-4", "DESKTOP-NAKFFMT", "WIN-5E07COS9ALR", "B30F0242-1C6A-4", "DESKTOP-VRSQLAG", "Q9IATRKPRH", "XC64ZB", "DESKTOP-D019GDM", "DESKTOP-WI8CLET", "SERVER1", "LISA-PC", "DESKTOP-B0T93D6", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "COMPNAME_4491", "WILEYPC", "WORK", "KATHLROGE", "DESKTOP-TKGQ6GH", "6C4E733F-C2D9-4", "RALPHS-PC", "DESKTOP-WG3MYJS", "DESKTOP-7XC6GEZ", "DESKTOP-5OV9S0O", "QarZhrdBpj", "ORELEEPC", "ARCHIBALDPC", "DESKTOP-NNSJYNR", "JULIA-PC", "DESKTOP-BQISITB", "d1bnJkfVlH", ];
    const BLACKLISTED_WINDOW_TITLES: &[&str] = &[ "proxifier", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy", "titanHide", "ilspy", "x32dbg", "codecracker", "simpleassembly", "process hacker", "pc-ret", "http debugger", "Centos", "process monitor", "debug", "reverse", "de4dot", "fiddler", "die", "crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark", "debugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper", "petools", "scyllahide", "megadumper", "reversal", "ksdumper", "dbgclr", "HxD", "ollydbg", "http", "wpe pro", "dbg", "httpanalyzer", "httpdebug", "PhantOm", "kgdb", "x32_dbg", "proxy", "phantom", "mdbg", "system explorer", "protection_id", "charles", "pepper", "hxd", "procmon", "MegaDumper", "ghidra", "0harmony", "hacker", "SAE", "mdb", "cheat engine", ];

    unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        unsafe {
            let found_blacklisted = &mut *(lparam.0 as *mut bool);
            let mut buffer = [0u16; 256];
            let length = GetWindowTextW(hwnd, &mut buffer);
            
            if length > 0 {
                let window_title = String::from_utf16_lossy(&buffer[..length as usize]).to_lowercase();
                if BLACKLISTED_WINDOW_TITLES.iter().any(|&blacklisted| window_title.contains(blacklisted)) {
                    *found_blacklisted = true;
                    return FALSE; // Stop enumeration
                }
            }
        }
        TRUE // Continue enumeration
    }
    fn enum_windows_and_check() -> bool {
        let mut found_blacklisted = false;
        unsafe {
            let _ = EnumWindows(Some(enum_windows_proc), LPARAM(&mut found_blacklisted as *mut _ as isize));
        }
        found_blacklisted
    }

    fn check_banned_uuid() -> bool {
        if let Ok(output) = Command::new("wmic").args(&["csproduct", "get", "uuid"]).output() {
            let uuid = String::from_utf8_lossy(&output.stdout).trim().to_uppercase();
            BANNED_UUIDS.iter().any(|&banned| uuid.contains(banned))
        } else { false }
    }

    pub fn check_blacklisted_windows() -> bool {
        if let Ok(hostname) = std::env::var("COMPUTERNAME") {
            if BANNED_COMPUTER_NAMES.iter().any(|&name| hostname.eq_ignore_ascii_case(name)) { return true; }
        }
        if check_banned_uuid() { return true; }
        if enum_windows_and_check() { return true; }
        // Process check is now handled by bad_processes::detect() in run_all_checks
        false
    }
}

pub mod hooks_detection {
    use super::*;

    const KERNEL_FUNCTIONS: &[&str] = &[ "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "CloseHandle", "OutputDebugStringA", "GetTickCount", "SetHandleInformation" ];
    const NTDLL_FUNCTIONS: &[&str] = &[ "NtQueryInformationProcess", "NtSetInformationThread", "NtClose", "NtGetContextThread", "NtQuerySystemInformation", "NtCreateFile", "NtCreateProcess", "NtCreateSection", "NtCreateThread", "NtYieldExecution", "NtCreateUserProcess" ];
    const USER32_FUNCTIONS: &[&str] = &[ "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA", "GetForegroundWindow", "GetWindowTextLengthA", "GetWindowTextA", "BlockInput", "CreateWindowExW", "CreateWindowExA" ];
    const WIN32U_FUNCTIONS: &[&str] = &[ "NtUserBlockInput", "NtUserFindWindowEx", "NtUserQueryWindow", "NtUserGetForegroundWindow" ];

    fn check_function_hooks(module_name: &str, functions: &[&str]) -> bool {
        unsafe {
            if let Ok(module_handle) = GetModuleHandleA(PCSTR(CString::new(module_name).unwrap().as_ptr() as *const u8)) {
                for &function_name in functions {
                    if let Some(proc_addr) = GetProcAddress(module_handle, PCSTR(CString::new(function_name).unwrap().as_ptr() as *const u8)) {
                        let first_byte = *(proc_addr as *const u8);
                        if first_byte == 0x90 || first_byte == 0xE9 { return true; } // NOP or JMP
                    }
                }
            }
        }
        false
    }

    pub fn detect_hooks_on_common_winapi_functions(module_name: Option<&str>, functions: Option<&[&str]>) -> bool {
        if check_function_hooks("kernel32.dll", KERNEL_FUNCTIONS) ||
           check_function_hooks("kernelbase.dll", KERNEL_FUNCTIONS) ||
           check_function_hooks("ntdll.dll", NTDLL_FUNCTIONS) ||
           check_function_hooks("user32.dll", USER32_FUNCTIONS) ||
           check_function_hooks("win32u.dll", WIN32U_FUNCTIONS) {
            return true;
        }
        if let (Some(module), Some(funcs)) = (module_name, functions) {
            if check_function_hooks(module, funcs) { return true; }
        }
        false
    }
}

pub mod shadow_defender_detection {
    use super::utils::*;
    
    pub fn detect_shadow_defender() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") {
            if path_exists(&format!("{}\\Shadow Defender\\", pf)) { return true; }
        }
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") {
            if path_exists(&format!("{}\\Shadow Defender\\", pf_x86)) { return true; }
        }
        if registry_value_exists("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Shadow Defender") { return true; }
        if registry_key_exists("HKCR", "CLSID\\{78C3F4BC-C7BC-48E4-AD72-2DD16F6704A9}") { return true; }
        if registry_key_exists("HKCR", "TypeLib\\{3A5C2EFF-619A-481D-8D5D-A6968DB02AF1}\\1.0\\0\\win64") { return true; }
        if registry_key_exists("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{93A07A0D-454E-43d1-86A9-5DE9C5F4411A}") { return true; }
        if registry_key_exists("HKLM", "SOFTWARE\\Shadow Defender") { return true; }
        if registry_key_exists("HKLM", "SYSTEM\\ControlSet001\\Services\\{0CBD4F48-3751-475D-BE88-4F271385B672}") { return true; }
        if registry_key_exists("HKLM", "SYSTEM\\ControlSet001\\Services\\diskpt") { return true; }
        if service_exists("Shadow Defender Service") { return true; }
        false
    }
}


pub mod mitigation_policy_patch {
    use super::*;

    pub fn configure_process_mitigation_policy() -> std::result::Result<(), String> {
        const PROCESS_SIGNATURE_POLICY_MITIGATION: u32 = 8;
        #[repr(C)]
        struct ProcessMitigationBinarySignaturePolicy { microsoft_signed_only: u32 }

        unsafe {
            let kernel32 = GetModuleHandleA(s!("kernel32.dll")).map_err(|e| e.to_string())?;
            let set_process_mitigation_policy = GetProcAddress(kernel32, s!("SetProcessMitigationPolicy")).ok_or("SetProcessMitigationPolicy not found".to_string())?;
            type SetProcessMitigationPolicyFn = unsafe extern "system" fn(u32, *const std::ffi::c_void, u32) -> BOOL;
            let set_policy: SetProcessMitigationPolicyFn = mem::transmute(set_process_mitigation_policy);
            let policy = ProcessMitigationBinarySignaturePolicy { microsoft_signed_only: 1 };
            if set_policy(PROCESS_SIGNATURE_POLICY_MITIGATION, &policy as *const _ as *const std::ffi::c_void, mem::size_of_val(&policy) as u32).as_bool() {
                Ok(())
            } else {
                Err("Failed to set mitigation policy".to_string())
            }
        }
    }
}

pub mod anyrun_detection {
    use std::process::Command;
    pub fn anyrun_detection() -> Result<bool, String> {
        if let Ok(output) = Command::new("getmac").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.to_uppercase().contains("52-54-00") { return Ok(true); }
        }
        Ok(false)
    }
}

pub mod clean_environment_detection {
    fn count_installed_programs() -> usize {
        let mut count = 0;
        let uninstall_keys = [ "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ];
        for key_path in &uninstall_keys {
            if let Ok(output) = std::process::Command::new("reg").args(&["query", &format!("HKLM\\{}", key_path)]).output() {
                if output.status.success() {
                    count += String::from_utf8_lossy(&output.stdout).matches("HKEY_LOCAL_MACHINE").count();
                }
            }
        }
        count
    }
    pub fn detect_clean_environment() -> bool {
        count_installed_programs() >= 10
    }
}

pub mod comodo_antivirus_detection {
    use super::utils::*;
    pub fn detect_comodo_antivirus() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") { if path_exists(&format!("{}\\COMODO\\COMODO Internet Security\\", pf)) { return true; }}
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if path_exists(&format!("{}\\COMODO\\COMODO Internet Security\\", pf_x86)) { return true; }}
        if let Some(sys_root) = get_env_var("SystemRoot") { if path_exists(&format!("{}\\System32\\drivers\\cmdguard.sys", sys_root)) { return true; }}
        if registry_key_exists("HKLM", "SOFTWARE\\COMODO\\CIS") { return true; }
        if service_exists("cmdagent") { return true; }
        false
    }
}

pub mod cyber_capture {
    use std::fs;
    use super::utils::get_env_var;
    pub fn create_directory() -> bool {
        if let Some(program_files) = get_env_var("ProgramFiles") {
            let dir = format!("{}\\antvirusdefender2025", program_files);
            return fs::create_dir_all(&dir).is_ok();
        }
        false
    }
}

pub mod deep_freeze_detection {
    use super::utils::*;
    pub fn detect_deep_freeze() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") { if path_exists(&format!("{}\\Faronics\\Deep Freeze\\", pf)) { return true; }}
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if path_exists(&format!("{}\\Faronics\\Deep Freeze\\", pf_x86)) { return true; }}
        if let Some(sys_root) = get_env_var("SystemRoot") { if path_exists(&format!("{}\\Persi0.sys", sys_root)) { return true; }}
        if registry_key_exists("HKCR", "TypeLib\\{C5D763D9-2422-4B2D-A425-02D5BD016239}\\1.0\\HELPDIR") { return true; }
        if let Ok(output) = get_command_output("reg", &["query", "HKLM\\SOFTWARE\\Microsoft\\Wbem\\CIMOM", "/v", "Autorecover MOFs"]) {
            if output.to_lowercase().contains("faronics") { return true; }
        }
        if service_is_running("DFServ") { return true; }
        false
    }
}

pub mod hyperv_check {
    use super::utils::*;
    pub fn detect_hyperv() -> Result<bool, String> {
        if let Ok(output) = get_command_output("reg", &["query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization", "/v", "Enabled"]) {
            if output.contains("0x1") { return Ok(true); }
        }
        if service_is_running("vmms") || service_is_running("vmbus") { return Ok(true); }
        if process_is_running("vmms.exe") { return Ok(true); }
        Ok(false)
    }
}

pub mod kvm_check {
    use super::utils::*;
    pub fn check_for_kvm() -> Result<bool, String> {
        let bad_drivers = ["balloon.sys", "netkvm.sys", "vioinput", "viofs.sys", "vioser.sys"];
        if let Some(system_root) = get_env_var("SystemRoot") {
            let system32_path = format!("{}\\System32", system_root);
            for driver in &bad_drivers {
                if path_exists(&format!("{}\\{}", system32_path, driver)) { return Ok(true); }
            }
        }
        Ok(false)
    }
}

pub mod monitor_metrics {
    use super::*;
    pub fn is_screen_small() -> std::result::Result<bool, String> {
        unsafe {
            let width = GetSystemMetrics(SM_CXSCREEN);
            let height = GetSystemMetrics(SM_CYSCREEN);
            Ok(width < 800 || height < 600)
        }
    }
}

pub mod parallels_check {
    use std::fs;
    use super::utils::*;
    pub fn check_for_parallels() -> Result<bool, String> {
        let parallels_drivers = ["prl_sf", "prl_tg", "prl_eth"];
        if let Some(sys_root) = get_env_var("SystemRoot") {
            let sys32_folder = format!("{}\\System32", sys_root);
            if let Ok(entries) = fs::read_dir(&sys32_folder) {
                for entry in entries.flatten() {
                    let filename = entry.file_name().to_string_lossy().to_lowercase();
                    if parallels_drivers.iter().any(|d| filename.contains(d)) { return Ok(true); }
                }
            }
        }
        Ok(false)
    }
}

pub mod powershell_check {
    use std::process::Command;
    pub fn run_powershell_command(ps_command: &str) -> Result<String, String> {
        let output = Command::new("powershell.exe").args(&["-NoProfile", "-NonInteractive", "-Command", ps_command]).output().map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;
        if output.status.success() { Ok(String::from_utf8_lossy(&output.stdout).trim().to_string()) } 
        else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
    }
}

pub mod qemu_check {
    use std::fs;
    use super::utils::*;
    pub fn check_for_qemu() -> Result<bool, String> {
        let qemu_drivers = ["qemu-ga", "qemuwmi"];
        if let Some(sys_root) = get_env_var("SystemRoot") {
            let sys32 = format!("{}\\System32", sys_root);
            if let Ok(entries) = fs::read_dir(&sys32) {
                for entry in entries.flatten() {
                    let filename = entry.file_name().to_string_lossy().to_lowercase();
                    if qemu_drivers.iter().any(|d| filename.contains(d)) { return Ok(true); }
                }
            }
        }
        Ok(false)
    }
}

pub mod recent_file_activity {
    use std::fs;
    use super::utils::*;
    pub fn recent_file_activity_check() -> Result<bool, String> {
        let appdata = get_env_var("APPDATA").ok_or("APPDATA environment variable not found")?;
        let rec_dir = format!("{}\\Microsoft\\Windows\\Recent", appdata);
        match fs::read_dir(&rec_dir) {
            Ok(entries) => Ok(entries.count() < 20),
            Err(e) => Err(format!("Failed to read recent directory: {}", e)),
        }
    }
}

pub mod repetitive_process {
    use std::collections::HashMap;
    use std::process::Command;
    pub fn check() -> Result<bool, String> {
        let output = Command::new("tasklist").output().map_err(|e| format!("Failed to execute tasklist: {}", e))?;
        let mut process_counts: HashMap<String, usize> = HashMap::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some(process_name) = line.split_whitespace().next() {
                if process_name != "svchost.exe" {
                    *process_counts.entry(process_name.to_string()).or_insert(0) += 1;
                }
            }
        }
        Ok(process_counts.values().any(|&count| count > 60))
    }
}

pub mod admin_check {
    use std::ffi::OsStr;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{PCSTR, PCWSTR};
    use crate::BOOL;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// Returns true if the current process is running with administrative privileges.
    /// Uses IsUserAnAdmin exported from shell32.dll via GetProcAddress to avoid build-time
    /// signature issues with different windows crate versions.
    pub fn is_admin() -> bool {
        unsafe {
            // Get handle to shell32.dll
            if let Ok(shell32) = GetModuleHandleA(PCSTR(b"shell32.dll\0".as_ptr())) {
                if let Some(proc_addr) = GetProcAddress(shell32, PCSTR(b"IsUserAnAdmin\0".as_ptr())) {
                    // Signature: BOOL IsUserAnAdmin(void);
                    let is_admin_fn: unsafe extern "system" fn() -> BOOL = mem::transmute(proc_addr);
                    return is_admin_fn().as_bool();
                }
            }
            false
        }
    }

    /// Relaunch current executable elevated (UAC) using ShellExecuteW with verb "runas".
    /// Returns Ok(()) if ShellExecute indicates success (>32 per WinAPI convention).
    pub fn elevate_process() -> Result<(), String> {
        // Helper to transform to null-terminated wide string Vec<u16>
        fn to_wide_null(s: &OsStr) -> Vec<u16> {
            s.encode_wide().chain(std::iter::once(0)).collect()
        }

        let current_exe = std::env::current_exe().map_err(|e| format!("Failed to get current exe path: {}", e))?;
        let args: String = std::env::args().skip(1).collect::<Vec<_>>().join(" ");

        let verb = to_wide_null(OsStr::new("runas"));
        let exe_path = to_wide_null(current_exe.as_os_str());
        let args_wide = to_wide_null(OsStr::new(&args));

        // Call ShellExecuteW
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(exe_path.as_ptr()),
                // pass null if no args (args_wide will be a single null u16 if empty)
                if args_wide.len() > 1 { PCWSTR(args_wide.as_ptr()) } else { PCWSTR(std::ptr::null()) },
                PCWSTR(std::ptr::null()),
                SW_SHOWNORMAL,
            )
        };

        // ShellExecuteW returns an HINSTANCE-like value; values > 32 indicate success.
        if (result.0 as isize) > 32 {
            Ok(())
        } else {
            Err(format!("ShellExecuteW failed or elevation cancelled (raw return = {:?})", result.0))
        }
    }
}

pub mod runtime_detector {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OperatingSystem { Unknown, Windows, Linux, MacOS }

    pub fn detect_os() -> OperatingSystem {
        match std::env::consts::OS {
            "windows" => OperatingSystem::Windows,
            "linux" => OperatingSystem::Linux,
            "macos" => OperatingSystem::MacOS,
            _ => OperatingSystem::Unknown,
        }
    }

    pub fn is_windows() -> bool {
        matches!(detect_os(), OperatingSystem::Windows)
    }
}

// critical_process.rs (or paste into your file)
pub mod critical_process {
    use std::mem;
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    /// Set the current process as critical using RtlSetProcessIsCritical.
    /// Returns Ok(()) on NT success (STATUS_SUCCESS == 0), Err(...) otherwise.
    ///
    /// WARNING: making a process critical means terminating that process (or letting it crash)
    /// may cause a system crash (BSOD). Use only when you fully understand the consequences.
    pub fn set_process_critical() -> Result<(), String> {
        unsafe {
            // Get ntdll module handle
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()))
                .map_err(|e| format!("GetModuleHandleA(ntdll.dll) failed: {}", e))?;

            // Get address of RtlSetProcessIsCritical
            let proc_addr = GetProcAddress(ntdll, PCSTR(b"RtlSetProcessIsCritical\0".as_ptr()))
                .ok_or_else(|| "RtlSetProcessIsCritical not found in ntdll".to_string())?;

            // Signature (native):
            // NTSTATUS RtlSetProcessIsCritical(BOOLEAN NewValue, PBOOLEAN OldValue, BOOLEAN IsCritical);
            // BOOLEAN is 8-bit; NTSTATUS is i32.
            type RtlSetProcessIsCriticalFn = unsafe extern "system" fn(u8, *mut u8, u8) -> i32;

            let set_critical: RtlSetProcessIsCriticalFn = mem::transmute(proc_addr);

            // NewValue = TRUE (1), OldValue = NULL, IsCritical = FALSE (0)
            let status = set_critical(1u8, std::ptr::null_mut(), 0u8);

            // STATUS_SUCCESS == 0
            if status == 0 {
                Ok(())
            } else {
                Err(format!("RtlSetProcessIsCritical failed (NTSTATUS = 0x{:X})", status as u32))
            }
        }
    }
}

pub mod all_tokens {
    use super::*;
    
    const TOKENS: &[&str] = &[ "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemtimePrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege" ];

    pub fn enable() -> std::result::Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let mut h_token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token)?;

            for token_name in TOKENS {
                let privilege_name: Vec<u16> = token_name.encode_utf16().chain(std::iter::once(0)).collect();
                let mut luid = LUID::default();
                if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(privilege_name.as_ptr()), &mut luid).is_ok() {
                    let tp = TOKEN_PRIVILEGES {
                        PrivilegeCount: 1,
                        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
                    };
                    let _ = AdjustTokenPrivileges(h_token, false, Some(&tp), 0, None, None);
                }
            }
            CloseHandle(h_token)?;
        }
        Ok(())
    }
}

pub mod sandboxie_detection {
    use super::utils::*;
    pub fn detect_sandboxie() -> bool {
        if let Some(pf) = get_env_var("ProgramFiles") { if path_exists(&format!("{}\\Sandboxie\\", pf)) { return true; }}
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if path_exists(&format!("{}\\Sandboxie\\", pf_x86)) { return true; }}
        if service_exists("SbieSvc") { return true; }
        let keys = [ "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Classes\\*\\shell\\sandbox", "HKCU\\Software\\Classes\\Folder\\shell\\sandbox" ];
        for key in &keys { if execute_command("reg", &["query", key]) { return true; } }
        false
    }
}

pub mod triage_detection {
    use super::powershell_check;
    pub fn triage_check() -> Result<bool, String> {
        let output = powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_DiskDrive | Select-Object -ExpandProperty Model")?;
        let output_upper = output.to_uppercase();
        Ok(output_upper.contains("DADY HARDDISK") || output_upper.contains("QEMU HARDDISK"))
    }
}

pub mod usb_check {
    use super::utils::*;
    pub fn plugged_in() -> Result<bool, String> {
        if registry_key_exists("HKLM", "SYSTEM\\ControlSet001\\Services\\USBSTOR") { return Ok(true); }
        if let Ok(output) = get_command_output("reg", &["query", "HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR"]) {
            if output.matches("HKEY_LOCAL_MACHINE").count() > 0 { return Ok(true); }
        }
        Ok(false)
    }
}

pub mod username_check {
    use super::utils::*;
    pub fn check_for_blacklisted_names() -> bool {
        let blacklisted_names = [ "johnson", "miller", "malware", "maltest", "currentuser", "sandbox", "virus", "john doe", "test user", "sand box", "wdagutilityaccount", "bruno", "george", "harry johnson" ];
        if let Some(username) = get_env_var("USERNAME") {
            let username_lower = username.to_lowercase();
            return blacklisted_names.iter().any(|&name| username_lower == name);
        }
        false
    }
}

pub mod virtualbox_detection {
    use super::powershell_check;
    pub fn graphics_card_check() -> Result<bool, String> {
        let output = powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty Name")?;
        Ok(output.to_lowercase().contains("virtualbox"))
    }
}

pub mod vm_artifacts {
    use std::fs;
    use std::path::Path;
    use super::utils::*;

    pub fn vm_artifacts_detect() -> bool {
        const BAD_FILE_NAMES: &[&str] = &[ "VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vmmouse.sys", "vboxogl.dll" ];
        if let Some(sys_root) = get_env_var("SystemRoot") {
            let system32_folder = format!("{}\\System32", sys_root);
            if let Ok(entries) = fs::read_dir(&system32_folder) {
                for entry in entries.flatten() {
                    let filename = entry.file_name().to_string_lossy().to_lowercase();
                    if BAD_FILE_NAMES.iter().any(|&f| filename == f.to_lowercase()) { return true; }
                }
            }
        }
        if let Some(pf) = get_env_var("ProgramFiles") { if Path::new(&format!("{}\\VMware", pf)).exists() || Path::new(&format!("{}\\oracle\\virtualbox guest additions", pf)).exists() { return true; } }
        if let Some(pf_x86) = get_env_var("ProgramFiles(x86)") { if Path::new(&format!("{}\\VMware", pf_x86)).exists() || Path::new(&format!("{}\\oracle\\virtualbox guest additions", pf_x86)).exists() { return true; } }
        false
    }
}

pub mod vm_platform_check {
    use super::powershell_check;
    fn get_bios_serial() -> Result<String, String> { powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber") }
    fn get_system_product_name() -> Result<String, String> { powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model") }
    fn get_system_manufacturer() -> Result<String, String> { powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer") }

    pub fn detect_vm_platform() -> Result<bool, String> {
        let serial = get_bios_serial()?.to_lowercase();
        let model = get_system_product_name()?.to_lowercase();
        let manufacturer = get_system_manufacturer()?.to_lowercase();

        if serial == "0" { return Ok(true); }
        let vm_indicators = ["vmware", "virtual", "microsoft", "innotek", "virtualbox"];
        for indicator in &vm_indicators {
            if model.contains(indicator) || manufacturer.contains(indicator) || serial.contains(indicator) { return Ok(true); }
        }
        Ok(false)
    }
}

pub mod vmware_detection {
    use super::powershell_check;
    pub fn graphics_card_check() -> Result<bool, String> {
        let output = powershell_check::run_powershell_command("Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty Name")?;
        Ok(output.to_lowercase().contains("vmware"))
    }
}


// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_detection() {
        println!("Detected OS: {:?}", runtime_detector::detect_os());
        assert_eq!(runtime_detector::is_windows(), cfg!(windows));
    }

    #[test] 
    fn test_admin_check() {
        println!("Running as admin: {}", admin_check::is_admin());
    }

    #[test]
    fn test_debugger_detection() {
        println!("Debugger present: {}", debugger_detection::is_debugger_present());
    }

    #[test]
    fn test_remote_debugger() {
        if let Ok(result) = debugger_detection::check_remote_debugger() {
            println!("Remote debugger present: {}", result);
        }
    }

    #[test]
    fn test_parent_process() {
        println!("Suspicious parent process: {}", parent_anti_debug::parent_anti_debug());
    }

    #[test]
    fn test_uptime_check() {
        if let Ok(uptime) = pc_uptime::get_uptime_in_seconds() {
            println!("System uptime: {} seconds", uptime);
        }
    }

    #[test]
    fn test_process_count() {
        if let Ok(count) = running_processes::get_running_processes_count() {
            println!("Running processes: {}", count);
        }
    }

    #[test]
    fn test_bad_processes() {
        if let Ok(result) = bad_processes::detect() {
            println!("Bad processes detected: {}", result);
        }
    }

    #[test]
    fn test_vm_detection() {
        println!("VM environment detected: {}", run_vm_checks());
    }

    #[test]
    fn test_environment_checks() {
        println!("Suspicious environment detected: {}", run_environment_checks());
    }

    #[test]
    fn test_internet_connection() {
        if let Ok(connected) = internet_check::check_connection() {
            println!("Internet connection available: {}", connected);
        }
    }

    #[test]
    fn test_screen_size() {
        if let Ok(small_screen) = monitor_metrics::is_screen_small() {
            println!("Small screen detected: {}", small_screen);
        }
    }

    #[test]
    fn test_username_check() {
        println!("Blacklisted username: {}", username_check::check_for_blacklisted_names());
    }

    #[test]
    fn test_usb_devices() {
        if let Ok(usb_detected) = usb_check::plugged_in() {
            println!("USB devices detected: {}", usb_detected);
        }
    }

    #[test]
    fn test_installed_programs() {
        println!("Clean environment (10+ programs): {}", clean_environment_detection::detect_clean_environment());
    }

    #[test]
    fn test_privilege_escalation() {
        if admin_check::is_admin() {
            match all_tokens::enable() {
                Ok(_) => println!("Successfully enabled all available privileges"),
                Err(e) => println!("Failed to enable privileges: {}", e),
            }
        } else {
            println!("Not running as admin, cannot test privilege escalation");
        }
    }

    #[test]
    fn test_all_checks() {
        let detected = run_all_checks();
        println!("Anti-analysis measures detected: {}", detected);
        println!("Debug checks: {}", run_debug_checks());
        println!("VM checks: {}", run_vm_checks());
        println!("Environment checks: {}", run_environment_checks());
        println!("Process checks: {}", run_process_checks());
    }

    #[test]
    fn test_windows_specific() {
        if runtime_detector::is_windows() {
            let detected = run_windows_specific_checks();
            println!("Windows-specific checks detected threats: {}", detected);
        } else {
            println!("Not running on Windows, skipping Windows-specific tests");
        }
    }
}
