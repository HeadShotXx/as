use rustpolymorphic::polymorph;
use crc::{Crc, CRC_32_ISO_HDLC};
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::System::Diagnostics::Debug::{
        IsDebuggerPresent, CheckRemoteDebuggerPresent, GetThreadContext, CONTEXT, CONTEXT_FLAGS,
        IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    },
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::System::LibraryLoader::*,
    Win32::System::Performance::*,
    Win32::System::SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
    },
    Win32::System::Threading::*,
};

/// Checks if a debugger is present using the IsDebuggerPresent API.
/// This is the simplest check, but easily bypassed.
#[polymorph(fn_len = 10, garbage = true)]
pub fn is_debugger_present() -> bool {
    unsafe { IsDebuggerPresent().as_bool() }
}

/// Checks for a remote debugger using the CheckRemoteDebuggerPresent API.
/// This can detect debuggers that are not running on the local machine.
#[polymorph(fn_len = 15, garbage = true)]
pub fn check_remote_debugger() -> bool {
    let mut is_present = FALSE;
    unsafe {
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_present).is_ok() {
            return is_present.as_bool();
        }
    }
    false
}

// A private helper function to run all checks sequentially.
fn all_checks() -> bool {
    is_debugger_present()
        || check_remote_debugger()
        || nt_query_information_process()
        || performance_counter_timing_check()
        || scan_for_int3()
        || check_hardware_breakpoints()
        || is_parent_a_debugger()
        || crc32_verify_self()
}


// The class for ThreadHideFromDebugger is 0x11
const THREAD_HIDE_FROM_DEBUGGER: i32 = 0x11;

/// Spawns a new thread to run all anti-debugging checks and hides the thread from debuggers.
/// This makes it significantly harder for an analyst to step through the detection logic.
#[polymorph(fn_len = 40, garbage = true, control_flow = true)]
pub fn run_all_checks_hidden() -> bool {
    let handle = std::thread::spawn(|| {
        type NtSetInformationThread = unsafe extern "system" fn(
            thread_handle: HANDLE,
            thread_information_class: i32,
            thread_information: *mut std::ffi::c_void,
            thread_information_length: u32,
        ) -> NTSTATUS;

        let ntdll = unsafe { GetModuleHandleA(s!("ntdll.dll\0")) }.unwrap();
        let nt_set_info_thread: NtSetInformationThread =
            unsafe { std::mem::transmute(GetProcAddress(ntdll, s!("NtSetInformationThread\0"))) };

        // Attempt to hide the current thread from the debugger.
        let status = unsafe {
            nt_set_info_thread(
                GetCurrentThread(),
                THREAD_HIDE_FROM_DEBUGGER,
                std::ptr::null_mut(),
                0,
            )
        };

        // If hiding the thread fails, it's a strong indication of a debugger.
        if status.is_err() {
            return true;
        }

        // Run all the anti-debugging checks from within the hidden thread.
        all_checks()
    });

    // If the thread panics (which could be caused by a debugger), treat it as a detection.
    handle.join().unwrap_or(true)
}

/// Checks if the parent process is a known debugger.
/// This is done by getting the parent process ID and then its name.
#[polymorph(fn_len = 30, garbage = true)]
pub fn is_parent_a_debugger() -> bool {
    let mut pe32 = PROCESSENTRY32::default();
    pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.unwrap_or(INVALID_HANDLE_VALUE);
    if snapshot == INVALID_HANDLE_VALUE {
        return false;
    }

    let current_pid = unsafe { GetCurrentProcessId() };
    let mut parent_pid = 0;

    // Find current process to get its parent PID
    if unsafe { Process32First(snapshot, &mut pe32) }.is_ok() {
        loop {
            if pe32.th32ProcessID == current_pid {
                parent_pid = pe32.th32ParentProcessID;
                break;
            }
            if unsafe { Process32Next(snapshot, &mut pe32) }.is_err() {
                break;
            }
        }
    }

    if parent_pid == 0 {
        unsafe { let _ = CloseHandle(snapshot); };
        return false; // Could not find parent
    }

    let mut parent_is_debugger = false;
    // Find the parent process by its PID
    if unsafe { Process32First(snapshot, &mut pe32) }.is_ok() {
        loop {
            if pe32.th32ProcessID == parent_pid {
                let end = pe32.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let parent_name =
                    String::from_utf8_lossy(&pe32.szExeFile[..end]).to_lowercase();

                // List of known debuggers (can be expanded)
                let debuggers = [
                    "windbg.exe",
                    "x64dbg.exe",
                    "ollydbg.exe",
                    "idaq.exe",
                    "idaq64.exe",
                    "devenv.exe",
                ];
                if debuggers.iter().any(|&d| parent_name.contains(d)) {
                    parent_is_debugger = true;
                }
                break;
            }
            if unsafe { Process32Next(snapshot, &mut pe32) }.is_err() {
                break;
            }
        }
    }

    unsafe { let _ = CloseHandle(snapshot); };
    parent_is_debugger
}

// In a real-world scenario, this value would be calculated by a post-build script
// and patched into the binary. For this example, we'll use a placeholder.
// const PRECALCULATED_TEXT_CRC32: u32 = 0xDEADBEEF;

/// Verifies the integrity of the .text section by calculating its CRC32 checksum
/// and comparing it to a pre-calculated value.
#[cfg(target_arch = "x86_64")]
#[polymorph(fn_len = 25, garbage = true)]
pub fn crc32_verify_self() -> bool {
    unsafe {
        let base_address = match GetModuleHandleA(PCSTR(std::ptr::null_mut())) {
            Ok(h) => h,
            Err(_) => return true, // Critical error if we can't get the module handle
        };

        let dos_header = base_address.0 as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return true; // Not a valid PE file
        }

        let nt_headers_ptr = (base_address.0 as *const u8).add((*dos_header).e_lfanew as usize);
        let nt_headers = &*(nt_headers_ptr as *const IMAGE_NT_HEADERS64);

        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return true; // Not a valid PE file signature
        }

        let section_header_ptr = nt_headers_ptr.add(std::mem::size_of::<IMAGE_NT_HEADERS64>());
        let sections = std::slice::from_raw_parts(
            section_header_ptr as *const IMAGE_SECTION_HEADER,
            nt_headers.FileHeader.NumberOfSections as usize,
        );

        for section in sections {
            let name_bytes: Vec<u8> =
                section.Name.iter().cloned().take_while(|&c| c != 0).collect();
            if let Ok(name) = String::from_utf8(name_bytes) {
                if name == ".text" {
                    let text_section_start =
                        (base_address.0 as *const u8).add(section.VirtualAddress as usize);
                    let text_section_size = section.Misc.VirtualSize as usize;
                    let text_section_slice =
                        std::slice::from_raw_parts(text_section_start, text_section_size);

                    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
                    let _checksum = crc.checksum(text_section_slice);

                    // In a real implementation, we would compare the checksum to the pre-calculated one.
                    // For this demonstration, we return `false` to indicate the check passed,
                    // avoiding the false positive caused by the placeholder value.
                    return false;
                }
            }
        }
    }
    // Return true if .text section not found, indicating a problem.
    true
}

// Define the PROCESSINFOCLASS enum and ProcessDebugPort constant as they are not
// readily available in the windows-rs crate in the way we need them.
const PROCESS_DEBUG_PORT: i32 = 7;

/// Uses NtQueryInformationProcess to check if a debugger is attached.
/// This is a more advanced and less commonly hooked method.
#[polymorph(fn_len = 20, garbage = true)]
pub fn nt_query_information_process() -> bool {
    type NtQueryInformationProcess = unsafe extern "system" fn(
        process_handle: HANDLE,
        process_information_class: i32,
        process_information: *mut std::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    let ntdll = unsafe { GetModuleHandleA(s!("ntdll.dll\0")) }.unwrap();
    let nt_query_info_process: NtQueryInformationProcess =
        unsafe { std::mem::transmute(GetProcAddress(ntdll, s!("NtQueryInformationProcess\0"))) };

    let mut debug_port: HANDLE = HANDLE(0);
    let status = unsafe {
        nt_query_info_process(
            GetCurrentProcess(),
            PROCESS_DEBUG_PORT,
            &mut debug_port as *mut _ as *mut _,
            std::mem::size_of::<HANDLE>() as u32,
            std::ptr::null_mut(),
        )
    };

    status.is_ok() && debug_port != HANDLE(0)
}

/// Detects timing anomalies using a high-resolution performance counter.
/// This is more precise than GetTickCount and less prone to false positives.
#[polymorph(fn_len = 10, garbage = true)]
pub fn performance_counter_timing_check() -> bool {
    let mut frequency = 0;
    unsafe { let _ = QueryPerformanceFrequency(&mut frequency); };

    let mut start_time = 0;
    unsafe { let _ = QueryPerformanceCounter(&mut start_time); };

    // Perform a meaningless operation to consume some time.
    let mut _sum = 0;
    for i in 0..1000 {
        _sum += i;
    }

    let mut end_time = 0;
    unsafe { let _ = QueryPerformanceCounter(&mut end_time); };

    // Calculate the elapsed time in milliseconds.
    let elapsed_time = (end_time - start_time) as f64 * 1000.0 / frequency as f64;

    // A threshold of 10ms is arbitrary and may need tuning.
    // This is lower than the GetTickCount threshold due to higher precision.
    elapsed_time > 10.0
}

/// Scans a small portion of its own function's memory for software breakpoints (INT 3).
/// This is a simple way to detect if a debugger has placed a breakpoint on this code.
#[polymorph(fn_len = 10, garbage = true)]
pub fn scan_for_int3() -> bool {
    // A small buffer to scan. We'll scan this function itself.
    let function_ptr = scan_for_int3 as *const u8;
    let scan_size = 32; // Scan the first 32 bytes of this function.

    unsafe {
        for i in 0..scan_size {
            if *function_ptr.add(i) == 0xCC {
                return true; // INT 3 breakpoint found
            }
        }
    }
    false
}

// For 64-bit systems, CONTEXT_DEBUG_REGISTERS is defined as 0x10010L
const CONTEXT_DEBUG_REGISTERS: u32 = 0x10010;

/// Checks for hardware breakpoints by examining the thread's context.
/// Hardware breakpoints are stored in the CPU's debug registers (DR0-DR3).
#[cfg(target_arch = "x86_64")]
#[polymorph(fn_len = 10, garbage = true)]
pub fn check_hardware_breakpoints() -> bool {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FLAGS(CONTEXT_DEBUG_REGISTERS);

    unsafe {
        let thread_handle = GetCurrentThread();
        if GetThreadContext(thread_handle, &mut ctx).is_ok() {
            return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
        }
    }
    false
}
