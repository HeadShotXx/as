use clap::Parser;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the DLL to inject
    #[arg(short, long)]
    dll: String,
}

/// Try to find chrome.exe in common installation directories
fn find_chrome_exe() -> Option<String> {
    let common_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ];
    for path in common_paths {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

fn main() {
    let args = Args::parse();

    // Prepare the DLL path as a wide string
    let dll_path = std::path::Path::new(&args.dll)
        .canonicalize()
        .expect("Failed to get absolute path to DLL");
    let dll_path_u16: Vec<u16> = dll_path.as_os_str().encode_wide().chain(Some(0)).collect();

    // Build command line for chrome.exe
    // We'll use "chrome.exe" as the command line, letting Windows search PATH
    let chrome_exe = "chrome.exe";
    let mut cmd_line: Vec<u16> = OsStr::new(chrome_exe).encode_wide().chain(Some(0)).collect();

    unsafe {
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        // Create process with lpApplicationName = NULL so the system searches PATH
        let success = CreateProcessW(
            ptr::null(),                     // lpApplicationName (NULL)
            cmd_line.as_mut_ptr(),           // lpCommandLine (mutable, includes "chrome.exe")
            ptr::null_mut(),                 // lpProcessAttributes
            ptr::null_mut(),                 // lpThreadAttributes
            0,                               // bInheritHandles
            CREATE_SUSPENDED,                // dwCreationFlags
            ptr::null_mut(),                 // lpEnvironment
            ptr::null(),                     // lpCurrentDirectory
            &mut startup_info,               // lpStartupInfo
            &mut process_info,               // lpProcessInformation
        );

        if success == 0 {
            let error = GetLastError();
            if error == ERROR_FILE_NOT_FOUND {
                // Try to locate chrome.exe in common install paths
                if let Some(path) = find_chrome_exe() {
                    // Retry with full path
                    let full_path_wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
                    let mut cmd_full = full_path_wide.clone();
                    let success2 = CreateProcessW(
                        full_path_wide.as_ptr(),
                        cmd_full.as_mut_ptr(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        0,
                        CREATE_SUSPENDED,
                        ptr::null_mut(),
                        ptr::null(),
                        &mut startup_info,
                        &mut process_info,
                    );
                    if success2 == 0 {
                        eprintln!("Failed to create chrome.exe process even with full path: {}", GetLastError());
                        return;
                    }
                } else {
                    eprintln!("chrome.exe not found. Ensure Google Chrome is installed and its directory is in your PATH, or provide a custom path.");
                    return;
                }
            } else {
                eprintln!("Failed to create chrome.exe process: {}", error);
                return;
            }
        }

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        let target_pid = process_info.dwProcessId;

        println!("Created chrome.exe with PID: {}", target_pid);

        // ... (rest of the injection code remains the same) ...

        // Allocate memory for DLL path
        let remote_mem = VirtualAllocEx(
            process_handle,
            ptr::null(),
            dll_path_u16.len() * 2,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            eprintln!("Failed to allocate memory in target process: {}", GetLastError());
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
            return;
        }

        // Write DLL path
        if WriteProcessMemory(
            process_handle,
            remote_mem,
            dll_path_u16.as_ptr() as *const _,
            dll_path_u16.len() * 2,
            ptr::null_mut(),
        ) == 0 {
            eprintln!("Failed to write to target process memory: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
            return;
        }

        // Get LoadLibraryW address
        let kernel32_name: Vec<u16> = OsStr::new("kernel32.dll").encode_wide().chain(Some(0)).collect();
        let kernel32_handle = GetModuleHandleW(kernel32_name.as_ptr());
        if kernel32_handle == 0 {
            eprintln!("Failed to get kernel32 handle: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
            return;
        }

        let load_library_addr = GetProcAddress(kernel32_handle, b"LoadLibraryW\0".as_ptr());
        if load_library_addr.is_none() {
            eprintln!("Failed to get LoadLibraryW address: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
            return;
        }

        // Create remote thread
        let remote_thread = CreateRemoteThread(
            process_handle,
            ptr::null(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            remote_mem,
            0,
            ptr::null_mut(),
        );
        if remote_thread == 0 {
            eprintln!("Failed to create remote thread: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
            return;
        }

        // Wait for LoadLibraryW to complete
        WaitForSingleObject(remote_thread, INFINITE);

        // Check exit code
        let mut exit_code: u32 = 0;
        if GetExitCodeThread(remote_thread, &mut exit_code) != 0 {
            if exit_code == 0 {
                eprintln!("LoadLibraryW failed in target process.");
            } else {
                println!("Successfully injected DLL! Module handle: 0x{:X}", exit_code);
            }
        } else {
            eprintln!("Failed to get thread exit code: {}", GetLastError());
        }

        // Clean up
        CloseHandle(remote_thread);
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

        // Resume main thread
        if ResumeThread(thread_handle) == u32::MAX {
            eprintln!("Failed to resume main thread: {}", GetLastError());
        } else {
            println!("Resumed chrome.exe main thread.");
        }

        CloseHandle(process_handle);
        CloseHandle(thread_handle);
    }
}