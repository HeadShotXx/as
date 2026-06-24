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

    /// Target process name or PID
    #[arg(short, long)]
    target: String,
}

fn get_process_id_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_matches(char::from(0))
                    .to_string();
                if name.eq_ignore_ascii_case(process_name) {
                    CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

fn main() {
    let args = Args::parse();

    let target_pid = if let Ok(pid) = args.target.parse::<u32>() {
        pid
    } else {
        match get_process_id_by_name(&args.target) {
            Some(pid) => pid,
            None => {
                eprintln!("Could not find process: {}", args.target);
                return;
            }
        }
    };

    println!("Target PID: {}", target_pid);

    let dll_path = std::path::Path::new(&args.dll)
        .canonicalize()
        .expect("Failed to get absolute path to DLL");
    let dll_path_u16: Vec<u16> = dll_path.as_os_str().encode_wide().chain(Some(0)).collect();

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            0,
            target_pid,
        );

        if process_handle == 0 {
            eprintln!("Failed to open process: {}", GetLastError());
            return;
        }

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
            return;
        }

        if WriteProcessMemory(
            process_handle,
            remote_mem,
            dll_path_u16.as_ptr() as *const _,
            dll_path_u16.len() * 2,
            ptr::null_mut(),
        ) == 0
        {
            eprintln!("Failed to write to target process memory: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return;
        }

        let kernel32_name: Vec<u16> = OsStr::new("kernel32.dll").encode_wide().chain(Some(0)).collect();
        let kernel32_handle = GetModuleHandleW(kernel32_name.as_ptr());
        if kernel32_handle == 0 {
            eprintln!("Failed to get kernel32 handle: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return;
        }

        let load_library_addr = GetProcAddress(kernel32_handle, b"LoadLibraryW\0".as_ptr());
        if load_library_addr.is_none() {
            eprintln!("Failed to get LoadLibraryW address: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return;
        }

        let thread_handle = CreateRemoteThread(
            process_handle,
            ptr::null(),
            0,
            Some(std::mem::transmute(load_library_addr)),
            remote_mem,
            0,
            ptr::null_mut(),
        );

        if thread_handle == 0 {
            eprintln!("Failed to create remote thread: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return;
        }

        WaitForSingleObject(thread_handle, INFINITE);

        let mut exit_code: u32 = 0;
        if GetExitCodeThread(thread_handle, &mut exit_code) != 0 {
            if exit_code == 0 {
                eprintln!("LoadLibraryW failed in target process.");
            } else {
                println!("Successfully injected DLL! Module handle: 0x{:X}", exit_code);
            }
        } else {
            eprintln!("Failed to get thread exit code: {}", GetLastError());
        }

        CloseHandle(thread_handle);
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process_handle);
    }
}
