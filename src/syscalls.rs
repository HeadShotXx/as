#![allow(dead_code)]
use std::ffi::CString;
use crate::windows::{GetModuleHandleA, GetProcAddress, NTSTATUS, HANDLE, PVOID, ULONG};
use std::arch::asm;

// Dynamically resolves the System Service Number (SSN) for a given function.
fn get_ssn(func_name: &str) -> u32 {
    let func_c_str = CString::new(func_name).unwrap();
    let ntdll_c_str = CString::new("ntdll.dll").unwrap();

    unsafe {
        let ntdll_handle = GetModuleHandleA(ntdll_c_str.as_ptr());
        let func_addr = GetProcAddress(ntdll_handle, func_c_str.as_ptr());

        if !func_addr.is_null() {
            // In x64 ntdll.dll functions, the SSN is at offset 4.
            let ssn_ptr = (func_addr as *const u8).add(4) as *const u32;
            return *ssn_ptr;
        }
    }
    0
}

#[inline]
pub unsafe fn NtClose(handle: HANDLE) -> NTSTATUS {
    let ssn = get_ssn("NtClose");
    let status: NTSTATUS;
    asm!(
        "mov eax, r10d",
        "syscall",
        in("r10") ssn,
        inout("rcx") handle => _,
        lateout("rax") status,
        out("r11") _,
    );
    status
}

#[inline]
pub unsafe fn NtQueryInformationProcess(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: PVOID,
    process_information_length: ULONG,
    return_length: *mut ULONG,
) -> NTSTATUS {
    let ssn = get_ssn("NtQueryInformationProcess");
    let status: NTSTATUS;
    asm!(
        "mov eax, r10d",
        "syscall",
        in("r10") ssn,
        inout("rcx") process_handle => _,
        in("rdx") process_information_class,
        in("r8") process_information,
        in("r9") process_information_length,
        in("r12") return_length,
        lateout("rax") status,
        out("r11") _,
    );
    status
}

#[inline]
pub unsafe fn NtReadVirtualMemory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    number_of_bytes_to_read: usize,
    number_of_bytes_read: *mut usize,
) -> NTSTATUS {
    let ssn = get_ssn("NtReadVirtualMemory");
    let status: NTSTATUS;
    asm!(
        "mov eax, r10d",
        "syscall",
        in("r10") ssn,
        inout("rcx") process_handle => _,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") number_of_bytes_to_read,
        in("r12") number_of_bytes_read,
        lateout("rax") status,
        out("r11") _,
    );
    status
}

#[inline]
pub unsafe fn NtWriteVirtualMemory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    number_of_bytes_to_write: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS {
    let ssn = get_ssn("NtWriteVirtualMemory");
    let status: NTSTATUS;
    asm!(
        "mov eax, r10d",
        "syscall",
        in("r10") ssn,
        inout("rcx") process_handle => _,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") number_of_bytes_to_write,
        in("r12") number_of_bytes_written,
        lateout("rax") status,
        out("r11") _,
    );
    status
}

#[inline]
pub unsafe fn NtResumeThread(
    thread_handle: HANDLE,
    suspend_count: *mut u32,
) -> NTSTATUS {
    let ssn = get_ssn("NtResumeThread");
    let status: NTSTATUS;
    asm!(
        "mov eax, r10d",
        "syscall",
        in("r10") ssn,
        inout("rcx") thread_handle => _,
        in("rdx") suspend_count,
        lateout("rax") status,
        out("r11") _,
    );
    status
}
