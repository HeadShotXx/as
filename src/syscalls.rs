//! Indirect syscalls for the PE loader.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::collections::HashMap;
use lazy_static::lazy_static;
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID, ULONG};
use winapi::shared::basetsd::SIZE_T;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use std::sync::Mutex;
use std::arch::asm;

lazy_static! {
    static ref SYSCALLS: Mutex<HashMap<&'static str, u16>> = {
        let mut m = HashMap::new();
        m.insert("NtAllocateVirtualMemory", 0);
        m.insert("NtProtectVirtualMemory", 0);
        m.insert("NtFlushInstructionCache", 0);
        Mutex::new(m)
    };
}

/// Initializes the syscall numbers.
pub fn init_syscalls() {
    let mut syscalls = SYSCALLS.lock().unwrap();
    syscalls.insert("NtAllocateVirtualMemory", get_syscall_number("NtAllocateVirtualMemory"));
    syscalls.insert("NtProtectVirtualMemory", get_syscall_number("NtProtectVirtualMemory"));
    syscalls.insert("NtFlushInstructionCache", get_syscall_number("NtFlushInstructionCache"));
}

/// Retrieves the syscall number for a given function.
fn get_syscall_number(func_name: &str) -> u16 {
    unsafe {
        let module = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const i8);
        let func_addr = GetProcAddress(module, func_name.as_ptr() as *const i8);
        if func_addr.is_null() {
            return 0;
        }
        let func_bytes = std::slice::from_raw_parts(func_addr as *const u8, 8);
        if func_bytes[0] == 0x4c
            && func_bytes[1] == 0x8b
            && func_bytes[2] == 0xd1
            && func_bytes[3] == 0xb8
            && func_bytes[6] == 0x00
            && func_bytes[7] == 0x00
        {
            return (func_bytes[5] as u16) << 8 | func_bytes[4] as u16;
        }
        0
    }
}

/// Wrapper for NtAllocateVirtualMemory.
pub unsafe fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: &mut PVOID,
    zero_bits: ULONG,
    region_size: &mut SIZE_T,
    allocation_type: ULONG,
    protect: ULONG,
) -> NTSTATUS {
    let syscall_id = *SYSCALLS.lock().unwrap().get("NtAllocateVirtualMemory").unwrap();
    let status: NTSTATUS;

    unsafe {
        asm!(
            "sub rsp, 40",
            "mov [rsp + 32], r9",
            "mov [rsp + 40], r10",
            "mov r10, rcx",
            "mov eax, {0:e}",
            "syscall",
            "add rsp, 40",
            "ret",
            in(reg) syscall_id as u32,
            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") zero_bits,
            in("r9") region_size,
            in("r10") allocation_type,
            in("r11") protect,
            lateout("rax") status,
        );
    }

    status
}

/// Wrapper for NtProtectVirtualMemory.
pub unsafe fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: &mut PVOID,
    region_size: &mut SIZE_T,
    new_protect: ULONG,
    old_protect: &mut ULONG,
) -> NTSTATUS {
    let syscall_id = *SYSCALLS.lock().unwrap().get("NtProtectVirtualMemory").unwrap();
    let status: NTSTATUS;

    unsafe {
        asm!(
            "sub rsp, 40",
            "mov [rsp + 32], r9",
            "mov [rsp + 40], r10",
            "mov r10, rcx",
            "mov eax, {0:e}",
            "syscall",
            "add rsp, 40",
            "ret",
            in(reg) syscall_id as u32,
            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") region_size,
            in("r9") new_protect,
            in("r10") old_protect,
            lateout("rax") status,
        );
    }

    status
}

/// Wrapper for NtFlushInstructionCache.
pub unsafe fn nt_flush_instruction_cache(
    process_handle: HANDLE,
    base_address: PVOID,
    length: SIZE_T,
) -> NTSTATUS {
    let syscall_id = *SYSCALLS.lock().unwrap().get("NtFlushInstructionCache").unwrap();
    let status: NTSTATUS;

    unsafe {
        asm!(
            "mov r10, rcx",
            "mov eax, {0:e}",
            "syscall",
            "ret",
            in(reg) syscall_id as u32,
            in("rcx") process_handle,
            in("rdx") base_address,
            in("r8") length,
            lateout("rax") status,
        );
    }

    status
}
