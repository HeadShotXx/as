#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFlushInstructionCache};
use ntapi::ntldr::{LdrLoadDll, LdrGetProcedureAddress};
use winapi::shared::ntdef::{NTSTATUS, UNICODE_STRING, ANSI_STRING};
use winapi::um::winnt::PVOID;

use std::arch::asm;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;

use lazy_static::lazy_static;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

lazy_static! {
    static ref SYSCALLS: Mutex<HashMap<&'static str, Syscall>> = {
        let mut map = HashMap::new();
        map.insert("NtAllocateVirtualMemory", get_syscall("NtAllocateVirtualMemory").unwrap());
        map.insert("NtProtectVirtualMemory", get_syscall("NtProtectVirtualMemory").unwrap());
        map.insert("LdrLoadDll", get_syscall("LdrLoadDll").unwrap());
        map.insert("LdrGetProcedureAddress", get_syscall("LdrGetProcedureAddress").unwrap());
        map.insert("NtFlushInstructionCache", get_syscall("NtFlushInstructionCache").unwrap());
        Mutex::new(map)
    };
}

pub struct Syscall {
    pub address: *mut c_void,
    pub number: u32,
}

impl Syscall {
    pub fn new(address: *mut c_void, number: u32) -> Self {
        Self { address, number }
    }
}

pub fn get_syscall(func_name: &str) -> Option<Syscall> {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _);
        if ntdll.is_null() {
            return None;
        }

        let func_addr = GetProcAddress(ntdll, func_name.as_ptr() as _);
        if func_addr.is_null() {
            return None;
        }

        let syscall_number = *(func_addr as *const u8).add(4) as u32;

        Some(Syscall::new(func_addr as _, syscall_number))
    }
}

#[naked]
pub unsafe extern "system" fn indirect_syscall_ntallocatevirtualmemory(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> NTSTATUS {
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_number}",
        "syscall",
        "ret",
        syscall_number = const SYSCALLS.lock().unwrap().get("NtAllocateVirtualMemory").unwrap().number,
        options(noreturn)
    );
}

#[naked]
pub unsafe extern "system" fn indirect_syscall_ntprotectvirtualmemory(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS {
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_number}",
        "syscall",
        "ret",
        syscall_number = const SYSCALLS.lock().unwrap().get("NtProtectVirtualMemory").unwrap().number,
        options(noreturn)
    );
}

#[naked]
pub unsafe extern "system" fn indirect_syscall_ldrloaddll(
    DllPath: *const UNICODE_STRING,
    DllCharacteristics: *const u32,
    ModuleHandle: *mut HMODULE,
) -> NTSTATUS {
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_number}",
        "syscall",
        "ret",
        syscall_number = const SYSCALLS.lock().unwrap().get("LdrLoadDll").unwrap().number,
        options(noreturn)
    );
}

#[naked]
pub unsafe extern "system" fn indirect_syscall_ldrgetprocedureaddress(
    ModuleHandle: HMODULE,
    FunctionName: *const ANSI_STRING,
    FunctionOrdinal: u16,
    FunctionAddress: *mut FARPROC,
) -> NTSTATUS {
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_number}",
        "syscall",
        "ret",
        syscall_number = const SYSCALLS.lock().unwrap().get("LdrGetProcedureAddress").unwrap().number,
        options(noreturn)
    );
}

#[naked]
pub unsafe extern "system" fn indirect_syscall_ntflushinstructioncache(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut c_void,
    Length: usize,
) -> NTSTATUS {
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_number}",
        "syscall",
        "ret",
        syscall_number = const SYSCALLS.lock().unwrap().get("NtFlushInstructionCache").unwrap().number,
        options(noreturn)
    );
}
