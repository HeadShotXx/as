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
    pub static ref SYSCALLS: Mutex<HashMap<&'static str, Syscall>> = {
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

unsafe impl Send for Syscall {}
unsafe impl Sync for Syscall {}

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

pub unsafe fn indirect_ntallocatevirtualmemory(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> NTSTATUS {
    let syscall_number = SYSCALLS.lock().unwrap().get("NtAllocateVirtualMemory").unwrap().number;
    let mut status: NTSTATUS;
    unsafe {
        asm!(
            "sub rsp, 40",
            "mov [rsp + 32], r12",
            "mov [rsp + 40], r13",
            "mov r10, rcx",
            "syscall",
            "add rsp, 40",
            in("rax") syscall_number,
            in("rcx") ProcessHandle,
            in("rdx") BaseAddress,
            in("r8") ZeroBits,
            in("r9") RegionSize,
            in("r12") AllocationType,
            in("r13") Protect,
            lateout("rax") status,
            clobber_abi("C")
        );
    }
    status
}

pub unsafe fn indirect_ntprotectvirtualmemory(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS {
    let syscall_number = SYSCALLS.lock().unwrap().get("NtProtectVirtualMemory").unwrap().number;
    let mut status: NTSTATUS;
    unsafe {
        asm!(
            "sub rsp, 40",
            "mov [rsp + 32], r12",
            "mov r10, rcx",
            "syscall",
            "add rsp, 40",
            in("rax") syscall_number,
            in("rcx") ProcessHandle,
            in("rdx") BaseAddress,
            in("r8") RegionSize,
            in("r9") NewProtect,
            in("r12") OldProtect,
            lateout("rax") status,
            clobber_abi("C")
        );
    }
    status
}

pub unsafe fn indirect_ldrloaddll(
    DllPath: *const u32,
    DllCharacteristics: *const u32,
    ModuleFileName: *const UNICODE_STRING,
    ModuleHandle: *mut HMODULE,
) -> NTSTATUS {
    let syscall_number = SYSCALLS.lock().unwrap().get("LdrLoadDll").unwrap().number;
    let mut status: NTSTATUS;
    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") syscall_number,
            in("rcx") DllPath,
            in("rdx") DllCharacteristics,
            in("r8") ModuleFileName,
            in("r9") ModuleHandle,
            lateout("rax") status,
            clobber_abi("C")
        );
    }
    status
}

pub unsafe fn indirect_ldrgetprocedureaddress(
    ModuleHandle: HMODULE,
    FunctionName: *const ANSI_STRING,
    FunctionOrdinal: u16,
    FunctionAddress: *mut FARPROC,
) -> NTSTATUS {
    let syscall_number = SYSCALLS.lock().unwrap().get("LdrGetProcedureAddress").unwrap().number;
    let mut status: NTSTATUS;
    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") syscall_number,
            in("rcx") ModuleHandle,
            in("rdx") FunctionName,
            in("r8") FunctionOrdinal,
            in("r9") FunctionAddress,
            lateout("rax") status,
            clobber_abi("C")
        );
    }
    status
}

pub unsafe fn indirect_ntflushinstructioncache(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut c_void,
    Length: usize,
) -> NTSTATUS {
    let syscall_number = SYSCALLS.lock().unwrap().get("NtFlushInstructionCache").unwrap().number;
    let mut status: NTSTATUS;
    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") syscall_number,
            in("rcx") ProcessHandle,
            in("rdx") BaseAddress,
            in("r8") Length,
            lateout("rax") status,
            clobber_abi("C")
        );
    }
    status
}
