#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_assignments)]

use std::collections::HashMap;
use std::ffi::c_void;
use lazy_static::lazy_static;
use ntapi::ntpebteb::{PTEB, PPEB};
use std::ptr::{null, null_mut};
use winapi::shared::minwindef::HMODULE;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS,
};
use std::arch::asm;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

lazy_static! {
    pub static ref SYSCALLS: Syscalls = Syscalls::new().unwrap();
}

#[derive(Debug)]
pub struct Syscalls {
    syscalls: HashMap<String, usize>,
}

impl Syscalls {
    pub fn new() -> Result<Self> {
        let mut syscalls = HashMap::new();
        let ntdll_base = unsafe { get_ntdll_base() };
        if ntdll_base.is_null() {
            return Err("Failed to get ntdll base address".into());
        }

        let function_names = vec![
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtFreeVirtualMemory",
            "NtWriteVirtualMemory",
            "NtCreateThreadEx",
            "NtWaitForSingleObject",
            "NtClose",
        ];

        for name in function_names {
            let syscall_number = unsafe { get_syscall_number(ntdll_base, name)? };
            syscalls.insert(name.to_string(), syscall_number);
        }

        Ok(Syscalls { syscalls })
    }

    pub fn get_syscall_number(&self, function_name: &str) -> Option<&usize> {
        self.syscalls.get(function_name)
    }
}

unsafe fn get_ntdll_base() -> HMODULE {
    let peb: PPEB = {
        let mut teb: PTEB;
        asm!("mov {}, gs:[0x30]", out(reg) teb);
        (*teb).ProcessEnvironmentBlock
    };
    let ldr = (*peb).Ldr;
    let in_load_order_module_list = &(*ldr).InLoadOrderModuleList;
    let mut current_entry = in_load_order_module_list.Flink;
    let ntdll_base = loop {
        let ldr_data_table_entry = current_entry as *const ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
        let base_dll_name = (*ldr_data_table_entry).BaseDllName;
        let dll_name_slice = std::slice::from_raw_parts(base_dll_name.Buffer, (base_dll_name.Length / 2) as usize);
        let dll_name = String::from_utf16(dll_name_slice).unwrap_or_default();
        if dll_name.eq_ignore_ascii_case("ntdll.dll") {
            break (*ldr_data_table_entry).DllBase;
        }
        current_entry = (*current_entry).Flink;
        if current_entry as *const _ == in_load_order_module_list as *const _ {
            return null_mut();
        }
    };
    ntdll_base as HMODULE
}

unsafe fn get_syscall_number(module_base: HMODULE, function_name: &str) -> Result<usize> {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let optional_header = &(*nt_headers).OptionalHeader;
    let export_directory = (module_base as usize
        + optional_header
            .DataDirectory[winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize)
        as *const IMAGE_EXPORT_DIRECTORY;

    let names = std::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as usize,
    );
    let functions = std::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as usize,
    );
    let name_ordinals = std::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as usize,
    );

    for i in 0..(*export_directory).NumberOfNames as usize {
        let current_name_rva = names[i];
        let current_name_ptr = (module_base as usize + current_name_rva as usize) as *const i8;
        let current_name = std::ffi::CStr::from_ptr(current_name_ptr).to_str()?;
        if current_name.eq_ignore_ascii_case(function_name) {
            let ordinal = name_ordinals[i];
            let function_rva = functions[ordinal as usize];
            let function_ptr = (module_base as usize + function_rva as usize) as *const u8;

            if *function_ptr == 0x4c
                && *function_ptr.add(1) == 0x8b
                && *function_ptr.add(2) == 0xd1
                && *function_ptr.add(3) == 0xb8
            {
                let syscall_number = *(function_ptr.add(4) as *const u32);
                return Ok(syscall_number as usize);
            }
        }
    }

    Err(format!("Syscall for {} not found", function_name).into())
}

#[inline(never)]
pub unsafe fn nt_allocate_virtual_memory(
    process_handle: *mut c_void,
    base_address: &mut *mut c_void,
    zero_bits: usize,
    region_size: &mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    let syscall_number = SYSCALLS.get_syscall_number("NtAllocateVirtualMemory").unwrap();
    let status: i32;
    asm!(
        "sub rsp, 40",
        "mov [rsp + 32], {protect:e}",
        "mov [rsp + 24], {allocation_type:e}",
        "mov r10, rcx",
        "syscall",
        "add rsp, 40",
        protect = in(reg) protect,
        allocation_type = in(reg) allocation_type,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") zero_bits,
        in("r9") region_size,
        in("eax") *syscall_number,
        lateout("eax") status,
        clobber_abi("system")
    );
    status
}

#[inline(never)]
pub unsafe fn nt_protect_virtual_memory(
    process_handle: *mut c_void,
    base_address: &mut *mut c_void,
    region_size: &mut usize,
    new_protect: u32,
    old_protect: &mut u32,
) -> i32 {
    let syscall_number = SYSCALLS.get_syscall_number("NtProtectVirtualMemory").unwrap();
    let status: i32;
    asm!(
        "sub rsp, 40",
        "mov [rsp + 32], {old_protect}",
        "mov r10, rcx",
        "syscall",
        "add rsp, 40",
        old_protect = in(reg) old_protect,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") region_size,
        in("r9") new_protect,
        in("eax") *syscall_number,
        lateout("eax") status,
        clobber_abi("system")
    );
    status
}
