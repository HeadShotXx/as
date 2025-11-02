//! Syscalls module for true indirect syscalls.

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::ffi::c_void;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64,
};

// A simple hashing function for function names to use as keys.
const fn fnv1a_hash(s: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < s.len() {
        hash ^= s[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

lazy_static! {
    // Stores the mapping of function name hashes to syscall numbers.
    static ref SYSCALL_MAP: HashMap<u32, u16> = unsafe {
        let mut map = HashMap::new();
        init_syscalls(&mut map);
        map
    };
}

/// Initializes the syscall map by parsing ntdll.dll.
unsafe fn init_syscalls(map: &mut HashMap<u32, u16>) {
    let module_base = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const i8) as *mut u8;
    if module_base.is_null() {
        return;
    }

    let dos_header = &*(module_base as *const IMAGE_DOS_HEADER);
    let nt_headers =
        &*(module_base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;
    let export_dir =
        &*(module_base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);

    let names = core::slice::from_raw_parts(
        module_base.add(export_dir.AddressOfNames as usize) as *const u32,
        export_dir.NumberOfNames as usize,
    );
    let funcs = core::slice::from_raw_parts(
        module_base.add(export_dir.AddressOfFunctions as usize) as *const u32,
        export_dir.NumberOfFunctions as usize,
    );
    let ords = core::slice::from_raw_parts(
        module_base.add(export_dir.AddressOfNameOrdinals as usize) as *const u16,
        export_dir.NumberOfNames as usize,
    );

    for i in 0..export_dir.NumberOfNames as usize {
        let name_rva = names[i];
        let name_ptr = module_base.add(name_rva as usize) as *const i8;
        let name = std::ffi::CStr::from_ptr(name_ptr).to_bytes();

        // We are only interested in Nt* functions.
        if name.starts_with(b"Nt") {
            let func_idx = ords[i] as usize;
            let func_rva = funcs[func_idx];
            let func_ptr = module_base.add(func_rva as usize);

            // Look for the syscall number in the function stub.
            // mov r10, rcx
            // mov eax, SSN
            // The bytes for `mov eax, SSN` are b8, followed by the 4-byte SSN.
            // We only need the first two bytes of the SSN.
            if *(func_ptr.add(3)) == 0xB8 {
                let ssn = *(func_ptr.add(4) as *const u16);
                let hash = fnv1a_hash(name);
                map.insert(hash, ssn);
            }
        }
    }
}

/// Executes a syscall with the given number and arguments.
#[inline(always)]
unsafe fn do_syscall(
    ssn: u16,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> i32 {
    let status: i32;
    std::arch::asm!(
        "sub rsp, 0x28",      // Allocate shadow space
        "mov [rsp + 0x20], r12", // Pass 5th argument on the stack
        "mov [rsp + 0x28], r13", // Pass 6th argument on the stack
        "mov r10, rcx",
        "mov eax, {ssn}",
        "syscall",
        "add rsp, 0x28",      // Deallocate shadow space
        "ret",
        ssn = in(reg) ssn as u32,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        in("r12") arg5,
        in("r13") arg6,
        lateout("rax") status,
        options(nostack, raw)
    );
    status
}

/// Allocates virtual memory.
pub unsafe fn nt_allocate_virtual_memory(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    zero_bits: u32,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    let hash = fnv1a_hash(b"NtAllocateVirtualMemory");
    if let Some(&ssn) = SYSCALL_MAP.get(&hash) {
        do_syscall(
            ssn,
            process_handle as u64,
            base_address as u64,
            zero_bits as u64,
            region_size as u64,
            allocation_type as u64,
            protect as u64,
        )
    } else {
        // Fallback or error.
        -1
    }
}

/// Flushes the instruction cache.
pub unsafe fn nt_flush_instruction_cache(
    process_handle: *mut c_void,
    base_address: *mut c_void,
    length: usize,
) -> i32 {
    let hash = fnv1a_hash(b"NtFlushInstructionCache");
    if let Some(&ssn) = SYSCALL_MAP.get(&hash) {
        do_syscall(
            ssn,
            process_handle as u64,
            base_address as u64,
            length as u64,
            0,
            0,
            0,
        )
    } else {
        -1
    }
}

/// Protects virtual memory.
pub unsafe fn nt_protect_virtual_memory(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let hash = fnv1a_hash(b"NtProtectVirtualMemory");
    if let Some(&ssn) = SYSCALL_MAP.get(&hash) {
        do_syscall(
            ssn,
            process_handle as u64,
            base_address as u64,
            region_size as u64,
            new_protect as u64,
            old_protect as u64,
            0,
        )
    } else {
        -1
    }
}
