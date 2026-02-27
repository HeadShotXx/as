#[repr(C)]
struct LIST_ENTRY {
    next: *mut LIST_ENTRY,
    prev: *mut LIST_ENTRY,
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *mut core::ffi::c_void,
    entry_point: *mut core::ffi::c_void,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

#[repr(C)]
struct PEB_LDR_DATA {
    length: u32,
    initialized: u8,
    reserved: [u8; 3],
    ss_handle: *mut core::ffi::c_void,
    in_load_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct PEB {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: [u8; 21],
    ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

pub unsafe fn get_module_base(module_name: &str) -> Option<*mut core::ffi::c_void> {
    let peb_ptr: *mut PEB;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb_ptr
    );

    if peb_ptr.is_null() { return None; }

    let ldr = (*peb_ptr).ldr;
    if ldr.is_null() { return None; }

    let head = &mut (*ldr).in_load_order_module_list;
    let mut current_entry = (*head).next;

    while !current_entry.is_null() && current_entry != head {
        let entry = current_entry as *mut LDR_DATA_TABLE_ENTRY;

        if !(*entry).base_dll_name.buffer.is_null() {
            let name_slice = std::slice::from_raw_parts(
                (*entry).base_dll_name.buffer,
                ((*entry).base_dll_name.length / 2) as usize,
            );
            let name = String::from_utf16_lossy(name_slice);

            if name.eq_ignore_ascii_case(module_name) {
                return Some((*entry).dll_base);
            }
        }

        current_entry = (*current_entry).next;
    }

    None
}

pub unsafe fn get_export_address(module_base: *mut core::ffi::c_void, func_name: &str) -> Option<*mut core::ffi::c_void> {
    if module_base.is_null() { return None; }

    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return None;
    }

    let nt_header = (module_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt_header).Signature != 0x4550 {
        return None;
    }

    let export_dir_rva = (*nt_header).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = (module_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names_rva = (module_base as usize + (*export_dir).AddressOfNames as usize) as *const u32;
    let functions_rva = (module_base as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;
    let ordinals_rva = (module_base as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..(*export_dir).NumberOfNames {
        let name_ptr = (module_base as usize + *names_rva.add(i as usize) as usize) as *const i8;
        if let Ok(name) = std::ffi::CStr::from_ptr(name_ptr).to_str() {
            if name == func_name {
                let ordinal = *ordinals_rva.add(i as usize);
                let func_rva = *functions_rva.add(ordinal as usize);
                return Some((module_base as usize + func_rva as usize) as *mut core::ffi::c_void);
            }
        }
    }

    None
}

pub fn get_syscall_info(func_name: &str) -> Option<(u32, *mut core::ffi::c_void, *mut core::ffi::c_void)> {
    unsafe {
        let ntdll_base = get_module_base("ntdll.dll")?;
        let func_addr = get_export_address(ntdll_base, func_name)?;

        let func_bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

        for i in 0..16 {
            if func_bytes[i] == 0x4c && func_bytes[i+1] == 0x8b && func_bytes[i+2] == 0xd1 && func_bytes[i+3] == 0xb8 {
                let low = u32::from(func_bytes[i+4]);
                let high = u32::from(func_bytes[i+5]);
                let id = (high << 8) | low;

                let mut syscall_inst = std::ptr::null_mut();
                let mut ret_gadget = std::ptr::null_mut();

                for j in 0..32 {
                    if func_bytes[j] == 0x0f && func_bytes[j+1] == 0x05 {
                        syscall_inst = (func_addr as usize + j) as *mut core::ffi::c_void;
                        if func_bytes[j+2] == 0xc3 {
                             ret_gadget = (func_addr as usize + j + 2) as *mut core::ffi::c_void;
                        }
                    }
                }

                if syscall_inst.is_null() {
                    if let Some(gadget) = get_syscall_gadget("ntdll.dll") {
                        syscall_inst = gadget;
                        ret_gadget = (gadget as usize + 2) as *mut core::ffi::c_void;
                    }
                }

                if !syscall_inst.is_null() && !ret_gadget.is_null() {
                    return Some((id, syscall_inst, ret_gadget));
                }
            }
        }

        None
    }
}

fn get_syscall_gadget(module_name: &str) -> Option<*mut core::ffi::c_void> {
    unsafe {
        let module_base = get_module_base(module_name)?;
        let dos_header = module_base as *const IMAGE_DOS_HEADER;
        let nt_header = (module_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let size_of_image = (*nt_header).OptionalHeader.SizeOfImage as usize;

        let module_bytes = std::slice::from_raw_parts(module_base as *const u8, size_of_image);

        for i in 0..(size_of_image - 2) {
            if module_bytes[i] == 0x0f && module_bytes[i+1] == 0x05 && module_bytes[i+2] == 0xc3 {
                return Some((module_base as usize + i) as *mut core::ffi::c_void);
            }
        }
        None
    }
}

pub fn get_syscall_number(module_name: &str, func_name: &str) -> Option<u32> {
    unsafe {
        let module_base = get_module_base(module_name)?;
        let func_addr = get_export_address(module_base, func_name)?;

        let func_bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

        for i in 0..16 {
            if func_bytes[i] == 0x4c && func_bytes[i+1] == 0x8b && func_bytes[i+2] == 0xd1 && func_bytes[i+3] == 0xb8 {
                let low = u32::from(func_bytes[i+4]);
                let high = u32::from(func_bytes[i+5]);
                return Some((high << 8) | low);
            }
            if func_bytes[i] == 0xb8 && func_bytes[i+5] == 0x4c && func_bytes[i+6] == 0x8b && func_bytes[i+7] == 0xd1 {
                let low = u32::from(func_bytes[i+1]);
                let high = u32::from(func_bytes[i+2]);
                return Some((high << 8) | low);
            }
        }

        None
    }
}
