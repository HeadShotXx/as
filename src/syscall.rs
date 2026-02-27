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

    let ldr = (*peb_ptr).ldr;
    let mut current_entry = (*ldr).in_load_order_module_list.next;

    while current_entry != &mut (*ldr).in_load_order_module_list {
        let entry = current_entry as *mut LDR_DATA_TABLE_ENTRY;
        let name_slice = std::slice::from_raw_parts(
            (*entry).base_dll_name.buffer,
            ((*entry).base_dll_name.length / 2) as usize,
        );
        let name = String::from_utf16_lossy(name_slice);

        if name.to_lowercase() == module_name.to_lowercase() {
            return Some((*entry).dll_base);
        }

        current_entry = (*current_entry).next;
    }

    None
}

pub unsafe fn get_export_address(module_base: *mut core::ffi::c_void, func_name: &str) -> Option<*mut core::ffi::c_void> {
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
        let name = std::ffi::CStr::from_ptr(name_ptr).to_str().ok()?;

        if name == func_name {
            let ordinal = *ordinals_rva.add(i as usize);
            let func_rva = *functions_rva.add(ordinal as usize);
            return Some((module_base as usize + func_rva as usize) as *mut core::ffi::c_void);
        }
    }

    None
}

pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    unsafe {
        let ntdll_base = get_module_base("ntdll.dll")?;
        let func_addr = get_export_address(ntdll_base, func_name)?;

        let func_bytes = std::slice::from_raw_parts(func_addr as *const u8, 8);

        if func_bytes[0] == 0x4c
            && func_bytes[1] == 0x8b
            && func_bytes[2] == 0xd1
            && func_bytes[3] == 0xb8
            && func_bytes[6] == 0x00
            && func_bytes[7] == 0x00
        {
            let high = u32::from(func_bytes[5]);
            let low = u32::from(func_bytes[4]);
            let syscall_number = (high << 8) | low;
            return Some(syscall_number);
        }

        None
    }
}
