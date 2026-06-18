use std::ffi::c_void;
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_DOS_HEADER,
};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

#[repr(C)]
pub struct DllInfo {
    pub base: *mut c_void,
    pub load_library_a: unsafe extern "system" fn(*const u8) -> HINSTANCE,
    pub get_proc_address: unsafe extern "system" fn(HINSTANCE, *const u8) -> *mut c_void,
    pub relocation_required: bool,
}

/// Bu fonksiyon position-independent olmalı.
/// Global değişken, string literal veya relocation gerektiren hiçbir şey kullanamaz.
/// Tüm sabitler stack'te ya da inline olarak üretilmeli.
#[no_mangle]
#[link_section = ".text"]
pub unsafe extern "system" fn realign_pe(dll_info_ptr: *mut DllInfo) {
    let dll_info = &*dll_info_ptr;
    let base = dll_info.base;
    let load_library_a = dll_info.load_library_a;
    let get_proc_address = dll_info.get_proc_address;

    let dos_header = base as *const IMAGE_DOS_HEADER;
    let nt_headers =
        (base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

    // ----------------------------------------------------------------
    // 1. Relocations
    // ----------------------------------------------------------------
    if dll_info.relocation_required {
        // DataDirectory[5] = IMAGE_DIRECTORY_ENTRY_BASERELOC
        let reloc_dir = &(*nt_headers).OptionalHeader.DataDirectory[5];
        if reloc_dir.VirtualAddress != 0 {
            let delta = base as isize - (*nt_headers).OptionalHeader.ImageBase as isize;

            let mut block_ptr =
                (base as usize + reloc_dir.VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION;

            // SizeOfBlock == 0 olan ya da VirtualAddress == 0 olan blok sonu belirtir
            while (*block_ptr).SizeOfBlock >= 8 && (*block_ptr).VirtualAddress != 0 {
                let block_size = (*block_ptr).SizeOfBlock as usize;
                let header_size = core::mem::size_of::<IMAGE_BASE_RELOCATION>();
                let entry_count = (block_size - header_size) / core::mem::size_of::<u16>();
                let entries = (block_ptr as usize + header_size) as *const u16;

                for i in 0..entry_count {
                    let entry = *entries.add(i);
                    let rel_type = entry >> 12;
                    let offset = (entry & 0x0FFF) as usize;

                    // IMAGE_REL_BASED_DIR64 = 10
                    if rel_type == 10 {
                        let patch =
                            (base as usize + (*block_ptr).VirtualAddress as usize + offset)
                                as *mut isize;
                        *patch += delta;
                    }
                }

                block_ptr = (block_ptr as usize + block_size) as *const IMAGE_BASE_RELOCATION;
            }
        }
    }

    // ----------------------------------------------------------------
    // 2. Imports
    // ----------------------------------------------------------------
    // DataDirectory[1] = IMAGE_DIRECTORY_ENTRY_IMPORT
    let import_dir = &(*nt_headers).OptionalHeader.DataDirectory[1];
    if import_dir.VirtualAddress != 0 {
        let mut import_desc =
            (base as usize + import_dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        // Name == 0 olan descriptor sonu belirtir
        while (*import_desc).Name != 0 {
            let lib_name = (base as usize + (*import_desc).Name as usize) as *const u8;
            let h_module = load_library_a(lib_name);

            // OriginalFirstThunk yoksa FirstThunk'u kullan (bound imports vs.)
            let oft = (*import_desc).Anonymous.OriginalFirstThunk;
            let mut orig_thunk = if oft != 0 {
                (base as usize + oft as usize) as *mut IMAGE_THUNK_DATA64
            } else {
                (base as usize + (*import_desc).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64
            };

            let mut first_thunk =
                (base as usize + (*import_desc).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;

            while (*orig_thunk).u1.AddressOfData != 0 {
                // Bit 63 set → ordinal ile import
                if (*orig_thunk).u1.Ordinal >> 63 != 0 {
                    let ordinal = ((*orig_thunk).u1.Ordinal & 0xFFFF) as *const u8;
                    (*first_thunk).u1.Function =
                        get_proc_address(h_module, ordinal) as u64;
                } else {
                    let ibn = (base as usize + (*orig_thunk).u1.AddressOfData as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    let func_name = (*ibn).Name.as_ptr();
                    (*first_thunk).u1.Function =
                        get_proc_address(h_module, func_name) as u64;
                }

                orig_thunk = orig_thunk.add(1);
                first_thunk = first_thunk.add(1);
            }

            import_desc = import_desc.add(1);
        }
    }

    // ----------------------------------------------------------------
    // 3. Entry Point
    // ----------------------------------------------------------------
    let ep_rva = (*nt_headers).OptionalHeader.AddressOfEntryPoint;
    if ep_rva != 0 {
        let ep_addr = base as usize + ep_rva as usize;
        let entry_point: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> BOOL =
            core::mem::transmute(ep_addr);
        entry_point(base, DLL_PROCESS_ATTACH, core::ptr::null_mut());
    }
}

#[no_mangle]
#[link_section = ".text"]
pub extern "system" fn realign_pe_end() {}