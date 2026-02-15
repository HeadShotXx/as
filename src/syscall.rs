use polimorphic::str_obf;
use windows::{
    core::*,
    Win32::System::LibraryLoader::*,
};

pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    unsafe {
        let ntdll_str = str_obf!("ntdll.dll\0");
        let ntdll_handle = GetModuleHandleA(PCSTR(ntdll_str.as_ptr())).expect("Failed to get a handle to ntdll.dll");
        if ntdll_handle.is_invalid() {
            return None;
        }

        let c_func_name = std::ffi::CString::new(func_name).unwrap();
        let func_addr = GetProcAddress(ntdll_handle, PCSTR(c_func_name.as_ptr() as *const u8));
        if func_addr.is_none() {
            return None;
        }

        let func_bytes = std::slice::from_raw_parts(func_addr.unwrap() as *const u8, 8);

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
