use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    h_module: HINSTANCE,
    ul_reason_for_call: u32,
    lp_reserved: *mut std::ffi::c_void,
) -> BOOL {
    if ul_reason_for_call == DLL_PROCESS_ATTACH {
        let message: Vec<u16> = OsStr::new("DLL Injected Successfully!\0")
            .encode_wide()
            .collect();
        unsafe {
            OutputDebugStringW(message.as_ptr());
        }
    }
    1
}
