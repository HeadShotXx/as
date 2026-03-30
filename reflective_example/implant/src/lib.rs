use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, TRUE};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    lpv_reserved: *const std::ffi::c_void,
) -> BOOL {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            unsafe {

                let _ = std::fs::write(
                    "C:\\injected_debug.txt",
                    "DllMain DLL_PROCESS_ATTACH reached\n",
                );

                MessageBoxA(
                    0,
                    b"Reflective DLL Injected Successfully!\0".as_ptr(),
                    b"Success\0".as_ptr(),
                    MB_OK,
                );
            }
        }
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    }
    TRUE
}