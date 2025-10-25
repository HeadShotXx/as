use std::env;
use std::fs;
use rand::Rng;

fn transform_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <input-file>", args.get(0).unwrap_or(&"obin_generator".to_string()));
        return;
    }

    let path = &args[1];
    eprintln!("[*] Reading file: {}", path);

    match fs::read(path) {
        Ok(data) => {
            eprintln!("[+] File size: {} bytes", data.len());

            let key: [u8; 32] = rand::thread_rng().gen();
            eprintln!("[+] Generated a new random 32-byte SECRET_KEY.");

            let obfuscated_data = transform_data(&data, &key);

            let mut key_output = String::from("const SECRET_KEY: &[u8] = &[\n    ");
            for (i, byte) in key.iter().enumerate() {
                key_output.push_str(&format!("0x{:02x}, ", byte));
                if (i + 1) % 16 == 0 {
                    key_output.push_str("\n    ");
                }
            }
            if key_output.ends_with(", ") {
                key_output.pop();
                key_output.pop();
            }
            key_output.push_str("\n];\n");


            let mut payload_output = String::from("const PAYLOAD: &[u8] = &[\n    ");
            for (i, byte) in obfuscated_data.iter().enumerate() {
                payload_output.push_str(&format!("0x{:02x}, ", byte));
                if (i + 1) % 16 == 0 {
                    payload_output.push_str("\n    ");
                }
            }
            if payload_output.ends_with(", ") {
                payload_output.pop();
                payload_output.pop();
            }
            payload_output.push_str("\n];");

            if let Err(e) = fs::write("key.rs", key_output) {
                eprintln!("[✗] Failed to write key.rs: {}", e);
                return;
            }
            eprintln!("[+] SECRET_KEY written to key.rs");

            if let Err(e) = fs::write("payload.rs", payload_output) {
                eprintln!("[✗] Failed to write payload.rs: {}", e);
                return;
            }
            eprintln!("[+] PAYLOAD written to payload.rs");

            eprintln!("\n[✓] Successfully generated files. Please copy the contents of key.rs and payload.rs into your tulpar project.");
        }
        Err(e) => eprintln!("[✗] Failed to read file: {}", e),
    }
}
