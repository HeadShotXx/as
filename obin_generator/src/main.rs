use std::env;
use std::fs;

const SECRET_KEY: &[u8] = b"change-this-secret-key-to-something-unique";

fn transform_data(data: &[u8]) -> Vec<u8> {
    if SECRET_KEY.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ SECRET_KEY[i % SECRET_KEY.len()])
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <input-file>", args[0]);
        return;
    }

    let path = &args[1];
    println!("[*] Reading file: {}", path);
    match fs::read(path) {
        Ok(data) => {
            println!("[+] File size: {} bytes", data.len());
            let obfuscated_data = transform_data(&data);
            let out_path = format!("{}.obin", path);
            match fs::write(&out_path, &obfuscated_data) {
                Ok(_) => println!("[+] Wrote obfuscated binary to: {}", out_path),
                Err(e) => eprintln!("[✗] Failed to write {}: {}", out_path, e),
            }
        }
        Err(e) => eprintln!("[✗] Failed to read file: {}", e),
    }
}
