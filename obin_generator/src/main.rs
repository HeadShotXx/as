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
        eprintln!("Usage: {} <input-file>", args.get(0).unwrap_or(&"obin_generator".to_string()));
        return;
    }

    let path = &args[1];
    eprintln!("[*] Reading file: {}", path);
    match fs::read(path) {
        Ok(data) => {
            eprintln!("[+] File size: {} bytes", data.len());
            let obfuscated_data = transform_data(&data);

            let mut output = String::from("const PAYLOAD: &[u8] = &[\n    ");

            for (i, byte) in obfuscated_data.iter().enumerate() {
                output.push_str(&format!("0x{:02x}, ", byte));
                if (i + 1) % 16 == 0 {
                    output.push_str("\n    ");
                }
            }

            if output.ends_with(", ") {
                output.pop();
                output.pop();
            }

            output.push_str("\n];");

            println!("{}", output);
        }
        Err(e) => eprintln!("[✗] Failed to read file: {}", e),
    }
}
