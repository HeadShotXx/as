#!/usr/bin/env python3
import os
import sys

def transform_data(data, key):
    if not key:
        return data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def generate_rust_obfuscation(input_data):
    """
    Takes binary data, obfuscates it, and returns formatted Rust code for the key and payload byte arrays.
    """
    key = os.urandom(32)
    obfuscated_data = transform_data(input_data, key)

    indent = "    "

    key_lines = []
    for i in range(0, len(key), 16):
        chunk = key[i:i+16]
        key_lines.append(indent + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    key_output = "\n".join(key_lines)

    payload_lines = []
    for i in range(0, len(obfuscated_data), 16):
        chunk = obfuscated_data[i:i+16]
        payload_lines.append(indent + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    payload_output = "\n".join(payload_lines)

    return key_output, payload_output

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input-file>")
        return

    path = sys.argv[1]
    print(f"[*] Reading file: {path}")

    try:
        with open(path, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"[✗] Failed to read file: {e}")
        return

    print(f"[+] File size: {len(data)} bytes")

    key_array_str, payload_array_str = generate_rust_obfuscation(data)

    key_file_content = f"const SECRET_KEY: &[u8] = &[\n{key_array_str}\n];\n"
    payload_file_content = f"const PAYLOAD: &[u8] = &[\n{payload_array_str}\n];"

    try:
        with open("key.rs", 'w') as f:
            f.write(key_file_content)
        print("[+] SECRET_KEY written to key.rs")
    except IOError as e:
        print(f"[✗] Failed to write key.rs: {e}")
        return

    try:
        with open("payload.rs", 'w') as f:
            f.write(payload_file_content)
        print("[+] PAYLOAD written to payload.rs")
    except IOError as e:
        print(f"[✗] Failed to write payload.rs: {e}")
        return

    print("\n[+] Successfully generated files. Please copy the contents of key.rs and payload.rs into your tulpar project.")

if __name__ == "__main__":
    main()
