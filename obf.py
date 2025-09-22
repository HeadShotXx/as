import os
import argparse

def xor_obfuscate(input_string, key):
    """XORs the input string with the given key."""
    input_bytes = input_string.encode('utf-8')
    return bytes([c ^ k for c, k in zip(input_bytes, key * (len(input_bytes) // len(key) + 1))])

def generate_rust_function(input_string, function_name, key_length):
    """Generates a self-contained Rust function that returns the decrypted string."""
    key = os.urandom(key_length)
    obfuscated_data = xor_obfuscate(input_string, key)

    obfuscated_array_str = ", ".join(map(str, obfuscated_data))
    key_array_str = ", ".join(map(str, key))

    # Using a raw f-string to handle the braces in Rust code easily
    rust_function = rf"""
pub fn {function_name}() -> String {{
    // Nested helper function to keep it self-contained
    fn xor_decrypt(data: &[u8], key: &[u8]) -> String {{
        data.iter()
            .zip(key.iter().cycle())
            .map(|(&x, &y)| (x ^ y) as char)
            .collect()
    }}

    let encrypted_data: [u8; {len(obfuscated_data)}] = [{obfuscated_array_str}];
    let key: [u8; {len(key)}] = [{key_array_str}];

    xor_decrypt(&encrypted_data, &key)
}}
"""
    return rust_function

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a self-contained Rust function to return an obfuscated string.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "string_to_obfuscate",
        type=str,
        help="The string to obfuscate."
    )
    parser.add_argument(
        "--name",
        dest="function_name",
        default="get_obfuscated_string",
        help="The name for the generated Rust function (default: get_obfuscated_string)."
    )
    parser.add_argument(
        "--key-length",
        type=int,
        default=8,
        help="The length of the random key for XOR obfuscation (default: 8)."
    )
    args = parser.parse_args()

    # Generate the Rust function code
    rust_code = generate_rust_function(args.string_to_obfuscate, args.function_name, args.key_length)

    # Print the result to standard output
    print("// Copy and paste the following function into your Rust code:")
    print(rust_code)
