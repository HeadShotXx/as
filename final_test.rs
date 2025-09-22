// Copy and paste the following function into your Rust code:

pub fn get_final_string() -> String {
    // Nested helper function to keep it self-contained
    fn xor_decrypt(data: &[u8], key: &[u8]) -> String {
        data.iter()
            .zip(key.iter().cycle())
            .map(|(&x, &y)| (x ^ y) as char)
            .collect()
    }

    let encrypted_data: [u8; 36] = [94, 56, 215, 196, 187, 141, 149, 182, 107, 37, 131, 133, 179, 194, 132, 160, 56, 37, 209, 204, 164, 141, 150, 188, 106, 58, 134, 133, 139, 143, 184, 182, 107, 112, 229, 135];
    let key: [u8; 8] = [24, 81, 185, 165, 215, 173, 225, 211];

    xor_decrypt(&encrypted_data, &key)
}

fn main() {
    let my_string = get_final_string();
    println!("{}", my_string);
}
