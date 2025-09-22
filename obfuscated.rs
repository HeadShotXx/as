
// Injected by obfuscator
fn xor_decrypt(data: &[u8], key: &[u8]) -> String {
    data.iter()
        .zip(key.iter().cycle())
        .map(|(&x, &y)| (x ^ y) as char)
        .collect()
}


fn another_function(s: &str) {
    println!({
    let encrypted_string: [u8; 40] = [13, 142, 182, 181, 68, 211, 67, 12, 48, 136, 184, 230, 13, 211, 23, 24, 43, 137, 178, 230, 5, 206, 88, 10, 49, 131, 173, 230, 2, 213, 89, 29, 45, 143, 176, 168, 94, 128, 76, 3];
    let key: [u8; 8] = [89, 230, 223, 198, 100, 160, 55, 126];
    xor_decrypt(&encrypted_string, &key)
}, s);
}

fn main() {
    println!({
    let encrypted_string: [u8; 37] = [156, 70, 208, 233, 76, 112, 0, 52, 188, 74, 207, 165, 74, 47, 0, 52, 188, 70, 156, 227, 74, 46, 83, 52, 244, 87, 217, 246, 87, 124, 83, 52, 166, 74, 210, 226, 2];
    let key: [u8; 8] = [212, 35, 188, 133, 35, 92, 32, 64];
    xor_decrypt(&encrypted_string, &key)
});

    let message = {
    let encrypted_string: [u8; 40] = [1, 246, 51, 112, 18, 9, 56, 255, 52, 190, 41, 119, 64, 9, 37, 184, 117, 255, 41, 112, 91, 7, 37, 186, 49, 190, 46, 108, 18, 1, 107, 169, 52, 236, 51, 98, 80, 12, 46, 241];
    let key: [u8; 8] = [85, 158, 90, 3, 50, 96, 75, 223];
    xor_decrypt(&encrypted_string, &key)
};
    println!({
    let encrypted_string: [u8; 2] = [166, 77];
    let key: [u8; 8] = [221, 48, 48, 255, 41, 237, 14, 33];
    xor_decrypt(&encrypted_string, &key)
}, message);

    let with_escapes = {
    let encrypted_string: [u8; 60] = [91, 253, 198, 109, 216, 192, 151, 229, 114, 184, 199, 124, 138, 192, 138, 162, 51, 239, 221, 124, 144, 137, 184, 231, 118, 235, 215, 105, 136, 204, 128, 229, 98, 237, 219, 124, 157, 218, 184, 231, 51, 249, 218, 108, 216, 200, 196, 167, 114, 251, 223, 123, 148, 200, 151, 173, 51, 196, 232, 38];
    let key: [u8; 8] = [19, 152, 180, 8, 248, 169, 228, 197];
    xor_decrypt(&encrypted_string, &key)
};
    println!({
    let encrypted_string: [u8; 2] = [26, 130];
    let key: [u8; 8] = [97, 255, 209, 210, 46, 207, 246, 242];
    xor_decrypt(&encrypted_string, &key)
}, with_escapes);

    another_function({
    let encrypted_string: [u8; 31] = [249, 125, 250, 117, 136, 67, 220, 98, 212, 125, 230, 125, 143, 85, 203, 103, 152, 41, 249, 60, 157, 6, 200, 118, 214, 62, 226, 117, 147, 72, 128];
    let key: [u8; 8] = [184, 93, 150, 28, 252, 38, 174, 3];
    xor_decrypt(&encrypted_string, &key)
});
}
