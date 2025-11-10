use my_lib::get_secret_message;
use obfuscator::{obfuscate, obfuscate_string};

#[obfuscate(garbage = true, fonk_len = 12)]
fn junk_test() {
    println!("This is a test function with junk code.");
}

#[obfuscate(garbage = true, fonk_len = 12, cf = true)]
fn kontrol_et(sayi: i32) {
    if sayi > 0 {
        println!("Sayı pozitif!");
    } else if sayi < 0 {
        println!("Sayı negatif!");
    } else {
        println!("Sayı sıfır!");
    }
}

#[obfuscate(main = true, garbage = true, fonk_len = 5)]
fn main() {
    junk_test();
	kontrol_et(10);
    let my_secret_string = get_secret_message();
    println!("Decrypted string from my_lib: {}", my_secret_string);
	let my_secret_string1 = obfuscate_string!("Hello, this is a secret message!");
    println!("Decrypted string: {}", my_secret_string1);
}
