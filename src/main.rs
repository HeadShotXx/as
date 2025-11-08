use my_lib::get_secret_message;
use obfuscator::{obfuscate, obfuscate_main, obfuscate_junk};

#[obfuscate_junk]
fn junk_test() {
    println!("This is a test function with junk code.");
}

#[obfuscate_main]
fn main() {
    junk_test();
    let my_secret_string = get_secret_message();
    println!("Decrypted string from my_lib: {}", my_secret_string);
	let my_secret_string1 = obfuscate!("Hello, this is a secret message!");
    println!("Decrypted string: {}", my_secret_string1);
}