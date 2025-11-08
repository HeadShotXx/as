use my_lib::get_secret_message;
use obfuscator::obfuscate;

fn run_app() {
    let my_secret_string = get_secret_message();
    println!("Decrypted string from my_lib: {}", my_secret_string);
	let my_secret_string1 = obfuscate!("Hello, this is a secret message!");
    println!("Decrypted string: {}", my_secret_string1);
}

fn main() {
    run_app();
}
