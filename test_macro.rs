use obfuscator::{obfuscate_string, obfuscate_bytes, obfuscate};

#[obfuscate(garbage=true, fonk_len=10)]
fn test_function() {
    let s = obfuscate_string!("Hello, Polymorphism!");
    println!("{}", s);
    let b = obfuscate_bytes!(b"Secret Data");
    println!("{:?}", b);
}

fn main() {
    test_function();
}
