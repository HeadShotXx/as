use polimorphic::str_obf;

fn main() {
    println!("Test 1: {}", str_obf!("Hello Polymorphism!"));
    println!("Test 2: {}", str_obf!("Another test string"));
    println!("Test 3: {}", str_obf!("Short"));
    println!("Test 4: {}", str_obf!("Very long string that might trigger different paths in the deobfuscation engine"));
}
