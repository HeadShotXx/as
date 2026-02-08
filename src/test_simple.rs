use polimorphic::str_obf;

fn main() {
    let s1 = str_obf!("Test string 1");
    let s2 = str_obf!("Test string 2");
    assert_eq!(s1, "Test string 1", "String 1 mismatch: {}", s1);
    assert_eq!(s2, "Test string 2", "String 2 mismatch: {}", s2);
    println!("OK");
}
