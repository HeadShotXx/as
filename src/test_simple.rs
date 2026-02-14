use polimorphic::str_obf;

fn main() {
    let s1 = str_obf!("Test string 1");
    let s2 = str_obf!("Test string 2");

    println!("{}", s1);
    println!("{}", s2);
}