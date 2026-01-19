use polimorphic::str_obf;

fn main() {
    println!("{}", str_obf!("This is a secret message."));
    println!("{}", str_obf!("The launch code is 1234."));
    println!("{}", str_obf!("Don't tell anyone."));
}
