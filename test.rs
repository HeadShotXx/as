fn another_function(s: &str) {
    println!("This string is from another function: {}", s);
}

fn main() {
    println!("Hello, this is the first test string!");

    let message = "This is a string assigned to a variable.";
    println!("{}", message);

    let with_escapes = "Here is a string with \\\"escaped quotes\\\" and a backslash \\\\.";
    println!("{}", with_escapes);

    another_function("A literal passed to a function.");
}
