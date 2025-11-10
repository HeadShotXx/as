use obfuscator::obfuscate_string;

pub fn get_secret_message() -> String {
    obfuscate_string!("This is a secret message from my_lib!").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let message = get_secret_message();
        assert_eq!(message, "This is a secret message from my_lib!");
    }

    #[obfuscator::obfuscate(inline = true)]
    fn inlined_function() -> i32 {
        42
    }

    #[test]
    fn test_inlined_function() {
        assert_eq!(inlined_function(), 42);
    }
}
