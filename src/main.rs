use polimorphic::str_obf;
use std::io;

fn main() {
    println!("{}", str_obf!("Simple Calculator"));
    println!("{}", str_obf!("-----------------"));

    loop {
        println!("{}", str_obf!("Please enter the first number:"));
        let mut num1 = String::new();
        io::stdin().read_line(&mut num1).expect("Failed to read line");
        let num1: f64 = match num1.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("{}", str_obf!("Invalid input. Please enter a number."));
                continue;
            }
        };

        println!("{}", str_obf!("Please enter the operator (+, -, *, /):"));
        let mut operator = String::new();
        io::stdin().read_line(&mut operator).expect("Failed to read line");
        let operator = operator.trim();

        println!("{}", str_obf!("Please enter the second number:"));
        let mut num2 = String::new();
        io::stdin().read_line(&mut num2).expect("Failed to read line");
        let num2: f64 = match num2.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("{}", str_obf!("Invalid input. Please enter a number."));
                continue;
            }
        };

        let result = match operator {
            "+" => num1 + num2,
            "-" => num1 - num2,
            "*" => num1 * num2,
            "/" => {
                if num2 != 0.0 {
                    num1 / num2
                } else {
                    println!("{}", str_obf!("Error: Division by zero!"));
                    continue;
                }
            }
            _ => {
                println!("{}", str_obf!("Invalid operator."));
                continue;
            }
        };

        println!("{} {} {} = {}", num1, operator, num2, result);

        println!("{}", str_obf!("Do you want to perform another calculation? (yes/no)"));
        let mut again = String::new();
        io::stdin().read_line(&mut again).expect("Failed to read line");
        if again.trim().to_lowercase() != "yes" {
            break;
        }
    }
}
