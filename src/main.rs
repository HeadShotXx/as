#![allow(non_snake_case)]
mod power;
use crate::power::run_all_checks;

fn main() {
    if run_all_checks() {
        // Analysis tool detected, exit gracefully or mislead.
        println!("Analysis tool detected. Exiting.");
        return;
    }

    println!("Payload executed successfully.");
}
