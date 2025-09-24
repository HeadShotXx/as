mod anti_vm;

fn main() {
    let indicators = anti_vm::detect_vm_indicators();
    if indicators.is_empty() {
        println!("[WARNING] No VM indicators detected. This does not guarantee that the environment is not virtualized.");
    } else {
        println!("[INFO] VM detected. The program will continue to run inside the VM.");
        println!("[INFO] The following indicators were found:");
        for (i, indicator) in indicators.iter().enumerate() {
            println!("  {}. {}", i + 1, indicator);
        }
    }
}