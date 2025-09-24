mod anti_vm;

fn main() {
    let vm_indicators = anti_vm::detect_vm_indicators();
    if vm_indicators.is_empty() {
        println!("No direct signs of a VM detected.");
    } else {
        println!("Potential VM indicators found:");
        for indicator in vm_indicators {
            println!("- {}", indicator);
        }
    }
}