mod anti_vm;

fn main() {
    println!("Running cross-platform VM indicator detection (non-stealthy).");

    let indicators = anti_vm::detect_vm_indicators();
    if indicators.is_empty() {
        println!("[+] No obvious VM indicators found (this is not a guarantee of physical machine).");
    } else {
        println!("[!] VM indicators detected ({}):", indicators.len());
        for (i, it) in indicators.iter().enumerate() {
            println!("  {}. {}", i + 1, it);
        }
    }
}
