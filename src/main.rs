mod anti_vm;

fn main() {
    let indicators = anti_vm::run_analysis();
    if indicators.is_empty() {
        println!("System integrity checks passed.");
    } else {
        println!("System anomalies detected:");
        for (i, indicator) in indicators.iter().enumerate() {
            println!("[{}] {}", i + 1, indicator);
        }
    }
}