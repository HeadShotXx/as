use windows_sys::Win32::System::Threading::{DEBUG_PROCESS, DEBUG_ONLY_THIS_PROCESS};
fn main() {
    println!("DEBUG_PROCESS: {}", DEBUG_PROCESS);
    println!("DEBUG_ONLY_THIS_PROCESS: {}", DEBUG_ONLY_THIS_PROCESS);
}
