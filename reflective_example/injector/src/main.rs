pub mod bootstrapper;

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;

use crate::bootstrapper::{realign_pe, realign_pe_end, DllInfo};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: injector.exe <path_to_dll> [process_name]");
        println!("       injector.exe --list");
        return;
    }

    if args[1] == "--list" {
        unsafe { list_processes(); }
        return;
    }

    let dll_path = &args[1];
    let process_name = if args.len() > 2 { &args[2] } else { "notepad.exe" };

    let dll_bytes = std::fs::read(dll_path).expect("Failed to read DLL file");

    unsafe {
        let process_id = find_process_id(process_name).expect("Failed to find process");
        println!("[+] Found process {} with ID: {}", process_name, process_id);

        let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if h_process == 0 {
            panic!("Failed to open process");
        }

        inject_dll(h_process, &dll_bytes);

        CloseHandle(h_process);
    }
}

unsafe fn list_processes() {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        println!("Failed to create snapshot");
        return;
    }

    let mut entry: PROCESSENTRY32 = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if Process32First(snapshot, &mut entry) != 0 {
        loop {
            let exe_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                .to_string_lossy();
            println!("PID: {}, Name: {}", entry.th32ProcessID, exe_name);

            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
}

unsafe fn find_process_id(name: &str) -> Option<u32> {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry: PROCESSENTRY32 = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if Process32First(snapshot, &mut entry) != 0 {
        loop {
            let exe_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                .to_string_lossy();
            if exe_name.to_lowercase() == name.to_lowercase() {
                CloseHandle(snapshot);
                return Some(entry.th32ProcessID);
            }

            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }

    CloseHandle(snapshot);
    None
}

unsafe fn inject_dll(h_process: HANDLE, dll_bytes: &[u8]) {
    // --- Validate PE headers ---
    let dos_header = dll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Invalid DOS signature");
    }

    let nt_headers = (dll_bytes.as_ptr() as usize + (*dos_header).e_lfanew as usize)
        as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        panic!("Not a 64-bit DLL");
    }

    let image_size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
    let preferred_base = (*nt_headers).OptionalHeader.ImageBase as *const c_void;

    println!("[*] Image size: {} bytes", image_size);
    println!("[*] Preferred base: {:?}", preferred_base);

    // --- 1. Allocate memory for DLL in remote process ---
    let mut remote_base = VirtualAllocEx(
        h_process,
        preferred_base,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    let mut relocation_required = false;
    if remote_base.is_null() {
        println!("[!] Preferred base unavailable, allocating elsewhere (relocation required)");
        relocation_required = true;
        remote_base = VirtualAllocEx(
            h_process,
            null(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
    }

    if remote_base.is_null() {
        panic!("Failed to allocate memory in target process");
    }

    println!("[+] Allocated DLL memory at: {:?} (relocation={})", remote_base, relocation_required);

    // --- 2. Write PE headers ---
    let headers_written = WriteProcessMemory(
        h_process,
        remote_base,
        dll_bytes.as_ptr() as *const c_void,
        (*nt_headers).OptionalHeader.SizeOfHeaders as usize,
        null_mut(),
    );
    if headers_written == 0 {
        panic!("Failed to write PE headers");
    }
    println!("[+] PE headers written ({} bytes)", (*nt_headers).OptionalHeader.SizeOfHeaders);

    // --- 3. Write sections ---
    let sections_ptr = (nt_headers as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let num_sections = (*nt_headers).FileHeader.NumberOfSections;

    println!("[*] Writing {} sections...", num_sections);

    for i in 0..num_sections {
        let section = &*sections_ptr.add(i as usize);

        // Section adını güvenli şekilde oku
        let name_bytes = &section.Name;
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let section_name = std::str::from_utf8(&name_bytes[..name_len]).unwrap_or("?");

        // Raw data yoksa (BSS gibi) yaz
        if section.PointerToRawData == 0 || section.SizeOfRawData == 0 {
            println!("  [*] Section {} skipped (no raw data, VirtualSize={})",
                section_name,
                section.Misc.VirtualSize
            );
            continue;
        }

        let remote_section_addr =
            (remote_base as usize + section.VirtualAddress as usize) as *mut c_void;
        let local_section_addr =
            (dll_bytes.as_ptr() as usize + section.PointerToRawData as usize) as *const c_void;

        // Dosyada bulunan ham veriyi yaz; VirtualSize daha büyükse geri kalan
        // VirtualAllocEx tarafından zaten sıfırlanmış olur (MEM_COMMIT garantisi).
        let size_to_write = section.SizeOfRawData as usize;

        let written = WriteProcessMemory(
            h_process,
            remote_section_addr,
            local_section_addr,
            size_to_write,
            null_mut(),
        );

        if written == 0 {
            println!("  [!] WARNING: Failed to write section {}", section_name);
        } else {
            println!(
                "  [+] Section {} -> {:?} ({} bytes raw, {} bytes virtual)",
                section_name,
                remote_section_addr,
                size_to_write,
                section.Misc.VirtualSize
            );
        }
    }

    // --- 4. Bootstrapper (DllInfo + realign_pe kodu) hazırla ---

    // kernel32 fonksiyonlarını al
    let h_kernel32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
        b"kernel32.dll\0".as_ptr(),
    );
    if h_kernel32 == 0 {
        panic!("Failed to get kernel32 handle");
    }

    let load_library_a_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
        h_kernel32,
        b"LoadLibraryA\0".as_ptr(),
    ).expect("Failed to find LoadLibraryA");

    let get_proc_address_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
        h_kernel32,
        b"GetProcAddress\0".as_ptr(),
    ).expect("Failed to find GetProcAddress");

    let dll_info = DllInfo {
        base: remote_base,
        load_library_a: std::mem::transmute(load_library_a_ptr),
        get_proc_address: std::mem::transmute(get_proc_address_ptr),
        relocation_required,
    };

    // --- 5. Bootstrapper boyutunu hesapla ---
    // realign_pe ile realign_pe_end mutlaka aynı object file'dan,
    // link script'te yan yana olmalı — bu yaklaşımın en kırılgan noktası.
    let start_ptr = realign_pe as usize;
    let end_ptr   = realign_pe_end as usize;

    // Her ihtimale karşı iki yönde de hesapla
    let bootstrapper_size = if end_ptr > start_ptr {
        end_ptr - start_ptr
    } else {
        // Compiler sırayı ters çevirmişse makul bir üst limit kullan
        println!("[!] WARNING: realign_pe_end <= realign_pe, using fallback size 4096");
        4096
    };

    println!("[*] Bootstrapper size: {} bytes", bootstrapper_size);

    // DllInfo + kod birlikte
    let total_bootstrap_size = std::mem::size_of::<DllInfo>() + bootstrapper_size;

    // --- 6. Remote'a bootstrapper belleği ayır ---
    let remote_bootstrap_mem = VirtualAllocEx(
        h_process,
        null(),
        total_bootstrap_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_bootstrap_mem.is_null() {
        panic!("Failed to allocate bootstrapper memory");
    }

    println!("[+] Bootstrapper memory at: {:?}", remote_bootstrap_mem);

    // DllInfo yaz (başa)
    let info_written = WriteProcessMemory(
        h_process,
        remote_bootstrap_mem,
        &dll_info as *const DllInfo as *const c_void,
        std::mem::size_of::<DllInfo>(),
        null_mut(),
    );
    if info_written == 0 {
        panic!("Failed to write DllInfo");
    }

    // realign_pe kodunu yaz (DllInfo'nun hemen ardına)
    let remote_code_addr =
        (remote_bootstrap_mem as usize + std::mem::size_of::<DllInfo>()) as *mut c_void;

    let code_written = WriteProcessMemory(
        h_process,
        remote_code_addr,
        realign_pe as *const c_void,
        bootstrapper_size,
        null_mut(),
    );
    if code_written == 0 {
        panic!("Failed to write bootstrapper code");
    }

    println!("[+] Bootstrapper written. Launching remote thread...");

    // --- 7. Remote thread başlat ---
    // Thread start = kod başlangıcı, argüman = DllInfo pointer'ı (belleğin başı)
    let h_thread = CreateRemoteThread(
        h_process,
        null(),
        0,
        std::mem::transmute(remote_code_addr),
        remote_bootstrap_mem, // DllInfo pointer olarak geçir
        0,
        null_mut(),
    );

    if h_thread == 0 {
        panic!("Failed to create remote thread");
    }

    println!("[+] Remote thread created: {:?}", h_thread);
    WaitForSingleObject(h_thread, INFINITE);
    println!("[+] Remote thread finished.");
    CloseHandle(h_thread);
}