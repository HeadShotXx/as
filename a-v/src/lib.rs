use rustpolymorphic::{polymorph, obf_str};
use raw_cpuid::CpuId;

use std::ffi::OsStr;

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};

use windows::Win32::Foundation::CloseHandle;

use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};

use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows::Win32::System::Diagnostics::ToolHelp::{
	
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Registry::{
	
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
	
};
use windows::Win32::System::SystemInformation::{
    GetPhysicallyInstalledSystemMemory, GetSystemInfo, SYSTEM_INFO,
};

#[polymorph(fn_len = 10, garbage = true)]
pub fn check_cpuid_hypervisor() -> bool {
    let cpuid = CpuId::new();
    if let Some(hypervisor_info) = cpuid.get_hypervisor_info() {
        match hypervisor_info.identify() {
            raw_cpuid::Hypervisor::VMware
            | raw_cpuid::Hypervisor::KVM
            | raw_cpuid::Hypervisor::HyperV
            | raw_cpuid::Hypervisor::Xen
            | raw_cpuid::Hypervisor::QEMU => true,
            raw_cpuid::Hypervisor::Unknown(ebx, ecx, edx) => {
                let mut vendor_id: [u8; 12] = [0; 12];
                vendor_id[0..4].copy_from_slice(&ebx.to_le_bytes());
                vendor_id[4..8].copy_from_slice(&ecx.to_le_bytes());
                vendor_id[8..12].copy_from_slice(&edx.to_le_bytes());
                let vendor = std::str::from_utf8(&vendor_id).unwrap_or("");
                matches!(vendor, "VBoxVBoxVBox" | "prl hyperv")
            }
            _ => false,
        }
    } else {
        false
    }
}

#[polymorph(fn_len = 20, garbage = true)]
pub fn check_memory_size() -> bool {
    let mut total_memory_in_kb: u64 = 0;
    if unsafe { GetPhysicallyInstalledSystemMemory(&mut total_memory_in_kb) }.is_ok() {
        let total_memory_in_gb = total_memory_in_kb / 1024 / 1024;
        let common_vm_sizes = [1, 2, 4];
        common_vm_sizes.contains(&total_memory_in_gb)
    } else {
        false
    }
}

#[polymorph(fn_len = 30, garbage = true)]
pub fn check_mac_address() -> bool {
    let mut buffer_size: u32 = 0;
    unsafe {
        GetAdaptersInfo(None, &mut buffer_size);
    }

    if buffer_size == 0 {
        return false;
    }

    let mut adapter_info_buffer: Vec<u8> = vec![0; buffer_size as usize];
    let adapter_info_ptr = adapter_info_buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

    if unsafe { GetAdaptersInfo(Some(adapter_info_ptr), &mut buffer_size) } == 0 {
        let vm_mac_prefixes = [
            obf_str!("00:05:69"),
            obf_str!("00:0C:29"),
            obf_str!("00:1C:14"),
            obf_str!("00:50:56"),
            obf_str!("08:00:27"),
            obf_str!("00:1C:42"),
            obf_str!("52:54:00"),
        ];

        let mut current_adapter = adapter_info_ptr;
        while !current_adapter.is_null() {
            let mac_address_len = unsafe { (*current_adapter).AddressLength } as usize;
            if mac_address_len == 6 {
                let mac_address_slice = unsafe { &(&(*current_adapter).Address)[0..mac_address_len] };
                let mac_address_str = mac_address_slice
                    .iter()
                    .map(|&byte| format!("{:02X}", byte))
                    .collect::<Vec<String>>()
                    .join(":");

                for prefix in &vm_mac_prefixes {
                    if mac_address_str.starts_with(&**prefix) {
                        return true;
                    }
                }
            }
            current_adapter = unsafe { (*current_adapter).Next };
        }
    }

    false
}

#[polymorph(fn_len = 15, garbage = true)]
pub fn check_bios() -> bool {
    let mut key_handle: HKEY = HKEY(0);
    let subkey_pcwstr = to_pcwstr(&obf_str!("HARDWARE\\DESCRIPTION\\System"));
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_pcwstr.as_ptr()),
            0,
            KEY_READ,
            &mut key_handle,
        )
    }
    .is_err()
    {
        return false;
    }

    let vm_bios_strings = [
        obf_str!("VMware"),
        obf_str!("VirtualBox"),
        obf_str!("QEMU"),
        obf_str!("Hyper-V"),
        obf_str!("Parallels"),
        obf_str!("Xen"),
    ];
    let value_names = [obf_str!("SystemBiosVersion"), obf_str!("VideoBiosVersion")];

    for value_name in &value_names {
        let mut buffer: [u16; 256] = [0; 256];
        let mut buffer_size = (buffer.len() * std::mem::size_of::<u16>()) as u32;
        let value_name_pcwstr = to_pcwstr(&**value_name);
        if unsafe {
            RegQueryValueExW(
                key_handle,
                PCWSTR(value_name_pcwstr.as_ptr()),
                None,
                None,
                Some(buffer.as_mut_ptr() as *mut u8),
                Some(&mut buffer_size),
            )
        }
        .is_ok()
        {
            let value = String::from_utf16_lossy(&buffer[..buffer_size as usize / 2]);
            for vm_string in &vm_bios_strings {
                if value.contains(&**vm_string) {
                    unsafe {
                        let _ = RegCloseKey(key_handle);
                    };
                    return true;
                }
            }
        }
    }

    unsafe {
        let _ = RegCloseKey(key_handle);
    };
    false
}

#[polymorph(fn_len = 12, garbage = true)]
pub fn check_cpu_cores() -> bool {
    let mut system_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetSystemInfo(&mut system_info);
    }
    matches!(system_info.dwNumberOfProcessors, 1 | 2)
}

#[polymorph(fn_len = 25, garbage = true)]
pub fn check_disk_size() -> bool {
    let mut total_number_of_bytes: u64 = 0;
    let root_path = to_pcwstr(&obf_str!("C:\\"));
    if unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(root_path.as_ptr()),
            None,
            Some(&mut total_number_of_bytes),
            None,
        )
    }
    .is_ok()
    {
        let common_vm_sizes = [
            60 * 1024 * 1024 * 1024,
            80 * 1024 * 1024 * 1024,
            100 * 1024 * 1024 * 1024,
        ];
        common_vm_sizes.contains(&total_number_of_bytes)
    } else {
        false
    }
}

#[polymorph(fn_len = 35, garbage = true)]
pub fn check_display_adapter() -> bool {
    let mut video_key_handle: HKEY = HKEY(0);
    let video_key_path = to_pcwstr(&obf_str!("SYSTEM\\CurrentControlSet\\Control\\Video"));
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(video_key_path.as_ptr()),
            0,
            KEY_READ,
            &mut video_key_handle,
        )
    }
    .is_err()
    {
        return false;
    }

    let vm_adapters = [
        obf_str!("VMware SVGA"),
        obf_str!("VirtualBox Graphics Adapter"),
        obf_str!("Hyper-V Video"),
        obf_str!("QEMU Standard VGA"),
        obf_str!("Parallels Display Adapter"),
    ];

    let mut i = 0;
    loop {
        let mut subkey_name_buffer: [u16; 256] = [0; 256];
        let mut subkey_name_len = subkey_name_buffer.len() as u32;
        if unsafe {
            RegEnumKeyExW(
                video_key_handle,
                i,
                PWSTR(subkey_name_buffer.as_mut_ptr()),
                &mut subkey_name_len,
                None,
                PWSTR(std::ptr::null_mut()),
                None,
                None,
            )
        }
        .is_err()
        {
            break;
        }
        i += 1;

        let subkey_name =
            String::from_utf16_lossy(&subkey_name_buffer[..subkey_name_len as usize]);
        let adapter_key_path =
            format!("SYSTEM\\CurrentControlSet\\Control\\Video\\{}\\0000", subkey_name);
        let mut adapter_key_handle: HKEY = HKEY(0);
        let adapter_key_pcwstr = to_pcwstr(&adapter_key_path);
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(adapter_key_pcwstr.as_ptr()),
                0,
                KEY_READ,
                &mut adapter_key_handle,
            )
        }
        .is_ok()
        {
            let value_name = to_pcwstr(&obf_str!("DriverDesc"));
            let mut buffer: [u16; 256] = [0; 256];
            let mut buffer_size = (buffer.len() * std::mem::size_of::<u16>()) as u32;
            if unsafe {
                RegQueryValueExW(
                    adapter_key_handle,
                    PCWSTR(value_name.as_ptr()),
                    None,
					
                    None,
					
                    Some(buffer.as_mut_ptr() as *mut u8),
                    Some(&mut buffer_size),
                )
            }
            .is_ok()
            {
                let value = String::from_utf16_lossy(&buffer[..buffer_size as usize / 2]);
                for vm_adapter in &vm_adapters {
                    if value.contains(&**vm_adapter) {
                        unsafe {
                            let _ = RegCloseKey(adapter_key_handle);
                            let _ = RegCloseKey(video_key_handle);
                        };
                        return true;
                    }
                }
            }
            unsafe {
                let _ = RegCloseKey(adapter_key_handle);
            };
        }
    }

    unsafe {
        let _ = RegCloseKey(video_key_handle);
    };
    false
}

#[polymorph(fn_len = 18, garbage = true)]
pub fn check_pci_devices() -> bool {
    let mut pci_key_handle: HKEY = HKEY(0);
    let pci_key_path = to_pcwstr(&obf_str!("SYSTEM\\CurrentControlSet\\Enum\\PCI"));
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(pci_key_path.as_ptr()),
            0,
            KEY_READ,
            &mut pci_key_handle,
        )
    }
    .is_err()
    {
        return false;
    }

    let vm_pci_devices = [
        obf_str!("VMware VMCI"),
        obf_str!("VirtualBox Guest Service"),
        obf_str!("Red Hat VirtIO"),
    ];

    let mut i = 0;
    loop {
        let mut subkey_name_buffer: [u16; 256] = [0; 256];
        let mut subkey_name_len = subkey_name_buffer.len() as u32;
        if unsafe {
            RegEnumKeyExW(
                pci_key_handle,
                i,
                PWSTR(subkey_name_buffer.as_mut_ptr()),
                &mut subkey_name_len,
                None,
                PWSTR(std::ptr::null_mut()),
                None,
                None,
            )
        }
        .is_err()
        {
            break;
        }
        i += 1;

        let subkey_name =
            String::from_utf16_lossy(&subkey_name_buffer[..subkey_name_len as usize]);
        let device_key_path = format!("SYSTEM\\CurrentControlSet\\Enum\\PCI\\{}", subkey_name);
		
        let mut device_key_handle: HKEY = HKEY(0);
        let device_key_pcwstr = to_pcwstr(&device_key_path);
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(device_key_pcwstr.as_ptr()),
                0,
                KEY_READ,
                &mut device_key_handle,
            )
        }
        .is_ok()
        {
            let value_name = to_pcwstr(&obf_str!("DeviceDesc"));
            let mut buffer: [u16; 256] = [0; 256];
            let mut buffer_size = (buffer.len() * std::mem::size_of::<u16>()) as u32;
            if unsafe {
                RegQueryValueExW(
                    device_key_handle,
                    PCWSTR(value_name.as_ptr()),
                    None,
                    None,
                    Some(buffer.as_mut_ptr() as *mut u8),
                    Some(&mut buffer_size),
                )
            }
            .is_ok()
            {
                let value = String::from_utf16_lossy(&buffer[..buffer_size as usize / 2]);
                for vm_device in &vm_pci_devices {
                    if value.contains(&**vm_device) {
                        unsafe {
                            let _ = RegCloseKey(device_key_handle);
                            let _ = RegCloseKey(pci_key_handle);
                        };
                        return true;
                    }
                }
            }
            unsafe {
                let _ = RegCloseKey(device_key_handle);
            };
        }
    }

    unsafe {
        let _ = RegCloseKey(pci_key_handle);
    };
    false
}

#[polymorph(fn_len = 22, garbage = true)]
pub fn check_drivers() -> bool {
    let mut services_key_handle: HKEY = HKEY(0);
    let services_key_path = to_pcwstr(&obf_str!("SYSTEM\\CurrentControlSet\\Services"));
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(services_key_path.as_ptr()),
            0,
            KEY_READ,
            &mut services_key_handle,
        )
    }
    .is_err()
    {
        return false;
    }

    let vm_drivers = [
        obf_str!("virtio"),
        obf_str!("vmxnet"),
        obf_str!("pvscsi"),
        obf_str!("vboxguest"),
        obf_str!("vmware"),
        obf_str!("vmusb"),
        obf_str!("vmx86"),
    ];

    let mut i = 0;
    loop {
        let mut subkey_name_buffer: [u16; 256] = [0; 256];
        let mut subkey_name_len = subkey_name_buffer.len() as u32;
        if unsafe {
            RegEnumKeyExW(
                services_key_handle,
                i,
                PWSTR(subkey_name_buffer.as_mut_ptr()),
                &mut subkey_name_len,
                None,
                PWSTR(std::ptr::null_mut()),
                None,
                None,
            )
        }
        .is_err()
        {
            break;
        }
        i += 1;

        let subkey_name =
            String::from_utf16_lossy(&subkey_name_buffer[..subkey_name_len as usize]);
        let service_key_path = format!("SYSTEM\\CurrentControlSet\\Services\\{}", subkey_name);
        let mut service_key_handle: HKEY = HKEY(0);
        let service_key_pcwstr = to_pcwstr(&service_key_path);
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(service_key_pcwstr.as_ptr()),
                0,
                KEY_READ,
                &mut service_key_handle,
            )
        }
        .is_ok()
        {
            let value_name = to_pcwstr(&obf_str!("ImagePath"));
            let mut buffer: [u16; 256] = [0; 256];
            let mut buffer_size = (buffer.len() * std::mem::size_of::<u16>()) as u32;
            if unsafe {
                RegQueryValueExW(
                    service_key_handle,
                    PCWSTR(value_name.as_ptr()),
                    None,
                    None,
                    Some(buffer.as_mut_ptr() as *mut u8),
                    Some(&mut buffer_size),
                )
            }
            .is_ok()
            {
                let value = String::from_utf16_lossy(&buffer[..buffer_size as usize / 2]);
                for vm_driver in &vm_drivers {
                    if value.contains(&**vm_driver) {
                        unsafe {
                            let _ = RegCloseKey(service_key_handle);
                            let _ = RegCloseKey(services_key_handle);
                        };
                        return true;
                    }
                }
            }
            unsafe {
                let _ = RegCloseKey(service_key_handle);
            };
        }
    }

    unsafe {
        let _ = RegCloseKey(services_key_handle);
    };
    false
}

fn to_pcwstr(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

#[polymorph(fn_len = 10, garbage = true)]
pub fn check_vm_registry_keys() -> bool {
    let vm_keys = [
        obf_str!("SOFTWARE\\VMware, Inc.\\VMware Tools"),
        obf_str!("SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"),
        obf_str!("SYSTEM\\CurrentControlSet\\Services\\VBoxMouse"),
        obf_str!("SYSTEM\\CurrentControlSet\\Services\\VBoxSF"),
		
        obf_str!("SYSTEM\\CurrentControlSet\\Services\\VBoxVideo"),
    ];

    for key_path in &vm_keys {
        let subkey_pcwstr = to_pcwstr(&**key_path);
        let mut key_handle: HKEY = HKEY(0);
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_pcwstr.as_ptr()),
                0,
                KEY_READ,
                &mut key_handle,
            )
        };

        if result.is_ok() {
            unsafe {
                let _ = RegCloseKey(key_handle);
            };
            return true;
        }
    }

    false
}

#[polymorph(fn_len = 28, garbage = true)]
pub fn check_vm_processes() -> bool {
    let snapshot_handle = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => handle,
        Err(_) => return false,
    };

    if snapshot_handle.is_invalid() {
        return false;
    }

    let mut process_entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot_handle, &mut process_entry) }.is_err() {
        unsafe {
            let _ = CloseHandle(snapshot_handle);
        };
        return false;
    }

    let vm_processes = [
        obf_str!("vmtoolsd.exe"),
        obf_str!("VMwareService.exe"),
        obf_str!("VMwareTray.exe"),
        obf_str!("VBoxService.exe"),
        obf_str!("VBoxTray.exe"),
        obf_str!("qemu-ga.exe"),
        obf_str!("prl_tools_service.exe"),
    ];

    loop {
        let exe_file_slice = {
            let len = process_entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(process_entry.szExeFile.len());
            &process_entry.szExeFile[..len]
        };
        let process_name = String::from_utf16_lossy(exe_file_slice);
        for vm_process in &vm_processes {
            if process_name.eq_ignore_ascii_case(&**vm_process) {
                unsafe {
                    let _ = CloseHandle(snapshot_handle);
                };
                return true;
            }
        }

        if unsafe { Process32NextW(snapshot_handle, &mut process_entry) }.is_err() {
            break;
        }
    }

    unsafe {
        let _ = CloseHandle(snapshot_handle);
    };
    false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[polymorph(fn_len = 10, garbage = true)]
pub fn check_rdtsc_timing() -> bool {
    use std::arch::x86_64::_rdtsc;
    const SAMPLES: u32 = 10;
    const THRESHOLD: u64 = 1000;
    let mut total_diff: u64 = 0;
    for _ in 0..SAMPLES {
        let t1 = unsafe { _rdtsc() };
        let t2 = unsafe { _rdtsc() };
        let diff = t2 - t1;
        total_diff += diff;
    }
    let avg_diff = total_diff / SAMPLES as u64;
    avg_diff > THRESHOLD
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_rdtsc_timing() -> bool {
    false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[polymorph(fn_len = 10, garbage = true)]
pub fn check_cpuid_timing() -> bool {
    use std::arch::x86_64::_rdtsc;
    use raw_cpuid::CpuId;
    const SAMPLES: u32 = 10;
    const THRESHOLD: u64 = 400;
    let mut total_diff: u64 = 0;
    for _ in 0..SAMPLES {
        let t1 = unsafe { _rdtsc() };
        let _cpuid = CpuId::new();
        let t2 = unsafe { _rdtsc() };
        let diff = t2 - t1;
        total_diff += diff;
    }
    let avg_diff = total_diff / SAMPLES as u64;
    avg_diff > THRESHOLD
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn check_cpuid_timing() -> bool {
    false
}

#[polymorph(fn_len = 10, garbage = true)]
pub fn check_filesystem_artifacts() -> bool {
    let vm_dirs = [
        obf_str!("C:\\Program Files\\VMware"),
        obf_str!("C:\\Program Files\\Oracle"),
        obf_str!("C:\\Program Files\\VirtualBox"),
        obf_str!("C:\\Program Files\\Parallels"),
        obf_str!("C:\\Program Files\\QEMU"),
    ];

    for dir in &vm_dirs {
        if Path::new(&**dir).exists() {
            return true;
        }
    }

    false
}

#[polymorph(fn_len = 40, garbage = true, control_flow = true)]
pub fn is_virtualized() -> bool {
    check_cpuid_hypervisor()
        || check_mac_address()
        || check_bios()
        || check_cpu_cores()
        || check_memory_size()
        || check_disk_size()
        || check_display_adapter()
        || check_pci_devices()
        || check_drivers()
        || check_vm_registry_keys()
        || check_vm_processes()
        || check_rdtsc_timing()
}
