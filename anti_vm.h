#ifndef ANTI_VM_H
#define ANTI_VM_H

#include <vector>
#include <string>
#include <array>
#include <cstring> // For memcpy

// --- Platform-specific includes ---
#if defined(_WIN32)
    #include <winsock2.h>
    #include <iphlpapi.h>
    #include <ws2tcpip.h>
    #include <tlhelp32.h>
    #include <winreg.h>
    #include <shlobj.h>
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "shell32.lib")
    #if defined(_MSC_VER)
        #include <intrin.h>
    #endif
#elif defined(__linux__)
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <dirent.h>
    #include <unistd.h>
    #include <fstream>
    #include <sstream>
    #include <sys/stat.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif


namespace AntiVM {

    // Forward declarations for the check functions
    inline bool checkCPUID();
    inline bool checkMACAddress();
    inline bool checkProcesses();
    inline bool checkRegistry();
    inline bool checkFileSystem();

    // --- Main Detection Function ---
    inline bool isVM() {
        return checkCPUID() ||
               checkMACAddress() ||
               checkProcesses() ||
               checkRegistry() ||
               checkFileSystem();
    }

    // --- CPUID Checks ---
    inline void cpuid(int function_id, std::array<int, 4>& registers) {
#if defined(_MSC_VER)
        __cpuidex(registers.data(), function_id, 0);
#elif defined(__GNUC__) || defined(__clang__)
        __cpuid_count(function_id, 0, registers[0], registers[1], registers[2], registers[3]);
#else
        registers.fill(0);
#endif
    }

    inline bool checkHypervisorBit() {
        std::array<int, 4> registers;
        cpuid(1, registers);
        return (registers[2] & (1 << 31)) != 0;
    }

    inline bool checkHypervisorBrand() {
        std::array<int, 4> registers;
        cpuid(0x40000000, registers);

        char vendor[13];
        memcpy(vendor, &registers[1], 4);
        memcpy(vendor + 4, &registers[2], 4);
        memcpy(vendor + 8, &registers[3], 4);
        vendor[12] = '\0';

        const std::vector<std::string> vm_vendors = {
            "VMwareVMware", "Microsoft Hv", "KVMKVMKVM", "VBoxVBoxVBox", "XenVMMXenVMM", "prl hyperv"
        };

        std::string vendor_str(vendor);
        for (const auto& vm_vendor : vm_vendors) {
            if (vendor_str.find(vm_vendor) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    inline bool checkCPUID() {
        return checkHypervisorBit() || checkHypervisorBrand();
    }

    // --- MAC Address Check ---
    inline bool checkMACAddress() {
        const std::vector<std::string> vm_mac_prefixes = {
            //"00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
            //"08:00:27", "0A:00:27",                         // VirtualBox
            //"00:03:FF", "00:15:5D",                         // Microsoft Hyper-V
            //"00:16:3E",                                     // Xen
            //"00:A0:B1"                                      // Parallels
        };

#if defined(_WIN32)
        ULONG buffer_size = 0;
        if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &buffer_size) != ERROR_BUFFER_OVERFLOW) {
            return false;
        }

        std::vector<BYTE> buffer(buffer_size);
        PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)buffer.data();

        if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &buffer_size) != NO_ERROR) {
            return false;
        }

        for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next) {
            if (adapter->PhysicalAddressLength != 6) continue;

            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     adapter->PhysicalAddress[0], adapter->PhysicalAddress[1], adapter->PhysicalAddress[2],
                     adapter->PhysicalAddress[3], adapter->PhysicalAddress[4], adapter->PhysicalAddress[5]);

            std::string mac(mac_str);
            for (const auto& prefix : vm_mac_prefixes) {
                if (mac.rfind(prefix, 0) == 0) {
                    return true;
                }
            }
        }
#elif defined(__linux__)
        struct if_nameindex* if_nidxs = if_nameindex();
        if (if_nidxs == nullptr) {
            return false;
        }

        for (struct if_nameindex* intf = if_nidxs; intf->if_index != 0 || intf->if_name != nullptr; intf++) {
            std::string mac_path = "/sys/class/net/" + std::string(intf->if_name) + "/address";
            std::ifstream mac_file(mac_path);
            if (mac_file.is_open()) {
                std::string mac_addr;
                mac_file >> mac_addr;
                for (char &c : mac_addr) c = toupper(c);

                for (const auto& prefix : vm_mac_prefixes) {
                    if (mac_addr.rfind(prefix, 0) == 0) {
                        if_freenameindex(if_nidxs);
                        return true;
                    }
                }
            }
        }
        if_freenameindex(if_nidxs);
#endif
        return false;
    }

    // --- Process Check ---
    inline bool checkProcesses() {
        const std::vector<std::string> vm_processes = {
            // VMware
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmacthlp.exe",
            // VirtualBox
            "VBoxService.exe", "VBoxTray.exe",
            // Parallels
            "prl_cc.exe", "prl_tools.exe",
            // QEMU
            "qemu-ga.exe"
        };

#if defined(_WIN32)
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return false;
        }

        do {
            std::string process_name(pe32.szExeFile);
            for (const auto& vm_process : vm_processes) {
                if (process_name == vm_process) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
#elif defined(__linux__)
        DIR* dir = opendir("/proc");
        if (dir == nullptr) {
            return false;
        }

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_DIR) {
                char* endptr;
                long pid = strtol(entry->d_name, &endptr, 10);
                if (*endptr == '\0') { // It's a numeric directory (a PID)
                    std::string cmdline_path = std::string("/proc/") + entry->d_name + "/comm";
                    std::ifstream cmdline_file(cmdline_path);
                    if (cmdline_file.is_open()) {
                        std::string process_name;
                        cmdline_file >> process_name;
                        for (const auto& vm_process : vm_processes) {
                            if (process_name == vm_process) {
                                closedir(dir);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        closedir(dir);
#endif
        return false;
    }

    // --- Registry Check (Windows specific) ---
    inline bool checkRegistry() {
#if defined(_WIN32)
        const std::vector<std::pair<HKEY, std::string>> vm_reg_keys = {
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools"},
            {HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__"},
            {HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\RSDT\\VBOX__"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxGuest"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxMouse"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxService"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxSF"},
            {HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxVideo"}
        };

        for (const auto& key_pair : vm_reg_keys) {
            HKEY hKey;
            if (RegOpenKeyExA(key_pair.first, key_pair.second.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
        }
#endif
        return false;
    }

    // --- File System Check ---
    inline bool checkFileSystem() {
        const std::vector<std::string> vm_files_dirs = {
    #if defined(_WIN32)
            // VMware
            "\\system32\\drivers\\vmmouse.sys",
            "\\system32\\drivers\\vmhgfs.sys",
            "\\system32\\drivers\\vmx_svga.sys",
            "\\system32\\drivers\\vmci.sys",
            "\\system32\\drivers\\vmxnet.sys",
            "\\Program Files\\VMware\\VMware Tools\\",
            // VirtualBox
            "\\system32\\drivers\\VBoxMouse.sys",
            "\\system32\\drivers\\VBoxGuest.sys",
            "\\system32\\drivers\\VBoxSF.sys",
            "\\system32\\drivers\\VBoxVideo.sys",
            "\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
            // QEMU
            "\\system32\\drivers\\qemupciserial.sys"

    #elif defined(__linux__)
            // VMware
            "/usr/bin/vmware-toolbox-cmd",
            "/etc/vmware-tools",
            // VirtualBox
            "/usr/lib/virtualbox/VBoxGuestAdditions.so",
            "/etc/init.d/vboxadd",
            "/dev/vboxguest",
            // KVM/QEMU
            "/dev/virtio-ports/com.redhat.spice.0"
    #endif
        };

        for (const auto& path : vm_files_dirs) {
    #if defined(_WIN32)
            std::string full_path;
            if (path.rfind("\\system32\\", 0) == 0) {
                char system_root[MAX_PATH];
                if (GetEnvironmentVariableA("SystemRoot", system_root, MAX_PATH) == 0) continue;
                full_path = std::string(system_root) + path;
            } else if (path.rfind("\\Program Files\\", 0) == 0) {
                char pf_path[MAX_PATH];
                if (SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, pf_path) != S_OK) continue;
                full_path = std::string(pf_path) + path.substr(strlen("\\Program Files"));
            } else {
                continue;
            }

            DWORD attribs = GetFileAttributesA(full_path.c_str());
            if (attribs != INVALID_FILE_ATTRIBUTES) {
                return true;
            }
    #elif defined(__linux__)
            struct stat buffer;
            if (stat(path.c_str(), &buffer) == 0) {
                return true;
            }
    #endif
        }
        return false;
    }
}

#endif // ANTI_VM_H