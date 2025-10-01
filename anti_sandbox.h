#ifndef ANTI_SANDBOX_H
#define ANTI_SANDBOX_H

// This header contains functions to detect sandbox and virtualized environments.
// The techniques used are a combination of CPU, memory, hardware, and artifact checks.

#ifdef _WIN32
#include <windows.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <Iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#else
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <linux/if_packet.h>
#endif

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <algorithm>

namespace AntiSandbox {

    // Checks if the CPUID hypervisor bit is set, indicating a virtualized environment.
    bool check_cpuid() {
#ifdef _WIN32
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        return (cpuInfo[2] >> 31) & 1;
#elif defined(__GNUC__) || defined(__clang__)
        unsigned int eax, ebx, ecx, edx;
        eax = 1;
        __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "0"(eax));
        return (ecx >> 31) & 1;
#else
        return false; // Unsupported compiler
#endif
    }

    // Performs a timing attack to detect sandbox execution.
    // Many sandboxes patch sleep-related functions to return immediately,
    // causing the sleep duration to be unnaturally short.
    bool check_timing() {
        const int sleep_duration_ms = 500;
        auto start = std::chrono::high_resolution_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_duration_ms));
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start;

        // If the sleep duration was significantly less than expected, it's a sign of a sandbox.
        // We allow a small margin for system clock inaccuracies.
        return elapsed.count() < (sleep_duration_ms * 0.7);
    }

    // Checks for low RAM, which can indicate a sandbox environment.
    bool check_ram() {
#ifdef _WIN32
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        GlobalMemoryStatusEx(&status);
        return status.ullTotalPhys / (1024 * 1024) < 2048; // Less than 2GB RAM
#else
        long pages = sysconf(_SC_PHYS_PAGES);
        long page_size = sysconf(_SC_PAGE_SIZE);
        return pages * page_size / (1024 * 1024) < 2048; // Less than 2GB RAM
#endif
    }

    // Checks for known VM MAC addresses.
    bool check_mac_address() {
        std::vector<std::string> vm_mac_prefixes = {
            "00:05:69", // VMware
            "00:0C:29", // VMware
            "00:1C:14", // VMware
            "00:50:56", // VMware
            "08:00:27"  // VirtualBox
        };

#ifdef _WIN32
        ULONG bufferSize = 0;
        if (GetAdaptersInfo(NULL, &bufferSize) != ERROR_BUFFER_OVERFLOW) {
            return false;
        }

        std::vector<BYTE> buffer(bufferSize);
        PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

        if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_SUCCESS) {
            while (pAdapterInfo) {
                char mac_addr[18];
                sprintf_s(mac_addr, sizeof(mac_addr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    pAdapterInfo->Address[0], pAdapterInfo->Address[1],
                    pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                    pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

                std::string mac_str(mac_addr);
                for (const auto& prefix : vm_mac_prefixes) {
                    if (mac_str.rfind(prefix, 0) == 0) {
                        return true;
                    }
                }
                pAdapterInfo = pAdapterInfo->Next;
            }
        }
#else
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            return false;
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                char mac_addr[18];
                sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
                    s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                    s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);

                std::string mac_str(mac_addr);
                for (const auto& prefix : vm_mac_prefixes) {
                    if (mac_str.rfind(prefix, 0) == 0) {
                        freeifaddrs(ifaddr);
                        return true;
                    }
                }
            }
        }
        freeifaddrs(ifaddr);
#endif
        return false;
    }

    // Checks for common VM hardware names in the registry (Windows).
    bool check_hardware_names() {
#ifdef _WIN32
        const char* devices[] = {
            "\\\\.\\VBoxGuest",
            "\\\\.\\VBoxMouse",
            "\\\\.\\VBoxVideo",
            "\\\\.\\VMware"
        };

        for (const char* device : devices) {
            HANDLE hFile = CreateFileA(device, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                return true;
            }
        }
#endif
        return false;
    }

    // Checks for Linux-specific VM artifacts.
    bool check_linux_artifacts() {
#ifndef _WIN32
        // Check for virtualization strings in /sys/class/dmi/id/
        std::vector<std::string> dmi_files = {
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor"
        };
        std::vector<std::string> vm_strings = {
            "VMware", "VirtualBox", "KVM", "QEMU"
        };

        for (const auto& file_path : dmi_files) {
            std::ifstream file(file_path);
            if (file.is_open()) {
                std::string line;
                while (std::getline(file, line)) {
                    for (const auto& vm_str : vm_strings) {
                        if (line.find(vm_str) != std::string::npos) {
                            return true;
                        }
                    }
                }
            }
        }
#endif
        return false;
    }

    // Checks for virtualization-related registry keys on Windows.
    bool check_registry_keys() {
#ifdef _WIN32
        const char* keys[] = {
            "HARDWARE\\ACPI\\DSDT\\VBOX__",
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
        };
        HKEY hKey;
        for (const char* key : keys) {
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
        }
#endif
        return false;
    }

    // Checks for common VM files on the system (Windows).
    bool check_vm_files() {
#ifdef _WIN32
        char systemDir[MAX_PATH];
        GetSystemDirectoryA(systemDir, MAX_PATH);

        std::vector<std::string> files = {
            std::string(systemDir) + "\\drivers\\VBoxMouse.sys",
            std::string(systemDir) + "\\drivers\\VBoxGuest.sys",
            std::string(systemDir) + "\\drivers\\vmhgfs.sys"
        };

        for (const auto& file : files) {
            if (GetFileAttributesA(file.c_str()) != INVALID_FILE_ATTRIBUTES) {
                return true;
            }
        }
#endif
        return false;
    }

    // Checks for running analysis tools.
    bool check_running_processes() {
        std::vector<std::string> process_names = {
            "wireshark.exe", "ollydbg.exe", "procexp.exe", "idaq.exe", "idaq64.exe", "gdb"
        };

#ifdef _WIN32
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (const auto& name : process_names) {
                    if (_stricmp(pe32.szExeFile, name.c_str()) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
#else
        DIR* dir = opendir("/proc");
        if (dir == NULL) {
            return false;
        }

        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                std::string pid_str = entry->d_name;
                if (std::all_of(pid_str.begin(), pid_str.end(), ::isdigit)) {
                    std::string comm_path = "/proc/" + pid_str + "/comm";
                    std::ifstream comm_file(comm_path);
                    if (comm_file.is_open()) {
                        std::string process_name;
                        std::getline(comm_file, process_name);
                        for (const auto& name : process_names) {
                            if (process_name.find(name) != std::string::npos) {
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

} // namespace AntiSandbox

#endif // ANTI_SANDBOX_H