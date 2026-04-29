#ifndef SYSINFO_HPP
#define SYSINFO_HPP

#include <string>
#include "json.hpp"

using json = nlohmann::json;

class SysInfo {
public:
    // Tüm bu fonksiyonları public altına taşıyoruz
    static json getAllInfo();
    static std::string getOS();
    static std::string getPCName();
    static std::string getAntivirus();
    static std::string getRegValue(void* hKeyRoot, const char* subKey, const char* valueName);
    static std::string getCPU();
    static std::string getRAM();
    static std::string getGPU();
    static std::string getUsername();
    static std::string getHDDSerial();
    static std::string getMacAddress();
    static std::string getBattery();
    static std::string getUptime();
    static std::string getListDrivers();
    static std::string getListUSB();
};

#endif