#ifndef MEMORYLOADER_HPP
#define MEMORYLOADER_HPP

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

class MemoryLoader {
public:
    static HMODULE Load(const std::vector<unsigned char>& buffer);
    static FARPROC GetExportAddress(HMODULE hMod, const std::string& funcName);
};

#endif
