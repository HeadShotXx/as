#ifndef MEMORYLOADER_HPP
#define MEMORYLOADER_HPP

#include <vector>
#include <windows.h>

class MemoryLoader {
public:
    // DLL buffer'ını belleğe yükler ve HMODULE döner
    static HMODULE Load(const std::vector<unsigned char>& buffer);
};

#endif