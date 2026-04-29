#ifndef PLUGINMANAGER_HPP
#define PLUGINMANAGER_HPP

#include <string>
#include <map>
#include <vector>
#include <windows.h>
#include <winsock2.h>

class PluginManager {
private:
    std::map<std::string, HMODULE> loadedPlugins;

public:
    bool isPluginLoaded(const std::string& pluginId);
    bool loadPluginFromMemory(const std::string& pluginId, const std::vector<unsigned char>& buffer);
    bool loadPluginFromFile(const std::string& pluginId, const std::string& filePath);
    void executePlugin(const std::string& pluginId, const std::string& funcName, SOCKET serverSock);
};

#endif