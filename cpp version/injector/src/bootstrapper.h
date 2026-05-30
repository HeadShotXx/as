#pragma once
#include <windows.h>

typedef HINSTANCE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

struct DllInfo {
    void* base;
    pLoadLibraryA load_library_a;
    pGetProcAddress get_proc_address;
    BOOL relocation_required;
};

extern "C" void CALLBACK realign_pe(DllInfo* dll_info_ptr);
extern "C" void realign_pe_end();
