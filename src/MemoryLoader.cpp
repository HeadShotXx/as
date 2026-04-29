#include "MemoryLoader.hpp"
#include <iostream>

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

HMODULE MemoryLoader::Load(const std::vector<unsigned char>& buffer) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return nullptr;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // 1. Allocate memory for the image
    void* imageBase = VirtualAlloc(nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!imageBase) return nullptr;

    // 2. Copy headers
    memcpy(imageBase, buffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

    // 3. Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            memcpy((char*)imageBase + section->VirtualAddress, buffer.data() + section->PointerToRawData, section->SizeOfRawData);
        }
    }

    // 4. Handle Relocations
    IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size > 0) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((char*)imageBase + relocDir.VirtualAddress);
        uintptr_t delta = (uintptr_t)((char*)imageBase - ntHeaders->OptionalHeader.ImageBase);

        while (reloc->VirtualAddress != 0) {
            DWORD size = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD entry = (PWORD)(reloc + 1);

            for (DWORD i = 0; i < size; i++) {
                int type = entry[i] >> 12;
                int offset = entry[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* pdw = (uint32_t*)((char*)imageBase + reloc->VirtualAddress + offset);
                    *pdw += (uint32_t)delta;
                }
#ifdef _WIN64
                else if (type == IMAGE_REL_BASED_DIR64) {
                    uint64_t* pdw = (uint64_t*)((char*)imageBase + reloc->VirtualAddress + offset);
                    *pdw += (uint64_t)delta;
                }
#endif
            }
            reloc = (PIMAGE_BASE_RELOCATION)((char*)reloc + reloc->SizeOfBlock);
        }
    }

    // 5. Handle IAT
    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)imageBase + importDir.VirtualAddress);
        while (importDesc->Name != 0) {
            char* libName = (char*)imageBase + importDesc->Name;
            HMODULE hLib = LoadLibraryA(libName);
            if (hLib) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((char*)imageBase + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((char*)imageBase + importDesc->OriginalFirstThunk);

                while (thunk->u1.AddressOfData != 0) {
                    FARPROC funcAddr;
                    if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        funcAddr = GetProcAddress(hLib, (LPCSTR)(originalThunk->u1.Ordinal & 0xFFFF));
                    } else {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((char*)imageBase + originalThunk->u1.AddressOfData);
                        funcAddr = GetProcAddress(hLib, importByName->Name);
                    }
                    thunk->u1.Function = (uintptr_t)funcAddr;
                    thunk++;
                    originalThunk++;
                }
            }
            importDesc++;
        }
    }

    // 6. Call DllMain
    if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        DllMainFunc dllMain = (DllMainFunc)((char*)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        dllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, nullptr);
    }

    return (HMODULE)imageBase;
}

FARPROC MemoryLoader::GetExportAddress(HMODULE hMod, const std::string& funcName) {
    if (!hMod) return nullptr;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)hMod + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDir.Size == 0) return nullptr;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((char*)hMod + exportDir.VirtualAddress);
    PDWORD names = (PDWORD)((char*)hMod + exports->AddressOfNames);
    PWORD ordinals = (PWORD)((char*)hMod + exports->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)((char*)hMod + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)hMod + names[i];
        if (funcName == name) {
            return (FARPROC)((char*)hMod + functions[ordinals[i]]);
        }
    }

    return nullptr;
}
