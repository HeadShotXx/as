#include "MemoryLoader.hpp"
#include <iostream>

#pragma pack(push, 1)
typedef struct _RELOC_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} RELOC_ENTRY, *PRELOC_ENTRY;
#pragma pack(pop)

HMODULE MemoryLoader::Load(const std::vector<unsigned char>& buffer) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return NULL;

    PBYTE pRawData = (PBYTE)buffer.data();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pRawData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    if (buffer.size() < (size_t)pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return NULL;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pRawData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Mimari kontrolü (x86 vs x64 mismatch engelleme)
#ifdef _WIN64
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;
#else
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return NULL;
#endif

    // 1. ImageBase için bellek ayır
    PBYTE pImageBase = (PBYTE)VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) return NULL;

    // 2. Headerları kopyala
    memcpy(pImageBase, pRawData, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // 3. Sectionları kopyala
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].VirtualAddress == 0) continue;
        if (pSectionHeader[i].SizeOfRawData > 0) {
            if (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData <= buffer.size()) {
                memcpy(pImageBase + pSectionHeader[i].VirtualAddress, pRawData + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData);
            }
        }
    }

    // 4. Relocation (Yeniden Konumlandırma) düzeltmesi
    DWORD_PTR delta = (DWORD_PTR)(pImageBase - (PBYTE)pNtHeaders->OptionalHeader.ImageBase);
    if (delta != 0) {
        auto& relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0 && relocDir.VirtualAddress != 0) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pImageBase + relocDir.VirtualAddress);
            while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntry = (PWORD)(pReloc + 1);
                for (DWORD i = 0; i < count; i++) {
                    WORD type = pEntry[i] >> 12;
                    WORD offset = pEntry[i] & 0xFFF;
                    if (type == 0) continue; // IMAGE_REL_BASED_ABSOLUTE

                    PBYTE pTarget = pImageBase + pReloc->VirtualAddress + offset;
                    if (type == 10) { // IMAGE_REL_BASED_DIR64
                        *((PULONGLONG)pTarget) += (ULONGLONG)delta;
                    } else if (type == 3) { // IMAGE_REL_BASED_HIGHLOW
                        *((PDWORD)pTarget) += (DWORD)delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    // 5. IAT (Import Address Table) çözümleme
    auto& importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0 && importDir.VirtualAddress != 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBase + importDir.VirtualAddress);
        while (pImportDesc->Name != 0) {
            HMODULE hLib = LoadLibraryA((LPCSTR)(pImageBase + pImportDesc->Name));
            if (!hLib) {
                VirtualFree(pImageBase, 0, MEM_RELEASE);
                return NULL;
            }

            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImageBase + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (pImportDesc->OriginalFirstThunk != 0) ?
                (PIMAGE_THUNK_DATA)(pImageBase + pImportDesc->OriginalFirstThunk) : pThunk;

            while (pOrigThunk->u1.AddressOfData != 0) {
                FARPROC proc = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                    proc = GetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(pImageBase + pOrigThunk->u1.AddressOfData);
                    proc = GetProcAddress(hLib, (LPCSTR)pIBN->Name);
                }

                if (!proc) {
                    VirtualFree(pImageBase, 0, MEM_RELEASE);
                    return NULL;
                }
                pThunk->u1.Function = (DWORD_PTR)proc;
                pThunk++;
                pOrigThunk++;
            }
            pImportDesc++;
        }
    }

    // 6. TLS Callbacks (Essential for modern C++/MinGW DLLs)
    auto& tlsDirAttr = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDirAttr.Size > 0 && tlsDirAttr.VirtualAddress != 0) {
        PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)(pImageBase + tlsDirAttr.VirtualAddress);
        if (pTlsDir->AddressOfCallBacks != 0) {
            PIMAGE_TLS_CALLBACK* ppCallback = (PIMAGE_TLS_CALLBACK*)pTlsDir->AddressOfCallBacks;
            while (ppCallback && *ppCallback) {
                (*ppCallback)((LPVOID)pImageBase, DLL_PROCESS_ATTACH, NULL);
                ppCallback++;
            }
        }
    }

    // 7. Exception Directory (x64 SEH için)
#ifdef _WIN64
    auto& exceptionDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exceptionDir.Size > 0 && exceptionDir.VirtualAddress != 0) {
        RtlAddFunctionTable(
            (PRUNTIME_FUNCTION)(pImageBase + exceptionDir.VirtualAddress),
            exceptionDir.Size / sizeof(RUNTIME_FUNCTION),
            (DWORD64)pImageBase
        );
    }
#endif

    FlushInstructionCache(GetCurrentProcess(), pImageBase, pNtHeaders->OptionalHeader.SizeOfImage);

    // 8. DllMain'i çağır
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, LPVOID);
        PDLL_MAIN pDllMain = (PDLL_MAIN)(pImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        pDllMain((HMODULE)pImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    return (HMODULE)pImageBase;
}

FARPROC MemoryLoader::GetExportAddress(HMODULE hMod, const char* name) {
    if (!hMod) return NULL;

    PBYTE pBase = (PBYTE)hMod;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    auto& exportDirAttr = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirAttr.Size == 0 || exportDirAttr.VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportDirAttr.VirtualAddress);
    PDWORD pNames = (PDWORD)(pBase + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)(pBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        if (strcmp(name, (const char*)(pBase + pNames[i])) == 0) {
            return (FARPROC)(pBase + pFunctions[pOrdinals[i]]);
        }
    }

    return NULL;
}
