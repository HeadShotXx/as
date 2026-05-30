#pragma once

#include <windows.h>
#include <winnt.h>

typedef struct _DllInfo {
    void* base;
    HINSTANCE (WINAPI *load_library_a)(const char*);
    void* (WINAPI *get_proc_address)(HINSTANCE, const char*);
    bool relocation_required;
} DllInfo;

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((section(".text")))
inline void WINAPI realign_pe(DllInfo* dll_info) {
    if (!dll_info || !dll_info->base) return;

    void* base = dll_info->base;
    auto load_library_a = dll_info->load_library_a;
    auto get_proc_address = dll_info->get_proc_address;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((ULONG_PTR)base + dos_header->e_lfanew);

    // 1. Relocations
    if (dll_info->relocation_required) {
        IMAGE_DATA_DIRECTORY reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.VirtualAddress != 0) {
            LONG_PTR delta = (LONG_PTR)base - (LONG_PTR)nt_headers->OptionalHeader.ImageBase;
            PIMAGE_BASE_RELOCATION block_ptr = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)base + reloc_dir.VirtualAddress);

            while (block_ptr->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION) && block_ptr->VirtualAddress != 0) {
                DWORD entry_count = (block_ptr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)((ULONG_PTR)block_ptr + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < entry_count; i++) {
                    WORD entry = entries[i];
                    WORD rel_type = entry >> 12;
                    WORD offset = entry & 0x0FFF;

                    if (rel_type == IMAGE_REL_BASED_DIR64) {
                        ULONG_PTR* patch = (ULONG_PTR*)((ULONG_PTR)base + block_ptr->VirtualAddress + offset);
                        *patch += delta;
                    }
                }
                block_ptr = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)block_ptr + block_ptr->SizeOfBlock);
            }
        }
    }

    // 2. Imports
    IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress != 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)base + import_dir.VirtualAddress);

        while (import_desc->Name != 0) {
            const char* lib_name = (const char*)((ULONG_PTR)base + import_desc->Name);
            HINSTANCE h_module = load_library_a(lib_name);

            if (h_module) {
                PIMAGE_THUNK_DATA64 orig_thunk = (PIMAGE_THUNK_DATA64)((ULONG_PTR)base + (import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk));
                PIMAGE_THUNK_DATA64 first_thunk = (PIMAGE_THUNK_DATA64)((ULONG_PTR)base + import_desc->FirstThunk);

                while (orig_thunk->u1.AddressOfData != 0) {
                    if (IMAGE_SNAP_BY_ORDINAL64(orig_thunk->u1.Ordinal)) {
                        first_thunk->u1.Function = (ULONG_PTR)get_proc_address(h_module, (const char*)IMAGE_ORDINAL64(orig_thunk->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)base + (ULONG_PTR)orig_thunk->u1.AddressOfData);
                        first_thunk->u1.Function = (ULONG_PTR)get_proc_address(h_module, (const char*)ibn->Name);
                    }
                    orig_thunk++;
                    first_thunk++;
                }
            }
            import_desc++;
        }
    }

    // 3. Entry Point
    if (nt_headers->OptionalHeader.AddressOfEntryPoint != 0) {
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t entry_point = (DllMain_t)((ULONG_PTR)base + nt_headers->OptionalHeader.AddressOfEntryPoint);
        entry_point((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
}

__attribute__((section(".text")))
inline void WINAPI realign_pe_end() {}

#ifdef __cplusplus
}
#endif
