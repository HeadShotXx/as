#include "bootstrapper.h"

// Position-independent PE loader
extern "C" __declspec(code_seg(".text")) void CALLBACK realign_pe(DllInfo* dll_info_ptr) {
    DllInfo info = *dll_info_ptr;
    void* base = info.base;
    pLoadLibraryA _LoadLibraryA = info.load_library_a;
    pGetProcAddress _GetProcAddress = info.get_proc_address;

    auto dos_header = (PIMAGE_DOS_HEADER)base;
    auto nt_headers = (PIMAGE_NT_HEADERS64)((size_t)base + dos_header->e_lfanew);

    // 1. Relocations
    if (info.relocation_required) {
        auto reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->VirtualAddress != 0) {
            size_t delta = (size_t)base - nt_headers->OptionalHeader.ImageBase;
            auto block_ptr = (PIMAGE_BASE_RELOCATION)((size_t)base + reloc_dir->VirtualAddress);

            while (block_ptr->SizeOfBlock >= 8 && block_ptr->VirtualAddress != 0) {
                size_t entry_count = (block_ptr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto entries = (WORD*)((size_t)block_ptr + sizeof(IMAGE_BASE_RELOCATION));

                for (size_t i = 0; i < entry_count; i++) {
                    WORD entry = entries[i];
                    WORD type = entry >> 12;
                    WORD offset = entry & 0x0FFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        auto patch = (size_t*)((size_t)base + block_ptr->VirtualAddress + offset);
                        *patch += delta;
                    }
                }
                block_ptr = (PIMAGE_BASE_RELOCATION)((size_t)block_ptr + block_ptr->SizeOfBlock);
            }
        }
    }

    // 2. Imports
    auto import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->VirtualAddress != 0) {
        auto import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)base + import_dir->VirtualAddress);

        while (import_desc->Name != 0) {
            auto lib_name = (LPCSTR)((size_t)base + import_desc->Name);
            HMODULE h_module = _LoadLibraryA(lib_name);

            auto oft = import_desc->OriginalFirstThunk;
            auto orig_thunk = (PIMAGE_THUNK_DATA64)((size_t)base + (oft ? oft : import_desc->FirstThunk));
            auto first_thunk = (PIMAGE_THUNK_DATA64)((size_t)base + import_desc->FirstThunk);

            while (orig_thunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL64(orig_thunk->u1.Ordinal)) {
                    first_thunk->u1.Function = (size_t)_GetProcAddress(h_module, (LPCSTR)IMAGE_ORDINAL64(orig_thunk->u1.Ordinal));
                } else {
                    auto ibn = (PIMAGE_IMPORT_BY_NAME)((size_t)base + (size_t)orig_thunk->u1.AddressOfData);
                    first_thunk->u1.Function = (size_t)_GetProcAddress(h_module, ibn->Name);
                }
                orig_thunk++;
                first_thunk++;
            }
            import_desc++;
        }
    }

    // 3. Entry Point
    if (nt_headers->OptionalHeader.AddressOfEntryPoint != 0) {
        auto entry_point = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))((size_t)base + nt_headers->OptionalHeader.AddressOfEntryPoint);
        entry_point((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
}

extern "C" __declspec(code_seg(".text")) void realign_pe_end() {}
