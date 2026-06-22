#include <windows.h>
#include <stdint.h>

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);

struct DllInfo {
    void* base;
    LoadLibraryA_t load_library_a;
    GetProcAddress_t get_proc_address;
    bool relocation_required;
};

// Simplified Win32 structures for position-independent code
struct IMAGE_BASE_RELOCATION_ {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

struct IMAGE_IMPORT_DESCRIPTOR_ {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct IMAGE_IMPORT_BY_NAME_ {
    uint16_t Hint;
    char Name[1];
};

typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);

// Note: When compiling with GCC/MinGW, use -fno-stack-protector -fno-exceptions -fno-asynchronous-unwind-tables
// to keep the code as position-independent and self-contained as possible.

extern "C" __declspec(dllexport) void NTAPI realign_pe(DllInfo* dll_info) {
    if (!dll_info) return;

    void* base = dll_info->base;
    LoadLibraryA_t _LoadLibraryA = dll_info->load_library_a;
    GetProcAddress_t _GetProcAddress = dll_info->get_proc_address;

    auto* dos_header = (PIMAGE_DOS_HEADER)base;
    auto* nt_headers = (PIMAGE_NT_HEADERS64)((size_t)base + dos_header->e_lfanew);

    // 1. Relocations
    if (dll_info->relocation_required) {
        auto& reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.VirtualAddress != 0) {
            size_t delta = (size_t)base - (size_t)nt_headers->OptionalHeader.ImageBase;
            auto* block_ptr = (IMAGE_BASE_RELOCATION_*)((size_t)base + reloc_dir.VirtualAddress);

            while (block_ptr->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION_) && block_ptr->VirtualAddress != 0) {
                uint32_t entry_count = (block_ptr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_)) / sizeof(uint16_t);
                uint16_t* entries = (uint16_t*)((size_t)block_ptr + sizeof(IMAGE_BASE_RELOCATION_));

                for (uint32_t i = 0; i < entry_count; i++) {
                    uint16_t entry = entries[i];
                    uint16_t rel_type = entry >> 12;
                    uint16_t offset = entry & 0x0FFF;

                    if (rel_type == IMAGE_REL_BASED_DIR64) {
                        size_t* patch = (size_t*)((size_t)base + block_ptr->VirtualAddress + offset);
                        *patch += delta;
                    }
                }
                block_ptr = (IMAGE_BASE_RELOCATION_*)((size_t)block_ptr + block_ptr->SizeOfBlock);
            }
        }
    }

    // 2. Imports
    auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress != 0) {
        auto* import_desc = (IMAGE_IMPORT_DESCRIPTOR_*)((size_t)base + import_dir.VirtualAddress);

        while (import_desc->Name != 0) {
            char* lib_name = (char*)((size_t)base + import_desc->Name);
            HMODULE h_module = _LoadLibraryA(lib_name);

            uint64_t* orig_thunk = (uint64_t*)((size_t)base + (import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk));
            uint64_t* first_thunk = (uint64_t*)((size_t)base + import_desc->FirstThunk);

            while (*orig_thunk != 0) {
                if ((*orig_thunk) & (1ULL << 63)) {
                    uint64_t ordinal = (*orig_thunk) & 0xFFFF;
                    *first_thunk = (uint64_t)_GetProcAddress(h_module, (LPCSTR)ordinal);
                } else {
                    auto* ibn = (IMAGE_IMPORT_BY_NAME_*)((size_t)base + (size_t)(*orig_thunk));
                    *first_thunk = (uint64_t)_GetProcAddress(h_module, ibn->Name);
                }
                orig_thunk++;
                first_thunk++;
            }
            import_desc++;
        }
    }

    // 3. Entry Point
    uint32_t ep_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
    if (ep_rva != 0) {
        auto entry_point = (DllMain_t)((size_t)base + ep_rva);
        entry_point((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }
}

extern "C" __declspec(dllexport) void NTAPI realign_pe_end() {}
