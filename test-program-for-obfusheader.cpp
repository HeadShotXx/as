// main.cpp
// Test program for obfusheader.h (example usage of main macros/features)
// Requires obfusheader.h in include path (same folder or include/)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

// include the header (repo: ac3ss0r/obfusheader.h)
#include "obfusheader.h"

INLINE void demo_inline_function() {
    // INLINE forces inlining according to header config
    printf(OBF("INLINE function called\n"));
}

int main() {
    // 1) OBF macro: strings, integers, hex, booleans, etc.
    printf(OBF("==== OBF (compile-time encrypted constants) ====\n"));
    printf("char*: %s\n", OBF("hello_obfus"));
    printf("int (dec): %d\n", OBF(42));
    printf("long long: %llu\n", OBF(9223372036854775807ULL));
    printf("int (hex): 0x%x\n", OBF(0xDEADBEEF));
    printf("boolean: %d\n", OBF(true));

    // 2) MAKEOBF - create encrypted storage and reuse safely
    printf(OBF("\n==== MAKEOBF (persist encrypted storage on stack-scope) ====\n"));
    auto obfval = MAKEOBF("persistent_secret");
    // cast to char* for printing (example from README)
    printf("MAKEOBF: %s\n", (char*)obfval);

    // 3) CALL - call hiding demo (hides direct call)
    printf(OBF("\n==== CALL (call-hiding demo) ====\n"));
    CALL(&printf, OBF("This printf was invoked through CALL macro!\n"));

    // 4) CALL_EXPORT - import hiding demo (windows/linux)
    // Example: dynamically resolve and call MessageBoxA on Windows (if available).
    // For portability we try to demonstrate with a C runtime function name resolution:
    printf(OBF("\n==== CALL_EXPORT (import hiding demo) ====\n"));
    // Note: CALL_EXPORT expects exact signature; here we show conceptual usage.
#if defined(_WIN32)
    // This will locate LoadLibraryA and call it (demo). Wrapped in if to avoid errors on non-windows.
    if (CALL_EXPORT("kernel32.dll", "LoadLibraryA", HMODULE(*)(LPCSTR), "user32.dll")) {
        CALL_EXPORT("user32.dll", "MessageBoxA", int(*)(HWND, const char*, const char*, unsigned int),
                    0, OBF("Obfusheader Message"), OBF("Title"), 0);
    } else {
        printf(OBF("CALL_EXPORT demo: LoadLibraryA not available / failed.\n"));
    }
#else
    printf(OBF("CALL_EXPORT demo skipped (not Windows in this run).\n"));
#endif

    // 5) WATERMARK - embed ascii art/watermark into binary (no visible runtime effect)
    WATERMARK("=== WATERMARK START ===",
              "  obfusheader demo watermark",
              "=== WATERMARK END ===");

    printf(OBF("\n==== RND (compile-time random) & INLINE demo ====\n"));
    // 6) RND - compile-time random
    printf("RND(0,100) -> %d\n", RND(0, 100));

    // 7) INLINE demo
    demo_inline_function();

    // 8) inline_* helper functions (e.g. inline_strcmp) used with OBF
    printf(OBF("\n==== inline_strcmp demo ====\n"));
    const char* pw = OBF("secret_pw"); // note: not safe to keep pointer across scope in some optimizations (see README)
    if (inline_strcmp(pw, OBF("secret_pw")) == OBF(0)) {
        printf(OBF("Password match (inline_strcmp)\n"));
    } else {
        printf(OBF("Password mismatch\n"));
    }

    // 9) Example of using numeric OBF inside logic
    if (OBF(10) + OBF(5) == OBF(15)) {
        printf(OBF("Numeric OBF works in expressions\n"));
    }

    printf(OBF("\n==== End of obfusheader demo ====\n"));

    return 0;
}
