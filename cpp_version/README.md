# C++ Version: Injector & Payload

This directory contains the C++ translation of the original Rust project. It consists of a reflective injector and a browser data extraction payload.

## Structure
- `injector/`: Contains the C++ source for the injector.
- `payload/`: Contains the C++ source for the payload DLL.

## Dependencies
- **MinGW-w64**: For cross-compiling to Windows on Linux.
- **SQLite3**: The payload requires the SQLite3 amalgamation (`sqlite3.c` and `sqlite3.h`). Download from [sqlite.org](https://www.sqlite.org/download.html) and place them in the `payload/` directory.
- **nlohmann/json**: The payload requires the `json.hpp` header. Download from [nlohmann/json](https://github.com/nlohmann/json) and place it in the `payload/nlohmann/` directory.

## Compilation

### Injector
```bash
x86_64-w64-mingw32-g++ -O2 injector/main.cpp -o injector/injector.exe -ladvapi32 -static
```

### Payload
```bash
x86_64-w64-mingw32-gcc -c payload/sqlite3.c -o payload/sqlite3.o
x86_64-w64-mingw32-g++ -O2 -shared payload/main.cpp payload/sqlite3.o -o payload/payload.dll -lbcrypt -lcrypt32 -lole32 -loleaut32 -static -I.
```

## Usage
1. Compile the payload to `payload.dll`.
2. Encode `payload.dll` to Base64 and replace the `EMBEDDED_DLL_BASE64` constant in `injector/main.cpp`.
3. Compile the injector to `injector.exe`.
4. Run `injector.exe [browser_name]` (e.g., `injector.exe chrome`).
