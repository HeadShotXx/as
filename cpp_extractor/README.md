# Browser MasterKey Extractor (C++ Version)

This is a C++ port of the Rust-based browser extractor that uses the debugger method to attach to Chromium-based browsers and extract the "App-Bound" (v20) master key from memory.

## Features
- Support for Google Chrome, Microsoft Edge, Brave, Opera Stable, and Opera GX.
- Extracts Passwords, Cookies, Autofill data, and History.
- Uses Windows Hardware Breakpoints to intercept the master key decryption process.
- Decrypts AES-GCM (v10 and v20) blobs using the Windows CNG (BCrypt) API.
- Minimal dependencies (uses standard Win32 APIs and standard C++).

## Prerequisites
- Windows OS (64-bit recommended).
- A C++ compiler (MSVC or MinGW-w64).
- SQLite3 development files (header and library).

## Compilation Instructions

### Using MSVC (Command Line)
1. Open "Developer Command Prompt for VS".
2. Navigate to the `cpp_extractor` directory.
3. Compile using `cl.exe`:
   ```cmd
   cl /EHsc /O2 /std:c++17 main.cpp sqlite3.c /link crypt32.lib bcrypt.lib user32.lib advapi32.lib shell32.lib /out:extractor.exe
   ```

### Using MinGW-w64 (g++)
1. Navigate to the `cpp_extractor` directory.
2. Compile using `g++`:
   ```bash
   g++ -O3 -std=c++17 main.cpp sqlite3.c -o extractor.exe -lcrypt32 -lbcrypt -luser32 -ladvapi32 -lshell32
   ```

## Usage
1. Run `extractor.exe` as an administrator.
2. The program will:
   - Close any running instances of the supported browsers.
   - Start each browser in a suspended/debug state.
   - Scan the browser DLL for the target decryption routine.
   - Set hardware breakpoints on all threads.
   - Capture the decrypted master key from registers when the breakpoint is hit.
   - Extract and decrypt profile data into folders (e.g., `chrome_extract/`).

## Project Structure
- `main.cpp`: Contains the entire implementation, including the Win32 debugger logic, PE scanning, cryptography wrappers, and SQLite extraction.
- `chrome_extract/`, `edge_extract/`, etc.: Output directories created after a successful run.

## Logic Overview
This port preserves the exact logic of the original Rust project:
1. **PE Scanning**: Scans `.rdata` for the App-Bound provider result code string and `.text` for the corresponding `LEA` instruction to find the target address.
2. **Debugger Loop**: Uses `DEBUG_ONLY_THIS_PROCESS` to catch DLL loads and thread creations, applying hardware breakpoints (DR0) to intercept execution at the target address.
3. **Register Extraction**: When the breakpoint is hit, it reads `R14`/`R15` registers to find the master key structure in memory.
4. **Data Extraction**: Uses the captured key to decrypt SQLite-stored data using AES-GCM.
