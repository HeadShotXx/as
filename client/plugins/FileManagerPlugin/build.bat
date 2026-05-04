@echo off
if not exist "..\..\build" mkdir "..\..\build"

echo [+] FileManagerPlugin is being compiled...
g++ -O2 -shared main.cpp -o ../../build/FileManagerPlugin.dll -lws2_32 -lshell32 -lole32 -static-libgcc -static-libstdc++

if %ERRORLEVEL% EQU 0 (
    echo [!] Compilation successful: ../../build/FileManagerPlugin.dll
) else (
    echo [-] An error occurred!
)
