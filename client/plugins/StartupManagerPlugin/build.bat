@echo off
if not exist build mkdir build

echo [+] Startup Manager Plugin Derleniyor...
g++ -O2 -shared main.cpp -o build/StartupManagerPlugin.dll ^
    -lws2_32 -lshlwapi -lole32 -loleaut32 -luuid -static

if %ERRORLEVEL% EQU 0 (
    echo [!] Derleme Basarili: build/StartupManagerPlugin.dll
) else (
    echo [-] Hata Olustu!
)
pause
