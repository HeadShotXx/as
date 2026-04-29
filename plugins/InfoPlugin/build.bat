@echo off
if not exist build mkdir build

echo [+] Information Plugin Derleniyor...
g++ -O2 -shared main.cpp -o ../../information.dll ^
    -lws2_32 -ladvapi32 -luser32 -static-libgcc -static-libstdc++

if %ERRORLEVEL% EQU 0 (
    echo [!] Derleme Basarili: ../../information.dll
) else (
    echo [-] Hata Olustu!
)
pause