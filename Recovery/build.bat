@echo off
if not exist "build" mkdir build
x86_64-w64-mingw32-g++ -O2 -std=c++17 -shared main.cpp sqlite3.c -o build/RecoveryPlugin.dll -lws2_32 -lcrypt32 -lbcrypt -lole32 -lshell32 -ladvapi32 -static-libgcc -static-libstdc++ -static
if %errorlevel% neq 0 (
    echo Build failed!
) else (
    echo Build successful: build/RecoveryPlugin.dll
)
