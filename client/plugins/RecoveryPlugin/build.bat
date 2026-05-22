@echo off
if not exist "build" mkdir build
gcc -c sqlite3.c -o build/sqlite3.o
g++ -O2 -std=c++17 -shared main.cpp build/sqlite3.o -o build/RecoveryPlugin.dll -lws2_32 -lcrypt32 -lbcrypt -luser32 -ladvapi32 -lshell32 -lole32 -luuid -static-libgcc -static-libstdc++ -static
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b %errorlevel%
)
echo Build successful: build/RecoveryPlugin.dll
