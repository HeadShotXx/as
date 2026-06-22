@echo off
set GXX=g++
set GCC=gcc
set STD=-std=c++17
set SHELLCODE_FLAGS=-fno-stack-protector -fno-exceptions -fno-asynchronous-unwind-tables

echo [*] Compiling SQLite3...
%GCC% -c includes/sqlite3.c -o includes/sqlite3.o

echo [*] Compiling Proxy DLL...
%GXX% %STD% -O2 -shared proxydll/src/main.cpp includes/sqlite3.o -o proxy.dll -Iincludes -lbcrypt -lcrypt32 -lole32 -loleaut32 -lws2_32 -luuid -static

echo [*] Compiling Injector...
%GXX% %STD% -O2 injector/src/main.cpp injector/src/bootstrapper.cpp %SHELLCODE_FLAGS% -o injector.exe -Iincludes -lbcrypt -lcrypt32 -lole32 -loleaut32 -lws2_32 -luuid -static

echo [!] Done.
pause
