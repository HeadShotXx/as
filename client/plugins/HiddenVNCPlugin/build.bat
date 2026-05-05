@echo off
g++ -O3 -shared -static -static-libgcc -static-libstdc++ main.cpp -o ../../HiddenVNCPlugin.dll -lws2_32 -lgdiplus -lgdi32 -lole32 -lshell32 -I../../include
