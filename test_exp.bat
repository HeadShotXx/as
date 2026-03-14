@echo off
setlocal enabledelayedexpansion
set "m=echo"
set "p1=m"
set "p2=p1"
echo Testing triple expansion:
for /f "delims=" %%A in ("!p2!") do (
    echo A is %%A
    for /f "delims=" %%B in ("!%%A!") do (
        echo B is %%B
        for /f "delims=" %%C in ("!%%B!") do (
            echo C is %%C
            %%C Hello World
        )
    )
)
