@echo off
setlocal enabledelayedexpansion

:: Test 1: Parentheses in quotes
echo "This ( is not a block )"

:: Test 2: Nested FOR with complex parentheses
for /l %%a in (1,1,2) do (
    echo Outer %%a
    for /f "delims=" %%b in ("inner ( paren )") do (
        echo %%b
    )
)

:: Test 3: Arithmetic overflow
set /a "val=2147483647 + 1"
echo Overflow: !val!

:: Test 4: Special characters and carets
echo ! ^ " = %%

exit /b
