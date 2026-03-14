@echo off
setlocal enabledelayedexpansion
set "TARGET=MYLABEL"
goto :%TARGET%
echo Fail
:MYLABEL
echo Success
set "CMD1=SET"
set "CMD2=ECHO"
call !CMD1! "VAR=Hello"
call !CMD2! !VAR!
