@echo off
set "V=abcde"
for /L %%A in (1,1,1) do set "V=%V:~1%%V:~0,1%"
echo %V%
