@echo off
title Sistem Analiz Aracı
echo Sistem Bilgileri Toplaniyor...
echo Kullanici: %USERNAME%
echo Tarih: %DATE% %TIME%
set "TEMP_LOG=%temp%\test_log.txt"
echo Bu bir test dosyasidir > "%TEMP_LOG%"
echo Log dosyasi olusturuldu: %TEMP_LOG%
pause
exit