import argparse
import random
import re
import string

# C++ keywords to avoid renaming
KEYWORDS = {
    # Standard C++
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
    "class", "compl", "concept", "const", "consteval", "constexpr", "constinit",
    "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
    "default", "delete", "do", "double", "dynamic_cast", "else", "enum",
    "explicit", "export", "extern", "false", "float", "for", "friend", "goto",
    "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept",
    "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private",
    "protected", "public", "reflexpr", "register", "reinterpret_cast",
    "requires", "return", "short", "signed", "sizeof", "static", "size_t",
    "static_assert", "static_cast", "struct", "switch", "synchronized",
    "template", "this", "thread_local", "throw", "true", "try", "typedef",
    "typeid", "typename", "union", "unsigned", "using", "virtual", "void",
    "volatile", "wchar_t", "while", "xor", "xor_eq",

    # Standard Library
    "std", "cout", "wcout", "cin", "wcin", "endl", "string", "wstring", "vector", "map", "set",
    "list", "deque", "stack", "queue", "priority_queue", "pair",
    "tuple", "array", "unordered_map", "unordered_set", "shared_ptr",
    "unique_ptr", "weak_ptr", "thread", "mutex", "atomic", "future",
    "promise", "chrono", "iostream", "sstream", "wstringstream", "fstream", "algorithm",
    "to_wstring", "size", "find", "replace", "substr", "find_last_not_of", "c_str",
    "length", "data", "begin", "end", "get", "hex", "npos",

    # Windows API Types & Constants
    "HANDLE", "PVOID", "LPWSTR", "DWORD", "BOOL", "NTSTATUS", "ULONG", "ULONG_PTR",
    "USHORT", "BYTE", "SIZE_T", "PULONG", "STARTUPINFOW", "PROCESS_INFORMATION",
    "SECURITY_ATTRIBUTES", "PROCESS_BASIC_INFORMATION", "PEB", "TEB",
    "CUSTOM_PEB", "CUSTOM_RTL_USER_PROCESS_PARAMETERS", "ProcessBasicInformation",
    "CREATE_SUSPENDED", "CREATE_NEW_CONSOLE", "FALSE", "NULL", "PebBaseAddress",
    "dwProcessId", "dwThreadId", "hProcess", "hThread", "cb", "nLength", "ProcessParameters",
    "CommandLine", "Length", "MaximumLength", "ImageBaseAddress", "Ldr",

    # Windows API Functions (CRITICAL ADDITION)
    "CreateProcessW", "NtQueryInformationProcess", "NtReadVirtualMemory",
    "NtWriteVirtualMemory", "NtResumeThread", "CloseHandle", "GetLastError",
    "ReadProcessMemory", "WriteProcessMemory", "ResumeThread", "OpenProcess",
    "VirtualAllocEx", "VirtualFreeEx", "VirtualProtectEx", "GetProcAddress",
    "LoadLibraryA", "LoadLibraryW", "FreeLibrary", "GetModuleHandleA", "GetModuleHandleW",
    "CreateFileW", "CreateFileA", "ReadFile", "WriteFile", "SetFilePointer",
    "GetFileSize", "CloseHandle", "FindFirstFileW", "FindFirstFileA",
    "FindNextFileW", "FindNextFileA", "FindClose", "CreateDirectoryW",
    "CreateDirectoryA", "RemoveDirectoryW", "RemoveDirectoryA", "DeleteFileW",
    "DeleteFileA", "MoveFileW", "MoveFileA", "CopyFileW", "CopyFileA",
    "GetCurrentDirectoryW", "GetCurrentDirectoryA", "SetCurrentDirectoryW",
    "SetCurrentDirectoryA", "GetTempPathW", "GetTempPathA", "CreateThread",
    "ExitThread", "WaitForSingleObject", "WaitForMultipleObjects", "Sleep",
    "GetTickCount", "GetSystemTime", "GetLocalTime", "QueryPerformanceCounter",
    "QueryPerformanceFrequency", "CreateMutexW", "CreateMutexA", "ReleaseMutex",
    "CreateEventW", "CreateEventA", "SetEvent", "ResetEvent", "CreateSemaphoreW",
    "CreateSemaphoreA", "ReleaseSemaphore", "InitializeCriticalSection",
    "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
    "RegOpenKeyExW", "RegOpenKeyExA", "RegQueryValueExW", "RegQueryValueExA",
    "RegSetValueExW", "RegSetValueExA", "RegCloseKey", "RegCreateKeyExW",
    "RegCreateKeyExA", "RegDeleteKeyW", "RegDeleteKeyA", "RegDeleteValueW",
    "RegDeleteValueA", "GetConsoleWindow", "AllocConsole", "FreeConsole",
    "SetConsoleTitle", "SetConsoleTitleA", "SetConsoleTitleW",
    "GetStdHandle", "SetStdHandle", "WriteConsoleW", "WriteConsoleA",
    "ReadConsoleW", "ReadConsoleA", "MessageBoxW", "MessageBoxA",
    "ShowWindow", "UpdateWindow", "GetWindowTextW", "GetWindowTextA",
    "SetWindowTextW", "SetWindowTextA", "FindWindowW", "FindWindowA",
    "GetWindowRect", "SetWindowPos", "MoveWindow", "IsWindow",
    "DestroyWindow", "PostMessageW", "PostMessageA", "SendMessageW",
    "SendMessageA", "GetMessageW", "GetMessageA", "PeekMessageW",
    "PeekMessageA", "TranslateMessage", "DispatchMessageW", "DispatchMessageA",
    "wcslen", "wcscpy", "wcscat", "wcscmp", "wcsncmp", "wcsstr", "wcstok",
    "malloc", "free", "calloc", "realloc", "memcpy", "memmove", "memset",
    "memcmp", "strlen", "strcpy", "strcat", "strcmp", "strncmp", "strstr",
    "strtok", "printf", "sprintf", "fprintf", "scanf", "sscanf", "fscanf",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind",
    "fflush", "feof", "ferror", "clearerr",

    # User-defined functions we want to preserve
    "PadRight", "Debug",

    # Reserved words
    "main", "include", "define", "pragma", "ifdef", "endif", "ifndef", "comment", "lib"
}

# Regular expressions for parsing
RE_STRING = re.compile(r'(L)?("([^"\\]*(?:\\.[^"\\]*)*)")|R"(\((?:[^\)]|\n)*\))"')
RE_COMMENT = re.compile(r'//.*?$|/\*.*?\*/', re.MULTILINE | re.DOTALL)
RE_IDENTIFIER = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b')
RE_PREPROCESSOR = re.compile(r'^\s*#.*', re.MULTILINE)

def minify(code):
    """Removes comments and extra whitespace."""
    preprocessor_lines = RE_PREPROCESSOR.findall(code)
    code = RE_PREPROCESSOR.sub('', code)
    code = RE_COMMENT.sub('', code)
    lines = [line.strip() for line in code.split('\n') if line.strip()]
    return '\n'.join(preprocessor_lines) + '\n' + '\n'.join(lines)

def get_random_name(length=8):
    """Generates a random identifier name."""
    return '_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def collect_identifiers(code):
    """Collects all valid identifiers from the code, avoiding protected contexts."""
    identifiers = set()

    # Process line by line to handle context correctly
    for line in code.split('\n'):
        # Skip preprocessor lines and extern "C" declarations to be safe
        if line.strip().startswith('#') or 'extern "C"' in line:
            continue

        temp_line = RE_COMMENT.sub('', line)
        temp_line = RE_STRING.sub('""', temp_line)

        for match in RE_IDENTIFIER.finditer(temp_line):
            identifier = match.group(0)
            if identifier not in KEYWORDS and not identifier.isupper():
                identifiers.add(identifier)

    return identifiers

def build_rename_map(identifiers):
    """Builds a map from original identifier to a new random name."""
    return {identifier: get_random_name() for identifier in identifiers}

def replace_identifiers(code, rename_map):
    """Replaces identifiers in the code, respecting context."""
    if not rename_map:
        return code

    sorted_keys = sorted(rename_map.keys(), key=len, reverse=True)
    pattern = r'\b(' + '|'.join(re.escape(key) for key in sorted_keys) + r')\b'

    processed_lines = []
    for line in code.split('\n'):
        # Skip preprocessor lines and extern "C" declarations to be safe
        if line.strip().startswith('#') or 'extern "C"' in line:
            processed_lines.append(line)
            continue

        literals = {}
        def store_literal(match_obj):
            key = f"__LITERAL_{len(literals)}__"
            literals[key] = match_obj.group(0)
            return key

        temp_line = RE_COMMENT.sub(store_literal, line)
        temp_line = RE_STRING.sub(store_literal, temp_line)

        temp_line = re.sub(pattern, lambda m: rename_map.get(m.group(0), m.group(0)), temp_line)

        for key, value in literals.items():
            temp_line = temp_line.replace(key, value, 1)

        processed_lines.append(temp_line)

    return '\n'.join(processed_lines)

def obfuscate_strings(code, key_byte=0x55):
    """Finds all C-style strings (non-wide), XORs them, and prepares for runtime decoding."""
    obfuscated_strings = []

    def repl(match):
        is_wide = match.group(1)
        original_str = match.group(3)
        raw_str = match.group(4)

        if is_wide or raw_str is not None:
            return match.group(0)

        if original_str is None:
            return match.group(0)

        decoded_str = bytes(original_str, 'utf-8').decode('unicode_escape')
        xored_bytes = [ord(b) ^ key_byte for b in decoded_str]

        array_id = len(obfuscated_strings)
        obfuscated_strings.append(xored_bytes)

        return f"_obf_str({array_id})"

    lines = code.split('\n')
    processed_lines = []
    for line in lines:
        if line.strip().startswith('#') or 'extern "C"' in line:
            processed_lines.append(line)
        else:
            processed_lines.append(RE_STRING.sub(repl, line))

    code = '\n'.join(processed_lines)
    return code, obfuscated_strings

def insert_string_runtime_helper(code, obfuscated_strings, key_byte=0x55):
    """Inserts the C++ helper code for decoding strings at runtime."""
    if not obfuscated_strings:
        return code

    helper_code = "\n// --- String Obfuscation Helper --- \n"
    helper_code += "namespace {\n"
    for i, data in enumerate(obfuscated_strings):
        helper_code += f"    char _obf_data_{i}[] = {{ {', '.join(map(str, data))}, 0 }};\n"
    helper_code += "\n    char* _obf_str_table[] = {\n"
    for i in range(len(obfuscated_strings)):
        helper_code += f"        _obf_data_{i},\n"
    helper_code += "    };\n\n"
    helper_code += "    char _obf_decode_buffer[4096];\n"
    helper_code += "    const char* _obf_str(int id) {\n"
    helper_code += f"        char* s = _obf_str_table[id];\n"
    helper_code += f"        int i = 0;\n"
    helper_code += f"        for (; s[i] != 0; ++i) _obf_decode_buffer[i] = s[i] ^ {key_byte};\n"
    helper_code += f"        _obf_decode_buffer[i] = 0;\n"
    helper_code += "        return _obf_decode_buffer;\n"
    helper_code += "    }\n"
    helper_code += "} // anonymous namespace\n"
    helper_code += "// --- End String Obfuscation Helper --- \n\n"

    last_include_pos = code.rfind("#include")
    if last_include_pos != -1:
        insert_pos = code.find('\n', last_include_pos) + 1
        return code[:insert_pos] + helper_code + code[insert_pos:]
    return helper_code + code

def main():
    parser = argparse.ArgumentParser(description="A simple C++ obfuscator.")
    parser.add_argument("-i", "--input", required=True, help="Input C++ file path.")
    parser.add_argument("-o", "--output", required=True, help="Output file path for obfuscated code.")
    args = parser.parse_args()

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            code = f.read()
    except FileNotFoundError:
        print(f"Error: Input file not found at {args.input}")
        return

    identifiers_to_rename = collect_identifiers(code)
    rename_map = build_rename_map(identifiers_to_rename)
    code = replace_identifiers(code, rename_map)

    code, strings = obfuscate_strings(code)
    code = insert_string_runtime_helper(code, strings)

    final_code = minify(code)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(final_code)

    print(f"Obfuscation complete. Output written to {args.output}")

if __name__ == "__main__":
    main()
