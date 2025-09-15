import argparse
import random
import re
import string

# C++ keywords to avoid renaming
KEYWORDS = {
    'alignas', 'alignof', 'and', 'and_eq', 'asm', 'auto', 'bitand', 'bitor', 'bool', 'break', 'case', 'catch',
    'char', 'char8_t', 'char16_t', 'char32_t', 'class', 'compl', 'concept', 'const', 'consteval', 'constexpr',
    'constinit', 'const_cast', 'continue', 'co_await', 'co_return', 'co_yield', 'decltype', 'default',
    'delete', 'do', 'double', 'dynamic_cast', 'else', 'enum', 'explicit', 'export', 'extern', 'false',
    'float', 'for', 'friend', 'goto', 'if', 'inline', 'int', 'long', 'mutable', 'namespace', 'new', 'noexcept',
    'not', 'not_eq', 'nullptr', 'operator', 'or', 'or_eq', 'private', 'protected', 'public', 'reflexpr',
    'register', 'reinterpret_cast', 'requires', 'return', 'short', 'signed', 'sizeof', 'static',
    'static_assert', 'static_cast', 'struct', 'switch', 'synchronized', 'template', 'this', 'thread_local',
    'throw', 'true', 'try', 'typedef', 'typeid', 'typename', 'union', 'unsigned', 'using', 'virtual',
    'void', 'volatile', 'wchar_t', 'while', 'xor', 'xor_eq'
}

# Common std and WinAPI names to avoid renaming
STD_NAMES = {
    # C++ std
    'std', 'string', 'wstring', 'vector', 'cout', 'wcout', 'endl', 'to_string', 'to_wstring', 'stringstream',
    'wstringstream', 'hex', 'find', 'replace', 'substr', 'length', 'size', 'c_str', 'find_last_not_of',
    'npos', 'begin', 'end', 'data', 'get', 'byte', 'str', 'size_t', 'wcslen',
    # WinAPI Types
    'BOOL', 'DWORD', 'HANDLE', 'NTSTATUS', 'PVOID', 'ULONG', 'PULONG', 'USHORT', 'SIZE_T', 'LPWSTR', 'BYTE',
    'STARTUPINFOW', 'SECURITY_ATTRIBUTES', 'PROCESS_INFORMATION', 'PROCESS_BASIC_INFORMATION', 'LPCWSTR',
    # WinAPI Functions
    'CreateProcessW', 'GetLastError', 'CloseHandle',
    # Native API
    'NtQueryInformationProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory', 'NtResumeThread',
    # WinAPI Constants
    'ProcessBasicInformation'
}

# Other reserved words
RESERVED_WORDS = {'main', 'include', 'define', 'pragma', 'ifdef', 'endif'}

# Regexes
RE_STRING = re.compile(r'(L?)"((?:\\.|[^"\\])*)"')
RE_CHAR = re.compile(r"L?'(\\.|[^'\\])'")
RE_COMMENT = re.compile(r'//.*?$|/\*.*?\*/', re.DOTALL | re.MULTILINE)
RE_IDENTIFIER = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b')
RE_PREPROCESSOR = re.compile(r'^\s*#.*$', re.MULTILINE)
RE_EXTERN_C = re.compile(r'extern\s*"C"')


def minify(code):
    """Removes comments and extra whitespace."""
    code = re.sub(RE_COMMENT, '', code)
    minified_lines = []
    for line in code.split('\n'):
        line = line.strip()
        if line:
            parts = re.split(r'("[^"]*")', line)
            for i, part in enumerate(parts):
                if i % 2 == 0:
                    parts[i] = re.sub(r'\s+', ' ', part)
            minified_lines.append("".join(parts))
    return '\n'.join(minified_lines)


def random_name(length=8):
    """Generates a random identifier name."""
    return '_' + ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def collect_identifiers(code):
    """Collects all valid identifiers for renaming."""
    identifiers = set()
    temp_code = re.sub(RE_STRING, '""', code)
    temp_code = re.sub(RE_CHAR, "''", temp_code)
    temp_code = re.sub(RE_COMMENT, '', temp_code)

    for match in RE_IDENTIFIER.finditer(temp_code):
        identifier = match.group(0)
        if (identifier not in KEYWORDS and
                identifier not in STD_NAMES and
                identifier not in RESERVED_WORDS and
                not (identifier.isupper() and len(identifier) > 1)):

            prev_chars = temp_code[max(0, match.start() - 2):match.start()]
            if '::' not in prev_chars and '->' not in prev_chars and '.' not in prev_chars:
                identifiers.add(identifier)

    return list(identifiers)


def build_rename_map(identifiers):
    """Builds a map from original names to new random names."""
    return {identifier: random_name() for identifier in identifiers}


def replace_identifiers(code, rename_map):
    """Replaces identifiers based on the rename map."""
    def repl(match):
        word = match.group(0)
        return rename_map.get(word, word)
    return re.sub(RE_IDENTIFIER, repl, code)


def obfuscate_strings(code, key_byte=0x55):
    """Replaces string literals with a runtime-decoding function call."""
    obfuscated_strings = []
    string_id_counter = 0

    def replace_string(match):
        nonlocal string_id_counter
        line_start = code.rfind('\n', 0, match.start()) + 1
        if code[line_start:].lstrip().startswith('#'):
            return match.group(0)

        prefix = match.group(1) or ""
        original_string = match.group(2)

        if 'R"(' in match.group(0):
            return match.group(0)

        is_wide = prefix == 'L'

        if is_wide:
            encoded_bytes = bytearray(original_string.encode('utf-16le'))
            replacement_func = "_obf_wstr"
        else:
            encoded_bytes = bytearray(original_string.encode('utf-8'))
            replacement_func = "_obf_str"

        obfuscated_data = [b ^ key_byte for b in encoded_bytes]

        obfuscated_strings.append({
            'id': string_id_counter,
            'data': obfuscated_data,
            'is_wide': is_wide,
            'original_len': len(original_string)
        })

        replacement = f"{replacement_func}({string_id_counter})"
        string_id_counter += 1
        return replacement

    code = re.sub(RE_STRING, replace_string, code)
    return code, obfuscated_strings, key_byte


def _safe_split_statements(code):
    """Safely splits a block of code into statements, respecting scopes."""
    statements = []
    current_statement = ""
    brace_level = 0
    paren_level = 0
    in_string = False

    for i, char in enumerate(code):
        current_statement += char

        if char == '"' and (i == 0 or code[i-1] != '\\'):
            in_string = not in_string
        if in_string:
            continue

        if char == '{': brace_level += 1
        elif char == '}': brace_level -= 1
        elif char == '(': paren_level += 1
        elif char == ')': paren_level -= 1

        if char == ';' and brace_level == 0 and paren_level == 0:
            statements.append(current_statement.strip())
            current_statement = ""

    if current_statement.strip():
        statements.append(current_statement.strip())

    return statements


def flatten_functions(code):
    """
    (Experimental) Attempts to apply control-flow flattening to simple functions.
    This is a basic implementation and will skip any functions with complex
    control flow (loops, returns, preprocessor directives, etc.) to ensure correctness.
    """
    func_pattern = re.compile(r'(\w+\s*[\*&]*\s+)(\w+)(\s*\([^)]*\))\s*\{([\s\S]*?)\n\}', re.DOTALL)

    last_end = 0
    new_code = ""

    for match in func_pattern.finditer(code):
        new_code += code[last_end:match.start()]

        return_type, func_name, args, body = match.groups()

        # Skip non-void functions and complex functions to be safe
        if 'void' not in return_type or any(kw in body for kw in ['for', 'while', 'switch', 'goto', 'return', 'case', 'default', '#']):
            new_code += match.group(0)
            last_end = match.end()
            if 'void' not in return_type:
                print(f"[-] Skipping flattening for non-void function '{func_name}'.")
            elif '#' in body:
                print(f"[-] Skipping flattening for function '{func_name}' due to preprocessor directives.")
            continue

        try:
            statements = _safe_split_statements(body)
            if not statements or len(statements) < 2:
                new_code += match.group(0)
                last_end = match.end()
                continue

            print(f"[+] Flattening function '{func_name}'")

            state_var = "_state_" + func_name
            flattened_body = f"""
    int {state_var} = 0;
    while (true) {{
        switch ({state_var}++) {{
"""
            for i, stmt in enumerate(statements):
                flattened_body += f"            case {i}: {stmt}; break;\n"

            flattened_body += f"""            case {len(statements)}: return;
        }}
    }}
"""
            new_code += f"{return_type} {func_name}{args} {{\n{flattened_body}\n}}"

        except Exception as e:
            print(f"[!] Error flattening function '{func_name}': {e}. Skipping.")
            new_code += match.group(0)

        last_end = match.end()

    new_code += code[last_end:]
    return new_code


def generate_string_helpers_and_data(obfuscated_strings, key_byte, rename_map):
    """Generates the C++ code for string decoding helpers and data arrays."""
    if not obfuscated_strings:
        return "", ""

    data_definitions = []
    data_array_names = []
    for s in obfuscated_strings:
        array_name = f"_obf_data_{s['id']}"
        data_array_names.append(array_name)
        blob_data = ', '.join(f"0x{b:02x}" for b in s['data'])
        data_definitions.append(f"static const unsigned char {array_name}[] = {{{blob_data}, 0x00, 0x00}};")

    all_data_defs = '\n'.join(data_definitions)

    helper_code = """
#include <string>
#include <vector>

static const unsigned char** _obf_data_ptr;
static const bool* _obf_is_wide_ptr;
static const int* _obf_len_ptr;
static unsigned char _xor_key;

// --- Wrapper and helpers for narrow strings ---
struct _obf_string_wrapper {
    std::string _s;
    operator std::string() const { return _s; }
    operator const char*() const { return _s.c_str(); }
    std::string operator+(const std::string& other) const { return _s + other; }
    std::string operator+(const char* other) const { return _s + other; }
};
std::string operator+(const std::string& lhs, const _obf_string_wrapper& rhs) { return lhs + rhs._s; }
std::string operator+(const char* lhs, const _obf_string_wrapper& rhs) { return lhs + rhs._s; }

// --- Wrapper and helpers for wide strings ---
struct _obf_wstring_wrapper {
    std::wstring _s;
    operator std::wstring() const { return _s; }
    operator const wchar_t*() const { return _s.c_str(); }
    std::wstring operator+(const std::wstring& other) const { return _s + other; }
    std::wstring operator+(const wchar_t* other) const { return _s + other; }
};
std::wstring operator+(const std::wstring& lhs, const _obf_wstring_wrapper& rhs) { return lhs + rhs._s; }
std::wstring operator+(const wchar_t* lhs, const _obf_wstring_wrapper& rhs) { return lhs + rhs._s; }

template<typename T>
T* _obf_decode_ptr(int id, T* buffer) {
    const unsigned char* data = _obf_data_ptr[id];
    int i = 0;
    while (true) {
        unsigned char c1 = data[i] ^ _xor_key;
        if (_obf_is_wide_ptr[id]) {
            unsigned char c2 = data[i+1] ^ _xor_key;
            if (c1 == 0 && c2 == 0) break;
            buffer[i/2] = (T)c1 | ((T)c2 << 8);
            i += 2;
        } else {
            if (c1 == 0) break;
            buffer[i] = (T)c1;
            i += 1;
        }
    }
    buffer[_obf_len_ptr[id]] = 0;
    return buffer;
}

_obf_string_wrapper _obf_str(int id) {
    std::vector<char> buffer(_obf_len_ptr[id] + 1);
    return { _obf_decode_ptr(id, buffer.data()) };
}

_obf_wstring_wrapper _obf_wstr(int id) {
    std::vector<wchar_t> buffer(_obf_len_ptr[id] + 1);
    return { _obf_decode_ptr(id, buffer.data()) };
}
"""
    data_ptr_name = rename_map.get('_obf_data_ptr', '_obf_data_ptr')
    is_wide_ptr_name = rename_map.get('_obf_is_wide_ptr', '_obf_is_wide_ptr')
    len_ptr_name = rename_map.get('_obf_len_ptr', '_obf_len_ptr')
    key_name = rename_map.get('_xor_key', '_xor_key')

    pointer_array_def = f"static const unsigned char* _obf_data_values[] = {{ {', '.join(data_array_names)} }};"
    is_wide_array_def = "static const bool _obf_is_wide_values[] = {" + ', '.join(str(s['is_wide']).lower() for s in obfuscated_strings) + "};"
    len_array_def = "static const int _obf_len_values[] = {" + ', '.join(str(s['original_len']) for s in obfuscated_strings) + "};"

    setup_code = f"""
{pointer_array_def}
{is_wide_array_def}
{len_array_def}
{data_ptr_name} = _obf_data_values;
{is_wide_ptr_name} = _obf_is_wide_values;
{len_ptr_name} = _obf_len_values;
{key_name} = {key_byte};
"""
    return all_data_defs + '\n' + helper_code, setup_code


def main():
    parser = argparse.ArgumentParser(description="A simple C++ obfuscator.")
    parser.add_argument('-i', '--input', required=True, help="Input .cpp file")
    parser.add_argument('-o', '--output', required=True, help="Output .cpp file")
    args = parser.parse_args()

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            code = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input}' not found.")
        return

    print("[+] Starting obfuscation...")

    placeholder_maps = {}
    def create_placeholder(name, value):
        if name not in placeholder_maps:
            placeholder_maps[name] = {}
        key = f"__{name.upper()}_{len(placeholder_maps[name])}__"
        placeholder_maps[name][key] = value
        return key

    def protect(match, name):
        return create_placeholder(name, match.group(0))

    code = RE_EXTERN_C.sub(lambda m: protect(m, 'extern_c'), code)

    print("[+] Attempting to flatten functions (experimental)...")
    code = flatten_functions(code)

    code = RE_PREPROCESSOR.sub(lambda m: protect(m, 'preprocessor'), code)

    print("[+] Obfuscating strings...")
    code, strings_to_obfuscate, key = obfuscate_strings(code)
    print(f"[+] Found and replaced {len(strings_to_obfuscate)} strings.")

    print("[+] Collecting and renaming identifiers...")
    helper_identifiers = [
        '_obf_str', '_obf_wstr', '_obf_decode_ptr', '_obf_data_ptr',
        '_obf_is_wide_ptr', '_obf_len_ptr', '_xor_key',
        '_obf_string_wrapper', '_obf_wstring_wrapper'
    ]
    user_identifiers = collect_identifiers(code)
    all_identifiers = list(set(user_identifiers + helper_identifiers))
    rename_map = build_rename_map(all_identifiers)

    global_defs, main_setup_code = generate_string_helpers_and_data(strings_to_obfuscate, key, rename_map)
    code = global_defs + '\n' + code

    code = replace_identifiers(code, rename_map)
    main_setup_code = replace_identifiers(main_setup_code, rename_map)
    print(f"[+] Renamed {len(all_identifiers)} identifiers.")

    if strings_to_obfuscate:
        main_match = re.search(r'\bmain\s*\([^)]*\)\s*\{', code)
        if main_match:
            main_body_start = main_match.end()
            code = code[:main_body_start] + '\n' + main_setup_code + code[main_body_start:]
            print("[+] Injected string data initializers into main.")
        else:
            print("[!] Could not find main() function to inject string initializers.")

    print("[+] Minifying code...")
    code = minify(code)

    for name, pmap in placeholder_maps.items():
        for key, value in pmap.items():
            code = code.replace(key, value)

    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(code)
        print(f"[+] Obfuscation complete. Output written to '{args.output}'.")
    except IOError:
        print(f"Error: Could not write to output file '{args.output}'.")

if __name__ == '__main__':
    main()
