#!/usr/bin/env python3
"""
Advanced Polymorphic C++ Code Obfuscator
========================================
A sophisticated obfuscation tool with multiple transformation techniques.
Author: Enhanced by AI Assistant
License: MIT
"""

import re
import random
import argparse
import string
import sys
import hashlib
import base64
from typing import Dict, List, Tuple, Set
import json

class ObfuscatorConfig:
    """Configuration class for obfuscation parameters"""
    def __init__(self):
        self.string_encryption_key = random.randint(0x10, 0xFF)
        self.rename_patterns = ['_var', '_func', '_obj']
        self.control_flow_complexity = 3
        self.dead_code_intensity = 2
        self.arithmetic_complexity = 2

class AdvancedObfuscator:
    """Main obfuscator class with polymorphic capabilities"""

    def __init__(self, config: ObfuscatorConfig):
        self.config = config
        self.keywords = {
            "alignas","alignof","and","and_eq","asm","auto","bitand","bitor","bool","break","case","catch","char",
            "class","compl","const","constexpr","const_cast","continue","decltype","default","delete","do","double",
            "dynamic_cast","else","enum","explicit","export","extern","false","float","for","friend","goto","if","inline",
            "int","long","mutable","namespace","new","noexcept","not","not_eq","nullptr","operator","or","or_eq","private",
            "protected","public","register","reinterpret_cast","return","short","signed","sizeof","static","struct","switch",
            "template","this","throw","true","try","typedef","typename","union","unsigned","using","virtual","void","volatile",
            "while","xor","xor_eq"
        }

        self.std_names = {
            "std", "cout", "cin", "getline", "endl", "to_string", "stoi", "stol", "stoul",
            "printf", "scanf", "puts", "gets", "main", "iostream", "vector", "string",
            "map", "unordered_map", "set", "list", "deque", "algorithm", "memory",
            "size_t", "push_back", "emplace_back", "reserve", "clear", "insert", "find",
            "wchar_t", "static_cast", "wcslen", "wstring", "wcout", "wcin", "wstringstream"
        }

        self.winapi_names = {
            # WinAPI Functions
            "CreateProcessW", "GetLastError", "CloseHandle",
            # NTAPI Functions
            "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtResumeThread", "NtQueryInformationProcess",
            # Structures and Members
            "STARTUPINFOW", "cb", "SECURITY_ATTRIBUTES", "nLength", "PROCESS_INFORMATION", "hProcess",
            "hThread", "dwProcessId", "dwThreadId", "PROCESS_BASIC_INFORMATION", "PebBaseAddress",
            "CUSTOM_PEB", "ImageBaseAddress", "Ldr", "ProcessParameters",
            "CUSTOM_RTL_USER_PROCESS_PARAMETERS", "Length", "MaximumLength", "CommandLine",
            # Types and Constants
            "HANDLE", "PVOID", "ULONG", "PULONG", "NTSTATUS", "BYTE", "USHORT", "LPWSTR", "BOOL",
            "DWORD", "SIZE_T", "CREATE_SUSPENDED", "CREATE_NEW_CONSOLE", "ProcessBasicInformation", "NULL"
        }

        # Regex patterns
        self.re_string = re.compile(r'L?R"(\([^\)]*\))"|L?R"[^"]*"|L?"(?:\\.|[^"\\])*"|L?\'(?:\\.|[^\'\\])*\'', re.DOTALL)
        self.re_identifier = re.compile(r'\b([A-Za-z_]\w*)\b')
        self.re_comment = re.compile(r'//.*?$|/\*.*?\*/', re.DOTALL | re.MULTILINE)
        self.re_preprocessor = re.compile(r'^[ \t]*#.*$', re.MULTILINE)
        self.re_number = re.compile(r'\b\d+\b')

        # Obfuscation state
        self.identifier_map = {}
        self.string_map = {}
        self.control_flow_labels = set()

    def generate_polymorphic_name(self, base_length=8) -> str:
        """Generate polymorphic variable names with different patterns"""
        patterns = [
            lambda: '_' + ''.join(random.choices(string.ascii_letters, k=base_length)),
            lambda: ''.join(random.choices(string.ascii_lowercase, k=2)) + '_' +
                   ''.join(random.choices(string.ascii_letters + string.digits, k=base_length-3)),
            lambda: '_' + ''.join(random.choices('lI1oO0', k=base_length//2)) +
                   ''.join(random.choices(string.ascii_letters, k=base_length//2)),
            lambda: '__' + hashlib.md5(str(random.random()).encode()).hexdigest()[:base_length-2]
        ]

        while True:
            name = random.choice(patterns)()
            if name not in self.keywords and name not in self.std_names and name not in self.winapi_names:
                return name

    def collect_identifiers(self, source: str) -> Dict[str, int]:
        """Collect all user-defined identifiers"""
        identifiers = {}

        # Remove strings and comments temporarily
        temp_source = self.re_string.sub('""', source)
        temp_source = self.re_comment.sub('', temp_source)
        temp_source = self.re_preprocessor.sub('', temp_source)

        for match in self.re_identifier.finditer(temp_source):
            identifier = match.group(1)
            if (identifier not in self.keywords and
                identifier not in self.std_names and
                identifier not in self.winapi_names and
                not identifier.isupper() and
                len(identifier) > 1):
                identifiers[identifier] = identifiers.get(identifier, 0) + 1

        return {k: v for k, v in identifiers.items() if v >= 1}

    def obfuscate_arithmetic(self, source: str) -> str:
        """Add arithmetic obfuscation to numeric literals"""
        def replace_number(match):
            num = int(match.group())
            if num == 0:
                return "0"
            elif num == 1:
                return "(2-1)"
            elif num < 10:
                # Simple arithmetic expressions
                operations = [
                    f"({num+5}-5)",
                    f"({num*2}/2)",
                    f"({num}+0)",
                    f"((({num}<<1)>>1))"
                ]
                return random.choice(operations)
            else:
                # More complex for larger numbers
                offset = random.randint(1, 100)
                return f"({num+offset}-{offset})"

        return self.re_number.sub(replace_number, source)

    def insert_dead_code(self, source: str) -> str:
        """Insert dead code blocks that never execute"""
        dead_code_snippets = [
            "if (false) { int x = 1; x++; }",
            "while (0) { break; }",
            "for (int i = 0; i < 0; ++i) { volatile char c = 'a'; }",
            "do {} while(0);"
        ]

        lines = source.split('\n')
        result_lines = []

        for line in lines:
            result_lines.append(line)

            # Insert dead code randomly in function bodies
            if (line.strip().endswith('{') and '=' not in line and
                not line.strip().startswith('#') and
                not line.strip().startswith('//') and
                random.random() < 0.1):  # 10% chance

                indent = len(line) - len(line.lstrip())
                dead_snippet = ' ' * (indent + 4) + random.choice(dead_code_snippets)
                result_lines.append(dead_snippet)

        return '\n'.join(result_lines)

    def obfuscate_control_flow(self, source: str) -> str:
        """Advanced control flow obfuscation with state machines"""

        # Find simple function bodies to obfuscate
        func_pattern = re.compile(
            r'(\w+\s+\w+\s*\([^)]*\)\s*\{)([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
            re.DOTALL
        )

        def obfuscate_function_body(match):
            header = match.group(1)
            body = match.group(2).strip()

            if (len(body) < 50 or
                'for' in body or 'while' in body or 'switch' in body or
                body.count('{') > 2):
                return match.group(0)  # Skip complex functions

            statements = [s.strip() for s in body.split(';') if s.strip()]
            if len(statements) < 2:
                return match.group(0)

            # Create state machine
            state_var = self.generate_polymorphic_name(6)
            end_label = self.generate_polymorphic_name(8)

            obfuscated_body = f"""
    int {state_var} = 0;
    while(true) {{
        switch({state_var}) {{"""

            for i, stmt in enumerate(statements):
                if not stmt.endswith(';'):
                    stmt += ';'
                next_state = random.randint(100, 999) if i < len(statements) - 1 else -1

                obfuscated_body += f"""
            case {i if i == 0 else random.randint(100, 999)}: {{
                {stmt}
                {state_var} = {next_state};
                break;
            }}"""

            obfuscated_body += f"""
            default: goto {end_label};
        }}
        if({state_var} == -1) break;
    }}
{end_label}:;"""

            return header + obfuscated_body + '\n}'

        return func_pattern.sub(obfuscate_function_body, source)

    def polymorphic_string_encryption(self, source: str) -> Tuple[str, List]:
        """Polymorphic string encryption with multiple algorithms"""
        strings_data = []

        def encrypt_string(match):
            original = match.group(0)

            # Skip raw strings and wide strings
            if original.startswith('R"') or original.startswith('L'):
                return original

            content = original[1:-1]  # Remove quotes

            try:
                # Try to decode escape sequences
                raw_bytes = content.encode('utf-8').decode('unicode_escape').encode('latin1')
            except:
                raw_bytes = content.encode('latin1', errors='ignore')

            # Choose encryption method randomly
            encryption_methods = [
                self._xor_encrypt,
                self._rotate_encrypt,
                self._substitute_encrypt
            ]

            method_id = random.randint(0, len(encryption_methods) - 1)
            encrypted_bytes = encryption_methods[method_id](raw_bytes)

            string_id = len(strings_data)
            strings_data.append({
                'data': list(encrypted_bytes),
                'length': len(encrypted_bytes),
                'method': method_id
            })

            return f'_decrypt_str({string_id})'

        new_source = self.re_string.sub(encrypt_string, source)
        return new_source, strings_data

    def _xor_encrypt(self, data: bytes) -> bytes:
        """XOR encryption with rotating key"""
        key_base = self.config.string_encryption_key
        return bytes((b ^ (key_base + i % 255)) % 256 for i, b in enumerate(data))

    def _rotate_encrypt(self, data: bytes) -> bytes:
        """ROT encryption"""
        return bytes((b + 13) % 256 for b in data)

    def _substitute_encrypt(self, data: bytes) -> bytes:
        """Simple substitution cipher"""
        return bytes((b ^ 0xAA) % 256 for b in data)

    def generate_decryption_runtime(self, strings_data: List) -> str:
        """Generate polymorphic decryption runtime"""
        if not strings_data:
            return ""

        # Build encrypted data blob
        blob_data = []
        offsets = []
        current_offset = 0

        for string_info in strings_data:
            offsets.append((current_offset, string_info['length'], string_info['method']))
            blob_data.extend(string_info['data'])
            current_offset += string_info['length']

        # Generate obfuscated runtime
        blob_var = self.generate_polymorphic_name(10)
        decode_func = self.generate_polymorphic_name(12)
        str_func = self.generate_polymorphic_name(8)
        table_var = self.generate_polymorphic_name(9)

        runtime_code = f"""
#include <string>
#include <vector>

static const unsigned char {blob_var}[] = {{
{','.join(map(str, blob_data))}
}};

static std::string {decode_func}(int offset, int len, int method) {{
    std::string result;
    result.reserve(len);

    for(int i = 0; i < len; i++) {{
        unsigned char byte = {blob_var}[offset + i];
        switch(method) {{
            case 0: // XOR with rotating key
                byte = (byte ^ (({self.config.string_encryption_key} + i) % 255)) % 256;
                break;
            case 1: // ROT
                byte = (byte - 13 + 256) % 256;
                break;
            case 2: // Substitution
                byte = (byte ^ 0xAA) % 256;
                break;
        }}
        result += static_cast<char>(byte);
    }}
    return result;
}}

static std::string {str_func}(int id) {{
    static const int {table_var}[][3] = {{
{','.join(f'        {{{off},{length},{method}}}' for off, length, method in offsets)}
    }};
    return {decode_func}({table_var}[id][0], {table_var}[id][1], {table_var}[id][2]);
}}

#define _decrypt_str(id) {str_func}(id)
"""
        return runtime_code

    def rename_identifiers(self, source: str, identifiers: Dict[str, int]) -> str:
        """Rename identifiers with collision detection"""
        reserved_names = set(self.keywords) | self.std_names | self.winapi_names | {'include', 'define', 'pragma', 'main'}

        # Build rename mapping
        rename_map = {}
        for identifier in identifiers:
            if identifier not in reserved_names:
                new_name = self.generate_polymorphic_name()
                while new_name in reserved_names or new_name in rename_map.values():
                    new_name = self.generate_polymorphic_name()
                rename_map[identifier] = new_name

        self.identifier_map = rename_map
        return self._apply_identifier_renaming(source, rename_map)

    def _apply_identifier_renaming(self, source: str, rename_map: Dict[str, str]) -> str:
        """Apply identifier renaming while preserving strings and namespace access"""
        lines = source.splitlines(keepends=True)
        result_lines = []

        for line in lines:
            if self.re_preprocessor.match(line):
                result_lines.append(line)
                continue

            result_lines.append(self._rename_in_line(line, rename_map))

        return ''.join(result_lines)

    def _rename_in_line(self, line: str, rename_map: Dict[str, str]) -> str:
        """Rename identifiers in a single line, preserving strings"""
        result = []
        last_pos = 0

        # Process strings first to avoid renaming inside them
        for string_match in self.re_string.finditer(line):
            # Process code segment before string
            code_segment = line[last_pos:string_match.start()]
            result.append(self._rename_in_code_segment(code_segment, rename_map))

            # Keep string unchanged
            result.append(string_match.group(0))
            last_pos = string_match.end()

        # Process remaining code
        remaining_code = line[last_pos:]
        result.append(self._rename_in_code_segment(remaining_code, rename_map))

        return ''.join(result)

    def _rename_in_code_segment(self, code: str, rename_map: Dict[str, str]) -> str:
        """Rename identifiers in code segment, avoiding namespace/member access"""
        def replacer(match):
            identifier = match.group(1)

            if identifier in self.keywords or identifier in self.std_names or identifier in self.winapi_names:
                return identifier

            match_start = match.start()

            # Check context to avoid renaming namespace/member access
            prefix = code[max(0, match_start-2):match_start]
            if '::' in prefix or '->' in prefix or '.' in prefix[-1:]:
                return identifier

            return rename_map.get(identifier, identifier)

        return self.re_identifier.sub(replacer, code)

    def minify_code(self, source: str) -> str:
        """Minify code while preserving functionality"""
        # Remove comments but preserve preprocessor directives
        source = self.re_comment.sub('', source)

        lines = []
        for line in source.splitlines():
            if self.re_preprocessor.match(line):
                lines.append(line.strip())
            else:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)

        return '\n'.join(lines) + '\n'

    def add_fake_complexity(self, source: str) -> str:
        """Add fake complexity that doesn't affect functionality"""
        complexity_additions = [
            "volatile int _complexity_var = 0;",
            "static const int _fake_array[] = {1,2,3,4,5};",
            "inline void _dummy_func() { static int x = 0; x++; }",
            "#define _FAKE_MACRO(x) ((x) + 0)",
            "namespace { int _internal_var = 42; }"
        ]

        # Add fake complexity at the beginning
        fake_code = '\n'.join(random.sample(complexity_additions, 2))

        return fake_code + '\n\n' + source

    def obfuscate(self, source: str, options: Dict[str, bool]) -> str:
        """Main obfuscation pipeline"""
        print("🔒 Starting advanced obfuscation process...")

        if options.get('add_fake_complexity', True):
            print("  ➕ Adding fake complexity...")
            source = self.add_fake_complexity(source)

        if options.get('rename_identifiers', True):
            print("  🔄 Collecting and renaming identifiers...")
            identifiers = self.collect_identifiers(source)
            source = self.rename_identifiers(source, identifiers)

        if options.get('obfuscate_strings', True):
            print("  🔐 Applying polymorphic string encryption...")
            source, strings_data = self.polymorphic_string_encryption(source)
            if strings_data:
                runtime = self.generate_decryption_runtime(strings_data)
                # Insert runtime after includes
                include_match = re.search(r'^(?:\s*#include[^\n]*\n)+', source, re.MULTILINE)
                if include_match:
                    insert_pos = include_match.end()
                    source = source[:insert_pos] + runtime + source[insert_pos:]
                else:
                    source = runtime + source

        if options.get('obfuscate_arithmetic', True):
            print("  ➗ Obfuscating arithmetic expressions...")
            source = self.obfuscate_arithmetic(source)

        if options.get('insert_dead_code', True):
            print("  💀 Inserting dead code...")
            source = self.insert_dead_code(source)

        if options.get('obfuscate_control_flow', True):
            print("  🔀 Obfuscating control flow...")
            try:
                source = self.obfuscate_control_flow(source)
            except Exception as e:
                print(f"  ⚠️  Control flow obfuscation skipped: {e}")

        if options.get('minify', True):
            print("  🗜️  Minifying code...")
            source = self.minify_code(source)

        print("✅ Obfuscation complete!")
        return source

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Polymorphic C++ Obfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python obfuscator.py -i input.cpp -o output.cpp
  python obfuscator.py -i code.cpp -o obfuscated.cpp --no-control-flow
  python obfuscator.py -i main.cpp -o result.cpp --intensity high
        """
    )

    parser.add_argument('-i', '--input', required=True, help='Input C++ file')
    parser.add_argument('-o', '--output', required=True, help='Output obfuscated file')

    # Obfuscation options
    parser.add_argument('--no-strings', action='store_true', help='Disable string obfuscation')
    parser.add_argument('--no-rename', action='store_true', help='Disable identifier renaming')
    parser.add_argument('--no-minify', action='store_true', help='Disable code minification')
    parser.add_argument('--no-control-flow', action='store_true', help='Disable control flow obfuscation')
    parser.add_argument('--no-arithmetic', action='store_true', help='Disable arithmetic obfuscation')
    parser.add_argument('--no-dead-code', action='store_true', help='Disable dead code insertion')
    parser.add_argument('--no-fake-complexity', action='store_true', help='Disable fake complexity')

    # Advanced options
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], default='medium',
                       help='Obfuscation intensity level')
    parser.add_argument('--seed', type=int, help='Random seed for reproducible obfuscation')
    parser.add_argument('--config', help='JSON config file for advanced settings')
    parser.add_argument('--stats', action='store_true', help='Show obfuscation statistics')

    args = parser.parse_args()

    # Set random seed if provided
    if args.seed:
        random.seed(args.seed)
        print(f"🎲 Using random seed: {args.seed}")

    try:
        # Read input file
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()

        # Create configuration
        config = ObfuscatorConfig()

        # Load config file if provided
        if args.config and os.path.exists(args.config):
            with open(args.config, 'r') as f:
                config_data = json.load(f)
                # Update config with loaded data
                for key, value in config_data.items():
                    if hasattr(config, key):
                        setattr(config, key, value)

        # Adjust intensity
        if args.intensity == 'low':
            config.control_flow_complexity = 1
            config.dead_code_intensity = 1
            config.arithmetic_complexity = 1
        elif args.intensity == 'high':
            config.control_flow_complexity = 5
            config.dead_code_intensity = 4
            config.arithmetic_complexity = 3

        # Create obfuscator
        obfuscator = AdvancedObfuscator(config)

        # Set obfuscation options
        options = {
            'obfuscate_strings': not args.no_strings,
            'rename_identifiers': not args.no_rename,
            'minify': not args.no_minify,
            'obfuscate_control_flow': not args.no_control_flow,
            'obfuscate_arithmetic': not args.no_arithmetic,
            'insert_dead_code': not args.no_dead_code,
            'add_fake_complexity': not args.no_fake_complexity,
        }

        # Perform obfuscation
        original_size = len(source_code)
        obfuscated_code = obfuscator.obfuscate(source_code, options)
        final_size = len(obfuscated_code)

        # Write output
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(obfuscated_code)

        print(f"\n🎉 Obfuscation completed successfully!")
        print(f"📁 Output saved to: {args.output}")

        if args.stats:
            print(f"\n📊 Statistics:")
            print(f"  Original size: {original_size:,} bytes")
            print(f"  Obfuscated size: {final_size:,} bytes")
            print(f"  Size change: {((final_size - original_size) / original_size) * 100:+.1f}%")
            print(f"  Identifiers renamed: {len(obfuscator.identifier_map)}")

        print(f"\n💡 Tip: If compilation fails, try --no-control-flow or lower --intensity")

    except FileNotFoundError:
        print(f"❌ Error: Input file '{args.input}' not found!")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during obfuscation: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
