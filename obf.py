import sys
import random
import string
import os
import re

def generate_random_name(length=5, used_names=None):
    if used_names is None:
        used_names = set()
    while True:
        name = "".join(random.choices(string.ascii_uppercase, k=length))
        if name not in used_names:
            used_names.add(name)
            return name

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    unique_chars = set()
    for line in lines:
        unique_chars.update(line)

    # Critical Batch control characters and metacharacters must NOT be obfuscated
    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')
    safe_chars = [c for c in unique_chars if c not in forbidden]

    # Add common ones
    for c in string.ascii_letters + string.digits + " .\\/-_":
        if c not in safe_chars and c not in forbidden:
            safe_chars.append(c)

    random.shuffle(safe_chars)
    master_string = "".join(safe_chars)

    used_vars = set()
    master_var = "_" + generate_random_name(5, used_vars)
    char_map = {}
    prefix = "_"

    char_assignments = []
    for i, char in enumerate(master_string):
        var_name = prefix + generate_random_name(4, used_vars)
        char_map[char] = var_name
        if random.random() > 0.5:
            char_assignments.append(f'set "{var_name}=%{master_var}:~{i},1%"')
        else:
            char_assignments.append(f'call set "{var_name}=%%{master_var}:~{i},1%%"')

    random.shuffle(char_assignments)

    obfuscated_lines = ["@echo off\n"]
    obfuscated_lines.append(f'set "{master_var}={master_string}"\n')

    for i, m_line in enumerate(char_assignments):
        obfuscated_lines.append(m_line + "\n")
        if i % 20 == 0 and random.random() < 0.1:
            obfuscated_lines.append(f'REM {generate_random_name(10)}\n')

    # Regex to protect:
    # 1. %VAR% (Standard, ensuring no spaces/delimiters inside for simple names)
    # 2. %~[modifier][digit] (Positional parameters like %1 or %~dp0)
    # 3. %digit or %* (Positional parameters like %1, %*)
    # 4. %%[letter] (FOR variables)
    # 5. ![VAR]! (Delayed expansion)
    pattern = r'(%[a-zA-Z0-9_#$@-]+%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+!)'

    for line in lines:
        stripped = line.lstrip()
        if not stripped:
            continue

        if stripped.startswith(":") and not stripped.startswith("::"):
            obfuscated_lines.append(line)
            continue

        if stripped.lower().startswith("@echo off"):
            continue

        parts = re.split(pattern, line, flags=re.IGNORECASE)

        new_line = ""
        for part in parts:
            if re.match(pattern, part, re.IGNORECASE):
                new_line += part
            else:
                for char in part:
                    if char in char_map and random.random() < 0.85:
                        new_line += f"%{char_map[char]}%"
                    else:
                        if char.isalpha() and random.random() < 0.1:
                            new_line += "^" + (char.upper() if random.random() > 0.5 else char.lower())
                        else:
                            new_line += char

        obfuscated_lines.append(new_line)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(obfuscated_lines)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python obf.py <input.bat>")
        sys.exit(1)

    input_bat = sys.argv[1]
    output_bat = "obf_" + os.path.basename(input_bat)

    obfuscate_batch(input_bat, output_bat)
    print(f"Obfuscated {input_bat} -> {output_bat}")
