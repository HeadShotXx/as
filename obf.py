import sys
import random
import string
import os
import re

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    # 1. Character Mapping
    char_map = {}
    # Excluding : and % to avoid breaking labels, parameters, and vars
    chars_to_map = string.ascii_letters + string.digits + " .\\/-_\""
    mapping_code = []

    prefix = "_" + generate_random_string(3)

    for char in chars_to_map:
        var_name = prefix + generate_random_string(4)
        char_map[char] = var_name
        mapping_code.append(f"set {var_name}={char}")

    random.shuffle(mapping_code)

    obfuscated_lines = ["@echo off\n"]
    obfuscated_lines.extend([line + "\n" for line in mapping_code])

    for line in lines:
        # Preserve original line to avoid breaking whitespace-sensitive commands
        # Check if it's a label
        stripped = line.lstrip()
        if stripped.startswith(":") and not stripped.startswith("::"):
            obfuscated_lines.append(line)
            continue

        if stripped.lower().startswith("@echo off"):
            continue

        # 2. Junk Code Insertion
        if random.random() < 0.1:
            junk_var = generate_random_string(5)
            junk_val = generate_random_string(10)
            obfuscated_lines.append(f"set {junk_var}={junk_val}\n")

        # 3. Intelligent Fragmentation & Replacement
        # Regex to find: %VAR%, %~dp0, %1, %%i
        # Matches:
        # 1. %[^% ]+% (Standard vars)
        # 2. %~[a-z0-9]*[0-9] (Positional parameters like %1 or %~dp0)
        # 3. %%[a-zA-Z] (FOR loop variables)
        pattern = r'(%[^% ]+%|%~[a-z0-9]*[0-9]|%%[a-zA-Z])'
        parts = re.split(pattern, line, flags=re.IGNORECASE)

        new_line = ""
        for part in parts:
            if re.match(pattern, part, re.IGNORECASE):
                # It's a protected variable/parameter
                new_line += part
            else:
                # Obfuscate normal text
                for char in part:
                    if char in char_map and random.random() < 0.7:
                        new_line += f"%{char_map[char]}%"
                    else:
                        if char.isalpha() and random.random() < 0.2:
                            new_line += "^" + char
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
