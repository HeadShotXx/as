import sys
import random
import string
import os
import re

def generate_random_name(length=5, used_names=None):
    if used_names is None:
        used_names = set()
    while True:
        chars = "IlO0_"
        name = "".join(random.choices(chars, k=length))
        if name not in used_names:
            used_names.add(name)
            return name

def generate_unreadable_string(length=50):
    noise_chars = string.ascii_letters + string.digits + "@#$_+-=[]{}|;:,.<>?/`~"
    return "".join(random.choices(noise_chars, k=length))

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    # ASCII mapping pool only
    mapping_pool = string.ascii_letters + string.digits + " .\\/-_"
    mapping_pool = list(set(mapping_pool))
    random.shuffle(mapping_pool)
    master_string = "".join(mapping_pool)

    used_vars = set()
    master_var = "__" + generate_random_name(8, used_vars)
    char_map = {}

    noise_vars = []
    for _ in range(3):
        nv = "___" + generate_random_name(10, used_vars)
        val = generate_unreadable_string(random.randint(50, 80))
        noise_vars.append((nv, val))

    char_assignments = []
    for i, char in enumerate(master_string):
        var_name = "_" + generate_random_name(6, used_vars)
        char_map[char] = var_name

        method = random.random()
        if method > 0.6:
            char_assignments.append(f'set "{var_name}=%{master_var}:~{i},1%"\n')
        elif method > 0.3:
            char_assignments.append(f'call set "{var_name}=%%{master_var}:~{i},1%%"\n')
        else:
            # Grouping dependent assignments to prevent shuffle issues
            tmp_var = "_" + generate_random_name(7, used_vars)
            grouped_set = f'set "{tmp_var}=%{master_var}:~{i},1%"\nset "{var_name}=%{tmp_var}%"\n'
            char_assignments.append(grouped_set)

    random.shuffle(char_assignments)

    obfuscated_lines = ["@echo off\n", "chcp 65001 >nul\n"]
    for nv, val in noise_vars:
        obfuscated_lines.append(f'set "{nv}={val}"\n')
    obfuscated_lines.append(f'set "{master_var}={master_string}"\n')

    for i, m_block in enumerate(char_assignments):
        obfuscated_lines.append(m_block)
        if i % 25 == 0 and random.random() < 0.15:
            obfuscated_lines.append(f'REM {generate_unreadable_string(15)}\n')

    # Precise regex for:
    # 1. %VAR%, %VAR:a=b%, %VAR:~0,1%
    # 2. %~modifiers digit
    # 3. %digit, %*
    # 4. %%[a-zA-Z]
    # 5. !VAR!, !VAR:a=b!, !VAR:~0,1!
    pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'

    for line in lines:
        stripped = line.lstrip()
        if not stripped:
            continue

        if stripped.startswith(":") and not stripped.startswith("::"):
            obfuscated_lines.append(line)
            continue

        if stripped.lower().startswith("@echo off"):
            continue

        # Limit dynamic execution to safe lines
        safe_for_dyn = not any(c in stripped for c in ('|', '>', '<', '&', '(', ')'))
        use_dynamic = safe_for_dyn and random.random() < 0.1 and len(stripped) > 10

        parts = re.split(pattern, line, flags=re.IGNORECASE)
        obfuscated_part_line = ""
        for part in parts:
            if part and re.match(pattern, part, re.IGNORECASE):
                obfuscated_part_line += part
            elif part:
                for char in part:
                    if char in char_map and random.random() < 0.8:
                        obfuscated_part_line += f"%{char_map[char]}%"
                    else:
                        if char.isalpha() and random.random() < 0.05:
                            obfuscated_part_line += "^" + (char.upper() if random.random() > 0.5 else char.lower())
                        else:
                            obfuscated_part_line += char

        if use_dynamic:
            dyn_var = "____" + generate_random_name(15, used_vars)
            obfuscated_lines.append(f'set "{dyn_var}={obfuscated_part_line.strip()}"\n')
            obfuscated_lines.append(f'call %{dyn_var}%\n')
        else:
            obfuscated_lines.append(obfuscated_part_line)

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
