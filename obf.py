import sys
import random
import string
import os
import re

def generate_random_name(length=5, used_names=None):
    if used_names is None:
        used_names = set()
    while True:
        # Using confusing-looking characters for variable names
        chars = "IlO0_"
        name = "".join(random.choices(chars, k=length))
        if name not in used_names:
            used_names.add(name)
            return name

def generate_unreadable_string(length=50):
    # Characters that look like garbage or noise
    noise_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?/`~"
    # Filter out chars that are forbidden in the master string for safety
    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')
    safe_noise = [c for c in noise_chars if c not in forbidden]
    return "".join(random.choices(safe_noise, k=length))

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
    master_var = "__" + generate_random_name(8, used_vars)
    char_map = {}

    # Noise strings to add confusion
    noise_vars = []
    for _ in range(5):
        nv = "___" + generate_random_name(10, used_vars)
        val = generate_unreadable_string(random.randint(60, 100))
        noise_vars.append((nv, val))

    char_assignments = []
    for i, char in enumerate(master_string):
        var_name = "_" + generate_random_name(6, used_vars)
        char_map[char] = var_name

        method = random.random()
        if method > 0.6:
            char_assignments.append(f'set "{var_name}=%{master_var}:~{i},1%"')
        elif method > 0.3:
            char_assignments.append(f'call set "{var_name}=%%{master_var}:~{i},1%%"')
        else:
            # Multi-level assignment for extra confusion
            tmp_var = "_" + generate_random_name(7, used_vars)
            char_assignments.append(f'set "{tmp_var}=%{master_var}:~{i},1%"')
            char_assignments.append(f'set "{var_name}=%{tmp_var}%"')

    random.shuffle(char_assignments)

    obfuscated_lines = ["@echo off\n"]

    # Add noise variables as junk in the header
    for nv, val in noise_vars:
        obfuscated_lines.append(f'set "{nv}={val}"\n')

    # Set Master Var
    obfuscated_lines.append(f'set "{master_var}={master_string}"\n')

    # Set character mappings with random noise insertion
    for i, m_line in enumerate(char_assignments):
        obfuscated_lines.append(m_line + "\n")
        if i % 15 == 0 and random.random() < 0.2:
            obfuscated_lines.append(f'REM {generate_unreadable_string(20)}\n')
            if random.random() < 0.1:
                junk_v = "__" + generate_random_name(12, used_vars)
                obfuscated_lines.append(f'set "{junk_v}=%{noise_vars[0][0]}:~{random.randint(0,10)},5%"\n')

    # Protection pattern
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

        # Occasionally use dynamic command construction for a line
        use_dynamic = random.random() < 0.15 and len(stripped) > 5

        parts = re.split(pattern, line, flags=re.IGNORECASE)
        obfuscated_part_line = ""
        for part in parts:
            if re.match(pattern, part, re.IGNORECASE):
                obfuscated_part_line += part
            else:
                for char in part:
                    if char in char_map and random.random() < 0.9:
                        obfuscated_part_line += f"%{char_map[char]}%"
                    else:
                        if char.isalpha() and random.random() < 0.15:
                            obfuscated_part_line += "^" + (char.upper() if random.random() > 0.5 else char.lower())
                        else:
                            obfuscated_part_line += char

        if use_dynamic:
            dyn_var = "____" + generate_random_name(15, used_vars)
            obfuscated_lines.append(f'set "{dyn_var}={obfuscated_part_line.strip()}"\n')
            obfuscated_lines.append(f'%{dyn_var}%\n')
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
