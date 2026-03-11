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

    used_vars = set()

    # 1. Multiple Character Pools
    pools = []
    pool_vars = []
    for _ in range(random.randint(3, 5)):
        pool_chars = list(string.ascii_letters + string.digits + " .\\/-_")
        random.shuffle(pool_chars)
        pool_str = "".join(pool_chars)
        pools.append(pool_str)
        pv = "__" + generate_random_name(8, used_vars)
        pool_vars.append(pv)

    char_map = {}
    char_assignments = []

    # Map all unique characters in the file across different pools randomly
    all_needed_chars = set()
    for line in lines:
        all_needed_chars.update(line)

    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')

    for char in all_needed_chars:
        if char in forbidden:
            continue

        # Pick a pool that has this character
        # Actually, all pools have all base characters, just shuffled.
        pool_idx = random.randint(0, len(pools) - 1)
        target_pool = pools[pool_idx]
        target_pool_var = pool_vars[pool_idx]

        char_idx = target_pool.find(char)
        if char_idx == -1:
            continue

        var_name = "_" + generate_random_name(6, used_vars)
        char_map[char] = var_name

        method = random.random()
        if method > 0.6:
            char_assignments.append(f'set "{var_name}=%{target_pool_var}:~{char_idx},1%"\n')
        elif method > 0.3:
            char_assignments.append(f'call set "{var_name}=%%{target_pool_var}:~{char_idx},1%%"\n')
        else:
            tmp_var = "_" + generate_random_name(7, used_vars)
            grouped_set = f'set "{tmp_var}=%{target_pool_var}:~{char_idx},1%"\nset "{var_name}=%{tmp_var}%"\n'
            char_assignments.append(grouped_set)

    random.shuffle(char_assignments)

    obfuscated_lines = ["@echo off\n", "chcp 65001 >nul\n"]

    # 2. Runtime Shuffle Logic
    # We create a variable that "shuffles" at runtime by iterative self-assignment
    shuffle_var = "__" + generate_random_name(10, used_vars)
    shuffle_pool = generate_unreadable_string(30)
    obfuscated_lines.append(f'set "{shuffle_var}={shuffle_pool}"\n')
    # A loop that superficially "shuffles" or just adds runtime noise
    loop_i = generate_random_name(2, set())
    obfuscated_lines.append(f'for /L %%{loop_i} in (1,1,20) do set "{shuffle_var}=%{shuffle_var}:~1%%{shuffle_var}:~0,1%"\n')

    # Add pool variables
    for pv, val in zip(pool_vars, pools):
        obfuscated_lines.append(f'set "{pv}={val}"\n')
        if random.random() < 0.2:
            obfuscated_lines.append(f'REM {generate_unreadable_string(20)}\n')

    # Add character assignments
    for i, m_block in enumerate(char_assignments):
        obfuscated_lines.append(m_block)
        if i % 30 == 0 and random.random() < 0.1:
            obfuscated_lines.append(f'set "___"={generate_unreadable_string(10)}"\n')

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

        safe_for_dyn = not any(c in stripped for c in ('|', '>', '<', '&', '(', ')'))
        use_dynamic = safe_for_dyn and random.random() < 0.15 and len(stripped) > 10

        parts = re.split(pattern, line, flags=re.IGNORECASE)
        obfuscated_part_line = ""
        for part in parts:
            if part and re.match(pattern, part, re.IGNORECASE):
                obfuscated_part_line += part
            elif part:
                for char in part:
                    if char in char_map and random.random() < 0.85:
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
