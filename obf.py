import sys
import random
import string
import os
import re

def generate_random_name(length=5, used_names=None):
    if used_names is None:
        used_names = set()
    while True:
        # Confusing character set for variable names
        chars = "IlO0_"
        name = "".join(random.choices(chars, k=length))
        if name not in used_names:
            used_names.add(name)
            return name

def generate_unreadable_string(length=50):
    noise_chars = string.ascii_letters + string.digits + "@#$_+-=[]{}|;:,.<>?/`~"
    # Safe chars for Batch command line noise
    safe_noise = [c for c in noise_chars if c not in ('%', '"', '^', '`', '&', '|', '<', '>', '(', ')', "'")]
    return "".join(random.choices(safe_noise, k=length))

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    used_vars = set()

    # 1. Dynamically Build Mapping Pool from ALL used chars in file
    unique_file_chars = set()
    for line in lines:
        unique_file_chars.update(line)

    # Structural characters that MUST remain literals to avoid breaking Batch logic
    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')

    # Base set of characters for pools
    mapping_pool_chars = sorted(list((unique_file_chars | set(string.ascii_letters + string.digits + " .\\/-_")) - set(forbidden)))

    # 2. Multi-layer Pure Batch Encoding (Pool Rotation)
    pools = []
    pool_vars = []
    shifts = []
    num_pools = random.randint(3, 4)

    for _ in range(num_pools):
        p_list = list(mapping_pool_chars)
        random.shuffle(p_list)
        pool_str = "".join(p_list)

        # Encoding: Rotation
        shift_val = random.randint(1, len(pool_str) - 1)
        encoded_pool = pool_str[shift_val:] + pool_str[:shift_val]

        pv = "__" + generate_random_name(8, used_vars)
        pools.append(pool_str)
        pool_vars.append(pv)
        shifts.append((pv, encoded_pool, shift_val, len(pool_str)))

    # 3. Variable Shadowing: Map each char to multiple random variables
    char_map = {}
    mapping_code = []
    for char in mapping_pool_chars:
        shadow_names = []
        # Each character gets 2-3 unique variable names
        for _ in range(random.randint(2, 3)):
            var_name = "_" + generate_random_name(random.randint(6, 12), used_vars)
            shadow_names.append(var_name)

            # Select a pool for this variable's definition
            p_idx = random.randint(0, len(pools) - 1)
            target_pv = pool_vars[p_idx]
            char_idx = pools[p_idx].find(char)

            if char_idx != -1:
                # Use different assignment methods for polymorphism
                method = random.random()
                if method > 0.6:
                    mapping_code.append(f'set "{var_name}=%{target_pv}:~{char_idx},1%"\n')
                elif method > 0.3:
                    mapping_code.append(f'call set "{var_name}=%%{target_pv}:~{char_idx},1%%"\n')
                else:
                    tmp_v = "_" + generate_random_name(7, used_vars)
                    mapping_code.append(f'set "{tmp_v}=%{target_pv}:~{char_idx},1%"\nset "{var_name}=%{tmp_v}%"\n')
        char_map[char] = shadow_names

    random.shuffle(mapping_code)

    # 4. String Fragmentation Pre-computation (Addressing 8,191 char limit)
    # Fragments are stored in the header to avoid parse-time expansion issues in blocks.
    fragments = []
    pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'

    obfuscated_body = []
    for line in lines:
        line = line.rstrip('\r\n')
        if not line: continue
        stripped = line.lstrip()
        if not stripped: continue

        # Preserve labels
        if stripped.startswith(":") and not stripped.startswith("::"):
            obfuscated_body.append(line + "\n")
            continue

        if stripped.lower().startswith("@echo off"): continue

        parts = re.split(pattern, line, flags=re.IGNORECASE)
        obfuscated_line_parts = []
        for part in parts:
            if not part: continue
            if re.match(pattern, part, re.IGNORECASE):
                # Protected variable or parameter
                obfuscated_line_parts.append(part)
            else:
                i = 0
                while i < len(part):
                    # Use chunks of 2-4 characters to balance obfuscation and line length
                    chunk_size = random.randint(2, 4)
                    chunk = part[i:i+chunk_size]

                    # 75% chance to use shadowed variables, 25% to use caret-escaped literals
                    # This reduces the overall length expansion to stay within Batch limits.
                    if random.random() < 0.75:
                        frag_str = ""
                        for c in chunk:
                            if c in char_map:
                                frag_str += f"%{random.choice(char_map[c])}%"
                            else:
                                # Fallback for characters not in pool (e.g. non-ASCII)
                                if c.isalpha():
                                    frag_str += "^" + (c.upper() if random.random() > 0.5 else c.lower())
                                else:
                                    frag_str += c

                        # Occasionally store the fragment in its own variable (Fragmentation)
                        if len(chunk) > 1 and random.random() < 0.2:
                            f_var = "____" + generate_random_name(15, used_vars)
                            fragments.append(f'set "{f_var}={frag_str}"\n')
                            obfuscated_line_parts.append(f"%{f_var}%")
                        else:
                            obfuscated_line_parts.append(frag_str)
                    else:
                        # Use literal characters with caret noise
                        lit_str = ""
                        for c in chunk:
                            if c.isalpha():
                                lit_str += "^" + (c.upper() if random.random() > 0.5 else c.lower())
                            else:
                                lit_str += c
                        obfuscated_line_parts.append(lit_str)
                    i += chunk_size

        obfuscated_body.append("".join(obfuscated_line_parts) + "\n")

    # 5. Construct Final Script
    final_lines = ["@echo off\n", "chcp 65001 >nul\n"]

    # Runtime Decoder Block (Pure Batch Pool Restoration)
    for pv, enc, shift, total in shifts:
        final_lines.append(f'set "{pv}={enc}"\n')
        l_var = random.choice(string.ascii_uppercase)
        back_shift = total - shift
        # This rotation restores the character pool at runtime
        final_lines.append(f'for /L %%{l_var} in (1,1,1) do set "{pv}=%{pv}:~{back_shift}%%{pv}:~0,{back_shift}%"\n')

    # Header Variables: Character Mappings & Fragments
    final_lines.extend(mapping_code)
    final_lines.extend(fragments)

    # Polymorphic Flow Noise
    start_lbl = generate_random_name(6, used_vars)
    final_lines.append(f"goto :{start_lbl}\n")
    for _ in range(2):
        final_lines.append(f":{generate_random_name(8, used_vars)}\n")
        final_lines.append(f'set "{generate_random_name(10, used_vars)}={generate_unreadable_string(15)}"\n')
    final_lines.append(f":{start_lbl}\n")

    # The actual obfuscated code (reconstructed from header variables)
    final_lines.extend(obfuscated_body)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(final_lines)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python obf.py <input.bat>")
        sys.exit(1)
    input_bat = sys.argv[1]
    output_bat = "obf_" + os.path.basename(input_bat)
    obfuscate_batch(input_bat, output_bat)
    print(f"Obfuscated {input_bat} -> {output_bat}")
