import sys
import random
import string
import os
import re

def generate_random_name(length=5, used_names=None):
    if used_names is None:
        used_names = set()
    while True:
        # Mix of confusing characters and underscores
        chars = "IlO0_"
        name = "".join(random.choices(chars, k=length))
        if name not in used_names:
            used_names.add(name)
            return name

def generate_unreadable_string(length=50):
    noise_chars = string.ascii_letters + string.digits + "@#$_+-=[]{}|;:,.<>?/`~"
    # Safe chars for Batch command line
    safe_noise = [c for c in noise_chars if c not in ('%', '"', '^', '`', '&', '|', '<', '>', '(', ')', "'")]
    return "".join(random.choices(safe_noise, k=length))

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.rstrip('\r\n') for l in f.readlines()]
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    used_vars = set()

    # 1. Dynamically Build Mapping Pool
    unique_file_chars = set()
    for line in lines:
        unique_file_chars.update(line)

    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')
    mapping_pool_chars = sorted(list((unique_file_chars | set(string.ascii_letters + string.digits + " .\\/-_")) - set(forbidden)))

    # 2. Multi-layer Pure Batch Encoding (Pool Rotation)
    pools = []
    pool_vars = []
    shifts = []
    num_pools = random.randint(3, 5)
    for _ in range(num_pools):
        p_list = list(mapping_pool_chars)
        random.shuffle(p_list)
        pool_str = "".join(p_list)
        shift_val = random.randint(1, len(pool_str) - 1)
        encoded_pool = pool_str[shift_val:] + pool_str[:shift_val]
        pv = "__" + generate_random_name(random.randint(6, 10), used_vars)
        pools.append(pool_str)
        pool_vars.append(pv)
        shifts.append((pv, encoded_pool, shift_val, len(pool_str)))

    # 3. Variable Shadowing
    char_map = {}
    mapping_code = []
    for char in mapping_pool_chars:
        shadow_names = []
        for _ in range(random.randint(2, 4)):
            var_name = "_" + generate_random_name(random.randint(6, 12), used_vars)
            shadow_names.append(var_name)
            p_idx = random.randint(0, len(pools) - 1)
            target_pv = pool_vars[p_idx]
            char_idx = pools[p_idx].find(char)
            if char_idx != -1:
                if random.random() > 0.5:
                    mapping_code.append(f'set "{var_name}=%{target_pv}:~{char_idx},1%"\n')
                else:
                    tmp_v = "_" + generate_random_name(7, used_vars)
                    mapping_code.append(f'set "{tmp_v}=%{target_pv}:~{char_idx},1%"\nset "{var_name}=%{tmp_v}%"\n')
        char_map[char] = shadow_names
    random.shuffle(mapping_code)

    # 4. Control-flow Flattening
    blocks = []
    current_block = []
    nest_level = 0
    for line in lines:
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.lower().startswith("@echo off"): continue
        nest_level += line.count('(')
        nest_level -= line.count(')')
        if nest_level == 0 and ((stripped.startswith(":") and not stripped.startswith("::")) or (random.random() < 0.3 and not stripped.lower().startswith("set "))):
            if current_block: blocks.append(current_block)
            current_block = []
        current_block.append(line)
    if current_block: blocks.append(current_block)

    # 5. Body Obfuscation with Fragmentation and Shadowing
    fragments = []
    pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'
    state_var = "_" + generate_random_name(10, used_vars)
    block_labels = [generate_random_name(10, used_vars) for _ in range(len(blocks))]
    dispatcher_label = generate_random_name(12, used_vars)
    end_id = generate_random_name(8, used_vars)

    flattened_blocks_data = []
    for idx, block in enumerate(blocks):
        obfuscated_block = [f":{block_labels[idx]}\n"]
        for line in block:
            stripped = line.lstrip()
            if stripped.startswith(":") and not stripped.startswith("::"):
                obfuscated_block.append(line + "\n")
                continue
            parts = re.split(pattern, line, flags=re.IGNORECASE)
            obf_line_parts = []
            for part in parts:
                if not part: continue
                if re.match(pattern, part, re.IGNORECASE):
                    obf_line_parts.append(part)
                else:
                    i = 0
                    while i < len(part):
                        chunk_size = random.randint(2, 4)
                        chunk = part[i:i+chunk_size]
                        if random.random() < 0.85:
                            frag_str = "".join([f"%{random.choice(char_map[c])}%" if c in char_map else c for c in chunk])
                            if len(chunk) > 1 and random.random() < 0.2:
                                f_var = "____" + generate_random_name(15, used_vars)
                                fragments.append(f'set "{f_var}={frag_str}"\n')
                                obf_line_parts.append(f"%{f_var}%")
                            else:
                                obf_line_parts.append(frag_str)
                        else:
                            lit = "".join(["^"+c if c.isalpha() and random.random() < 0.1 else c for c in chunk])
                            obf_line_parts.append(lit)
                        i += chunk_size
            obfuscated_block.append("".join(obf_line_parts) + "\n")
        next_state = block_labels[idx+1] if idx+1 < len(blocks) else end_id
        obfuscated_block.append(f'set "{state_var}={next_state}"\n')
        obfuscated_block.append(f"goto :{dispatcher_label}\n")
        flattened_blocks_data.append(obfuscated_block)

    # 6. Dead-Path Injection (Unreachable Blocks)
    for _ in range(3):
        dead_id = generate_random_name(10, used_vars)
        dead_block = [f":{dead_id}\n"]
        for _ in range(random.randint(2, 5)):
            v = generate_random_name(12, used_vars)
            val = generate_unreadable_string(20)
            dead_block.append(f'set "{v}={val}"\n')
        dead_block.append(f'set "{state_var}={random.choice(block_labels)}"\n') # Point back to real block
        dead_block.append(f"goto :{dispatcher_label}\n")
        flattened_blocks_data.append(dead_block)

    random.shuffle(flattened_blocks_data)

    # 7. Final Construction
    final_lines = ["@echo off\n", "chcp 65001 >nul\n"]

    # Fake Decoders and Real Decoders
    for _ in range(2):
        fv = "__" + generate_random_name(10, used_vars)
        val = generate_unreadable_string(40)
        final_lines.append(f'set "{fv}={val}"\n')
        l_v = random.choice(string.ascii_uppercase)
        final_lines.append(f'for /L %%{l_v} in (1,1,20) do set "{fv}=%{fv}:~1%%{fv}:~0,1%"\n')
        if random.random() < 0.5:
            final_lines.append(f'set "___"=%{fv}:~0,5%%"\n')

    for pv, enc, shift, total in shifts:
        final_lines.append(f'set "{pv}={enc}"\n')
        l_var = random.choice(string.ascii_uppercase)
        back_shift = total - shift
        final_lines.append(f'for /L %%{l_var} in (1,1,1) do set "{pv}=%{pv}:~{back_shift}%%{pv}:~0,{back_shift}%"\n')

    final_lines.extend(mapping_code)
    final_lines.extend(fragments)

    # Runtime Variable Swapping logic (Polymorphic Noise)
    for _ in range(5):
        if len(mapping_code) > 10:
            v1 = generate_random_name(10, used_vars)
            v2 = random.choice(list(used_vars))
            final_lines.append(f'set "{v1}=%{v2}%"\n')

    final_lines.append(f'set "{state_var}={block_labels[0]}"\n')
    final_lines.append(f":{dispatcher_label}\n")
    final_lines.append(f"goto :%{state_var}%\n")
    final_lines.append(f":{end_id}\n")
    final_lines.append("exit /b\n")

    for b in flattened_blocks_data:
        final_lines.extend(b)

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
