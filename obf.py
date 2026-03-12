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

    unique_file_chars = set()
    for line in lines:
        unique_file_chars.update(line)

    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')
    mapping_pool_chars = sorted(list((unique_file_chars | set(string.ascii_letters + string.digits + " .\\/-_")) - set(forbidden)))

    env_sources = {
        "COMSPEC": "C:\\Windows\\system32\\cmd.exe",
        "OS": "Windows_NT",
        "ALLUSERSPROFILE": "C:\\ProgramData",
        "SystemRoot": "C:\\Windows"
    }

    pools = []
    pool_vars = []
    pool_decoders = []
    num_pools = random.randint(3, 4)

    for _ in range(num_pools):
        p_list = list(mapping_pool_chars)
        random.shuffle(p_list)
        pool_str = "".join(p_list)

        shift = random.randint(1, len(pool_str) - 1)
        encoded = pool_str[shift:] + pool_str[:shift]

        pv = "__" + generate_random_name(8, used_vars)
        pools.append(pool_str)
        pool_vars.append(pv)

        loop_v = random.choice(string.ascii_uppercase)
        back_shift = len(pool_str) - shift

        # Batch needs %%A.
        # Python literal string '%%' becomes '%'
        # Python f-string '%%%%' becomes '%%'
        # So to get %%A in Batch:
        decoder_cmd = f'set "{pv}={encoded}"\n'
        decoder_cmd += f'for /L %%%%{loop_v} in (1,1,1) do set "{pv}=%{pv}:~{back_shift}%%%%{pv}:~0,{back_shift}%"\n'
        pool_decoders.append(decoder_cmd)

    char_map = {}
    mapping_code = []
    for char in mapping_pool_chars:
        shadow_names = []
        for _ in range(random.randint(2, 3)):
            var_name = "_" + generate_random_name(random.randint(6, 12), used_vars)
            shadow_names.append(var_name)

            p_idx = random.randint(0, len(pools) - 1)
            target_pv = pool_vars[p_idx]
            char_idx = pools[p_idx].find(char)

            if char_idx != -1:
                method = random.random()
                if method > 0.8: # Environment Indirection
                    src = None
                    for envar, enval in env_sources.items():
                        idx = enval.find(char)
                        if idx != -1:
                            src = (envar, idx)
                            break
                    if src:
                        mapping_code.append(f'if 1==1 set "{var_name}=%{src[0]}:~{src[1]},1%"\n')
                    else:
                        mapping_code.append(f'set "{var_name}=%{target_pv}:~{char_idx},1%"\n')
                elif method > 0.4: # Direct
                    mapping_code.append(f'set "{var_name}=%{target_pv}:~{char_idx},1%"\n')
                else: # Chained
                    v_link = "_" + generate_random_name(10, used_vars)
                    mapping_code.append(f'set "{v_link}=%{target_pv}:~{char_idx},1%"\n')
                    mapping_code.append(f'set "{var_name}=%{v_link}%"\n')
        char_map[char] = shadow_names
    random.shuffle(mapping_code)

    blocks = []
    current_block = []
    nest_level = 0
    for line in lines:
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.lower().startswith("@echo off"): continue
        nest_level += line.count('(') - line.count(')')
        if nest_level == 0 and ((stripped.startswith(":") and not stripped.startswith("::")) or (random.random() < 0.2 and not stripped.lower().startswith("set "))):
            if current_block: blocks.append(current_block)
            current_block = []
        current_block.append(line)
    if current_block: blocks.append(current_block)

    fragments = []
    pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'
    state_var = "_" + generate_random_name(10, used_vars)
    dispatcher_label = "L_" + generate_random_name(8, used_vars)
    end_id = random.randint(10000, 19999)
    block_ids = random.sample(range(1000, 9999), len(blocks))

    flattened_blocks_data = []
    for idx, block in enumerate(blocks):
        b_id = block_ids[idx]
        obf_block = [f":ID_{b_id}\n"]
        for line in block:
            stripped = line.lstrip()
            if stripped.startswith(":") and not stripped.startswith("::"):
                obf_block.append(line + "\n")
                continue
            parts = re.split(pattern, line, flags=re.IGNORECASE)
            obf_parts = []
            for part in parts:
                if not part: continue
                if re.match(pattern, part, re.IGNORECASE):
                    obf_parts.append(part)
                else:
                    i = 0
                    while i < len(part):
                        chunk_size = random.randint(2, 4)
                        chunk = part[i:i+chunk_size]
                        if random.random() < 0.8:
                            f_str = "".join([f"%{random.choice(char_map[c])}%" if c in char_map else c for c in chunk])
                            if len(chunk) > 2 and random.random() < 0.2:
                                f_var = "____" + generate_random_name(15, used_vars)
                                fragments.append(f'set "{f_var}={f_str}"\n')
                                obf_parts.append(f"%{f_var}%")
                            else:
                                obf_parts.append(f_str)
                        else:
                            obf_parts.append("".join(["^"+c if c.isalpha() and random.random() < 0.1 else c for c in chunk]))
                        i += chunk_size
            obf_block.append("".join(obf_parts) + "\n")
        next_id = block_ids[idx+1] if idx+1 < len(blocks) else end_id
        obf_block.append(f'set /a "{state_var}={next_id}"\n')
        obf_block.append(f"goto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    for _ in range(2):
        fake_id = random.randint(100, 999)
        fake_block = [f":ID_{fake_id}\n", f'set "{generate_random_name(10)}={generate_unreadable_string(20)}"\n', f'set /a "{state_var}={random.choice(block_ids)}"\n', f"goto :{dispatcher_label}\n"]
        flattened_blocks_data.append(fake_block)
    random.shuffle(flattened_blocks_data)

    final = ["@echo off\n", "chcp 65001 >nul\n"]
    final.extend(pool_decoders)
    final.extend(mapping_code)
    final.extend(fragments)
    final.append(f'set /a "{state_var}={block_ids[0]}"\n')
    final.append(f":{dispatcher_label}\n")
    final.append(f"goto :ID_%{state_var}%\n")
    final.append(f":ID_{end_id}\n")
    final.append("exit /b\n")
    for b in flattened_blocks_data: final.extend(b)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(final)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python obf.py <input.bat>")
        sys.exit(1)
    input_bat = sys.argv[1]
    output_bat = "obf_" + os.path.basename(input_bat)
    obfuscate_batch(input_bat, output_bat)
    print(f"Obfuscated {input_bat} -> {output_bat}")
