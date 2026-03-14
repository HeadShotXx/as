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
        name = random.choice("IlO_") + "".join(random.choices(chars, k=length-1))
        if name not in used_names:
            used_names.add(name)
            return name

def generate_unreadable_string(length=50):
    noise_chars = string.ascii_letters + string.digits + "@#$_+-=[]{}|;:,.<>?/`~"
    safe_noise = [c for c in noise_chars if c not in ('%', '"', '^', '`', '&', '|', '<', '>', '(', ')', "'")]
    return "".join(random.choices(safe_noise, k=length))

def generate_arithmetic(target):
    if random.random() < 0.05:
        return str(target)

    ops = ['+', '-', '*']
    parts = []
    current = target

    num_parts = random.randint(2, 4)
    for i in range(num_parts - 1):
        op = random.choice(ops)
        if op == '+':
            val = random.randint(1, 50)
            parts.append((val, '+'))
            current -= val
        elif op == '-':
            val = random.randint(1, 50)
            parts.append((val, '-'))
            current += val
        elif op == '*':
            val = random.randint(2, 6)
            mod = current % val
            if mod != 0:
                parts.append((mod, '+'))
            parts.append((val, '*'))
            current //= val

    expr = str(current)
    for val, op in reversed(parts):
        if op == '+':
            expr = f"({expr}+{val})"
        elif op == '-':
            expr = f"({expr}-{val})"
        elif op == '*':
            expr = f"({expr}*{val})"

    if random.random() < 0.3:
        noise_val = random.randint(1, 30)
        expr = f"({expr}+({noise_val}-{noise_val}))"

    return expr

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
    mapping_pool_chars = sorted(list((unique_file_chars | set(string.ascii_letters + string.digits + " .\\/-_:")) - set(forbidden)))
    mapping_pool_chars = [c for c in mapping_pool_chars if ord(c) < 128]

    pools = []
    pool_vars = []
    pool_decoders = []
    num_pools = random.randint(3, 4)
    for _ in range(num_pools):
        p_list = list(mapping_pool_chars)
        random.shuffle(p_list)
        pool_str = "".join(p_list)
        pools.append(pool_str)

        pv = "__" + generate_random_name(8, used_vars)
        pool_vars.append(pv)

        current_val = pool_str
        ops_chain = []
        for _ in range(random.randint(4, 6)):
            layer_type = random.choice(['sub', 'rot'])
            if layer_type == 'sub':
                c1 = random.choice(mapping_pool_chars)
                c2 = random.choice(mapping_pool_chars)
                if c1 != c2:
                    current_val = current_val.replace(c1, '\x00').replace(c2, c1).replace('\x00', c2)
                    ops_chain.append(('sub', c1, c2))
            elif layer_type == 'rot':
                s = random.randint(1, len(pool_str) - 1)
                current_val = current_val[s:] + current_val[:s]
                ops_chain.append(('rot', s))

        # Find a safe placeholder for swapping
        placeholder = None
        for _ in range(100):
            candidate = "".join(random.choices(string.ascii_uppercase, k=8))
            if candidate not in pool_str:
                placeholder = candidate
                break
        if not placeholder: placeholder = "TMP_RESTORE"

        decoder_cmds = [f'set "{pv}={current_val}"']
        for op in reversed(ops_chain):
            if op[0] == 'sub':
                decoder_cmds.append(f'call set "{pv}=%%{pv}:{op[1]}=#{placeholder}#%%"')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:{op[2]}={op[1]}%%"')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:#{placeholder}#={op[2]}%%"')
            elif op[0] == 'rot':
                s = (len(pool_str) - op[1]) % len(pool_str)
                v1 = "_" + generate_random_name(6, used_vars)
                v2 = "_" + generate_random_name(6, used_vars)
                decoder_cmds.append(f'set /a "{v1}={generate_arithmetic(s)}"')
                decoder_cmds.append(f'set /a "{v2}={generate_arithmetic(0)}"')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:~%{v1}%%%%%{pv}:~%{v2}%,%{v1}%%"')

        pool_decoders.append("\n".join(decoder_cmds) + "\n")

    env_sources = {"OS": "Windows_NT", "COMSPEC": "C:\\Windows\\system32\\cmd.exe"}

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
                if method > 0.85: # Env Indirection
                    src = None
                    for envar, enval in env_sources.items():
                        idx = enval.find(char)
                        if idx != -1:
                            src = (envar, idx)
                            break
                    if src:
                        v_idx = "_" + generate_random_name(6, used_vars)
                        mapping_code.append(f'set /a "{v_idx}={generate_arithmetic(src[1])}"\nif 1==1 call set "{var_name}=%{src[0]}:~%{v_idx}%,1%"\n')
                    else:
                        v_idx = "_" + generate_random_name(6, used_vars)
                        mapping_code.append(f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\ncall set "{var_name}=%%{target_pv}:~%{v_idx}%,1%%"\n')
                elif method > 0.45: # Direct or Dynamic CALL
                    v_idx = "_" + generate_random_name(6, used_vars)
                    mapping_code.append(f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\ncall set "{var_name}=%%{target_pv}:~%{v_idx}%,1%%"\n')
                else: # Chained Shadowing
                    v_link = "_" + generate_random_name(10, used_vars)
                    v_idx = "_" + generate_random_name(6, used_vars)
                    chained_set = f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\ncall set "{v_link}=%%{target_pv}:~%{v_idx}%,1%%"\nset "{var_name}=!{v_link}!"\n'
                    mapping_code.append(chained_set)
        char_map[char] = shadow_names
    random.shuffle(mapping_code)

    keywords = {"set", "if", "for", "goto", "call", "echo", "pause", "exit", "title", "rem", "chcp", "do", "in", "exist", "defined", "not", "errorlevel"}

    blocks = []
    current_block = []
    nest_level = 0
    for line in lines:
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.lower().startswith("@echo off"): continue
        nest_level += line.count('(') - line.count(')')
        if nest_level <= 0 and ((stripped.startswith(":") and not stripped.startswith("::")) or (random.random() < 0.25 and not stripped.lower().startswith("set "))):
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

            tokens = re.split(r'(\s+|[()&|<>])', line)
            obf_line_final = ""
            for token in tokens:
                if not token: continue
                if token.lower() in keywords:
                    if random.random() < 0.25 and token.lower() not in ("if", "for", "do", "in", "exist", "defined", "not", "errorlevel"):
                        kw_var = "_" + generate_random_name(8, used_vars)
                        kw_val = "".join(["^" + c if random.random() < 0.3 else c for c in token])
                        fragments.append(f'set "{kw_var}={kw_val}"\n')
                        obf_line_final += f"call !{kw_var}!"
                    else:
                        kw_obf = "".join(["^" + c if random.random() < 0.2 else c for c in token])
                        obf_line_final += kw_obf
                elif re.match(r'\s+|[()&|<>]+', token):
                    obf_line_final += token
                else:
                    parts = re.split(pattern, token, flags=re.IGNORECASE)
                    for part in parts:
                        if not part: continue
                        if re.match(pattern, part, re.IGNORECASE):
                            obf_line_final += part
                        else:
                            i = 0
                            while i < len(part):
                                chunk_size = random.randint(1, 3)
                                chunk = part[i:i+chunk_size]
                                frag_str = ""
                                for c in chunk:
                                    if c in char_map:
                                        v = random.choice(char_map[c])
                                        frag_str += f"!{v}!"
                                    elif c == '!':
                                        frag_str += "^!"
                                    else:
                                        frag_str += c

                                if len(chunk) > 1 and random.random() < 0.3:
                                    f_var = "____" + generate_random_name(15, used_vars)
                                    fragments.append(f'set "{f_var}={frag_str}"\n')
                                    obf_line_final += f"!{f_var}!"
                                else:
                                    obf_line_final += frag_str
                                i += chunk_size
            obf_block.append(obf_line_final + "\n")

        next_id = block_ids[idx+1] if idx+1 < len(blocks) else end_id
        obf_block.append(f'set /a "{state_var}={generate_arithmetic(next_id)}"\n')
        obf_block.append(f"goto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    for _ in range(2):
        fake_id = random.randint(100, 999)
        fake_block = [f":ID_{fake_id}\n", f'set "{generate_random_name(10)}={generate_unreadable_string(20)}"\n', f'set /a "{state_var}={generate_arithmetic(random.choice(block_ids))}"\n', f"goto :{dispatcher_label}\n"]
        flattened_blocks_data.append(fake_block)
    random.shuffle(flattened_blocks_data)

    final = ["@echo off\n", "setlocal enabledelayedexpansion\n", "chcp 65001 >nul\n"]
    final.extend(pool_decoders)
    final.extend(mapping_code)
    final.extend(fragments)
    final.append(f'set /a "{state_var}={generate_arithmetic(block_ids[0])}"\n')
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
