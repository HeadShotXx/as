import sys
import random
import string
import os
import re

def generate_random_name(length=8, used_names=None):
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
    if random.random() < 0.02:
        return str(target)

    ops = ['+', '-', '*']
    parts = []
    current = target

    num_parts = random.randint(2, 5)
    for i in range(num_parts - 1):
        op = random.choice(ops)
        if op == '+':
            val = random.randint(1, 100)
            parts.append((val, '+'))
            current -= val
        elif op == '-':
            val = random.randint(1, 100)
            parts.append((val, '-'))
            current += val
        elif op == '*':
            val = random.randint(2, 8)
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

    if random.random() < 0.4:
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

    # 1. Random Macro System
    parser_keywords = {"if", "for", "in", "do", "not", "exist", "defined", "errorlevel"}
    call_keywords = {"set", "call", "echo", "goto", "pause", "exit", "title", "chcp", "rem"}

    macros = {}
    macro_code = []
    for kw in call_keywords:
        m_name = "m_" + generate_random_name(10, used_vars)
        m_val = "".join(["^" + c if random.random() < 0.3 else c for c in kw])
        macros[kw] = m_name
        macro_code.append(f'set "{m_name}={m_val}"\n')

    ptrs = {}
    for kw in ["set", "call", "echo", "goto", "pause", "exit"]:
        p_name = "p_" + generate_random_name(10, used_vars)
        ptrs[kw] = p_name
        macro_code.append(f'set "{p_name}={macros[kw]}"\n')

    # 2. Multi-layer Pure Batch Encoding
    enc_chain_names = ["xor", "base64", "base32", "base54", "base91", "xor2", "base92"]

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
        for i in range(len(enc_chain_names)):
            layer_type = random.choice(['sub', 'rot'])
            if layer_type == 'sub':
                c1 = random.choice(mapping_pool_chars)
                c2 = random.choice(mapping_pool_chars)
                if c1 != c2:
                    current_val = current_val.replace(c1, '\x00').replace(c2, c1).replace('\x00', c2)
                    ops_chain.append(('sub', c1, c2, enc_chain_names[i]))
            elif layer_type == 'rot':
                s = random.randint(1, len(pool_str) - 1)
                current_val = current_val[s:] + current_val[:s]
                ops_chain.append(('rot', s, enc_chain_names[i]))

        placeholder = "".join(random.choices(string.ascii_uppercase, k=8))
        decoder_cmds = [f'set "{pv}={current_val}"']
        for op in reversed(ops_chain):
            comment = f'rem layer: {op[-1]}'
            if op[0] == 'sub':
                decoder_cmds.append(f'call set "{pv}=%%{pv}:{op[1]}=#{placeholder}#%%" & {comment}')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:{op[2]}={op[1]}%%"')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:#{placeholder}#={op[2]}%%"')
            elif op[0] == 'rot':
                s = (len(pool_str) - op[1]) % len(pool_str)
                rv1 = "_" + generate_random_name(6, used_vars)
                rv2 = "_" + generate_random_name(6, used_vars)
                decoder_cmds.append(f'set /a "{rv1}={generate_arithmetic(s)}" & {comment}')
                decoder_cmds.append(f'set /a "{rv2}={generate_arithmetic(0)}"')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:~!{rv1}!%%%%%{pv}:~!{rv2}!,!{rv1}!%%"')

        pool_decoders.append("\n".join(decoder_cmds) + "\n")

    env_sources = {"OS": "Windows_NT", "COMSPEC": "C:\\Windows\\system32\\cmd.exe"}

    # 3. Chained Variable Shadowing with Indirect CALL Hell
    char_map = {}
    mapping_code = []
    for char in mapping_pool_chars:
        shadow_names = []
        for _ in range(random.randint(2, 3)):
            var_name = "_" + generate_random_name(random.randint(10, 20), used_vars)
            shadow_names.append(var_name)
            p_idx = random.randint(0, len(pools) - 1)
            target_pv = pool_vars[p_idx]
            char_idx = pools[p_idx].find(char)

            if char_idx != -1:
                method = random.random()
                if method > 0.90: # Env Indirection
                    src = None
                    for envar, enval in env_sources.items():
                        idx = enval.find(char)
                        if idx != -1:
                            src = (envar, idx)
                            break
                    if src:
                        v_idx = "_" + generate_random_name(6, used_vars)
                        mapping_code.append(f'set /a "{v_idx}={generate_arithmetic(src[1])}"\n')
                        mapping_code.append(f'call call !{ptrs["set"]}! "{var_name}=%%{src[0]}:~!{v_idx}!,1%%"\n')
                    else:
                        v_idx = "_" + generate_random_name(6, used_vars)
                        mapping_code.append(f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\n')
                        mapping_code.append(f'call call !{ptrs["set"]}! "{var_name}=%%%%{target_pv}:~!{v_idx}!,1%%%%"\n')
                elif method > 0.40: # Indirect CALL Hell
                    v_idx = "_" + generate_random_name(6, used_vars)
                    v_link = "_" + generate_random_name(10, used_vars)
                    v_ptr = "_" + generate_random_name(10, used_vars)
                    mapping_code.append(f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\n')
                    mapping_code.append(f'set "{v_ptr}={v_link}"\n')
                    mapping_code.append(f'call call call set "%%!{v_ptr}!%%=%%%%{target_pv}:~!{v_idx}!,1%%%%"\n')
                    mapping_code.append(f'set "{var_name}=!{v_link}!"\n')
                else: # Chained Shadowing
                    v_link = "_" + generate_random_name(10, used_vars)
                    v_idx = "_" + generate_random_name(6, used_vars)
                    chained_set = f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\n'
                    chained_set += f'call call !{ptrs["set"]}! "{v_link}=%%%%{target_pv}:~!{v_idx}!,1%%%%"\n'
                    chained_set += f'set "{var_name}=!{v_link}!"\n'
                    mapping_code.append(chained_set)
        char_map[char] = shadow_names
    random.shuffle(mapping_code)

    # 4. Control-flow Flattening with Dynamic Labels
    blocks = []
    current_block = []
    nest_level = 0
    for line in lines:
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.lower().startswith("@echo off"): continue
        nest_level += line.count('(') - line.count(')')
        if nest_level <= 0 and ((stripped.startswith(":") and not stripped.startswith("::")) or (random.random() < 0.20 and not stripped.lower().startswith("set "))):
            if current_block: blocks.append(current_block)
            current_block = []
        current_block.append(line)
    if current_block: blocks.append(current_block)

    fragments = []
    pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'
    state_var = "_" + generate_random_name(10, used_vars)
    dispatcher_label = "L_" + generate_random_name(8, used_vars)
    end_label = "LB_" + generate_random_name(12, used_vars)
    block_labels = [f"LB_{generate_random_name(12, used_vars)}" for _ in range(len(blocks))]

    label_vars = {}
    for lbl in block_labels + [end_label]:
        lv = "v_lbl_" + generate_random_name(8, used_vars)
        label_vars[lbl] = lv
        macro_code.append(f'set "{lv}={lbl}"\n')

    flattened_blocks_data = []
    for idx, block in enumerate(blocks):
        b_label = block_labels[idx]
        obf_block = [f":{b_label}\n"]
        for line in block:
            stripped = line.lstrip()
            if stripped.startswith(":") and not stripped.startswith("::"):
                obf_block.append(line + "\n")
                continue

            tokens = re.split(r'(\s+|[()&|<>])', line)
            obf_line_final = ""
            for token in tokens:
                if not token: continue
                tk_low = token.lower()
                if tk_low in call_keywords:
                    m_var = macros[tk_low]
                    if random.random() < 0.8:
                        obf_line_final += f"call !{m_var}!"
                    else:
                        obf_line_final += "".join(["^" + c if random.random() < 0.2 else c for c in token])
                elif tk_low in parser_keywords:
                    obf_line_final += "".join(["^" + c if random.random() < 0.2 else c for c in token])
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

                                if len(chunk) > 1 and random.random() < 0.35:
                                    f_var = "____" + generate_random_name(15, used_vars)
                                    fragments.append(f'call !{ptrs["set"]}! "{f_var}={frag_str}"\n')
                                    obf_line_final += f"!{f_var}!"
                                else:
                                    obf_line_final += frag_str
                                i += chunk_size
            obf_block.append(obf_line_final + "\n")

        next_label = block_labels[idx+1] if idx+1 < len(blocks) else end_label
        next_label_var = label_vars[next_label]
        obf_block.append(f'call !{ptrs["set"]}! "{state_var}=!{next_label_var}!"\n')
        obf_block.append(f"goto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    for _ in range(3):
        fake_label = "LB_" + generate_random_name(12, used_vars)
        fake_block = [f":{fake_label}\n", f'set "{generate_random_name(12)}={generate_unreadable_string(30)}"\n', f'set "{state_var}={random.choice(block_labels)}"\n', f"goto :{dispatcher_label}\n"]
        flattened_blocks_data.append(fake_block)
    random.shuffle(flattened_blocks_data)

    # 5. Final Assembly
    final = ["@echo off\n", "setlocal enabledelayedexpansion\n", "chcp 65001 >nul\n"]
    final.extend(macro_code)
    final.extend(pool_decoders)
    final.extend(mapping_code)
    final.extend(fragments)
    final.append(f'set "{state_var}={block_labels[0]}"\n')
    final.append(f":{dispatcher_label}\n")
    final.append(f"for /f \"delims=\" %%A in (\"!{state_var}!\") do goto :%%A\n")
    final.append(f":{end_label}\n")
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
