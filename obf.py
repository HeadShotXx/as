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

def generate_unreadable_string(length=30):
    noise_chars = string.ascii_letters + string.digits + "@#$_+-=[]{}|;:,.<>?/`~"
    safe_noise = [c for c in noise_chars if c not in ('%', '"', '!', '&', '|', '<', '>', '(', ')', '^', "'", "`")]
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
        if op == '+': expr = f"({expr}+{val})"
        elif op == '-': expr = f"({expr}-{val})"
        elif op == '*': expr = f"({expr}*{val})"
    if random.random() < 0.3:
        noise_val = random.randint(1, 30)
        expr = f"({expr}+({noise_val}-{noise_val}))"
    return expr

def count_nesting(line, current_nest):
    in_quotes = False
    new_nest = current_nest
    i = 0
    while i < len(line):
        c = line[i]
        # Skip escaped characters
        if c == '^' and i + 1 < len(line):
            i += 2
            continue
        if c == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            if c == '(':
                new_nest += 1
            elif c == ')':
                new_nest -= 1
        i += 1
    return new_nest

def caret_obfuscate(text):
    if not text: return ""
    result = ""
    for i in range(len(text)):
        result += text[i]
        if i < len(text) - 1 and random.random() < 0.2 and text[i] in string.ascii_letters:
            result += "^"
    return result

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.rstrip('\r\n') for l in f.readlines()]
    except FileNotFoundError: return

    used_vars = set()
    unique_file_chars = set()
    for line in lines: unique_file_chars.update(line)
    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')
    mapping_pool_chars = sorted(list((unique_file_chars | set(string.ascii_letters + string.digits + " .\\/-_:")) - set(forbidden)))

    # 1. Random Macro System
    call_keywords = {"set", "call", "echo", "goto", "pause", "exit", "title", "chcp", "rem"}
    parser_keywords = {"if", "for", "in", "do", "not", "exist", "defined", "errorlevel", "else"}

    macros = {}
    macro_code = []
    for kw in call_keywords:
        m_name = "m_" + generate_random_name(10, used_vars)
        macro_code.append(f'set "{m_name}={caret_obfuscate(kw)}"\n')
        p1 = "p1_" + generate_random_name(10, used_vars)
        macro_code.append(f'set "{p1}={m_name}"\n')
        p2 = "p2_" + generate_random_name(10, used_vars)
        macro_code.append(f'set "{p2}={p1}"\n')
        macros[kw] = {"m": m_name, "p1": p1, "p2": p2}

    # 2. Multi-layer Pure Batch Encoding
    num_pools = random.randint(2, 3)
    pools, pool_vars, pool_decoders = [], [], []
    enc_layers = ["xor", "base64", "base32", "base54", "base91", "xor2", "base92"]

    for _ in range(num_pools):
        p_list = list(mapping_pool_chars)
        random.shuffle(p_list)
        pool_str = "".join(p_list)
        pools.append(pool_str)
        pv = "pool_" + generate_random_name(8, used_vars)
        pool_vars.append(pv)

        current_val = pool_str
        ops_chain = []
        for i in range(len(enc_layers)):
            layer_type = random.choice(['sub', 'rot'])
            if layer_type == 'sub':
                c1, c2 = random.sample(mapping_pool_chars, 2)
                current_val = current_val.replace(c1, '\x00').replace(c2, c1).replace('\x00', c2)
                ops_chain.append(('sub', c1, c2, enc_layers[i]))
            elif layer_type == 'rot':
                s = random.randint(1, len(pool_str) - 1)
                current_val = current_val[s:] + current_val[:s]
                ops_chain.append(('rot', s, enc_layers[i]))

        decoder_cmds = [f'set "{pv}={current_val}"\n']
        for op in reversed(ops_chain):
            noise = "rem " + generate_unreadable_string(random.randint(5, 15))
            if op[0] == 'sub':
                placeholder = "".join(random.choices(string.ascii_uppercase, k=random.randint(5, 8)))
                decoder_cmds.append(f'call set "{pv}=%%{pv}:{op[1]}=#{placeholder}#%%" & {noise}\n')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:{op[2]}={op[1]}%%"\n')
                decoder_cmds.append(f'call set "{pv}=%%{pv}:#{placeholder}#={op[2]}%%"\n')
            elif op[0] == 'rot':
                s_rev = (len(pool_str) - op[1]) % len(pool_str)
                rv1, rv2 = generate_random_name(6, used_vars), generate_random_name(6, used_vars)
                decoder_cmds.append(f'set /a "{rv1}={generate_arithmetic(s_rev)}" & {noise}\n')
                decoder_cmds.append(f'set /a "{rv2}={generate_arithmetic(0)}"\n')
                decoder_cmds.append(f'for /f "tokens=2 delims==" %%A in (\'set {rv1} ^^^| findstr /b /c:"{rv1}="\') do for /f "tokens=2 delims==" %%C in (\'set {rv2} ^^^| findstr /b /c:"{rv2}="\') do call set "{pv}=%%{pv}:~%%A%%%%%%{pv}:~%%C,%%A%%"\n')
        pool_decoders.append("".join(decoder_cmds))

    # 3. Variable Shadowing with Environment Indirection
    env_sources = {"OS": "Windows_NT", "COMSPEC": "C:\\Windows\\system32\\cmd.exe"}
    char_map = {}
    mapping_code = []
    for char in mapping_pool_chars:
        shadow_names = []
        for _ in range(random.randint(2, 3)):
            var_name = "v_c_" + generate_random_name(10, used_vars)
            shadow_names.append(var_name)
            p_idx = random.randint(0, len(pools) - 1)
            target_pv = pool_vars[p_idx]
            char_idx = pools[p_idx].find(char)
            if char_idx != -1:
                v_idx = "v_i_" + generate_random_name(6, used_vars)
                method = random.random()
                m_code_block = []
                if method > 0.90: # Environment extraction
                    src = next(((k, v.find(char)) for k,v in env_sources.items() if char in v), None)
                    if src:
                        m_code_block.append(f'set /a "{v_idx}={generate_arithmetic(src[1])}"\n')
                        m_code_block.append(f'for /f "tokens=2 delims==" %%I in (\'set {v_idx} ^^^| findstr /b /c:"{v_idx}="\') do call set "{var_name}=%%{src[0]}:~%%I,1%%"\n')
                    else:
                        m_code_block.append(f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\n')
                        m_code_block.append(f'for /f "tokens=2 delims==" %%I in (\'set {v_idx} ^^^| findstr /b /c:"{v_idx}="\') do call set "{var_name}=%%%%{target_pv}:~%%I,1%%%%"\n')
                elif method > 0.45: # Shadow Pointer
                    v_link, v_ptr = "v_l_" + generate_random_name(10, used_vars), "v_p_" + generate_random_name(10, used_vars)
                    m_code_block.append(f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\n')
                    m_code_block.append(f'set "{v_ptr}={v_link}"\n')
                    m_code_block.append(f'for /f "tokens=2 delims==" %%I in (\'set {v_idx} ^^^| findstr /b /c:"{v_idx}="\') do for /f "delims=" %%A in ("!{v_ptr}!") do call set "%%A=%%%%{target_pv}:~%%I,1%%%%"\n')
                    m_code_block.append(f'set "{var_name}=!{v_link}!"\n')
                else: # Direct Expansion
                    m_code_block.append(f'set /a "{v_idx}={generate_arithmetic(char_idx)}"\n')
                    m_code_block.append(f'for /f "tokens=2 delims==" %%I in (\'set {v_idx} ^^^| findstr /b /c:"{v_idx}="\') do call set "{var_name}=%%%%{target_pv}:~%%I,1%%%%"\n')
                mapping_code.append("".join(m_code_block))
        char_map[char] = shadow_names
    # Shuffling is safe because dependent assignments are now grouped in m_code_block
    random.shuffle(mapping_code)

    # 4. Control-flow Flattening
    blocks, current_block, nest_level = [], [], 0
    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.lower().startswith("@echo off"): continue
        prev_nest = nest_level
        nest_level = count_nesting(line, nest_level)
        if prev_nest <= 0 and nest_level <= 0 and (stripped.startswith(":") or random.random() < 0.2):
            if current_block: blocks.append(current_block)
            current_block = []
        current_block.append(line)
    if current_block: blocks.append(current_block)

    state_var = "v_s_" + generate_random_name(10, used_vars)
    block_labels = [generate_random_name(12, used_vars) for _ in range(len(blocks))]
    end_label = "LB_EXIT_" + generate_random_name(8, used_vars)
    label_vars = {lbl: "v_l_" + generate_random_name(10, used_vars) for lbl in block_labels + [end_label]}
    for lbl, lv in label_vars.items(): macro_code.append(f'set "{lv}={lbl}"\n')

    pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'
    flattened_data = []
    fragments = []

    for idx, block in enumerate(blocks):
        obf_block = [f":{block_labels[idx]}\n"]
        for line in block:
            if line.lstrip().startswith(":") and not line.lstrip().startswith("::"):
                obf_block.append(line + "\n"); continue
            tokens = re.split(r'(\s+|[()&|<>])', line)
            obf_line = ""
            for token in tokens:
                if not token: continue
                tk_low = token.lower()
                if tk_low in call_keywords:
                    m_dat = macros[tk_low]
                    if random.random() < 0.6:
                        obf_line += f"for /f \"delims=\" %%A in (\"!{m_dat['p2']}!\") do for /f \"delims=\" %%B in (\"!%%A!\") do for /f \"delims=\" %%C in (\"!%%B!\") do for /f \"delims=\" %%D in (\"!%%C!\") do %%D "
                    else:
                        obf_line += f"for /f \"delims=\" %%# in (\"!{m_dat['m']}!\") do %%# "
                elif tk_low in parser_keywords:
                    # Parser keywords MUST be literal and unquoted carets
                    obf_line += token
                elif re.match(r'\s+|[()&|<>]+', token):
                    obf_line += token
                else:
                    parts = re.split(pattern, token, flags=re.IGNORECASE)
                    for part in parts:
                        if not part: continue
                        if re.match(pattern, part, re.IGNORECASE):
                            obf_line += part
                        else:
                            i = 0
                            while i < len(part):
                                chunk_len = random.randint(1, 3)
                                chunk = part[i:i+chunk_len]
                                frag_str = "".join([f"!{random.choice(char_map[c])}!" if c in char_map else ("^!" if c == "!" else c) for c in chunk])
                                if len(chunk) > 1 and random.random() < 0.35:
                                    f_var = "v_f_" + generate_random_name(12, used_vars)
                                    fragments.append(f'for /f \"delims=\" %%# in (\"!m_{macros["set"]["m"][2:]}!\") do %%# "{f_var}={frag_str}"\n')
                                    obf_line += f"!{f_var}!"
                                else:
                                    obf_line += frag_str
                                i += chunk_len
            obf_block.append(obf_line + "\n")

        next_lbl_var = label_vars[block_labels[idx+1] if idx+1 < len(blocks) else end_label]
        obf_block.append(f'for /f \"delims=\" %%# in (\"!m_{macros["set"]["m"][2:]}!\") do %%# "{state_var}=!{next_lbl_var}!"\n')
        obf_block.append(f"goto :L_DISPATCH\n")
        flattened_data.append(obf_block)

    random.shuffle(flattened_data)
    final = ["@echo off\n", "setlocal enabledelayedexpansion\n", "chcp 65001 >nul 2>&1\n"]
    final.extend(macro_code); final.extend(pool_decoders); final.extend(mapping_code); final.extend(fragments)
    final.append(f'set "{state_var}=!{label_vars[block_labels[0]]}!"\n:L_DISPATCH\nfor /f \"delims=\" %%A in (\"!{state_var}!\") do goto :%%A\n:{end_label}\nexit /b\n')
    for b in flattened_data: final.extend(b)
    with open(output_file, 'w', encoding='utf-8') as f: f.writelines(final)

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    out = "obf_" + os.path.basename(sys.argv[1])
    obfuscate_batch(sys.argv[1], out)
    print(f"Obfuscated {sys.argv[1]} -> {out}")
