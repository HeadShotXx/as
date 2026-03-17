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

def to_int32(val):
    val = val % 4294967296
    if val > 2147483647:
        val -= 4294967296
    return val

def batch_div(a, b):
    if b == 0: return 0
    return to_int32(int(a / b))

def batch_mod(a, b):
    if b == 0: return 0
    return to_int32(a - (int(a / b) * b))

def generate_unreadable_string(length=50):
    noise_chars = string.ascii_letters + string.digits + "@#$_+-=[]{}|;:,.<>?/`~"
    safe_noise = [c for c in noise_chars if c not in ('%', '"', '^', '`', '&', '|', '<', '>', '(', ')', "'", '!', '=')]
    return "".join(random.choices(safe_noise, k=length))

def generate_arithmetic(target):
    target = to_int32(target)
    if random.random() < 0.05:
        return str(target)
    ops = ['+', '-', '*', '^']
    parts = []
    current = target
    num_parts = random.randint(4, 7)
    for i in range(num_parts - 1):
        op = random.choice(ops)
        if op == '+':
            val = random.randint(1, 100)
            parts.append((val, '+'))
            current = to_int32(current - val)
        elif op == '-':
            val = random.randint(1, 100)
            parts.append((val, '-'))
            current = to_int32(current + val)
        elif op == '*':
            val = random.randint(2, 5)
            mod = batch_mod(current, val)
            if mod != 0:
                parts.append((mod, '+'))
                current = to_int32(current - mod)
            parts.append((val, '*'))
            current = batch_div(current, val)
        elif op == '^':
            val = random.randint(1, 127)
            parts.append((val, '^'))
            current = to_int32(current ^ val)
    expr = str(current)
    for val, op in reversed(parts):
        s = random.choice([" ", ""])
        if op == '+':   expr = f"({expr}{s}+{s}{val})"
        elif op == '-': expr = f"({expr}{s}-{s}{val})"
        elif op == '*': expr = f"({expr}{s}*{s}{val})"
        elif op == '^': expr = f"({expr}{s}^{s}{val})"
    if random.random() < 0.2:
        n = random.randint(1, 50)
        expr = f"({expr}+({n}-{n}))"
    return expr

def tokenize_line(line):
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        if line[i] == '"':
            start = i
            i += 1
            while i < n:
                if line[i] == '"':
                    i += 1
                    break
                if line[i] == '^' and i + 1 < n:
                    i += 2
                else:
                    i += 1
            tokens.append(line[start:i])
        elif line[i] == '^' and i + 1 < n:
            if line[i+1] == '^' and i + 2 < n and line[i+2] == '!':
                tokens.append('^^!')
                i += 3
            else:
                tokens.append(line[i:i+2])
                i += 2
        elif i + 1 < n and line[i:i+2] in ('==', '&&', '||', '<<', '>>', '+=', '-=', '*=', '/=', '%=', '&=', '^=', '|='):
            tokens.append(line[i:i+2])
            i += 2
        elif line[i] in '%!':
            # Use regex for robust variable matching
            var_pattern = r'(%%~[a-zA-Z]+|%%[a-zA-Z]|%~[a-zA-Z0-9]*[0-9*]|%[0-9*]|%[a-zA-Z0-9_#$@*-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'
            match = re.match(var_pattern, line[i:])
            if match:
                var_token = match.group(0)
                tokens.append(var_token)
                i += len(var_token)
            else:
                tokens.append(line[i])
                i += 1
        elif line[i] in '()&|<>:=,; ':
            if line[i].isspace():
                start = i
                while i < n and line[i].isspace():
                    i += 1
                tokens.append(line[start:i])
            else:
                tokens.append(line[i])
                i += 1
        else:
            start = i
            while i < n and not line[i].isspace() and line[i] not in '"^()&|<>:=,;':
                i += 1
            tokens.append(line[start:i])
    return tokens

def generate_extraction(pool_var, index, target_var, used_vars, length=None):
    idx_var = "_" + generate_random_name(10, used_vars)
    arith_idx = generate_arithmetic(index)
    len_str = f",{length}" if length is not None else ""

    methods = [1, 2, 3]
    choice = random.choice(methods)

    def noise():
        if random.random() < 0.3:
            nv = "_" + generate_random_name(8, used_vars)
            return f's^et "{nv}={generate_unreadable_string(10)}"\n'
        return ""

    if choice == 1:
        return f'{noise()}s^et /a "{idx_var}={arith_idx}"\nf^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{target_var}=%%{pool_var}:~%%a{len_str}%%"\n'
    elif choice == 2:
        tilde_var = "_" + generate_random_name(8, used_vars)
        return f's^et "{tilde_var}=~"\n{noise()}s^et /a "{idx_var}={arith_idx}"\nf^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{target_var}=%%{pool_var}:!{tilde_var}!%%a{len_str}%%"\n'
    else:
        extra = random.randint(1, 5)
        tmp_var = "_" + generate_random_name(12, used_vars)
        if length is not None:
            return (f's^et /a "{idx_var}={arith_idx}"\n'
                    f'{noise()}f^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{tmp_var}=%%{pool_var}:~%%a,{length + extra}%%"\n'
                    f's^et "{target_var}=!{tmp_var}:~0,{length}!"\n')
        else:
            return f'{noise()}s^et /a "{idx_var}={arith_idx}"\nf^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{target_var}=%%{pool_var}:~%%a%%"\n'

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

    forbidden = set('\n\r%"!&|<>^(),;= \t#@$~[]')
    base_chars = set(string.ascii_letters + string.digits + ".\\/:-_")
    mapping_pool_chars = sorted(list(
        (unique_file_chars | base_chars) - forbidden
    ))
    mapping_pool_chars = [c for c in mapping_pool_chars if ord(c) < 128]

    pools      = []
    pool_vars  = []
    pool_decoders = []
    num_pools = random.randint(5, 8)

    for _ in range(num_pools):
        p_list = list(mapping_pool_chars)
        random.shuffle(p_list)
        pool_str = "".join(p_list)
        pools.append(pool_str)

        pv = "__" + generate_random_name(8, used_vars)
        pool_vars.append(pv)

        # Scramble using ONLY rotations.
        # Rotation decode uses :~N substring ops which are 100% reliable in CMD.
        # We apply 6-10 random rotations for strong obfuscation.
        current_val = pool_str
        ops_chain   = []
        for _ in range(random.randint(6, 10)):
            s = random.randint(1, len(pool_str) - 1)
            current_val = current_val[s:] + current_val[:s]
            ops_chain.append(s)

        pool_len     = len(pool_str)
        # Initialize pool in chunks
        chunk_size = random.randint(max(1, len(current_val)//4), max(2, len(current_val)//3))
        chunks = [current_val[i:i+chunk_size] for i in range(0, len(current_val), chunk_size)]
        decoder_cmds = [f's^et "{pv}={chunks[0]}"']
        for chunk in chunks[1:]:
            decoder_cmds.append(f's^et "{pv}=!{pv}!{chunk}"')

        for rot_amount in reversed(ops_chain):
            # Undo left-rotation by rot_amount -> rotate right by rot_amount
            split    = (pool_len - rot_amount) % pool_len
            v_suffix = "_" + generate_random_name(8, used_vars)
            v_prefix = "_" + generate_random_name(8, used_vars)
            decoder_cmds.append(generate_extraction(pv, split, v_suffix, used_vars))
            decoder_cmds.append(generate_extraction(pv, 0, v_prefix, used_vars, length=split))
            decoder_cmds.append(f's^et "{pv}=!{v_suffix}!!{v_prefix}!"')

        pool_decoders.append("\n".join(decoder_cmds) + "\n")

    # Character map
    env_sources = {
        "OS":      "Windows_NT",
        "COMSPEC": "C:\\Windows\\system32\\cmd.exe",
    }

    char_map     = {}
    mapping_code = []
    for char in mapping_pool_chars:
        shadow_names = []
        for _ in range(random.randint(3, 5)):
            var_name = "_" + generate_random_name(random.randint(3, 6), used_vars)
            shadow_names.append(var_name)
            p_idx      = random.randint(0, len(pools) - 1)
            target_pv  = pool_vars[p_idx]
            char_idx   = pools[p_idx].find(char)

            if char_idx != -1:
                method = random.random()
                if method > 0.85:
                    src = None
                    for envar, enval in env_sources.items():
                        idx = enval.find(char)
                        if idx != -1:
                            src = (envar, idx); break
                    if src:
                        mapping_code.append(
                            f'c^all s^et "{var_name}=%{src[0]}:~{src[1]},1%"\n')
                    else:
                        mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1))
                elif method > 0.45:
                    mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1))
                else:
                    v_link = "_" + generate_random_name(10, used_vars)
                    combined = generate_extraction(target_pv, char_idx, v_link, used_vars, length=1)
                    combined += f's^et "{var_name}=!{v_link}!"\n'
                    mapping_code.append(combined)
        char_map[char] = shadow_names
    random.shuffle(mapping_code)

    # Block splitter
    no_touch_kw  = {"if","for","do","in","exist","defined","not","errorlevel","else"}
    caret_ok_kw  = {"echo","pause","exit","title","chcp","set","call","goto","rem","mkdir","copy","del","msbuild.exe","wscript.exe"}
    all_keywords = no_touch_kw | caret_ok_kw

    blocks = []
    current_block = []
    nest_level = 0
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.lower().startswith("@echo off"): continue
        line_tokens = tokenize_line(line)
        for t in line_tokens:
            if t == '(': nest_level += 1
            elif t == ')': nest_level -= 1

        next_line_stripped = ""
        if idx + 1 < len(lines):
            next_line_stripped = lines[idx + 1].lstrip().lower()

        if nest_level <= 0 and (
            (stripped.startswith(":") and not stripped.startswith("::")) or
            (random.random() < 0.25 and not stripped.lower().startswith("set ") and not next_line_stripped.startswith("else"))
        ):
            if current_block: blocks.append(current_block)
            current_block = []
        current_block.append(line)
    if current_block: blocks.append(current_block)

    fragments  = []
    var_pattern = (
        r'(%%~[a-zA-Z]+|%%[a-zA-Z]|%~[a-zA-Z0-9]*[0-9*]|%[0-9*]|%[a-zA-Z0-9_#$@*-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%'
        r'|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'
    )

    state_var        = "_"  + generate_random_name(10, used_vars)
    dispatcher_label = "L_" + generate_random_name(8,  used_vars)
    bridge_labels = ["B_" + generate_random_name(8, used_vars) for _ in range(7)]
    setup_label   = "S_" + generate_random_name(8, used_vars)
    end_id    = random.randint(10000, 19999)
    block_ids = random.sample(range(1000, 9999), len(blocks))

    flattened_blocks_data = []
    for idx, block in enumerate(blocks):
        b_id      = block_ids[idx]
        obf_block = [f":ID_{b_id}\n"]

        for line in block:
            stripped = line.lstrip()
            if stripped.startswith(":") and not stripped.startswith("::"):
                obf_block.append(line + "\n"); continue

            tokens = tokenize_line(line)
            obf_line = ""

            for token in tokens:
                if not token: continue
                tl = token.lower()

                # CMD line length limit is 8191. We stay safe under 8000.
                is_long = len(obf_line) > 2000 # Start tapering early

                if token.startswith('"') and token.endswith('"') and len(token) >= 2:
                    obf_line += token
                elif token.startswith('^') and len(token) >= 2:
                    obf_line += token
                elif tl in all_keywords:
                    prob = 0.0 if is_long else (0.25 if tl in no_touch_kw else 0.55)
                    obf_line += "".join(
                        "^" + c if random.random() < prob and c not in ('"', '!', '=', '%', '^') else c
                        for c in token)
                elif re.match(r'^\s+$', token) or re.match(r'^[()&|<>:=,;]+$', token):
                    obf_line += token
                elif token.startswith('%') or token.startswith('!'):
                    obf_line += token
                elif any(c in token for c in '/\\<>|'):
                    # Preserving paths and redirection operators as literals
                    obf_line += token
                else:
                    parts = re.split(var_pattern, token, flags=re.IGNORECASE)
                    for part in parts:
                        if not part: continue
                        if re.match(var_pattern, part, re.IGNORECASE):
                            obf_line += part
                        else:
                            i = 0
                            while i < len(part):
                                sz    = random.randint(1, 3)
                                chunk = part[i:i+sz]
                                frag  = ""
                                for c in chunk:
                                    if c in char_map:
                                        frag += f"!{random.choice(char_map[c])}!"
                                    elif c == '!':
                                        frag += "^^!"
                                    else:
                                        prob_c = 0.0 if is_long else 0.25
                                        if random.random() < prob_c and c not in ('"', '!', '=', '%', '^'):
                                            frag += "^" + c
                                        else:
                                            frag += c
                                prob_f = 0.0 if is_long else 0.3
                                if len(chunk) > 1 and random.random() < prob_f:
                                    fv = "____" + generate_random_name(8, used_vars)
                                    fragments.append(f'set "{fv}={frag}"\n')
                                    obf_line += f"!{fv}!"
                                else:
                                    obf_line += frag
                                i += sz

            obf_block.append(obf_line + "\n")

        next_id = block_ids[idx+1] if idx+1 < len(blocks) else end_id
        obf_block.append(f's^et /a "{state_var}={generate_arithmetic(next_id)}"\n')
        obf_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    for _ in range(20):
        fid = random.randint(100, 999)
        flattened_blocks_data.append([
            f":ID_{fid}\n",
            f's^et "{generate_random_name(10, used_vars)}={generate_unreadable_string(20)}"\n',
            f's^et /a "{state_var}={generate_arithmetic(random.choice(block_ids))}"\n',
            f"g^oto :{dispatcher_label}\n",
        ])
    random.shuffle(flattened_blocks_data)

    final = [
        "@e^cho o^ff\n",
        "s^etlocal e^nabledelayedexpansion\n",
        "c^hcp 6^5001 >n^ul\n",
        f's^et "{state_var}=0"\n',
        f"g^oto :{setup_label}\n",
    ]
    for i, bl in enumerate(bridge_labels):
        target = bridge_labels[i+1] if i+1 < len(bridge_labels) else dispatcher_label
        final.append(f":{bl}\n")

        # Opaque predicates and dead paths
        if random.random() < 0.4:
            dead_target = "B_" + generate_random_name(8, used_vars)
            opaque = random.choice([f"i^f !random! l^ss 0", f"i^f 1==0", f"i^f d^efined _NON_EXISTENT_VAR_"])
            final.append(f'{opaque} g^oto :{dead_target}\n')

        if random.random() < 0.3:
            final.append(f'i^f 1==1 g^oto :{target}\n')
        else:
            final.append(f"g^oto :{target}\n")
    final.append(f":{setup_label}\n")
    final.extend(pool_decoders)
    final.extend(mapping_code)
    final.extend(fragments)
    final.append(f's^et /a "{state_var}={generate_arithmetic(block_ids[0])}"\n')
    final.append(f"g^oto :{bridge_labels[0]}\n")
    final.append(f":{dispatcher_label}\n")
    final.append(f'f^or /f "tokens=*" %%A in ("!{state_var}!") do g^oto :ID_%%A\n')
    final.append(f":ID_{end_id}\n")
    final.append("exit /b\n")
    for b in flattened_blocks_data:
        final.extend(b)

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
