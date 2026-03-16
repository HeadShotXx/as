import sys
import random
import string
import os
import re
import copy

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
    safe_noise = [c for c in noise_chars if c not in ('%', '"', '^', '`', '&', '|', '<', '>', '(', ')', "'", '!', '=')]
    return "".join(random.choices(safe_noise, k=length))

def generate_arithmetic(target):
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
            parts.append((val, '+')); current -= val
        elif op == '-':
            val = random.randint(1, 100)
            parts.append((val, '-')); current += val
        elif op == '*':
            val = random.randint(2, 5)
            mod = current % val
            if mod != 0:
                parts.append((mod, '+'))
            parts.append((val, '*')); current //= val
        elif op == '^':
            val = random.randint(1, 127)
            parts.append((val, '^')); current ^= val
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

def to_int32(n):
    n = n & 0xFFFFFFFF
    if n > 0x7FFFFFFF:
        n -= 0x100000000
    return n

class RollingState:
    def __init__(self, used_vars):
        self.rs_var = "_" + generate_random_name(10, used_vars)
        self.aux_var = "_" + generate_random_name(10, used_vars)
        self.cnt_var = "_" + generate_random_name(10, used_vars)
        self.rs_val = random.randint(100, 10000)
        self.aux_val = random.randint(100, 10000)
        self.cnt_val = 0
    def rehash(self):
        self.rs_val = random.randint(100, 10000)
        self.aux_val = random.randint(100, 10000)
        self.cnt_val = random.randint(0, 100)
        return f's^et /a "{self.rs_var}={self.rs_val}", "{self.aux_var}={self.aux_val}", "{self.cnt_var}={self.cnt_val}"\n'

def generate_advanced_junk(state, data_hint=None, index_hint=None, commutative=False):
    if state is None: return ""
    cmds = []
    num_instr = random.randint(3, 5)
    for _ in range(num_instr):
        choice = random.randint(0, 3)
        if commutative:
            # Fixed: Only use XOR and only RS to ensure true commutativity in shuffled sections
            op = '^'
            val = random.randint(1, 255)
            if data_hint is not None: val ^= (data_hint % 256)
            if index_hint is not None: val ^= (index_hint % 256)

            cmds.append(f's^et /a "{state.rs_var}{op}={val}"\n')
            state.rs_val = to_int32(state.rs_val ^ val)
        else:
            if choice == 0: # Cross dependent
                val = random.randint(1, 100)
                cmds.append(f's^et /a "{state.rs_var}^=(!{state.aux_var}! + {val})"\n')
                state.rs_val = to_int32(state.rs_val ^ (state.aux_val + val))
            elif choice == 1: # Data dependent branch
                if state.rs_val > state.aux_val:
                    cmds.append(f'i^f !{state.rs_var}! G^TR !{state.aux_var}! ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}-=1" )\n')
                    state.rs_val = to_int32(state.rs_val + 1)
                else:
                    cmds.append(f'i^f !{state.rs_var}! G^TR !{state.aux_var}! ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}-=1" )\n')
                    state.rs_val = to_int32(state.rs_val - 1)
            elif choice == 2: # Delayed effect
                old_rs = state.rs_val
                cmds.append(f's^et /a "{state.cnt_var}+=1", "{state.aux_var}^=!{state.rs_var}!"\n')
                state.cnt_val = to_int32(state.cnt_val + 1)
                state.aux_val = to_int32(state.aux_val ^ old_rs)
            else: # Triple domain dependency
                hint = (data_hint if data_hint else 0) ^ (index_hint if index_hint else 0)
                hint = hint % 1000
                cmds.append(f's^et /a "{state.rs_var}=(!{state.rs_var}! ^ !{state.cnt_var}!) + {hint}"\n')
                state.rs_val = to_int32((state.rs_val ^ state.cnt_val) + hint)
    return "".join(cmds)

def generate_extraction(pool_var, index, target_var, used_vars, length=None, state_obj=None, commutative=False):
    idx_var = "_" + generate_random_name(10, used_vars)

    if state_obj and not commutative:
        arith_idx = generate_arithmetic(to_int32(index ^ state_obj.rs_val))
        set_idx_cmd = f's^et /a "{idx_var}=({arith_idx}) ^ !{state_obj.rs_var}!"\n'
    else:
        arith_idx = generate_arithmetic(index)
        set_idx_cmd = f's^et /a "{idx_var}={arith_idx}"\n'

    len_str = f",{length}" if length is not None else ""

    methods = [1, 2, 3]
    choice = random.choice(methods)

    def noise():
        if state_obj:
            return generate_advanced_junk(state_obj, index_hint=index, commutative=commutative)
        if random.random() < 0.3:
            nv = "_" + generate_random_name(8, used_vars)
            return f's^et "{nv}={generate_unreadable_string(10)}"\n'
        return ""

    if choice == 1:
        return f'{noise()}{set_idx_cmd}f^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{target_var}=%%{pool_var}:~%%a{len_str}%%"\n'
    elif choice == 2:
        tilde_var = "_" + generate_random_name(8, used_vars)
        return f's^et "{tilde_var}=~"\n{noise()}{set_idx_cmd}f^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{target_var}=%%{pool_var}:!{tilde_var}!%%a{len_str}%%"\n'
    else:
        extra = random.randint(1, 5)
        tmp_var = "_" + generate_random_name(12, used_vars)
        if length is not None:
            return (f'{set_idx_cmd}'
                    f'{noise()}f^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{tmp_var}=%%{pool_var}:~%%a,{length + extra}%%"\n'
                    f's^et "{target_var}=!{tmp_var}:~0,{length}!"\n')
        else:
            return f'{noise()}{set_idx_cmd}f^or /f "delims=" %%a in ("!{idx_var}!") do c^all s^et "{target_var}=%%{pool_var}:~%%a%%"\n'

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.rstrip('\r\n') for l in f.readlines()]
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    used_vars = set()
    state_obj = RollingState(used_vars)
    # Corrected: Store initial state for the Batch header
    initial_rs = state_obj.rs_val
    initial_aux = state_obj.aux_val
    initial_cnt = state_obj.cnt_val

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
            decoder_cmds.append(generate_extraction(pv, split, v_suffix, used_vars, state_obj=state_obj))
            decoder_cmds.append(generate_extraction(pv, 0, v_prefix, used_vars, length=split, state_obj=state_obj))
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
            var_name = "_" + generate_random_name(random.randint(6, 12), used_vars)
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
                        mapping_code.append(generate_advanced_junk(state_obj, data_hint=ord(char), commutative=True))
                        mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, state_obj=state_obj, commutative=True))
                elif method > 0.45:
                    mapping_code.append(generate_advanced_junk(state_obj, data_hint=ord(char), commutative=True))
                    mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, state_obj=state_obj, commutative=True))
                else:
                    mapping_code.append(generate_advanced_junk(state_obj, data_hint=ord(char), commutative=True))
                    v_link = "_" + generate_random_name(10, used_vars)
                    combined = generate_extraction(target_pv, char_idx, v_link, used_vars, length=1, state_obj=state_obj, commutative=True)
                    combined += f's^et "{var_name}=!{v_link}!"\n'
                    mapping_code.append(combined)
        char_map[char] = shadow_names
    random.shuffle(mapping_code)

    # Block splitter
    no_touch_kw  = {"if","for","do","in","exist","defined","not","errorlevel"}
    caret_ok_kw  = {"echo","pause","exit","title","chcp","set","call","goto","rem"}
    all_keywords = no_touch_kw | caret_ok_kw

    blocks = []
    current_block = []
    nest_level = 0
    for line in lines:
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.lower().startswith("@echo off"): continue
        nest_level += line.count('(') - line.count(')')
        if nest_level <= 0 and (
            (stripped.startswith(":") and not stripped.startswith("::")) or
            (random.random() < 0.25 and not stripped.lower().startswith("set "))
        ):
            if current_block: blocks.append(current_block)
            current_block = []
        current_block.append(line)
    if current_block: blocks.append(current_block)

    fragments  = []
    var_pattern = (
        r'(%[a-zA-Z0-9_#$@*-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%'
        r'|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]'
        r'|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'
    )

    state_var        = "_"  + generate_random_name(10, used_vars)
    dispatcher_label = "L_" + generate_random_name(8,  used_vars)
    bridge_labels = ["B_" + generate_random_name(8, used_vars) for _ in range(7)]
    setup_label   = "S_" + generate_random_name(8, used_vars)
    end_id    = random.randint(10000, 19999)
    block_ids = random.sample(range(1000, 9999), len(blocks))

    flattened_blocks_data = []
    state_at_flow_start = copy.copy(state_obj)
    for idx, block in enumerate(blocks):
        b_id      = block_ids[idx]
        obf_block = [f":ID_{b_id}\n"]
        obf_block.append(state_obj.rehash()) # Entry sync to fix control flow drift

        for line in block:
            stripped = line.lstrip()
            if stripped.startswith(":") and not stripped.startswith("::"):
                obf_block.append(line + "\n"); continue

            tokens   = re.split(r'(\s+|[()&|<>])', line)
            obf_line = ""

            for token in tokens:
                if not token: continue
                tl = token.lower()

                if tl in all_keywords:
                    if tl in no_touch_kw:
                        obf_line += "".join(
                            "^" + c if random.random() < 0.25 else c
                            for c in token)
                    else:
                        obf_line += "".join(
                            "^" + c if random.random() < 0.55 else c
                            for c in token)
                elif re.match(r'^\s+$', token) or re.match(r'^[()&|<>]+$', token):
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
                                        frag += "^!"
                                    else:
                                        if random.random() < 0.25:
                                            frag += "^" + c
                                        else:
                                            frag += c
                                if len(chunk) > 1 and random.random() < 0.3:
                                    fv = "____" + generate_random_name(15, used_vars)
                                    # Fixed: Inject fragments into the block to avoid state drift
                                    junk = generate_advanced_junk(state_obj)
                                    obf_block.append(f'{junk}set "{fv}={frag}"\n')
                                    obf_line += f"!{fv}!"
                                else:
                                    obf_line += frag
                                i += sz

            obf_block.append(obf_line + "\n")

        next_id = block_ids[idx+1] if idx+1 < len(blocks) else end_id
        obf_block.append(generate_advanced_junk(state_obj))
        arith_next = generate_arithmetic(to_int32(next_id ^ state_obj.rs_val))
        obf_block.append(f's^et /a "{state_var}=({arith_next}) ^ !{state_obj.rs_var}!"\n')
        obf_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    for _ in range(20):
        fid = random.randint(100, 999)
        obf_fake = [f":ID_{fid}\n"]
        obf_fake.append(state_obj.rehash()) # Entry sync
        obf_fake.append(generate_advanced_junk(state_obj))
        obf_fake.append(f's^et "{generate_random_name(10, used_vars)}={generate_unreadable_string(20)}"\n')
        target_id = random.choice(block_ids)
        arith_target = generate_arithmetic(to_int32(target_id ^ state_obj.rs_val))
        obf_fake.append(f's^et /a "{state_var}=({arith_target}) ^ !{state_obj.rs_var}!"\n')
        obf_fake.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_fake)
    random.shuffle(flattened_blocks_data)

    final = [
        "@e^cho o^ff\n",
        "s^etlocal e^nabledelayedexpansion\n",
        # Fixed: Initialize with start values, not final values
        f's^et /a "{state_obj.rs_var}={initial_rs}", "{state_obj.aux_var}={initial_aux}", "{state_obj.cnt_var}={initial_cnt}"\n',
        "c^hcp 6^5001 >n^ul\n",
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
    # final.extend(fragments) # Fragments now injected directly into blocks
    final.append(generate_advanced_junk(state_at_flow_start))
    arith_start = generate_arithmetic(to_int32(block_ids[0] ^ state_at_flow_start.rs_val))
    final.append(f's^et /a "{state_var}=({arith_start}) ^ !{state_at_flow_start.rs_var}!"\n')
    final.append(f"g^oto :{bridge_labels[0]}\n")
    final.append(f":{dispatcher_label}\n")
    final.append(f'c^all g^oto :ID_%%{state_var}%%\n')
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
