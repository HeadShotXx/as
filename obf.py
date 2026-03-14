import sys
import random
import string
import os
import re

def count_nesting(line, current_nest):
    in_quotes = False
    new_nest = current_nest
    for c in line:
        if c == '"': in_quotes = not in_quotes
        elif not in_quotes:
            if c == '(': new_nest += 1
            elif c == ')': new_nest -= 1
    return new_nest

def caret_obfuscate(text):
    result = ""
    for char in text:
        result += char
        if random.random() < 0.12 and char not in "^%\"! ":
            result += "^"
    return result

def obfuscate_batch(input_file, output_file):
    try:
        # Read with utf-8 and ignore errors to be robust against various encodings
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            raw_lines = f.readlines()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    lines = []
    for l in raw_lines:
        s = l.strip()
        if not s: continue
        if s.lower().startswith("@echo off"): continue
        lines.append(l.rstrip('\r\n'))

    keywords = ["set", "call", "echo", "goto", "pause", "exit", "title", "rem"]

    header = [
        "@echo off\n",
        "setlocal enabledelayedexpansion\n",
        "chcp 65001 >nul 2>&1\n"
    ]

    # 1. Create keyword macros for indirect execution
    macros = {}
    for k in keywords:
        m_name = "k" + "".join(random.choices(string.ascii_letters, k=5))
        header.append(f'set "{m_name}={caret_obfuscate(k)}"\n')
        macros[k] = m_name

    # 2. Control Flow Flattening (State Machine)
    blocks, cur, nest = [], [], 0
    for l in lines:
        p = nest
        nest = count_nesting(l, nest)
        # Split into blocks at logical boundaries or labels
        if p <= 0 and nest <= 0 and (l.lstrip().startswith(":") or random.random() < 0.12):
            if cur: blocks.append(cur)
            cur = []
        cur.append(l)
    if cur: blocks.append(cur)

    state_var = "s" + "".join(random.choices(string.ascii_letters, k=4))
    labels = ["L" + str(i) + "".join(random.choices(string.ascii_letters, k=3)) for i in range(len(blocks))]
    end_lbl = "E" + "".join(random.choices(string.ascii_letters, k=5))

    header.append(f'set "{state_var}={labels[0]}"\n')
    header.append(":DISPATCH\n")
    header.append(f'if "!{state_var}!"=="{end_lbl}" exit /b\n')
    # Using a FOR loop to resolve the GOTO target reliably
    header.append(f'for /f "delims=" %%# in ("!{state_var}!") do goto %%#\n')

    # Regex for Batch variables: %VAR%, %~dp0, !VAR!, %%A
    var_pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'

    obf_blocks = []
    for i, block in enumerate(blocks):
        b_data = [f":{labels[i]}\n"]
        for l in block:
            if l.lstrip().startswith(":") and not l.lstrip().startswith("::"):
                b_data.append(l + "\n"); continue

            tokens = re.split(r'(\s+|[()&|<>])', l)
            ol = ""
            for t in tokens:
                if not t: continue
                tl = t.lower()
                if tl in macros:
                    # Robust execution via variable
                    ol += f"for %%# in (!{macros[tl]}!) do %%# "
                elif t in "()&|<> \t":
                    ol += t
                else:
                    # Obfuscate normal text while preserving variable references
                    parts = re.split(var_pattern, t, flags=re.IGNORECASE)
                    for part in parts:
                        if not part: continue
                        if re.match(var_pattern, part, re.IGNORECASE):
                            ol += part
                        else:
                            ol += caret_obfuscate(part)
            b_data.append(ol + "\n")

        # Transition to next state
        nxt = labels[i+1] if i+1 < len(blocks) else end_lbl
        b_data.append(f'set "{state_var}={nxt}"\ngoto DISPATCH\n')
        obf_blocks.append(b_data)

    # Shuffling blocks for maximum flow confusion
    random.shuffle(obf_blocks)
    for b in obf_blocks:
        header.extend(b)

    # Write output as UTF-8
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(header)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_bat = sys.argv[1]
        output_bat = "obf_" + os.path.basename(input_bat)
        obfuscate_batch(input_bat, output_bat)
        print(f"Obfuscated {input_bat} -> {output_bat}")
