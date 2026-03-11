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
    safe_noise = [c for c in noise_chars if c not in ('%', '"', "'", '^', '`')]
    return "".join(random.choices(safe_noise, k=length))

class MultiLayerEncoder:
    def __init__(self):
        # Alphabets sanitized of %, ", ', ^, `
        base_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        symbols = "!#$&()*+,-./:;<=>?@[]\\_{|}~"
        full_alphabet = base_chars + symbols
        self.alphabets = {
            "base32": base_chars[:32],
            "base45": (base_chars + " $-./:+*")[:45],
            "base54": base_chars[:54],
            "base64": (base_chars + "+/")[:64],
            "base91": full_alphabet[:91],
            "base92": (full_alphabet + " ")[:92]
        }

    def xor(self, data, key):
        return bytes([b ^ key for b in data])

    def encode_base_n(self, data, alphabet_name):
        alphabet = self.alphabets[alphabet_name]
        n = len(alphabet)
        val = int.from_bytes(b'\x01' + data, 'big')
        res = ""
        while val > 0:
            res = alphabet[val % n] + res
            val //= n
        return res

    def generate_sequence(self):
        bases = list(self.alphabets.keys())
        random.shuffle(bases)
        seq = [("xor", random.randint(1, 255))]
        for i in range(4):
            seq.append(("base", bases[i]))
        seq.append(("xor", random.randint(1, 255)))
        seq.append(("base", bases[4]))
        return seq

    def encode(self, data, sequence):
        res = data
        for step_type, val in sequence:
            if step_type == "xor":
                res = self.xor(res, val)
            else:
                res = self.encode_base_n(res, val).encode('ascii')
        return res.decode('ascii')

def obfuscate_batch(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    used_vars = set()
    encoder = MultiLayerEncoder()

    pools = []
    pool_vars = []
    encoded_pool_data = []

    for _ in range(random.randint(2, 3)):
        pool_chars = list(string.ascii_letters + string.digits + " .\\/-_")
        random.shuffle(pool_chars)
        pool_str = "".join(pool_chars)
        pools.append(pool_str)

        pv = "__" + generate_random_name(8, used_vars)
        pool_vars.append(pv)

        seq = encoder.generate_sequence()
        encoded_val = encoder.encode(pool_str.encode('utf-8'), seq)

        ev = "__" + generate_random_name(10, used_vars)
        encoded_pool_data.append((ev, encoded_val, seq, pv))

    char_map = {}
    char_assignments = []

    all_needed_chars = set()
    for line in lines:
        all_needed_chars.update(line)

    forbidden = ('\n', '\r', '%', '"', '!', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', ' ', '\t')

    for char in all_needed_chars:
        if char in forbidden: continue
        pool_idx = random.randint(0, len(pools) - 1)
        target_pool = pools[pool_idx]
        target_pool_var = pool_vars[pool_idx]
        char_idx = target_pool.find(char)
        if char_idx == -1: continue

        var_name = "_" + generate_random_name(6, used_vars)
        char_map[char] = var_name

        method = random.random()
        if method > 0.6:
            char_assignments.append(f'set "{var_name}=%{target_pool_var}:~{char_idx},1%"\n')
        elif method > 0.3:
            char_assignments.append(f'call set "{var_name}=%%{target_pool_var}:~{char_idx},1%%"\n')
        else:
            tmp_var = "_" + generate_random_name(7, used_vars)
            char_assignments.append(f'set "{tmp_var}=%{target_pool_var}:~{char_idx},1%"\nset "{var_name}=%{tmp_var}%"\n')

    random.shuffle(char_assignments)

    obfuscated_lines = ["@echo off\n", "chcp 65001 >nul\n"]
    for ev, encoded_val, seq, pv in encoded_pool_data:
        obfuscated_lines.append(f'set "{ev}={encoded_val}"\n')

    # PowerShell Decoding Stub
    ps_logic_var = "__" + generate_random_name(12, used_vars)
    ps_logic = "$ErrorActionPreference='SilentlyContinue';"
    ps_logic += "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Numerics');"
    ps_logic += "function f($s,$a){if($s -isnot [string]){$s=[System.Text.Encoding]::ASCII.GetString([byte[]]$s)};$n=$a.Length;$v=[System.Numerics.BigInteger]::Zero;foreach($c in $s.ToCharArray()){$v=$v*$n+$a.IndexOf($c)};$b=$v.ToByteArray();if($b.Length -gt 1 -and $b[-1] -eq 0){$b=$b[0..($b.Length-2)]};[System.Array]::Reverse($b);return $b[1..($b.Length-1)]};"

    for ev, _, seq, pv in encoded_pool_data:
        ps_logic += f"$d=[Environment]::GetEnvironmentVariable('{ev}','Process');"
        for step_type, val in reversed(seq):
            if step_type == "xor":
                ps_logic += f"$d=[byte[]]($d|%{{$_ -bxor {val}}});"
            else:
                alphabet = encoder.alphabets[val]
                ps_logic += f"$d=f $d '{alphabet}';"
        ps_logic += f"echo \"set `\"{pv}=$([System.Text.Encoding]::UTF8.GetString($d))`\"\";"

    # Escape for Batch 'set' command
    ps_logic_batch = ps_logic.replace('%', '%%')
    obfuscated_lines.append(f'set "{ps_logic_var}={ps_logic_batch}"\n')
    obfuscated_lines.append(f'for /f "usebackq tokens=*" %%A in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "iex $env:{ps_logic_var}"`) do %%A\n')

    # Runtime Shuffle / Junk
    shuffle_var = "__" + generate_random_name(10, used_vars)
    shuffle_pool = generate_unreadable_string(30)
    obfuscated_lines.append(f'set "{shuffle_var}={shuffle_pool}"\n')
    loop_i = random.choice(string.ascii_uppercase)
    obfuscated_lines.append(f'for /L %%{loop_i} in (1,1,20) do set "{shuffle_var}=%{shuffle_var}:~1%%{shuffle_var}:~0,1%"\n')

    for i, m_block in enumerate(char_assignments):
        obfuscated_lines.append(m_block)
        if i % 30 == 0 and random.random() < 0.1:
            obfuscated_lines.append(f'REM {generate_unreadable_string(15)}\n')

    pattern = r'(%[a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|%~[a-zA-Z]*[0-9*]|%[0-9*]|%%[a-zA-Z]|![a-zA-Z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!)'

    for line in lines:
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.startswith(":") and not stripped.startswith("::"):
            obfuscated_lines.append(line)
            continue
        if stripped.lower().startswith("@echo off"): continue

        safe_for_dyn = not any(c in stripped for c in ('|', '>', '<', '&', '(', ')'))
        use_dynamic = safe_for_dyn and random.random() < 0.1 and len(stripped) > 10

        parts = re.split(pattern, line, flags=re.IGNORECASE)
        obfuscated_part_line = ""
        for part in parts:
            if part and re.match(pattern, part, re.IGNORECASE):
                obfuscated_part_line += part
            elif part:
                for char in part:
                    if char in char_map and random.random() < 0.8:
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
