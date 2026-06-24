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
            parts.append((val, '*')); current = batch_div(current, val)
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

def batch_div(a, b):
    if b == 0: return 0
    # CMD's set /a uses truncation towards zero
    return int(float(a) / b)

def batch_mod(a, b):
    if b == 0: return 0
    # CMD's remainder matches truncation division
    return a - (b * int(float(a) / b))

class RollingState:
    def __init__(self, used_vars):
        self.rs_var = "_" + generate_random_name(10, used_vars)
        self.cnt_var = "_" + generate_random_name(10, used_vars)
        self.aux_var = "_" + generate_random_name(10, used_vars)
        self.last_rs_var = "_" + generate_random_name(10, used_vars)
        self.fb_var = "_" + generate_random_name(10, used_vars)
        self.ds_var = "_" + generate_random_name(10, used_vars)
        self.ms_var = "_" + generate_random_name(10, used_vars)

        self.rs_val = random.randint(100, 10000)
        self.cnt_val = random.randint(100, 10000)
        self.aux_val = random.randint(100, 10000)
        self.last_rs_val = random.randint(100, 10000)
        self.fb_val = random.randint(100, 10000)
        self.ds_val = random.randint(100, 10000)
        self.ms_val = random.randint(100, 10000)

    def rehash(self):
        self.rs_val = random.randint(100, 10000)
        self.cnt_val = random.randint(100, 10000)
        self.aux_val = random.randint(100, 10000)
        self.last_rs_val = random.randint(100, 10000)
        self.fb_val = random.randint(100, 10000)
        self.ds_val = random.randint(100, 10000)
        self.ms_val = random.randint(100, 10000)
        return f's^et /a "{self.rs_var}={self.rs_val}", "{self.cnt_var}={self.cnt_val}", "{self.aux_var}={self.aux_val}", "{self.last_rs_var}={self.last_rs_val}", "{self.fb_var}={self.fb_val}", "{self.ds_var}={self.ds_val}", "{self.ms_var}={self.ms_val}"\n'

def generate_advanced_junk_internal(state, data_val, idx_val):
    cmds = []
    choice = random.randint(0, 999)
    if choice == 0:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.aux_var}! ^ !{state.rs_var}!) + (!{state.last_rs_var}! * 23)"\n')
    if choice == 1:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.aux_var}! ^ !{state.fb_var}!) + (!{state.last_rs_var}! * 55)"\n')
    if choice == 2:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.cnt_var}! ^ !{state.rs_var}!) + (!{state.last_rs_var}! * 29)"\n')
    if choice == 3:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.cnt_var}! ^ !{state.rs_var}!) + (!{state.aux_var}! * 98)"\n')
    if choice == 4:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.cnt_var}! ^ !{state.fb_var}!) + (!{state.rs_var}! * 86)"\n')
    if choice == 5:
        cmds.append(f's^et /a "{state.aux_var}=(!{state.fb_var}! ^ !{state.rs_var}!) + (!{state.last_rs_var}! * 96)"\n')
    if choice == 6:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.cnt_var}! ^ !{state.fb_var}!) + (!{state.aux_var}! * 23)"\n')
    if choice == 7:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.cnt_var}! ^ !{state.fb_var}!) + (!{state.rs_var}! * 1)"\n')
    if choice == 8:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.rs_var}! ^ !{state.fb_var}!) + (!{state.aux_var}! * 80)"\n')
    if choice == 9:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.rs_var}! ^ !{state.last_rs_var}!) + (!{state.aux_var}! * 21)"\n')
    if choice == 10:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.aux_var}! ^ !{state.fb_var}!) + (!{state.rs_var}! * 88)"\n')
    if choice == 11:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.aux_var}! ^ !{state.last_rs_var}!) + (!{state.rs_var}! * 17)"\n')
    if choice == 12:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.rs_var}! ^ !{state.fb_var}!) + (!{state.aux_var}! * 11)"\n')
    if choice == 13:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.rs_var}! ^ !{state.fb_var}!) + (!{state.cnt_var}! * 39)"\n')
    if choice == 14:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.fb_var}! ^ !{state.cnt_var}!) + (!{state.last_rs_var}! * 16)"\n')
    if choice == 15:
        cmds.append(f's^et /a "{state.aux_var}=(!{state.cnt_var}! ^ !{state.last_rs_var}!) + (!{state.rs_var}! * 67)"\n')
    if choice == 16:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.cnt_var}! ^ !{state.rs_var}!) + (!{state.fb_var}! * 61)"\n')
    if choice == 17:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.fb_var}! ^ !{state.aux_var}!) + (!{state.cnt_var}! * 9)"\n')
    if choice == 18:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.last_rs_var}! ^ !{state.cnt_var}!) + (!{state.aux_var}! * 8)"\n')
    if choice == 19:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.rs_var}! ^ !{state.aux_var}!) + (!{state.last_rs_var}! * 51)"\n')
    if choice == 20:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.rs_var}! ^ !{state.aux_var}!) + (!{state.last_rs_var}! * 98)"\n')
    if choice == 21:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.aux_var}! ^ !{state.fb_var}!) + (!{state.cnt_var}! * 57)"\n')
    if choice == 22:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.aux_var}! ^ !{state.last_rs_var}!) + (!{state.fb_var}! * 91)"\n')
    if choice == 23:
        cmds.append(f's^et /a "{state.aux_var}=(!{state.last_rs_var}! ^ !{state.rs_var}!) + (!{state.cnt_var}! * 2)"\n')
    if choice == 24:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.aux_var}! ^ !{state.rs_var}!) + (!{state.fb_var}! * 55)"\n')
    if choice == 25:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.aux_var}! ^ !{state.rs_var}!) + (!{state.last_rs_var}! * 1)"\n')
    if choice == 26:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.last_rs_var}! ^ !{state.cnt_var}!) + (!{state.rs_var}! * 44)"\n')
    if choice == 27:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.aux_var}! ^ !{state.rs_var}!) + (!{state.last_rs_var}! * 64)"\n')
    if choice == 28:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.cnt_var}! ^ !{state.aux_var}!) + (!{state.rs_var}! * 25)"\n')
    if choice == 29:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.aux_var}! ^ !{state.last_rs_var}!) + (!{state.rs_var}! * 11)"\n')
    if choice == 30:
        cmds.append(f'i^f !{state.aux_var}! G^TR 1246 ( s^et /a "{state.fb_var}+=45" ) e^lse ( s^et /a "{state.fb_var}-=7" )\n')
    if choice == 31:
        cmds.append(f'i^f !{state.rs_var}! G^TR 1546 ( s^et /a "{state.aux_var}+=18" ) e^lse ( s^et /a "{state.aux_var}-=24" )\n')
    if choice == 32:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 4964 ( s^et /a "{state.last_rs_var}+=7" ) e^lse ( s^et /a "{state.last_rs_var}-=40" )\n')
    if choice == 33:
        cmds.append(f'i^f !{state.rs_var}! G^TR 3755 ( s^et /a "{state.last_rs_var}+=5" ) e^lse ( s^et /a "{state.last_rs_var}-=49" )\n')
    if choice == 34:
        cmds.append(f'i^f !{state.fb_var}! G^TR 2225 ( s^et /a "{state.rs_var}+=32" ) e^lse ( s^et /a "{state.rs_var}-=26" )\n')
    if choice == 35:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3103 ( s^et /a "{state.last_rs_var}+=42" ) e^lse ( s^et /a "{state.last_rs_var}-=44" )\n')
    if choice == 36:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3063 ( s^et /a "{state.last_rs_var}+=9" ) e^lse ( s^et /a "{state.last_rs_var}-=13" )\n')
    if choice == 37:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 4190 ( s^et /a "{state.cnt_var}+=17" ) e^lse ( s^et /a "{state.cnt_var}-=14" )\n')
    if choice == 38:
        cmds.append(f'i^f !{state.rs_var}! G^TR 1970 ( s^et /a "{state.rs_var}+=29" ) e^lse ( s^et /a "{state.rs_var}-=6" )\n')
    if choice == 39:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 1589 ( s^et /a "{state.fb_var}+=12" ) e^lse ( s^et /a "{state.fb_var}-=10" )\n')
    if choice == 40:
        cmds.append(f'i^f !{state.rs_var}! G^TR 1127 ( s^et /a "{state.cnt_var}+=4" ) e^lse ( s^et /a "{state.cnt_var}-=4" )\n')
    if choice == 41:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 2755 ( s^et /a "{state.fb_var}+=28" ) e^lse ( s^et /a "{state.fb_var}-=29" )\n')
    if choice == 42:
        cmds.append(f'i^f !{state.rs_var}! G^TR 1009 ( s^et /a "{state.aux_var}+=37" ) e^lse ( s^et /a "{state.aux_var}-=42" )\n')
    if choice == 43:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 4701 ( s^et /a "{state.aux_var}+=12" ) e^lse ( s^et /a "{state.aux_var}-=17" )\n')
    if choice == 44:
        cmds.append(f'i^f !{state.rs_var}! G^TR 4279 ( s^et /a "{state.aux_var}+=11" ) e^lse ( s^et /a "{state.aux_var}-=50" )\n')
    if choice == 45:
        cmds.append(f'i^f !{state.fb_var}! G^TR 708 ( s^et /a "{state.last_rs_var}+=22" ) e^lse ( s^et /a "{state.last_rs_var}-=45" )\n')
    if choice == 46:
        cmds.append(f'i^f !{state.rs_var}! G^TR 2021 ( s^et /a "{state.aux_var}+=47" ) e^lse ( s^et /a "{state.aux_var}-=50" )\n')
    if choice == 47:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 1495 ( s^et /a "{state.rs_var}+=6" ) e^lse ( s^et /a "{state.rs_var}-=15" )\n')
    if choice == 48:
        cmds.append(f'i^f !{state.fb_var}! G^TR 2994 ( s^et /a "{state.rs_var}+=25" ) e^lse ( s^et /a "{state.rs_var}-=18" )\n')
    if choice == 49:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 3803 ( s^et /a "{state.rs_var}+=31" ) e^lse ( s^et /a "{state.rs_var}-=27" )\n')
    if choice == 50:
        cmds.append(f'i^f !{state.rs_var}! G^TR 4497 ( s^et /a "{state.fb_var}+=13" ) e^lse ( s^et /a "{state.fb_var}-=1" )\n')
    if choice == 51:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 1391 ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}-=5" )\n')
    if choice == 52:
        cmds.append(f'i^f !{state.aux_var}! G^TR 3199 ( s^et /a "{state.last_rs_var}+=18" ) e^lse ( s^et /a "{state.last_rs_var}-=10" )\n')
    if choice == 53:
        cmds.append(f'i^f !{state.rs_var}! G^TR 3416 ( s^et /a "{state.cnt_var}+=34" ) e^lse ( s^et /a "{state.cnt_var}-=49" )\n')
    if choice == 54:
        cmds.append(f'i^f !{state.fb_var}! G^TR 2744 ( s^et /a "{state.last_rs_var}+=18" ) e^lse ( s^et /a "{state.last_rs_var}-=36" )\n')
    if choice == 55:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 3583 ( s^et /a "{state.cnt_var}+=15" ) e^lse ( s^et /a "{state.cnt_var}-=19" )\n')
    if choice == 56:
        cmds.append(f'i^f !{state.rs_var}! G^TR 1687 ( s^et /a "{state.aux_var}+=39" ) e^lse ( s^et /a "{state.aux_var}-=12" )\n')
    if choice == 57:
        cmds.append(f'i^f !{state.rs_var}! G^TR 2570 ( s^et /a "{state.last_rs_var}+=29" ) e^lse ( s^et /a "{state.last_rs_var}-=22" )\n')
    if choice == 58:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3582 ( s^et /a "{state.cnt_var}+=12" ) e^lse ( s^et /a "{state.cnt_var}-=43" )\n')
    if choice == 59:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3844 ( s^et /a "{state.fb_var}+=15" ) e^lse ( s^et /a "{state.fb_var}-=39" )\n')
    if choice == 60:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.aux_var}+=!{state.fb_var}! + 4"\n')
    if choice == 61:
        cmds.append(f'f^or /L %%i in (1,1,4) do s^et /a "{state.cnt_var}+=!{state.fb_var}! + 3"\n')
    if choice == 62:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.aux_var}+=!{state.rs_var}! + 1"\n')
    if choice == 63:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.aux_var}+=!{state.last_rs_var}! + 5"\n')
    if choice == 64:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.aux_var}+=!{state.last_rs_var}! + 9"\n')
    if choice == 65:
        cmds.append(f'f^or /L %%i in (1,1,4) do s^et /a "{state.last_rs_var}+=!{state.rs_var}! + 4"\n')
    if choice == 66:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.last_rs_var}+=!{state.cnt_var}! + 2"\n')
    if choice == 67:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.fb_var}+=!{state.rs_var}! + 9"\n')
    if choice == 68:
        cmds.append(f'f^or /L %%i in (1,1,4) do s^et /a "{state.aux_var}+=!{state.last_rs_var}! + 2"\n')
    if choice == 69:
        cmds.append(f'f^or /L %%i in (1,1,4) do s^et /a "{state.rs_var}+=!{state.fb_var}! + 6"\n')
    if choice == 70:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.rs_var}+=!{state.last_rs_var}! + 1"\n')
    if choice == 71:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.fb_var}+=!{state.cnt_var}! + 3"\n')
    if choice == 72:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.last_rs_var}+=!{state.aux_var}! + 8"\n')
    if choice == 73:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.rs_var}+=!{state.last_rs_var}! + 4"\n')
    if choice == 74:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.last_rs_var}+=!{state.rs_var}! + 2"\n')
    if choice == 75:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.fb_var}+=!{state.cnt_var}! + 1"\n')
    if choice == 76:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.rs_var}+=!{state.cnt_var}! + 2"\n')
    if choice == 77:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.fb_var}+=!{state.cnt_var}! + 6"\n')
    if choice == 78:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.rs_var}+=!{state.fb_var}! + 1"\n')
    if choice == 79:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.rs_var}+=!{state.last_rs_var}! + 3"\n')
    if choice == 80:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.last_rs_var}+=!{state.aux_var}! + 9"\n')
    if choice == 81:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.fb_var}+=!{state.cnt_var}! + 7"\n')
    if choice == 82:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.fb_var}+=!{state.aux_var}! + 2"\n')
    if choice == 83:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.rs_var}+=!{state.aux_var}! + 10"\n')
    if choice == 84:
        cmds.append(f'f^or /L %%i in (1,1,4) do s^et /a "{state.cnt_var}+=!{state.rs_var}! + 4"\n')
    if choice == 85:
        cmds.append(f'f^or /L %%i in (1,1,4) do s^et /a "{state.rs_var}+=!{state.cnt_var}! + 7"\n')
    if choice == 86:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.last_rs_var}+=!{state.fb_var}! + 1"\n')
    if choice == 87:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.aux_var}+=!{state.rs_var}! + 5"\n')
    if choice == 88:
        cmds.append(f'f^or /L %%i in (1,1,3) do s^et /a "{state.aux_var}+=!{state.rs_var}! + 2"\n')
    if choice == 89:
        cmds.append(f'f^or /L %%i in (1,1,2) do s^et /a "{state.cnt_var}+=!{state.last_rs_var}! + 2"\n')
    if choice == 90:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 27"\n')
    if choice == 91:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 65"\n')
    if choice == 92:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 36"\n')
    if choice == 93:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 59"\n')
    if choice == 94:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 12"\n')
    if choice == 95:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 72"\n')
    if choice == 96:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 86"\n')
    if choice == 97:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 96"\n')
    if choice == 98:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 46"\n')
    if choice == 99:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 96"\n')
    if choice == 100:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 89"\n')
    if choice == 101:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 59"\n')
    if choice == 102:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 20"\n')
    if choice == 103:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 27"\n')
    if choice == 104:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 83"\n')
    if choice == 105:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 89"\n')
    if choice == 106:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 39"\n')
    if choice == 107:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 49"\n')
    if choice == 108:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 97"\n')
    if choice == 109:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 71"\n')
    if choice == 110:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 30"\n')
    if choice == 111:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 29"\n')
    if choice == 112:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 36"\n')
    if choice == 113:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 70"\n')
    if choice == 114:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 63"\n')
    if choice == 115:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 58"\n')
    if choice == 116:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 79"\n')
    if choice == 117:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 39"\n')
    if choice == 118:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 29"\n')
    if choice == 119:
        cmds.append(f's^et /a "{state.last_rs_var}={state.rs_var}", "{state.rs_var}={state.aux_var} ^ !{state.fb_var}!", "{state.aux_var}={state.cnt_var} + 42"\n')
    if choice == 120:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.fb_var}! + {data_val}) ^ (!{state.last_rs_var}! - {idx_val})) + 35"\n')
    if choice == 121:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.cnt_var}! + {data_val}) ^ (!{state.last_rs_var}! - {idx_val})) + 21"\n')
    if choice == 122:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.cnt_var}! + {data_val}) ^ (!{state.rs_var}! - {idx_val})) + 19"\n')
    if choice == 123:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.cnt_var}! - {idx_val})) + 49"\n')
    if choice == 124:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.fb_var}! + {data_val}) ^ (!{state.rs_var}! - {idx_val})) + 49"\n')
    if choice == 125:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.rs_var}! + {data_val}) ^ (!{state.cnt_var}! - {idx_val})) + 36"\n')
    if choice == 126:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.aux_var}! + {data_val}) ^ (!{state.cnt_var}! - {idx_val})) + 2"\n')
    if choice == 127:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.rs_var}! + {data_val}) ^ (!{state.cnt_var}! - {idx_val})) + 10"\n')
    if choice == 128:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.aux_var}! - {idx_val})) + 50"\n')
    if choice == 129:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.cnt_var}! + {data_val}) ^ (!{state.last_rs_var}! - {idx_val})) + 47"\n')
    if choice == 130:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.cnt_var}! - {idx_val})) + 21"\n')
    if choice == 131:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.fb_var}! - {idx_val})) + 45"\n')
    if choice == 132:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.rs_var}! - {idx_val})) + 19"\n')
    if choice == 133:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.rs_var}! - {idx_val})) + 13"\n')
    if choice == 134:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.cnt_var}! - {idx_val})) + 3"\n')
    if choice == 135:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.rs_var}! + {data_val}) ^ (!{state.fb_var}! - {idx_val})) + 28"\n')
    if choice == 136:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.cnt_var}! + {data_val}) ^ (!{state.fb_var}! - {idx_val})) + 50"\n')
    if choice == 137:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.cnt_var}! + {data_val}) ^ (!{state.fb_var}! - {idx_val})) + 15"\n')
    if choice == 138:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.rs_var}! + {data_val}) ^ (!{state.last_rs_var}! - {idx_val})) + 30"\n')
    if choice == 139:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.aux_var}! - {idx_val})) + 17"\n')
    if choice == 140:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.aux_var}! + {data_val}) ^ (!{state.fb_var}! - {idx_val})) + 14"\n')
    if choice == 141:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.aux_var}! + {data_val}) ^ (!{state.rs_var}! - {idx_val})) + 5"\n')
    if choice == 142:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.rs_var}! + {data_val}) ^ (!{state.aux_var}! - {idx_val})) + 25"\n')
    if choice == 143:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.fb_var}! + {data_val}) ^ (!{state.aux_var}! - {idx_val})) + 10"\n')
    if choice == 144:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.rs_var}! + {data_val}) ^ (!{state.aux_var}! - {idx_val})) + 45"\n')
    if choice == 145:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.aux_var}! + {data_val}) ^ (!{state.last_rs_var}! - {idx_val})) + 14"\n')
    if choice == 146:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.fb_var}! - {idx_val})) + 15"\n')
    if choice == 147:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.aux_var}! + {data_val}) ^ (!{state.fb_var}! - {idx_val})) + 26"\n')
    if choice == 148:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.last_rs_var}! + {data_val}) ^ (!{state.rs_var}! - {idx_val})) + 22"\n')
    if choice == 149:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.rs_var}! + {data_val}) ^ (!{state.last_rs_var}! - {idx_val})) + 8"\n')
    if choice == 150:
        cmds.append(f's^et /a "{state.ms_var}=(!{state.fb_var}! ^ !{state.ds_var}!) + (!{state.rs_var}! * 3)"\n')
    if choice == 151:
        cmds.append(f's^et /a "{state.ds_var}=(!{state.ms_var}! ^ !{state.aux_var}!) + (!{state.cnt_var}! * 7)"\n')
    if choice == 152:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.ds_var}! ^ !{state.last_rs_var}!) + (!{state.ms_var}! * 2)"\n')
    if choice == 153:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.ms_var}! ^ !{state.cnt_var}!) + (!{state.ds_var}! * 5)"\n')
    if choice == 154:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.ds_var}! ^ !{state.rs_var}!) + (!{state.aux_var}! * 4)"\n')
    if choice == 155:
        cmds.append(f's^et /a "{state.aux_var}=(!{state.ms_var}! ^ !{state.fb_var}!) + (!{state.last_rs_var}! * 9)"\n')
    if choice == 156:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.ds_var}! ^ !{state.ms_var}!) + (!{state.fb_var}! * 6)"\n')
    if choice == 157:
        cmds.append(f's^et /a "{state.ms_var}=(!{state.rs_var}! ^ !{state.aux_var}!) + (!{state.ds_var}! * 8)"\n')
    if choice == 158:
        cmds.append(f's^et /a "{state.ds_var}=(!{state.fb_var}! ^ !{state.last_rs_var}!) + (!{state.rs_var}! * 1)"\n')
    if choice == 159:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.ms_var}! ^ !{state.cnt_var}!) + (!{state.aux_var}! * 10)"\n')
    if choice == 160:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.ds_var}! ^ !{state.ms_var}!) + (!{state.cnt_var}! * 11)"\n')
    if choice == 161:
        cmds.append(f's^et /a "{state.ms_var}=(!{state.aux_var}! ^ !{state.rs_var}!) + (!{state.ds_var}! * 12)"\n')
    if choice == 162:
        cmds.append(f's^et /a "{state.ds_var}=(!{state.cnt_var}! ^ !{state.fb_var}!) + (!{state.ms_var}! * 13)"\n')
    if choice == 163:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.last_rs_var}! ^ !{state.ds_var}!) + (!{state.aux_var}! * 14)"\n')
    if choice == 164:
        cmds.append(f's^et /a "{state.aux_var}=(!{state.ms_var}! ^ !{state.rs_var}!) + (!{state.fb_var}! * 15)"\n')
    if choice == 165:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.ds_var}! ^ !{state.cnt_var}!) + (!{state.ms_var}! * 16)"\n')
    if choice == 166:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.ms_var}! ^ !{state.fb_var}!) + (!{state.ds_var}! * 17)"\n')
    if choice == 167:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.aux_var}! ^ !{state.ms_var}!) + (!{state.rs_var}! * 18)"\n')
    if choice == 168:
        cmds.append(f's^et /a "{state.ds_var}=(!{state.cnt_var}! ^ !{state.rs_var}!) + (!{state.last_rs_var}! * 19)"\n')
    if choice == 169:
        cmds.append(f's^et /a "{state.ms_var}=(!{state.fb_var}! ^ !{state.ds_var}!) + (!{state.aux_var}! * 20)"\n')
    if choice == 170:
        cmds.append(f's^et /a "{state.ms_var}=((!{state.ds_var}! ^ !{state.rs_var}!) + (!{state.fb_var}! ^ !{state.aux_var}!)) ^ !{state.cnt_var}!"\n')
    if choice == 171:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.ms_var}! ^ !{state.fb_var}!) + (!{state.rs_var}! ^ !{state.last_rs_var}!)) ^ !{state.aux_var}!"\n')
    if choice == 172:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ds_var}! ^ !{state.aux_var}!) + (!{state.ms_var}! ^ !{state.cnt_var}!)) ^ !{state.fb_var}!"\n')
    if choice == 173:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.ms_var}! ^ !{state.cnt_var}!) + (!{state.ds_var}! ^ !{state.rs_var}!)) ^ !{state.last_rs_var}!"\n')
    if choice == 174:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.ds_var}! ^ !{state.last_rs_var}!) + (!{state.ms_var}! ^ !{state.fb_var}!)) ^ !{state.rs_var}!"\n')
    if choice == 175:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.ms_var}! ^ !{state.rs_var}!) + (!{state.ds_var}! ^ !{state.cnt_var}!)) ^ !{state.fb_var}!"\n')
    if choice == 176:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.ds_var}! ^ !{state.fb_var}!) + (!{state.ms_var}! ^ !{state.aux_var}!)) ^ !{state.cnt_var}!"\n')
    if choice == 177:
        cmds.append(f's^et /a "{state.ms_var}=((!{state.rs_var}! ^ !{state.aux_var}!) + (!{state.ds_var}! ^ !{state.last_rs_var}!)) ^ !{state.fb_var}!"\n')
    if choice == 178:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.fb_var}! ^ !{state.last_rs_var}!) + (!{state.rs_var}! ^ !{state.ms_var}!)) ^ !{state.cnt_var}!"\n')
    if choice == 179:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ms_var}! ^ !{state.cnt_var}!) + (!{state.aux_var}! ^ !{state.fb_var}!)) ^ !{state.ds_var}!"\n')
    if choice == 180:
        cmds.append(f's^et /a "{state.ms_var}=(!{state.ds_var}! * 3) + (!{state.fb_var}! / 2) - (!{state.rs_var}! %% 5)"\n')
    if choice == 181:
        cmds.append(f's^et /a "{state.ds_var}=(!{state.ms_var}! * 2) + (!{state.aux_var}! / 3) - (!{state.cnt_var}! %% 4)"\n')
    if choice == 182:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.ds_var}! * 4) + (!{state.last_rs_var}! / 5) - (!{state.ms_var}! %% 7)"\n')
    if choice == 183:
        cmds.append(f's^et /a "{state.fb_var}=(!{state.ms_var}! * 5) + (!{state.cnt_var}! / 4) - (!{state.ds_var}! %% 6)"\n')
    if choice == 184:
        cmds.append(f's^et /a "{state.cnt_var}=(!{state.ds_var}! * 6) + (!{state.rs_var}! / 7) - (!{state.aux_var}! %% 2)"\n')
    if choice == 185:
        cmds.append(f's^et /a "{state.aux_var}=(!{state.ms_var}! * 7) + (!{state.fb_var}! / 6) - (!{state.last_rs_var}! %% 3)"\n')
    if choice == 186:
        cmds.append(f's^et /a "{state.last_rs_var}=(!{state.ds_var}! * 2) + (!{state.ms_var}! / 4) - (!{state.fb_var}! %% 8)"\n')
    if choice == 187:
        cmds.append(f's^et /a "{state.ms_var}=(!{state.rs_var}! * 3) + (!{state.aux_var}! / 2) - (!{state.ds_var}! %% 9)"\n')
    if choice == 188:
        cmds.append(f's^et /a "{state.ds_var}=(!{state.fb_var}! * 4) + (!{state.last_rs_var}! / 3) - (!{state.rs_var}! %% 5)"\n')
    if choice == 189:
        cmds.append(f's^et /a "{state.rs_var}=(!{state.ms_var}! * 5) + (!{state.cnt_var}! / 5) - (!{state.aux_var}! %% 4)"\n')
    if choice == 190:
        cmds.append(f'i^f {data_val} G^TR 50 ( s^et /a "{state.ds_var}+={idx_val}" ) e^lse ( s^et /a "{state.ds_var}-={idx_val}" )\n')
    if choice == 191:
        cmds.append(f'i^f {idx_val} L^SS 20 ( s^et /a "{state.ms_var}+={data_val}" ) e^lse ( s^et /a "{state.ms_var}-={data_val}" )\n')
    if choice == 192:
        cmds.append(f'i^f {data_val} E^QU {idx_val} ( s^et /a "{state.rs_var}=!{state.ds_var}! * 2" ) e^lse ( s^et /a "{state.rs_var}=!{state.ms_var}! * 2" )\n')
    if choice == 193:
        cmds.append(f'i^f !{state.rs_var}! G^TR {data_val} ( s^et /a "{state.fb_var}+={idx_val}" ) e^lse ( s^et /a "{state.fb_var}-={idx_val}" )\n')
    if choice == 194:
        cmds.append(f'i^f !{state.ms_var}! L^SS {idx_val} ( s^et /a "{state.cnt_var}+={data_val}" ) e^lse ( s^et /a "{state.cnt_var}-={data_val}" )\n')
    if choice == 195:
        cmds.append(f'i^f !{state.ds_var}! G^TR !{state.ms_var}! ( s^et /a "{state.aux_var}+=1" ) e^lse ( s^et /a "{state.aux_var}-=1" )\n')
    if choice == 196:
        cmds.append(f'i^f !{state.fb_var}! L^SS !{state.cnt_var}! ( s^et /a "{state.last_rs_var}+=2" ) e^lse ( s^et /a "{state.last_rs_var}-=2" )\n')
    if choice == 197:
        cmds.append(f'i^f {data_val} G^TR 100 ( s^et /a "{state.ms_var}^={idx_val}" ) e^lse ( s^et /a "{state.ms_var}+={idx_val}" )\n')
    if choice == 198:
        cmds.append(f'i^f {idx_val} G^TR 50 ( s^et /a "{state.ds_var}*={data_val % 5 + 1}" ) e^lse ( s^et /a "{state.ds_var}+={data_val}" )\n')
    if choice == 199:
        cmds.append(f'i^f !{state.rs_var}! E^QU !{state.aux_var}! ( s^et /a "{state.ms_var}=!{state.fb_var}! + 1" ) e^lse ( s^et /a "{state.ms_var}=!{state.cnt_var}! + 1" )\n')
    if choice == 200:
        cmds.append(f'i^f {data_val} G^TR {idx_val} ( s^et /a "{state.ds_var}=(!{state.ms_var}! ^ !{state.rs_var}!)" ) e^lse ( s^et /a "{state.ds_var}=(!{state.ms_var}! + !{state.rs_var}!)" )\n')
    if choice == 201:
        cmds.append(f'i^f {idx_val} G^TR {data_val} ( s^et /a "{state.rs_var}=(!{state.fb_var}! ^ !{state.aux_var}!)" ) e^lse ( s^et /a "{state.rs_var}=(!{state.fb_var}! + !{state.aux_var}!)" )\n')
    if choice == 202:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 5000 ( s^et /a "{state.ms_var}=!{state.ds_var}! / 2" ) e^lse ( s^et /a "{state.ms_var}=!{state.ds_var}! * 2" )\n')
    if choice == 203:
        cmds.append(f'i^f !{state.last_rs_var}! L^SS 1000 ( s^et /a "{state.ds_var}=!{state.ms_var}! + {data_val}" ) e^lse ( s^et /a "{state.ds_var}=!{state.ms_var}! - {data_val}" )\n')
    if choice == 204:
        cmds.append(f'i^f !{state.fb_var}! G^TR !{state.rs_var}! ( s^et /a "{state.ms_var}+={idx_val}" ) e^lse ( s^et /a "{state.ms_var}^={idx_val}" )\n')
    if choice == 205:
        cmds.append(f'i^f {data_val} L^SS 30 ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}+=2" )\n')
    if choice == 206:
        cmds.append(f'i^f {idx_val} G^TR 70 ( s^et /a "{state.fb_var}-=1" ) e^lse ( s^et /a "{state.fb_var}-=2" )\n')
    if choice == 207:
        cmds.append(f'i^f !{state.aux_var}! G^TR !{state.cnt_var}! ( s^et /a "{state.ds_var}^=!{state.ms_var}!" ) e^lse ( s^et /a "{state.ds_var}+=1" )\n')
    if choice == 208:
        cmds.append(f'i^f !{state.ms_var}! L^SS !{state.ds_var}! ( s^et /a "{state.rs_var}+=!{state.fb_var}!" ) e^lse ( s^et /a "{state.rs_var}^=!{state.fb_var}!" )\n')
    if choice == 209:
        cmds.append(f'i^f {data_val} E^QU 0 ( s^et /a "{state.ms_var}=1" ) e^lse ( s^et /a "{state.ms_var}=!{state.ms_var}! + 1" )\n')
    if choice == 210:
        cmds.append(f'i^f {data_val} G^TR 10 ( s^et /a "{state.ds_var}=!{state.ds_var}! + !{state.ms_var}!" ) e^lse ( s^et /a "{state.ds_var}=!{state.ds_var}! - !{state.ms_var}!" )\n')
    if choice == 211:
        cmds.append(f'i^f {idx_val} L^SS 80 ( s^et /a "{state.rs_var}=!{state.rs_var}! ^ !{state.fb_var}!" ) e^lse ( s^et /a "{state.rs_var}=!{state.rs_var}! + !{state.fb_var}!" )\n')
    if choice == 212:
        cmds.append(f'i^f !{state.ms_var}! G^TR !{state.ds_var}! ( s^et /a "{state.fb_var}+={idx_val}" ) e^lse ( s^et /a "{state.fb_var}+={data_val}" )\n')
    if choice == 213:
        cmds.append(f'i^f !{state.rs_var}! L^SS !{state.aux_var}! ( s^et /a "{state.cnt_var}+=1" ) e^lse ( s^et /a "{state.cnt_var}-=1" )\n')
    if choice == 214:
        cmds.append(f'i^f !{state.fb_var}! G^TR !{state.cnt_var}! ( s^et /a "{state.ms_var}=!{state.ms_var}! + {data_val}" ) e^lse ( s^et /a "{state.ms_var}=!{state.ms_var}! + {idx_val}" )\n')
    if choice == 215:
        cmds.append(f'i^f {data_val} L^SS {idx_val} ( s^et /a "{state.ds_var}=!{state.ds_var}! * 2" ) e^lse ( s^et /a "{state.ds_var}=!{state.ds_var}! / 2" )\n')
    if choice == 216:
        cmds.append(f'i^f {idx_val} G^TR {data_val} ( s^et /a "{state.rs_var}=!{state.rs_var}! + 5" ) e^lse ( s^et /a "{state.rs_var}=!{state.rs_var}! - 5" )\n')
    if choice == 217:
        cmds.append(f'i^f !{state.aux_var}! E^QU !{state.fb_var}! ( s^et /a "{state.ms_var}=0" ) e^lse ( s^et /a "{state.ms_var}=!{state.ms_var}! ^ 0xFF" )\n')
    if choice == 218:
        cmds.append(f'i^f !{state.cnt_var}! G^TR !{state.last_rs_var}! ( s^et /a "{state.ds_var}+=1" ) e^lse ( s^et /a "{state.ds_var}-=1" )\n')
    if choice == 219:
        cmds.append(f'i^f !{state.ms_var}! L^SS 0 ( s^et /a "{state.ms_var}=1" ) e^lse ( s^et /a "{state.ms_var}=!{state.ms_var}! + 1" )\n')
    if choice == 220:
        cmds.append(f'i^f {data_val} G^TR 200 ( s^et /a "{state.rs_var}=!{state.rs_var}! ^ 0xAA" ) e^lse ( s^et /a "{state.rs_var}=!{state.rs_var}! ^ 0x55" )\n')
    if choice == 221:
        cmds.append(f'i^f {idx_val} L^SS 10 ( s^et /a "{state.ds_var}=!{state.ds_var}! + 10" ) e^lse ( s^et /a "{state.ds_var}=!{state.ds_var}! + 20" )\n')
    if choice == 222:
        cmds.append(f'i^f !{state.rs_var}! G^TR 1000 ( s^et /a "{state.ms_var}+=1" ) e^lse ( s^et /a "{state.ms_var}-=1" )\n')
    if choice == 223:
        cmds.append(f'i^f !{state.fb_var}! L^SS 500 ( s^et /a "{state.ds_var}=!{state.ds_var}! ^ !{state.ms_var}!" ) e^lse ( s^et /a "{state.ds_var}=!{state.ds_var}! + !{state.ms_var}!" )\n')
    if choice == 224:
        cmds.append(f'i^f !{state.cnt_var}! E^QU 0 ( s^et /a "{state.cnt_var}=1" ) e^lse ( s^et /a "{state.cnt_var}=!{state.cnt_var}! * 2" )\n')
    if choice == 225:
        cmds.append(f'i^f {data_val} G^TR 128 ( s^et /a "{state.ms_var}=!{state.ms_var}! + 1" ) e^lse ( s^et /a "{state.ms_var}=!{state.ms_var}! - 1" )\n')
    if choice == 226:
        cmds.append(f'i^f {idx_val} L^SS 128 ( s^et /a "{state.ds_var}=!{state.ds_var}! + 1" ) e^lse ( s^et /a "{state.ds_var}=!{state.ds_var}! - 1" )\n')
    if choice == 227:
        cmds.append(f'i^f !{state.aux_var}! G^TR 100 ( s^et /a "{state.rs_var}=!{state.rs_var}! + 1" ) e^lse ( s^et /a "{state.rs_var}=!{state.rs_var}! - 1" )\n')
    if choice == 228:
        cmds.append(f'i^f !{state.fb_var}! L^SS 100 ( s^et /a "{state.cnt_var}=!{state.cnt_var}! + 1" ) e^lse ( s^et /a "{state.cnt_var}=!{state.cnt_var}! - 1" )\n')
    if choice == 229:
        cmds.append(f'i^f !{state.ms_var}! E^QU !{state.ds_var}! ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}-=1" )\n')
    if choice == 230:
        cmds.append(f'f^or /L %%i in (1,1,2) do ( i^f {data_val} G^TR 50 ( s^et /a "{state.ms_var}+=%%i" ) )\n')
    if choice == 231:
        cmds.append(f'f^or /L %%i in (1,1,2) do ( i^f {idx_val} L^SS 50 ( s^et /a "{state.ds_var}+=%%i" ) )\n')
    if choice == 232:
        cmds.append(f'f^or /L %%i in (1,1,2) do ( i^f !{state.rs_var}! G^TR 1000 ( s^et /a "{state.fb_var}+=%%i" ) )\n')
    if choice == 233:
        cmds.append(f'f^or /L %%i in (1,1,2) do ( i^f !{state.cnt_var}! L^SS 5000 ( s^et /a "{state.aux_var}+=%%i" ) )\n')
    if choice == 234:
        cmds.append(f'f^or /L %%i in (1,1,2) do ( i^f !{state.ms_var}! E^QU !{state.ds_var}! ( s^et /a "{state.last_rs_var}+=%%i" ) )\n')
    if choice == 235:
        cmds.append(f'f^or /L %%h in (1,1,2) do f^or /L %%j in (1,1,2) do s^et /a "{state.ms_var}+=1"\n')
    if choice == 236:
        cmds.append(f'f^or /L %%h in (1,1,2) do f^or /L %%j in (1,1,2) do s^et /a "{state.ds_var}+=1"\n')
    if choice == 237:
        cmds.append(f'f^or /L %%h in (1,1,2) do f^or /L %%j in (1,1,2) do s^et /a "{state.rs_var}+=1"\n')
    if choice == 238:
        cmds.append(f'f^or /L %%h in (1,1,2) do f^or /L %%j in (1,1,2) do s^et /a "{state.fb_var}+=1"\n')
    if choice == 239:
        cmds.append(f'f^or /L %%h in (1,1,2) do f^or /L %%j in (1,1,2) do s^et /a "{state.cnt_var}+=1"\n')
    if choice == 240:
        cmds.append(f'i^f {data_val} G^TR 10 ( f^or /L %%i in (1,1,3) do s^et /a "{state.ms_var}+=%%i" )\n')
    if choice == 241:
        cmds.append(f'i^f {idx_val} L^SS 90 ( f^or /L %%i in (1,1,3) do s^et /a "{state.ds_var}+=%%i" )\n')
    if choice == 242:
        cmds.append(f'i^f !{state.ms_var}! G^TR !{state.ds_var}! ( f^or /L %%i in (1,1,2) do s^et /a "{state.rs_var}+=%%i" )\n')
    if choice == 243:
        cmds.append(f'i^f !{state.fb_var}! L^SS !{state.cnt_var}! ( f^or /L %%i in (1,1,2) do s^et /a "{state.aux_var}+=%%i" )\n')
    if choice == 244:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 0 ( f^or /L %%i in (1,1,2) do s^et /a "{state.ms_var}+=%%i" )\n')
    if choice == 245:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.ds_var}+=1" & i^f !{state.ds_var}! G^TR 10000 s^et /a "{state.ds_var}=0" )\n')
    if choice == 246:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.ms_var}+=1" & i^f !{state.ms_var}! G^TR 10000 s^et /a "{state.ms_var}=0" )\n')
    if choice == 247:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.rs_var}+=1" & i^f !{state.rs_var}! G^TR 10000 s^et /a "{state.rs_var}=0" )\n')
    if choice == 248:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.fb_var}+=1" & i^f !{state.fb_var}! G^TR 10000 s^et /a "{state.fb_var}=0" )\n')
    if choice == 249:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.cnt_var}+=1" & i^f !{state.cnt_var}! G^TR 10000 s^et /a "{state.cnt_var}=0" )\n')
    if choice == 250:
        cmds.append(f's^et /a "{state.ms_var}=0" & f^or /L %%i in (1,1,4) do s^et /a "{state.ms_var}+=!{state.ds_var}! %% 10"\n')
    if choice == 251:
        cmds.append(f's^et /a "{state.ds_var}=0" & f^or /L %%i in (1,1,4) do s^et /a "{state.ds_var}+=!{state.ms_var}! %% 10"\n')
    if choice == 252:
        cmds.append(f's^et /a "{state.rs_var}=0" & f^or /L %%i in (1,1,4) do s^et /a "{state.rs_var}+=!{state.fb_var}! %% 10"\n')
    if choice == 253:
        cmds.append(f's^et /a "{state.fb_var}=0" & f^or /L %%i in (1,1,4) do s^et /a "{state.fb_var}+=!{state.rs_var}! %% 10"\n')
    if choice == 254:
        cmds.append(f's^et /a "{state.cnt_var}=0" & f^or /L %%i in (1,1,4) do s^et /a "{state.cnt_var}+=!{state.aux_var}! %% 10"\n')
    if choice == 255:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.ms_var}+=%%i" & s^et /a "{state.ds_var}-=%%i" )\n')
    if choice == 256:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.rs_var}+=%%i" & s^et /a "{state.fb_var}-=%%i" )\n')
    if choice == 257:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.cnt_var}+=%%i" & s^et /a "{state.aux_var}-=%%i" )\n')
    if choice == 258:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.last_rs_var}+=%%i" & s^et /a "{state.ms_var}-=%%i" )\n')
    if choice == 259:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.ds_var}+=%%i" & s^et /a "{state.rs_var}-=%%i" )\n')
    if choice == 260:
        cmds.append(f'i^f !{state.ms_var}! G^TR !{state.ds_var}! ( i^f !{state.rs_var}! G^TR !{state.fb_var}! ( s^et /a "{state.ms_var}+=1" ) )\n')
    if choice == 261:
        cmds.append(f'i^f !{state.ds_var}! L^SS !{state.ms_var}! ( i^f !{state.fb_var}! L^SS !{state.rs_var}! ( s^et /a "{state.ds_var}+=1" ) )\n')
    if choice == 262:
        cmds.append(f'i^f !{state.rs_var}! G^TR !{state.fb_var}! ( i^f !{state.ms_var}! G^TR !{state.ds_var}! ( s^et /a "{state.rs_var}+=1" ) )\n')
    if choice == 263:
        cmds.append(f'i^f !{state.fb_var}! L^SS !{state.rs_var}! ( i^f !{state.ds_var}! L^SS !{state.ms_var}! ( s^et /a "{state.fb_var}+=1" ) )\n')
    if choice == 264:
        cmds.append(f'i^f !{state.cnt_var}! G^TR !{state.aux_var}! ( i^f !{state.ms_var}! G^TR !{state.ds_var}! ( s^et /a "{state.cnt_var}+=1" ) )\n')
    if choice == 265:
        cmds.append(f'f^or /L %%i in (1,1,1) do i^f 1==1 f^or /L %%j in (1,1,1) do s^et /a "{state.ms_var}+=1"\n')
    if choice == 266:
        cmds.append(f'f^or /L %%i in (1,1,1) do i^f 1==1 f^or /L %%j in (1,1,1) do s^et /a "{state.ds_var}+=1"\n')
    if choice == 267:
        cmds.append(f'f^or /L %%i in (1,1,1) do i^f 1==1 f^or /L %%j in (1,1,1) do s^et /a "{state.rs_var}+=1"\n')
    if choice == 268:
        cmds.append(f'f^or /L %%i in (1,1,1) do i^f 1==1 f^or /L %%j in (1,1,1) do s^et /a "{state.fb_var}+=1"\n')
    if choice == 269:
        cmds.append(f'f^or /L %%i in (1,1,1) do i^f 1==1 f^or /L %%j in (1,1,1) do s^et /a "{state.cnt_var}+=1"\n')
    if choice == 270:
        cmds.append(f'i^f 1==1 ( s^et /a "{state.ms_var}+=1" ) e^lse ( s^et /a "{state.ms_var}=0" )\n')
    if choice == 271:
        cmds.append(f'i^f not 1==0 ( s^et /a "{state.ds_var}+=1" ) e^lse ( s^et /a "{state.ds_var}=0" )\n')
    if choice == 272:
        cmds.append(f'i^f %random% G^TR -1 ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}=0" )\n')
    if choice == 273:
        cmds.append(f'i^f d^efined COMSPEC ( s^et /a "{state.fb_var}+=1" ) e^lse ( s^et /a "{state.fb_var}=0" )\n')
    if choice == 274:
        cmds.append(f'i^f e^xist %COMSPEC% ( s^et /a "{state.cnt_var}+=1" ) e^lse ( s^et /a "{state.cnt_var}=0" )\n')
    if choice == 275:
        cmds.append(f'i^f !{state.ms_var}! G^TR -2147483648 ( s^et /a "{state.ms_var}+=1" ) e^lse ( s^et /a "{state.ms_var}=0" )\n')
    if choice == 276:
        cmds.append(f'i^f !{state.ds_var}! L^SS 2147483647 ( s^et /a "{state.ds_var}+=1" ) e^lse ( s^et /a "{state.ds_var}=0" )\n')
    if choice == 277:
        cmds.append(f'i^f 1 L^SS 2 ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}=0" )\n')
    if choice == 278:
        cmds.append(f'i^f 2 G^TR 1 ( s^et /a "{state.fb_var}+=1" ) e^lse ( s^et /a "{state.fb_var}=0" )\n')
    if choice == 279:
        cmds.append(f'i^f "a"=="a" ( s^et /a "{state.cnt_var}+=1" ) e^lse ( s^et /a "{state.cnt_var}=0" )\n')
    if choice == 280:
        cmds.append(f'i^f not "a"=="b" ( s^et /a "{state.ms_var}+=1" ) e^lse ( s^et /a "{state.ms_var}=0" )\n')
    if choice == 281:
        cmds.append(f'i^f 0==0 ( s^et /a "{state.ds_var}+=1" ) e^lse ( s^et /a "{state.ds_var}=0" )\n')
    if choice == 282:
        cmds.append(f'i^f e^rr^orlevel 0 ( s^et /a "{state.rs_var}+=1" ) e^lse ( s^et /a "{state.rs_var}=0" )\n')
    if choice == 283:
        cmds.append(f'i^f d^efined {state.ms_var} ( s^et /a "{state.fb_var}+=1" ) e^lse ( s^et /a "{state.fb_var}+=1" )\n')
    if choice == 284:
        cmds.append(f'i^f not d^efined NON_EXISTENT_VAR ( s^et /a "{state.cnt_var}+=1" ) e^lse ( s^et /a "{state.cnt_var}=0" )\n')
    if choice == 285:
        cmds.append(f'i^f 1==1 ( i^f 2==2 ( s^et /a "{state.ms_var}+=1" ) )\n')
    if choice == 286:
        cmds.append(f'i^f 1==1 ( i^f 2==2 ( s^et /a "{state.ds_var}+=1" ) )\n')
    if choice == 287:
        cmds.append(f'i^f 1==1 ( i^f 2==2 ( s^et /a "{state.rs_var}+=1" ) )\n')
    if choice == 288:
        cmds.append(f'i^f 1==1 ( i^f 2==2 ( s^et /a "{state.fb_var}+=1" ) )\n')
    if choice == 289:
        cmds.append(f'i^f 1==1 ( i^f 2==2 ( s^et /a "{state.cnt_var}+=1" ) )\n')
    if choice == 290:
        cmds.append(f'f^or %%a in (1) do i^f %%a==1 ( s^et /a "{state.ms_var}+=1" )\n')
    if choice == 291:
        cmds.append(f'f^or %%a in (1) do i^f %%a==1 ( s^et /a "{state.ds_var}+=1" )\n')
    if choice == 292:
        cmds.append(f'f^or %%a in (1) do i^f %%a==1 ( s^et /a "{state.rs_var}+=1" )\n')
    if choice == 293:
        cmds.append(f'f^or %%a in (1) do i^f %%a==1 ( s^et /a "{state.fb_var}+=1" )\n')
    if choice == 294:
        cmds.append(f'f^or %%a in (1) do i^f %%a==1 ( s^et /a "{state.cnt_var}+=1" )\n')
    if choice == 295:
        cmds.append(f'i^f 1==1 ( s^et /a "{state.ms_var}+=1" ) & i^f 1==1 ( s^et /a "{state.ds_var}+=1" )\n')
    if choice == 296:
        cmds.append(f'i^f 1==1 ( s^et /a "{state.rs_var}+=1" ) & i^f 1==1 ( s^et /a "{state.fb_var}+=1" )\n')
    if choice == 297:
        cmds.append(f'i^f 1==1 ( s^et /a "{state.cnt_var}+=1" ) & i^f 1==1 ( s^et /a "{state.last_rs_var}+=1" )\n')
    if choice == 298:
        cmds.append(f'i^f 1==1 ( s^et /a "{state.ms_var}+=1" ) & i^f 1==1 ( s^et /a "{state.aux_var}+=1" )\n')
    if choice == 299:
        cmds.append(f'i^f 1==1 ( s^et /a "{state.ds_var}+=1" ) & i^f 1==1 ( s^et /a "{state.rs_var}+=1" )\n')
    if choice == 300:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.cnt_var}! ^ !{state.aux_var}!) * 47) + ((!{state.last_rs_var}! ^ !{state.ms_var}!) * 13) ^ (!{state.fb_var}! + {data_val})"\n')
    if choice == 301:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.cnt_var}! ^ !{state.aux_var}!) * 13) + ((!{state.rs_var}! ^ !{state.fb_var}!) * 30) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 302:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.aux_var}! ^ !{state.ds_var}!) * 26) + ((!{state.ms_var}! ^ !{state.last_rs_var}!) * 47) ^ (!{state.rs_var}! + {data_val})"\n')
    if choice == 303:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ds_var}! ^ !{state.ms_var}!) * 39) + ((!{state.aux_var}! ^ !{state.fb_var}!) * 11) ^ (!{state.last_rs_var}! + {data_val})"\n')
    if choice == 304:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ds_var}! ^ !{state.last_rs_var}!) * 5) + ((!{state.fb_var}! ^ !{state.ms_var}!) * 28) ^ (!{state.aux_var}! + {data_val})"\n')
    if choice == 305:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.fb_var}! ^ !{state.ms_var}!) * 18) + ((!{state.last_rs_var}! ^ !{state.rs_var}!) * 45) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 306:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ds_var}! ^ !{state.cnt_var}!) * 31) + ((!{state.aux_var}! ^ !{state.fb_var}!) * 9) ^ (!{state.last_rs_var}! + {data_val})"\n')
    if choice == 307:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.cnt_var}! ^ !{state.aux_var}!) * 44) + ((!{state.rs_var}! ^ !{state.last_rs_var}!) * 26) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 308:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.last_rs_var}! ^ !{state.aux_var}!) * 10) + ((!{state.rs_var}! ^ !{state.fb_var}!) * 43) ^ (!{state.cnt_var}! + {data_val})"\n')
    if choice == 309:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.fb_var}! ^ !{state.ms_var}!) * 23) + ((!{state.last_rs_var}! ^ !{state.aux_var}!) * 7) ^ (!{state.cnt_var}! + {data_val})"\n')
    if choice == 310:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ds_var}! ^ !{state.aux_var}!) * 36) + ((!{state.fb_var}! ^ !{state.last_rs_var}!) * 24) ^ (!{state.ms_var}! + {data_val})"\n')
    if choice == 311:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.last_rs_var}! ^ !{state.aux_var}!) * 2) + ((!{state.cnt_var}! ^ !{state.ms_var}!) * 41) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 312:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.fb_var}! ^ !{state.ms_var}!) * 15) + ((!{state.aux_var}! ^ !{state.rs_var}!) * 5) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 313:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ds_var}! ^ !{state.aux_var}!) * 28) + ((!{state.last_rs_var}! ^ !{state.ms_var}!) * 22) ^ (!{state.fb_var}! + {data_val})"\n')
    if choice == 314:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.fb_var}! ^ !{state.ms_var}!) * 41) + ((!{state.last_rs_var}! ^ !{state.aux_var}!) * 39) ^ (!{state.cnt_var}! + {data_val})"\n')
    if choice == 315:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.rs_var}! ^ !{state.fb_var}!) * 7) + ((!{state.ds_var}! ^ !{state.cnt_var}!) * 3) ^ (!{state.ms_var}! + {data_val})"\n')
    if choice == 316:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.ms_var}! ^ !{state.last_rs_var}!) * 20) + ((!{state.rs_var}! ^ !{state.cnt_var}!) * 20) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 317:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.ds_var}! ^ !{state.cnt_var}!) * 33) + ((!{state.fb_var}! ^ !{state.aux_var}!) * 37) ^ (!{state.rs_var}! + {data_val})"\n')
    if choice == 318:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.cnt_var}! ^ !{state.ds_var}!) * 46) + ((!{state.ms_var}! ^ !{state.fb_var}!) * 1) ^ (!{state.last_rs_var}! + {data_val})"\n')
    if choice == 319:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.ds_var}! ^ !{state.rs_var}!) * 12) + ((!{state.ms_var}! ^ !{state.cnt_var}!) * 18) ^ (!{state.fb_var}! + {data_val})"\n')
    if choice == 320:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ms_var}! ^ !{state.ds_var}!) * 25) + ((!{state.last_rs_var}! ^ !{state.fb_var}!) * 35) ^ (!{state.cnt_var}! + {data_val})"\n')
    if choice == 321:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.rs_var}! ^ !{state.aux_var}!) * 38) + ((!{state.last_rs_var}! ^ !{state.ms_var}!) * 52) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 322:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.ds_var}! ^ !{state.rs_var}!) * 4) + ((!{state.aux_var}! ^ !{state.ms_var}!) * 16) ^ (!{state.cnt_var}! + {data_val})"\n')
    if choice == 323:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.rs_var}! ^ !{state.last_rs_var}!) * 17) + ((!{state.fb_var}! ^ !{state.ms_var}!) * 33) ^ (!{state.ds_var}! + {data_val})"\n')
    if choice == 324:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.ds_var}! ^ !{state.aux_var}!) * 30) + ((!{state.ms_var}! ^ !{state.cnt_var}!) * 50) ^ (!{state.last_rs_var}! + {data_val})"\n')
    if choice == 325:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.fb_var}+=!{state.last_rs_var}! + %%i" & s^et /a "{state.last_rs_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}" )' + "\n")
    if choice == 326:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.rs_var}+=!{state.ds_var}! + %%i" & s^et /a "{state.ds_var}^=!{state.fb_var}! + !{state.aux_var}! + {idx_val}" )' + "\n")
    if choice == 327:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.last_rs_var}+=!{state.ds_var}! + %%i" & s^et /a "{state.ds_var}^=!{state.fb_var}! + !{state.rs_var}! + {idx_val}" )' + "\n")
    if choice == 328:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.rs_var}+=!{state.fb_var}! + %%i" & s^et /a "{state.fb_var}^=!{state.aux_var}! + !{state.ds_var}! + {idx_val}" )' + "\n")
    if choice == 329:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.cnt_var}+=!{state.aux_var}! + %%i" & s^et /a "{state.aux_var}^=!{state.ms_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 330:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.ms_var}+=!{state.rs_var}! + %%i" & s^et /a "{state.rs_var}^=!{state.cnt_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 331:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.fb_var}+=!{state.ms_var}! + %%i" & s^et /a "{state.ms_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}" )' + "\n")
    if choice == 332:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.ds_var}+=!{state.rs_var}! + %%i" & s^et /a "{state.rs_var}^=!{state.aux_var}! + !{state.cnt_var}! + {idx_val}" )' + "\n")
    if choice == 333:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.ms_var}+=!{state.last_rs_var}! + %%i" & s^et /a "{state.last_rs_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}" )' + "\n")
    if choice == 334:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.ds_var}+=!{state.cnt_var}! + %%i" & s^et /a "{state.cnt_var}^=!{state.aux_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 335:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.cnt_var}+=!{state.ds_var}! + %%i" & s^et /a "{state.ds_var}^=!{state.fb_var}! + !{state.rs_var}! + {idx_val}" )' + "\n")
    if choice == 336:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.fb_var}+=!{state.ms_var}! + %%i" & s^et /a "{state.ms_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}" )' + "\n")
    if choice == 337:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.fb_var}+=!{state.ds_var}! + %%i" & s^et /a "{state.ds_var}^=!{state.cnt_var}! + !{state.aux_var}! + {idx_val}" )' + "\n")
    if choice == 338:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.aux_var}+=!{state.rs_var}! + %%i" & s^et /a "{state.rs_var}^=!{state.cnt_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 339:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.ms_var}+=!{state.cnt_var}! + %%i" & s^et /a "{state.cnt_var}^=!{state.ds_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 340:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.cnt_var}+=!{state.ms_var}! + %%i" & s^et /a "{state.ms_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 341:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.cnt_var}+=!{state.ms_var}! + %%i" & s^et /a "{state.ms_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 342:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.ds_var}+=!{state.ms_var}! + %%i" & s^et /a "{state.ms_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}" )' + "\n")
    if choice == 343:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.rs_var}+=!{state.last_rs_var}! + %%i" & s^et /a "{state.last_rs_var}^=!{state.aux_var}! + !{state.cnt_var}! + {idx_val}" )' + "\n")
    if choice == 344:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.ds_var}+=!{state.ms_var}! + %%i" & s^et /a "{state.ms_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}" )' + "\n")
    if choice == 345:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.cnt_var}+=!{state.ms_var}! + %%i" & s^et /a "{state.ms_var}^=!{state.last_rs_var}! + !{state.rs_var}! + {idx_val}" )' + "\n")
    if choice == 346:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.aux_var}+=!{state.ds_var}! + %%i" & s^et /a "{state.ds_var}^=!{state.rs_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 347:
        cmds.append(f'f^or /L %%i in (1,1,5) do ( s^et /a "{state.cnt_var}+=!{state.fb_var}! + %%i" & s^et /a "{state.fb_var}^=!{state.last_rs_var}! + !{state.rs_var}! + {idx_val}" )' + "\n")
    if choice == 348:
        cmds.append(f'f^or /L %%i in (1,1,3) do ( s^et /a "{state.aux_var}+=!{state.rs_var}! + %%i" & s^et /a "{state.rs_var}^=!{state.ms_var}! + !{state.ds_var}! + {idx_val}" )' + "\n")
    if choice == 349:
        cmds.append(f'f^or /L %%i in (1,1,4) do ( s^et /a "{state.cnt_var}+=!{state.last_rs_var}! + %%i" & s^et /a "{state.last_rs_var}^=!{state.aux_var}! + !{state.fb_var}! + {idx_val}" )' + "\n")
    if choice == 350:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3850 ( i^f !{state.ms_var}! L^SS 2650 ( s^et /a "{state.last_rs_var}^=!{state.aux_var}! + {data_val}" ) e^lse ( s^et /a "{state.last_rs_var}+=!{state.rs_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.last_rs_var}=!{state.fb_var}! * 2" )' + "\n")
    if choice == 351:
        cmds.append(f'i^f !{state.ms_var}! G^TR 3861 ( i^f !{state.rs_var}! L^SS 2669 ( s^et /a "{state.cnt_var}^=!{state.ds_var}! + {data_val}" ) e^lse ( s^et /a "{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.cnt_var}=!{state.last_rs_var}! * 2" )' + "\n")
    if choice == 352:
        cmds.append(f'i^f !{state.fb_var}! G^TR 3872 ( i^f !{state.ds_var}! L^SS 2688 ( s^et /a "{state.aux_var}^=!{state.ms_var}! + {data_val}" ) e^lse ( s^et /a "{state.aux_var}+=!{state.rs_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.aux_var}=!{state.last_rs_var}! * 2" )' + "\n")
    if choice == 353:
        cmds.append(f'i^f !{state.ds_var}! G^TR 3883 ( i^f !{state.rs_var}! L^SS 2707 ( s^et /a "{state.cnt_var}^=!{state.last_rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.cnt_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.cnt_var}=!{state.aux_var}! * 2" )' + "\n")
    if choice == 354:
        cmds.append(f'i^f !{state.fb_var}! G^TR 3894 ( i^f !{state.ds_var}! L^SS 2726 ( s^et /a "{state.rs_var}^=!{state.aux_var}! + {data_val}" ) e^lse ( s^et /a "{state.rs_var}+=!{state.ms_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.rs_var}=!{state.last_rs_var}! * 2" )' + "\n")
    if choice == 355:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3905 ( i^f !{state.ds_var}! L^SS 2745 ( s^et /a "{state.fb_var}^=!{state.rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.fb_var}+=!{state.last_rs_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.fb_var}=!{state.aux_var}! * 2" )' + "\n")
    if choice == 356:
        cmds.append(f'i^f !{state.ds_var}! G^TR 3916 ( i^f !{state.ms_var}! L^SS 2764 ( s^et /a "{state.aux_var}^=!{state.cnt_var}! + {data_val}" ) e^lse ( s^et /a "{state.aux_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.aux_var}=!{state.last_rs_var}! * 2" )' + "\n")
    if choice == 357:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3927 ( i^f !{state.last_rs_var}! L^SS 2783 ( s^et /a "{state.ds_var}^=!{state.ms_var}! + {data_val}" ) e^lse ( s^et /a "{state.ds_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.ds_var}=!{state.rs_var}! * 2" )' + "\n")
    if choice == 358:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 3938 ( i^f !{state.rs_var}! L^SS 2802 ( s^et /a "{state.ms_var}^=!{state.aux_var}! + {data_val}" ) e^lse ( s^et /a "{state.ms_var}+=!{state.ds_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.ms_var}=!{state.fb_var}! * 2" )' + "\n")
    if choice == 359:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 3949 ( i^f !{state.ds_var}! L^SS 2821 ( s^et /a "{state.aux_var}^=!{state.cnt_var}! + {data_val}" ) e^lse ( s^et /a "{state.aux_var}+=!{state.ms_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.aux_var}=!{state.fb_var}! * 2" )' + "\n")
    if choice == 360:
        cmds.append(f'i^f !{state.ds_var}! G^TR 3960 ( i^f !{state.fb_var}! L^SS 2840 ( s^et /a "{state.ms_var}^=!{state.last_rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.ms_var}=!{state.rs_var}! * 2" )' + "\n")
    if choice == 361:
        cmds.append(f'i^f !{state.ms_var}! G^TR 3971 ( i^f !{state.last_rs_var}! L^SS 2859 ( s^et /a "{state.fb_var}^=!{state.aux_var}! + {data_val}" ) e^lse ( s^et /a "{state.fb_var}+=!{state.ds_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.fb_var}=!{state.rs_var}! * 2" )' + "\n")
    if choice == 362:
        cmds.append(f'i^f !{state.aux_var}! G^TR 3982 ( i^f !{state.cnt_var}! L^SS 2878 ( s^et /a "{state.rs_var}^=!{state.ms_var}! + {data_val}" ) e^lse ( s^et /a "{state.rs_var}+=!{state.last_rs_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.rs_var}=!{state.ds_var}! * 2" )' + "\n")
    if choice == 363:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 3993 ( i^f !{state.ms_var}! L^SS 2897 ( s^et /a "{state.rs_var}^=!{state.last_rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.rs_var}+=!{state.aux_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.rs_var}=!{state.fb_var}! * 2" )' + "\n")
    if choice == 364:
        cmds.append(f'i^f !{state.ds_var}! G^TR 4 ( i^f !{state.ms_var}! L^SS 2916 ( s^et /a "{state.fb_var}^=!{state.last_rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.fb_var}+=!{state.aux_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.fb_var}=!{state.rs_var}! * 2" )' + "\n")
    if choice == 365:
        cmds.append(f'i^f !{state.aux_var}! G^TR 15 ( i^f !{state.ds_var}! L^SS 2935 ( s^et /a "{state.rs_var}^=!{state.last_rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.rs_var}+=!{state.ms_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.rs_var}=!{state.cnt_var}! * 2" )' + "\n")
    if choice == 366:
        cmds.append(f'i^f !{state.fb_var}! G^TR 26 ( i^f !{state.rs_var}! L^SS 2954 ( s^et /a "{state.aux_var}^=!{state.cnt_var}! + {data_val}" ) e^lse ( s^et /a "{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.aux_var}=!{state.ds_var}! * 2" )' + "\n")
    if choice == 367:
        cmds.append(f'i^f !{state.rs_var}! G^TR 37 ( i^f !{state.cnt_var}! L^SS 2973 ( s^et /a "{state.ds_var}^=!{state.aux_var}! + {data_val}" ) e^lse ( s^et /a "{state.ds_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.ds_var}=!{state.last_rs_var}! * 2" )' + "\n")
    if choice == 368:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 48 ( i^f !{state.cnt_var}! L^SS 2992 ( s^et /a "{state.ds_var}^=!{state.rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.ds_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.ds_var}=!{state.ms_var}! * 2" )' + "\n")
    if choice == 369:
        cmds.append(f'i^f !{state.rs_var}! G^TR 59 ( i^f !{state.fb_var}! L^SS 3011 ( s^et /a "{state.aux_var}^=!{state.cnt_var}! + {data_val}" ) e^lse ( s^et /a "{state.aux_var}+=!{state.ms_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.aux_var}=!{state.last_rs_var}! * 2" )' + "\n")
    if choice == 370:
        cmds.append(f'i^f !{state.fb_var}! G^TR 70 ( i^f !{state.rs_var}! L^SS 3030 ( s^et /a "{state.last_rs_var}^=!{state.aux_var}! + {data_val}" ) e^lse ( s^et /a "{state.last_rs_var}+=!{state.cnt_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.last_rs_var}=!{state.ds_var}! * 2" )' + "\n")
    if choice == 371:
        cmds.append(f'i^f !{state.last_rs_var}! G^TR 81 ( i^f !{state.cnt_var}! L^SS 3049 ( s^et /a "{state.aux_var}^=!{state.rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.aux_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.aux_var}=!{state.ds_var}! * 2" )' + "\n")
    if choice == 372:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 92 ( i^f !{state.rs_var}! L^SS 3068 ( s^et /a "{state.last_rs_var}^=!{state.aux_var}! + {data_val}" ) e^lse ( s^et /a "{state.last_rs_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.last_rs_var}=!{state.ms_var}! * 2" )' + "\n")
    if choice == 373:
        cmds.append(f'i^f !{state.aux_var}! G^TR 103 ( i^f !{state.ds_var}! L^SS 3087 ( s^et /a "{state.last_rs_var}^=!{state.cnt_var}! + {data_val}" ) e^lse ( s^et /a "{state.last_rs_var}+=!{state.fb_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.last_rs_var}=!{state.ms_var}! * 2" )' + "\n")
    if choice == 374:
        cmds.append(f'i^f !{state.cnt_var}! G^TR 114 ( i^f !{state.fb_var}! L^SS 3106 ( s^et /a "{state.ds_var}^=!{state.last_rs_var}! + {data_val}" ) e^lse ( s^et /a "{state.ds_var}+=!{state.aux_var}! ^ {idx_val}" ) ) e^lse ( s^et /a "{state.ds_var}=!{state.rs_var}! * 2" )' + "\n")
    if choice == 375:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.ds_var}! ^ !{state.rs_var}!) + (!{state.aux_var}! ^ !{state.ms_var}!) - (!{state.fb_var}! ^ !{state.last_rs_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 376:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.last_rs_var}! ^ !{state.cnt_var}!) + (!{state.fb_var}! ^ !{state.aux_var}!) - (!{state.rs_var}! ^ !{state.ms_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 377:
        cmds.append(f's^et /a "{state.ms_var}=((!{state.rs_var}! ^ !{state.fb_var}!) + (!{state.ds_var}! ^ !{state.aux_var}!) - (!{state.last_rs_var}! ^ !{state.cnt_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 378:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.ms_var}! ^ !{state.ds_var}!) + (!{state.aux_var}! ^ !{state.cnt_var}!) - (!{state.rs_var}! ^ !{state.fb_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 379:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.rs_var}! ^ !{state.last_rs_var}!) + (!{state.aux_var}! ^ !{state.ds_var}!) - (!{state.ms_var}! ^ !{state.fb_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 380:
        cmds.append(f's^et /a "{state.ms_var}=((!{state.aux_var}! ^ !{state.rs_var}!) + (!{state.last_rs_var}! ^ !{state.ds_var}!) - (!{state.fb_var}! ^ !{state.cnt_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 381:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.cnt_var}! ^ !{state.ds_var}!) + (!{state.aux_var}! ^ !{state.ms_var}!) - (!{state.fb_var}! ^ !{state.rs_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 382:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.last_rs_var}! ^ !{state.rs_var}!) + (!{state.ds_var}! ^ !{state.ms_var}!) - (!{state.fb_var}! ^ !{state.aux_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 383:
        cmds.append(f's^et /a "{state.ms_var}=((!{state.aux_var}! ^ !{state.last_rs_var}!) + (!{state.fb_var}! ^ !{state.ds_var}!) - (!{state.rs_var}! ^ !{state.cnt_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 384:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.cnt_var}! ^ !{state.aux_var}!) + (!{state.ms_var}! ^ !{state.rs_var}!) - (!{state.ds_var}! ^ !{state.fb_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 385:
        cmds.append(f's^et /a "{state.aux_var}=((!{state.rs_var}! ^ !{state.cnt_var}!) + (!{state.ms_var}! ^ !{state.last_rs_var}!) - (!{state.fb_var}! ^ !{state.ds_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 386:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.rs_var}! ^ !{state.ds_var}!) + (!{state.aux_var}! ^ !{state.ms_var}!) - (!{state.fb_var}! ^ !{state.cnt_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 387:
        cmds.append(f's^et /a "{state.ms_var}=((!{state.aux_var}! ^ !{state.fb_var}!) + (!{state.cnt_var}! ^ !{state.last_rs_var}!) - (!{state.rs_var}! ^ !{state.ds_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 388:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.fb_var}! ^ !{state.last_rs_var}!) + (!{state.cnt_var}! ^ !{state.ms_var}!) - (!{state.rs_var}! ^ !{state.aux_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 389:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.aux_var}! ^ !{state.rs_var}!) + (!{state.ms_var}! ^ !{state.cnt_var}!) - (!{state.last_rs_var}! ^ !{state.fb_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 390:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.fb_var}! ^ !{state.aux_var}!) + (!{state.ds_var}! ^ !{state.last_rs_var}!) - (!{state.rs_var}! ^ !{state.ms_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 391:
        cmds.append(f's^et /a "{state.ms_var}=((!{state.last_rs_var}! ^ !{state.ds_var}!) + (!{state.fb_var}! ^ !{state.rs_var}!) - (!{state.aux_var}! ^ !{state.cnt_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 392:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.ms_var}! ^ !{state.aux_var}!) + (!{state.rs_var}! ^ !{state.fb_var}!) - (!{state.last_rs_var}! ^ !{state.ds_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 393:
        cmds.append(f's^et /a "{state.cnt_var}=((!{state.ds_var}! ^ !{state.aux_var}!) + (!{state.rs_var}! ^ !{state.ms_var}!) - (!{state.fb_var}! ^ !{state.last_rs_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 394:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.last_rs_var}! ^ !{state.aux_var}!) + (!{state.cnt_var}! ^ !{state.rs_var}!) - (!{state.ms_var}! ^ !{state.fb_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 395:
        cmds.append(f's^et /a "{state.rs_var}=((!{state.cnt_var}! ^ !{state.aux_var}!) + (!{state.fb_var}! ^ !{state.ds_var}!) - (!{state.ms_var}! ^ !{state.last_rs_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 396:
        cmds.append(f's^et /a "{state.fb_var}=((!{state.aux_var}! ^ !{state.ms_var}!) + (!{state.rs_var}! ^ !{state.cnt_var}!) - (!{state.last_rs_var}! ^ !{state.ds_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 397:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.aux_var}! ^ !{state.ms_var}!) + (!{state.fb_var}! ^ !{state.ds_var}!) - (!{state.rs_var}! ^ !{state.cnt_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 398:
        cmds.append(f's^et /a "{state.last_rs_var}=((!{state.ds_var}! ^ !{state.aux_var}!) + (!{state.cnt_var}! ^ !{state.rs_var}!) - (!{state.fb_var}! ^ !{state.ms_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 399:
        cmds.append(f's^et /a "{state.ds_var}=((!{state.cnt_var}! ^ !{state.fb_var}!) + (!{state.rs_var}! ^ !{state.ms_var}!) - (!{state.aux_var}! ^ !{state.last_rs_var}!)) + {data_val} + {idx_val}"\n')
    if choice == 400:
        cmds.append(f"i^f !{state.ds_var}! G^TR !{state.rs_var}! ( i^f !{state.ms_var}! L^SS !{state.last_rs_var}! ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 401:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ !{state.fb_var}!\", \"{state.rs_var}+=!{state.cnt_var}! ^ !{state.last_rs_var}!\", \"{state.cnt_var}+=!{state.aux_var}! ^ !{state.ms_var}!\", \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 402:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ms_var}! * 19) + (!{state.cnt_var}! / 8)\" & i^f !{state.rs_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 403:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.cnt_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.cnt_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 404:
        cmds.append(f"i^f !{state.aux_var}! G^TR !{state.ms_var}! ( i^f !{state.cnt_var}! L^SS !{state.last_rs_var}! ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 405:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ !{state.aux_var}!\", \"{state.rs_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ds_var}+=!{state.fb_var}! ^ !{state.cnt_var}!\", \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 406:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.last_rs_var}! * 13) + (!{state.fb_var}! / 5)\" & i^f !{state.ds_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 407:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.rs_var}! + !{state.ms_var}! + {data_val}\", \"{state.rs_var}^=!{state.ds_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 408:
        cmds.append(f"i^f !{state.ms_var}! G^TR !{state.rs_var}! ( i^f !{state.last_rs_var}! L^SS !{state.fb_var}! ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 409:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ !{state.cnt_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.fb_var}+=!{state.rs_var}! ^ !{state.last_rs_var}!\", \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 410:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! * 19) + (!{state.cnt_var}! / 5)\" & i^f !{state.fb_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 411:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.aux_var}! + !{state.rs_var}! + {data_val}\", \"{state.aux_var}^=!{state.ds_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 412:
        cmds.append(f"i^f !{state.aux_var}! G^TR !{state.rs_var}! ( i^f !{state.cnt_var}! L^SS !{state.ds_var}! ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 413:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.cnt_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.rs_var}!\", \"{state.fb_var}+=!{state.ms_var}! ^ !{state.aux_var}!\", \"{state.cnt_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 414:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.fb_var}! * 18) + (!{state.last_rs_var}! / 9)\" & i^f !{state.ds_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 415:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.ms_var}! + !{state.ds_var}! + {data_val}\", \"{state.ms_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 416:
        cmds.append(f"i^f !{state.fb_var}! G^TR !{state.rs_var}! ( i^f !{state.last_rs_var}! L^SS !{state.ms_var}! ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 417:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.rs_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.last_rs_var}+=!{state.aux_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 418:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.last_rs_var}! * 18) + (!{state.cnt_var}! / 3)\" & i^f !{state.aux_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 419:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.ds_var}! + !{state.aux_var}! + {data_val}\", \"{state.ds_var}^=!{state.ms_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 420:
        cmds.append(f"i^f !{state.fb_var}! G^TR !{state.ms_var}! ( i^f !{state.rs_var}! L^SS !{state.last_rs_var}! ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 421:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ !{state.cnt_var}!\", \"{state.ms_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.rs_var}+=!{state.fb_var}! ^ !{state.last_rs_var}!\", \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 422:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.last_rs_var}! * 10) + (!{state.rs_var}! / 10)\" & i^f !{state.ds_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 423:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.fb_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.fb_var}^=!{state.ms_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 424:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR !{state.ds_var}! ( i^f !{state.aux_var}! L^SS !{state.ms_var}! ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 425:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ !{state.rs_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ !{state.aux_var}!\", \"{state.fb_var}+=!{state.ds_var}! ^ !{state.last_rs_var}!\", \"{state.rs_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 426:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ms_var}! * 4) + (!{state.ds_var}! / 10)\" & i^f !{state.rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 427:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.cnt_var}^=!{state.aux_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.aux_var}^=!{state.cnt_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 428:
        cmds.append(f"i^f !{state.cnt_var}! G^TR !{state.last_rs_var}! ( i^f !{state.ds_var}! L^SS !{state.aux_var}! ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 429:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.rs_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 430:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.last_rs_var}! * 19) + (!{state.aux_var}! / 9)\" & i^f !{state.rs_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 431:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.cnt_var}^=!{state.last_rs_var}! + !{state.ms_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.cnt_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 432:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR !{state.fb_var}! ( i^f !{state.rs_var}! L^SS !{state.cnt_var}! ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 433:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.fb_var}! ^ !{state.aux_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.rs_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 434:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.last_rs_var}! * 10) + (!{state.rs_var}! / 9)\" & i^f !{state.ms_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 435:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.aux_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 436:
        cmds.append(f"i^f !{state.cnt_var}! G^TR !{state.rs_var}! ( i^f !{state.fb_var}! L^SS !{state.aux_var}! ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 437:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ !{state.last_rs_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ !{state.cnt_var}!\", \"{state.aux_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 438:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.fb_var}! * 20) + (!{state.ms_var}! / 2)\" & i^f !{state.rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 439:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.rs_var}^=!{state.fb_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 440:
        cmds.append(f"i^f !{state.cnt_var}! G^TR !{state.aux_var}! ( i^f !{state.last_rs_var}! L^SS !{state.fb_var}! ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 441:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.rs_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.cnt_var}! ^ !{state.last_rs_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 442:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.cnt_var}! * 9) + (!{state.ms_var}! / 7)\" & i^f !{state.fb_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 443:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.cnt_var}^=!{state.aux_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 444:
        cmds.append(f"i^f !{state.ds_var}! G^TR !{state.rs_var}! ( i^f !{state.cnt_var}! L^SS !{state.fb_var}! ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 445:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.cnt_var}! ^ !{state.last_rs_var}!\", \"{state.cnt_var}+=!{state.ds_var}! ^ !{state.rs_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 446:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.ms_var}! * 15) + (!{state.aux_var}! / 6)\" & i^f !{state.ds_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 447:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.ms_var}! + !{state.aux_var}! + {data_val}\", \"{state.ms_var}^=!{state.rs_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 448:
        cmds.append(f"i^f !{state.ds_var}! G^TR !{state.last_rs_var}! ( i^f !{state.fb_var}! L^SS !{state.ms_var}! ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 449:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ !{state.last_rs_var}!\", \"{state.aux_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 450:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.rs_var}! * 9) + (!{state.aux_var}! / 3)\" & i^f !{state.cnt_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 451:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.fb_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.fb_var}^=!{state.aux_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 452:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR !{state.rs_var}! ( i^f !{state.cnt_var}! L^SS !{state.ds_var}! ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 453:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ !{state.rs_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ !{state.aux_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.rs_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 454:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.last_rs_var}! * 8) + (!{state.aux_var}! / 8)\" & i^f !{state.cnt_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 455:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ms_var}! + !{state.rs_var}! + {data_val}\", \"{state.ms_var}^=!{state.aux_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 456:
        cmds.append(f"i^f !{state.rs_var}! G^TR !{state.ms_var}! ( i^f !{state.aux_var}! L^SS !{state.last_rs_var}! ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 457:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ !{state.last_rs_var}!\", \"{state.fb_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ !{state.cnt_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 458:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! * 3) + (!{state.rs_var}! / 8)\" & i^f !{state.fb_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 459:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.fb_var}! + !{state.ds_var}! + {data_val}\", \"{state.fb_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 460:
        cmds.append(f"i^f !{state.ds_var}! G^TR !{state.aux_var}! ( i^f !{state.fb_var}! L^SS !{state.last_rs_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 461:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ !{state.last_rs_var}!\", \"{state.aux_var}+=!{state.ds_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ !{state.rs_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 462:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.last_rs_var}! * 19) + (!{state.ds_var}! / 2)\" & i^f !{state.cnt_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 463:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ms_var}! + !{state.cnt_var}! + {data_val}\", \"{state.ms_var}^=!{state.aux_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 464:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR !{state.ms_var}! ( i^f !{state.cnt_var}! L^SS !{state.ds_var}! ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 465:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.rs_var}!\", \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 466:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! * 4) + (!{state.ds_var}! / 9)\" & i^f !{state.cnt_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 467:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.ds_var}! + !{state.fb_var}! + {data_val}\", \"{state.ds_var}^=!{state.last_rs_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 468:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR !{state.cnt_var}! ( i^f !{state.ds_var}! L^SS !{state.rs_var}! ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 469:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ !{state.fb_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ !{state.rs_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.aux_var}!\", \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 470:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.cnt_var}! * 7) + (!{state.ms_var}! / 9)\" & i^f !{state.last_rs_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 471:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.aux_var}! + !{state.cnt_var}! + {data_val}\", \"{state.aux_var}^=!{state.last_rs_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 472:
        cmds.append(f"i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( i^f !{state.rs_var}! L^SS !{state.ds_var}! ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 473:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ !{state.rs_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.cnt_var}!\", \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 474:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.cnt_var}! * 19) + (!{state.ms_var}! / 9)\" & i^f !{state.ds_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 475:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.rs_var}! + !{state.cnt_var}! + {data_val}\", \"{state.rs_var}^=!{state.last_rs_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 476:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR !{state.rs_var}! ( i^f !{state.aux_var}! L^SS !{state.ds_var}! ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 477:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ !{state.aux_var}!\", \"{state.cnt_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 478:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ds_var}! * 14) + (!{state.last_rs_var}! / 2)\" & i^f !{state.aux_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 479:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.ds_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.ds_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 480:
        cmds.append(f"i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( i^f !{state.ms_var}! L^SS !{state.cnt_var}! ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 481:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.aux_var}!\", \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.rs_var}! ^ !{state.fb_var}!\", \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 482:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ds_var}! * 3) + (!{state.fb_var}! / 2)\" & i^f !{state.rs_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 483:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.cnt_var}^=!{state.ms_var}! + !{state.rs_var}! + {data_val}\", \"{state.ms_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 484:
        cmds.append(f"i^f !{state.ds_var}! G^TR !{state.rs_var}! ( i^f !{state.fb_var}! L^SS !{state.aux_var}! ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 485:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.fb_var}+=!{state.rs_var}! ^ !{state.ms_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ !{state.last_rs_var}!\", \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 486:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.rs_var}! * 20) + (!{state.aux_var}! / 5)\" & i^f !{state.fb_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 487:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.ds_var}! + !{state.aux_var}! + {data_val}\", \"{state.ds_var}^=!{state.rs_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 488:
        cmds.append(f"i^f !{state.fb_var}! G^TR !{state.last_rs_var}! ( i^f !{state.aux_var}! L^SS !{state.rs_var}! ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 489:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ !{state.cnt_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 490:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.cnt_var}! * 16) + (!{state.last_rs_var}! / 8)\" & i^f !{state.ds_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 491:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.ds_var}! + !{state.fb_var}! + {data_val}\", \"{state.ds_var}^=!{state.ms_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 492:
        cmds.append(f"i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( i^f !{state.cnt_var}! L^SS !{state.ms_var}! ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 493:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ !{state.aux_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.ms_var}!\", \"{state.fb_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.aux_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 494:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.aux_var}! * 18) + (!{state.ds_var}! / 5)\" & i^f !{state.ms_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 495:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.cnt_var}^=!{state.rs_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 496:
        cmds.append(f"i^f !{state.ds_var}! G^TR !{state.ms_var}! ( i^f !{state.last_rs_var}! L^SS !{state.fb_var}! ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 497:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ !{state.rs_var}!\", \"{state.ms_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 498:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! * 16) + (!{state.aux_var}! / 6)\" & i^f !{state.fb_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 499:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ms_var}! + !{state.cnt_var}! + {data_val}\", \"{state.ms_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")

    if choice == 500:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.cnt_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 501:
        cmds.append(f"i^f !{state.ms_var}! G^TR 3265 ( i^f !{state.cnt_var}! L^SS 3508 ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 502:
        cmds.append(f"i^f !{state.ms_var}! G^TR 8259 ( i^f !{state.ds_var}! L^SS 1361 ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 503:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.cnt_var}! + !{state.ms_var}! + {data_val}\", \"{state.cnt_var}^=!{state.fb_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 504:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.last_rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.fb_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 505:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.cnt_var}! + !{state.ms_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ds_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 506:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.cnt_var}! + !{state.aux_var}! + {data_val}\", \"{state.cnt_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 507:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.aux_var}! * 4) + (!{state.ms_var}! / 3)\" & i^f !{state.ds_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 508:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! * 3) + (!{state.ms_var}! / 9)\" & i^f !{state.cnt_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 509:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.last_rs_var}! * 8) + (!{state.aux_var}! / 2)\" & i^f !{state.fb_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 510:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ !{state.ms_var}!\", \"{state.rs_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 511:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ds_var}! * 9) + (!{state.rs_var}! / 5)\" & i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 512:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.last_rs_var}! + !{state.ds_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.fb_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 513:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.fb_var}! * 7) + (!{state.last_rs_var}! / 10)\" & i^f !{state.rs_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 514:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ !{state.last_rs_var}!\", \"{state.aux_var}+=!{state.rs_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 515:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 516:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 517:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.ms_var}! * 5) + (!{state.fb_var}! / 6)\" & i^f !{state.ds_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 518:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 519:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 7526 ( i^f !{state.ds_var}! L^SS 3661 ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 520:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 521:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 522:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.rs_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 523:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.rs_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 524:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.aux_var}! + !{state.ds_var}! + {data_val}\", \"{state.aux_var}^=!{state.ds_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 525:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ !{state.cnt_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ !{state.cnt_var}!\", \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 526:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 527:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 528:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ms_var}! * 9) + (!{state.rs_var}! / 3)\" & i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 529:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.rs_var}^=!{state.last_rs_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 530:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.cnt_var}! * 4) + (!{state.last_rs_var}! / 6)\" & i^f !{state.ds_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 531:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 532:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.ds_var}! + !{state.rs_var}! + {data_val}\", \"{state.ds_var}^=!{state.ms_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 533:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ !{state.cnt_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ !{state.cnt_var}!\", \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 534:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.rs_var}! + !{state.aux_var}! + {data_val}\", \"{state.rs_var}^=!{state.ds_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 535:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.rs_var}^=!{state.ms_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 536:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.fb_var}! + !{state.aux_var}! + {data_val}\", \"{state.fb_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 537:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 8389 ( i^f !{state.rs_var}! L^SS 7613 ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 538:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ds_var}! + !{state.rs_var}! + {data_val}\", \"{state.ds_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 539:
        cmds.append(f"i^f !{state.ms_var}! G^TR 2015 ( i^f !{state.ds_var}! L^SS 6995 ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 540:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.fb_var}! + !{state.fb_var}! + {data_val}\", \"{state.fb_var}^=!{state.ds_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 541:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 2682 ( i^f !{state.fb_var}! L^SS 3767 ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 542:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 7802 ( i^f !{state.aux_var}! L^SS 8587 ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 543:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.aux_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 544:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.last_rs_var}! * 10) + (!{state.cnt_var}! / 3)\" & i^f !{state.aux_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 545:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 546:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ms_var}! * 3) + (!{state.fb_var}! / 5)\" & i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 547:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 548:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.last_rs_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 549:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.fb_var}^=!{state.rs_var}! + !{state.cnt_var}! + {data_val}\", \"{state.rs_var}^=!{state.fb_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 550:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.fb_var}! + !{state.ds_var}! + {data_val}\", \"{state.fb_var}^=!{state.last_rs_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 551:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.ms_var}! + !{state.cnt_var}! + {data_val}\", \"{state.ms_var}^=!{state.last_rs_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 552:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.cnt_var}^=!{state.ms_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.ms_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 553:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.rs_var}! * 10) + (!{state.ms_var}! / 3)\" & i^f !{state.fb_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 554:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 555:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! * 2) + (!{state.last_rs_var}! / 3)\" & i^f !{state.fb_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 556:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 557:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 6603 ( i^f !{state.rs_var}! L^SS 1276 ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 558:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 559:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ !{state.rs_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 560:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 561:
        cmds.append(f"i^f !{state.aux_var}! G^TR 3362 ( i^f !{state.cnt_var}! L^SS 1708 ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 562:
        cmds.append(f"i^f !{state.fb_var}! G^TR 5751 ( i^f !{state.aux_var}! L^SS 2950 ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 563:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ !{state.rs_var}!\", \"{state.fb_var}+=!{state.ds_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 564:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.rs_var}! %% 9) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 565:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.fb_var}! + !{state.fb_var}! + {data_val}\", \"{state.fb_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 566:
        cmds.append(f"i^f !{state.aux_var}! G^TR 2332 ( i^f !{state.ds_var}! L^SS 5325 ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 567:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.cnt_var}^=!{state.fb_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.fb_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 568:
        cmds.append(f"i^f !{state.rs_var}! G^TR 7917 ( i^f !{state.ds_var}! L^SS 6786 ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 569:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 570:
        cmds.append(f"i^f !{state.ms_var}! G^TR 3918 ( i^f !{state.ds_var}! L^SS 5965 ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 571:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.aux_var}! + !{state.aux_var}! + {data_val}\", \"{state.aux_var}^=!{state.ds_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 572:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.rs_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 573:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.rs_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 574:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.cnt_var}! * 6) + (!{state.rs_var}! / 5)\" & i^f !{state.ds_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 575:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! * 4) + (!{state.cnt_var}! / 7)\" & i^f !{state.fb_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 576:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.fb_var}! * 6) + (!{state.cnt_var}! / 6)\" & i^f !{state.ds_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 577:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ds_var}! * 5) + (!{state.cnt_var}! / 8)\" & i^f !{state.aux_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 578:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.cnt_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 579:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ !{state.ds_var}!\", \"{state.ms_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 580:
        cmds.append(f"i^f !{state.fb_var}! G^TR 5920 ( i^f !{state.ds_var}! L^SS 8126 ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 581:
        cmds.append(f"i^f !{state.ds_var}! G^TR 1877 ( i^f !{state.ms_var}! L^SS 3395 ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 582:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ !{state.cnt_var}!\", \"{state.ms_var}+=!{state.rs_var}! ^ !{state.cnt_var}!\", \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 583:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ !{state.aux_var}!\", \"{state.fb_var}+=!{state.ds_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 584:
        cmds.append(f"i^f !{state.ds_var}! G^TR 7022 ( i^f !{state.rs_var}! L^SS 6425 ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 585:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ds_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 586:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ms_var}! * 5) + (!{state.cnt_var}! / 3)\" & i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 587:
        cmds.append(f"i^f !{state.ms_var}! G^TR 2990 ( i^f !{state.aux_var}! L^SS 6953 ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 588:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.rs_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 589:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 9) + (!{state.rs_var}! / 4)\" & i^f !{state.last_rs_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 590:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 591:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 4) + (!{state.ds_var}! / 2)\" & i^f !{state.last_rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 592:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.rs_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 593:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.ds_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 594:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 6385 ( i^f !{state.aux_var}! L^SS 1028 ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 595:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.last_rs_var}! + !{state.rs_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ms_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 596:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 8325 ( i^f !{state.ms_var}! L^SS 5756 ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 597:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ms_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 598:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ !{state.cnt_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ !{state.cnt_var}!\", \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 599:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.rs_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 600:
        cmds.append(f"i^f !{state.aux_var}! G^TR 5320 ( i^f !{state.cnt_var}! L^SS 1764 ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 601:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.rs_var}^=!{state.ms_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 602:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.fb_var}! + !{state.fb_var}! + {data_val}\", \"{state.fb_var}^=!{state.rs_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 603:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 9) + (!{state.rs_var}! / 5)\" & i^f !{state.last_rs_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 604:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.rs_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 605:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 7157 ( i^f !{state.fb_var}! L^SS 5105 ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 606:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ !{state.last_rs_var}!\", \"{state.fb_var}+=!{state.rs_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 607:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.cnt_var}! + !{state.ds_var}! + {data_val}\", \"{state.cnt_var}^=!{state.fb_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 608:
        cmds.append(f"i^f !{state.rs_var}! G^TR 3867 ( i^f !{state.cnt_var}! L^SS 4716 ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 609:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.cnt_var}! + !{state.aux_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ds_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 610:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.fb_var}! * 8) + (!{state.last_rs_var}! / 8)\" & i^f !{state.rs_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 611:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 612:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.cnt_var}! + !{state.ms_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ms_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 613:
        cmds.append(f"i^f !{state.ds_var}! G^TR 8566 ( i^f !{state.rs_var}! L^SS 3814 ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 614:
        cmds.append(f"i^f !{state.fb_var}! G^TR 7714 ( i^f !{state.rs_var}! L^SS 6503 ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 615:
        cmds.append(f"i^f !{state.fb_var}! G^TR 8360 ( i^f !{state.cnt_var}! L^SS 8665 ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 616:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 617:
        cmds.append(f"i^f !{state.rs_var}! G^TR 6549 ( i^f !{state.last_rs_var}! L^SS 1927 ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 618:
        cmds.append(f"i^f !{state.fb_var}! G^TR 7609 ( i^f !{state.ds_var}! L^SS 7701 ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 619:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.aux_var}! + !{state.aux_var}! + {data_val}\", \"{state.aux_var}^=!{state.fb_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 620:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.fb_var}! %% 9) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 621:
        cmds.append(f"i^f !{state.aux_var}! G^TR 7188 ( i^f !{state.last_rs_var}! L^SS 8575 ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 622:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 623:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 624:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.ms_var}! + !{state.rs_var}! + {data_val}\", \"{state.ms_var}^=!{state.rs_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 625:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.aux_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 626:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.rs_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 627:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.cnt_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 628:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 629:
        cmds.append(f"i^f !{state.aux_var}! G^TR 3092 ( i^f !{state.ms_var}! L^SS 8247 ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 630:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.aux_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 631:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! * 10) + (!{state.aux_var}! / 4)\" & i^f !{state.cnt_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 632:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ !{state.rs_var}!\", \"{state.ms_var}+=!{state.ds_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 633:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 5417 ( i^f !{state.fb_var}! L^SS 8775 ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 634:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 5934 ( i^f !{state.rs_var}! L^SS 5725 ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 635:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.fb_var}! * 9) + (!{state.cnt_var}! / 9)\" & i^f !{state.last_rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 636:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ !{state.last_rs_var}!\", \"{state.ds_var}+=!{state.cnt_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 637:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.rs_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 638:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.ms_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 639:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.aux_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 640:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 2891 ( i^f !{state.aux_var}! L^SS 7479 ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 641:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.cnt_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 642:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.ds_var}! + !{state.rs_var}! + {data_val}\", \"{state.ds_var}^=!{state.last_rs_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 643:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.aux_var}! + !{state.rs_var}! + {data_val}\", \"{state.aux_var}^=!{state.ms_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 644:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.aux_var}! + !{state.cnt_var}! + {data_val}\", \"{state.aux_var}^=!{state.ms_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 645:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ !{state.ms_var}!\", \"{state.aux_var}+=!{state.fb_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 646:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ !{state.ds_var}!\", \"{state.aux_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 647:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ms_var}! + !{state.aux_var}! + {data_val}\", \"{state.ms_var}^=!{state.aux_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 648:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.last_rs_var}! * 3) + (!{state.cnt_var}! / 8)\" & i^f !{state.ms_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 649:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.cnt_var}! + !{state.fb_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ds_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 650:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! * 7) + (!{state.rs_var}! / 6)\" & i^f !{state.cnt_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 651:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.rs_var}! * 9) + (!{state.aux_var}! / 2)\" & i^f !{state.last_rs_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 652:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 9) + (!{state.ds_var}! / 8)\" & i^f !{state.last_rs_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 653:
        cmds.append(f"i^f !{state.aux_var}! G^TR 4503 ( i^f !{state.last_rs_var}! L^SS 5496 ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 654:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.cnt_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 655:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.aux_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 656:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.rs_var}^=!{state.ds_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 657:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.fb_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 658:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.fb_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 659:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.aux_var}! * 2) + (!{state.fb_var}! / 6)\" & i^f !{state.rs_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 660:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.cnt_var}^=!{state.ds_var}! + !{state.fb_var}! + {data_val}\", \"{state.ds_var}^=!{state.cnt_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 661:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 662:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ !{state.fb_var}!\", \"{state.cnt_var}+=!{state.ds_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 663:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.last_rs_var}! * 8) + (!{state.rs_var}! / 8)\" & i^f !{state.ms_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 664:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! * 2) + (!{state.last_rs_var}! / 2)\" & i^f !{state.fb_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 665:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ !{state.last_rs_var}!\", \"{state.rs_var}+=!{state.cnt_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 666:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 1692 ( i^f !{state.rs_var}! L^SS 8105 ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 667:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.aux_var}! * 2) + (!{state.ds_var}! / 6)\" & i^f !{state.last_rs_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 668:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.rs_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 669:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.fb_var}! + !{state.ds_var}! + {data_val}\", \"{state.fb_var}^=!{state.aux_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 670:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 6294 ( i^f !{state.ms_var}! L^SS 8868 ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 671:
        cmds.append(f"i^f !{state.rs_var}! G^TR 4026 ( i^f !{state.last_rs_var}! L^SS 7311 ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 672:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.fb_var}! * 5) + (!{state.rs_var}! / 8)\" & i^f !{state.ds_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 673:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.rs_var}^=!{state.ms_var}! + !{state.aux_var}! + {data_val}\", \"{state.ms_var}^=!{state.rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 674:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.ms_var}! + !{state.rs_var}! + {data_val}\", \"{state.ms_var}^=!{state.ds_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 675:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.ms_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 676:
        cmds.append(f"i^f !{state.ms_var}! G^TR 3462 ( i^f !{state.cnt_var}! L^SS 4427 ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 677:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! * 8) + (!{state.aux_var}! / 5)\" & i^f !{state.fb_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 678:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.aux_var}! + !{state.ds_var}! + {data_val}\", \"{state.aux_var}^=!{state.last_rs_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 679:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.aux_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 680:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.fb_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 681:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 682:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.fb_var}^=!{state.rs_var}! + !{state.aux_var}! + {data_val}\", \"{state.rs_var}^=!{state.fb_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 683:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.fb_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 684:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! * 4) + (!{state.aux_var}! / 6)\" & i^f !{state.cnt_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 685:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.fb_var}! * 10) + (!{state.rs_var}! / 10)\" & i^f !{state.last_rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 686:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.fb_var}! %% 9) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 687:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 8709 ( i^f !{state.fb_var}! L^SS 1320 ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 688:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ds_var}! * 9) + (!{state.ms_var}! / 6)\" & i^f !{state.rs_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 689:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.cnt_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 690:
        cmds.append(f"i^f !{state.aux_var}! G^TR 1223 ( i^f !{state.cnt_var}! L^SS 5576 ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 691:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ms_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 692:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.aux_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 693:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.rs_var}^=!{state.ds_var}! + !{state.ms_var}! + {data_val}\", \"{state.ds_var}^=!{state.rs_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 694:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.aux_var}+=!{state.rs_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 695:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 696:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.aux_var}! + !{state.aux_var}! + {data_val}\", \"{state.aux_var}^=!{state.ms_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 697:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.fb_var}^=!{state.aux_var}! + !{state.cnt_var}! + {data_val}\", \"{state.aux_var}^=!{state.fb_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 698:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 1872 ( i^f !{state.aux_var}! L^SS 7941 ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 699:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.cnt_var}! + !{state.ms_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ds_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 700:
        cmds.append(f"i^f !{state.fb_var}! G^TR 1398 ( i^f !{state.ms_var}! L^SS 6160 ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 701:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.ds_var}! + !{state.fb_var}! + {data_val}\", \"{state.ds_var}^=!{state.ms_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 702:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 8145 ( i^f !{state.ms_var}! L^SS 5807 ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 703:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 704:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.aux_var}^=!{state.rs_var}! + !{state.ds_var}! + {data_val}\", \"{state.rs_var}^=!{state.aux_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 705:
        cmds.append(f"i^f !{state.rs_var}! G^TR 8037 ( i^f !{state.cnt_var}! L^SS 3686 ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 706:
        cmds.append(f"i^f !{state.ms_var}! G^TR 4060 ( i^f !{state.aux_var}! L^SS 7453 ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 707:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.aux_var}! * 7) + (!{state.ms_var}! / 5)\" & i^f !{state.fb_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 708:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.cnt_var}^=!{state.ms_var}! + !{state.ds_var}! + {data_val}\", \"{state.ms_var}^=!{state.cnt_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 709:
        cmds.append(f"i^f !{state.ms_var}! G^TR 2667 ( i^f !{state.aux_var}! L^SS 6342 ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 710:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.ds_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 711:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.cnt_var}! + !{state.rs_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ms_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 712:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.fb_var}! * 7) + (!{state.ms_var}! / 4)\" & i^f !{state.ds_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 713:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ds_var}! + !{state.rs_var}! + {data_val}\", \"{state.ds_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 714:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ !{state.ds_var}!\", \"{state.ms_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 715:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.ms_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 716:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! %% 9) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 717:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.fb_var}! + !{state.cnt_var}! + {data_val}\", \"{state.fb_var}^=!{state.rs_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 718:
        cmds.append(f"i^f !{state.ms_var}! G^TR 8101 ( i^f !{state.ds_var}! L^SS 8783 ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 719:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.aux_var}! + !{state.fb_var}! + {data_val}\", \"{state.aux_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 720:
        cmds.append(f"i^f !{state.ms_var}! G^TR 4434 ( i^f !{state.last_rs_var}! L^SS 1525 ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 721:
        cmds.append(f"i^f !{state.ms_var}! G^TR 8406 ( i^f !{state.fb_var}! L^SS 5181 ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 722:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! * 9) + (!{state.last_rs_var}! / 4)\" & i^f !{state.aux_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 723:
        cmds.append(f"i^f !{state.rs_var}! G^TR 2778 ( i^f !{state.aux_var}! L^SS 8626 ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 724:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.cnt_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 725:
        cmds.append(f"i^f !{state.ms_var}! G^TR 1033 ( i^f !{state.cnt_var}! L^SS 8716 ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 726:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ms_var}! * 5) + (!{state.cnt_var}! / 5)\" & i^f !{state.rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 727:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 728:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 2675 ( i^f !{state.ds_var}! L^SS 8966 ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 729:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.aux_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 730:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ !{state.ds_var}!\", \"{state.aux_var}+=!{state.ms_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 731:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.last_rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.aux_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 732:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ !{state.aux_var}!\", \"{state.cnt_var}+=!{state.ms_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 733:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 734:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.cnt_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.cnt_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 735:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ !{state.rs_var}!\", \"{state.aux_var}+=!{state.fb_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 736:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ !{state.last_rs_var}!\", \"{state.rs_var}+=!{state.ms_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 737:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.rs_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 738:
        cmds.append(f"i^f !{state.ms_var}! G^TR 5741 ( i^f !{state.aux_var}! L^SS 7850 ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 739:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! * 10) + (!{state.ds_var}! / 7)\" & i^f !{state.aux_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 740:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.ms_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.ms_var}^=!{state.ds_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 741:
        cmds.append(f"i^f !{state.fb_var}! G^TR 1224 ( i^f !{state.rs_var}! L^SS 8301 ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 742:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 743:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.aux_var}! + !{state.rs_var}! + {data_val}\", \"{state.aux_var}^=!{state.last_rs_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 744:
        cmds.append(f"i^f !{state.aux_var}! G^TR 2937 ( i^f !{state.ds_var}! L^SS 6828 ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 745:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.rs_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 746:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.aux_var}^=!{state.ds_var}! + !{state.aux_var}! + {data_val}\", \"{state.ds_var}^=!{state.aux_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 747:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! * 9) + (!{state.ds_var}! / 5)\" & i^f !{state.fb_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 748:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.aux_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 749:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 3763 ( i^f !{state.last_rs_var}! L^SS 2432 ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 750:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ !{state.ds_var}!\", \"{state.aux_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 751:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.cnt_var}! * 8) + (!{state.fb_var}! / 9)\" & i^f !{state.ms_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 752:
        cmds.append(f"i^f !{state.ms_var}! G^TR 7099 ( i^f !{state.cnt_var}! L^SS 8486 ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 753:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.rs_var}! * 3) + (!{state.aux_var}! / 3)\" & i^f !{state.ms_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 754:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.rs_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 755:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ !{state.rs_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 756:
        cmds.append(f"i^f !{state.ms_var}! G^TR 6709 ( i^f !{state.rs_var}! L^SS 2810 ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 757:
        cmds.append(f"i^f !{state.rs_var}! G^TR 7637 ( i^f !{state.aux_var}! L^SS 1533 ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 758:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.ds_var}! * 3) + (!{state.last_rs_var}! / 10)\" & i^f !{state.ms_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 759:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 760:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.fb_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 761:
        cmds.append(f"i^f !{state.aux_var}! G^TR 8059 ( i^f !{state.cnt_var}! L^SS 5505 ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 762:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 5) + (!{state.rs_var}! / 9)\" & i^f !{state.last_rs_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 763:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 4639 ( i^f !{state.ms_var}! L^SS 8055 ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 764:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! * 8) + (!{state.rs_var}! / 8)\" & i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 765:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 766:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ !{state.cnt_var}!\", \"{state.aux_var}+=!{state.fb_var}! ^ !{state.cnt_var}!\", \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 767:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.last_rs_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 768:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.aux_var}^=!{state.cnt_var}! + !{state.cnt_var}! + {data_val}\", \"{state.cnt_var}^=!{state.aux_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 769:
        cmds.append(f"i^f !{state.ms_var}! G^TR 2239 ( i^f !{state.fb_var}! L^SS 8116 ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 770:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.aux_var}! * 9) + (!{state.fb_var}! / 9)\" & i^f !{state.rs_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 771:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 772:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.fb_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 773:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.cnt_var}! + !{state.fb_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ds_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 774:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.fb_var}! + !{state.ds_var}! + {data_val}\", \"{state.fb_var}^=!{state.ms_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 775:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 776:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.rs_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 777:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ms_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 778:
        cmds.append(f"i^f !{state.ds_var}! G^TR 3941 ( i^f !{state.fb_var}! L^SS 3674 ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 779:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 780:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ds_var}! * 7) + (!{state.cnt_var}! / 9)\" & i^f !{state.aux_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 781:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.aux_var}! * 8) + (!{state.ds_var}! / 3)\" & i^f !{state.fb_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 782:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.cnt_var}! + !{state.ds_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ds_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 783:
        cmds.append(f"i^f !{state.aux_var}! G^TR 6357 ( i^f !{state.ms_var}! L^SS 2066 ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 784:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 785:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.last_rs_var}! * 7) + (!{state.aux_var}! / 10)\" & i^f !{state.ms_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 786:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.rs_var}! * 5) + (!{state.ds_var}! / 9)\" & i^f !{state.ms_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 787:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 4491 ( i^f !{state.ds_var}! L^SS 7788 ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 788:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.fb_var}^=!{state.ms_var}! + !{state.fb_var}! + {data_val}\", \"{state.ms_var}^=!{state.fb_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 789:
        cmds.append(f"i^f !{state.ds_var}! G^TR 7788 ( i^f !{state.ms_var}! L^SS 7942 ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 790:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 1651 ( i^f !{state.rs_var}! L^SS 8380 ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 791:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.aux_var}! * 10) + (!{state.fb_var}! / 2)\" & i^f !{state.rs_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 792:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.rs_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 793:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.aux_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 794:
        cmds.append(f"i^f !{state.ms_var}! G^TR 3302 ( i^f !{state.ds_var}! L^SS 5234 ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 795:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.fb_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 796:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 1896 ( i^f !{state.cnt_var}! L^SS 4724 ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 797:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 798:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.aux_var}! * 2) + (!{state.cnt_var}! / 3)\" & i^f !{state.ms_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 799:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.cnt_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 800:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.aux_var}! * 2) + (!{state.rs_var}! / 5)\" & i^f !{state.last_rs_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 801:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.cnt_var}^=!{state.fb_var}! + !{state.rs_var}! + {data_val}\", \"{state.fb_var}^=!{state.cnt_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 802:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 2025 ( i^f !{state.ms_var}! L^SS 7917 ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 803:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.last_rs_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 804:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 3139 ( i^f !{state.rs_var}! L^SS 6860 ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 805:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.ms_var}! + !{state.ms_var}! + {data_val}\", \"{state.ms_var}^=!{state.ds_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 806:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.rs_var}! + !{state.rs_var}! + {data_val}\", \"{state.rs_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 807:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.rs_var}^=!{state.fb_var}! + !{state.fb_var}! + {data_val}\", \"{state.fb_var}^=!{state.rs_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 808:
        cmds.append(f"i^f !{state.fb_var}! G^TR 5937 ( i^f !{state.ms_var}! L^SS 8999 ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 809:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.cnt_var}! + !{state.ds_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ms_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 810:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 811:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.last_rs_var}! + !{state.ms_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.aux_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 812:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ !{state.rs_var}!\", \"{state.aux_var}+=!{state.last_rs_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 813:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.fb_var}! * 2) + (!{state.ds_var}! / 9)\" & i^f !{state.aux_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 814:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.aux_var}! + !{state.rs_var}! + {data_val}\", \"{state.aux_var}^=!{state.last_rs_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 815:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.ds_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 816:
        cmds.append(f"i^f !{state.fb_var}! G^TR 3772 ( i^f !{state.last_rs_var}! L^SS 6236 ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 817:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.aux_var}^=!{state.fb_var}! + !{state.rs_var}! + {data_val}\", \"{state.fb_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 818:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 819:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ !{state.aux_var}!\", \"{state.fb_var}+=!{state.cnt_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 820:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.cnt_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 821:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 822:
        cmds.append(f"i^f !{state.fb_var}! G^TR 2811 ( i^f !{state.cnt_var}! L^SS 4369 ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 823:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.fb_var}! * 7) + (!{state.aux_var}! / 4)\" & i^f !{state.rs_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 824:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.cnt_var}! * 9) + (!{state.rs_var}! / 2)\" & i^f !{state.fb_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 825:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 5) + (!{state.rs_var}! / 6)\" & i^f !{state.last_rs_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 826:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ !{state.last_rs_var}!\", \"{state.ms_var}+=!{state.rs_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 827:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.cnt_var}! + !{state.fb_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ms_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 828:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.cnt_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 829:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.last_rs_var}! * 4) + (!{state.aux_var}! / 9)\" & i^f !{state.ms_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 830:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.aux_var}! + !{state.cnt_var}! + {data_val}\", \"{state.aux_var}^=!{state.last_rs_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 831:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.aux_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 832:
        cmds.append(f"i^f !{state.aux_var}! G^TR 8931 ( i^f !{state.cnt_var}! L^SS 3827 ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 833:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.ds_var}! * 8) + (!{state.last_rs_var}! / 8)\" & i^f !{state.ms_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 834:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.last_rs_var}! * 6) + (!{state.rs_var}! / 8)\" & i^f !{state.aux_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 835:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ !{state.fb_var}!\", \"{state.rs_var}+=!{state.cnt_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 836:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 6) + (!{state.ds_var}! / 6)\" & i^f !{state.last_rs_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 837:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 838:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.cnt_var}! * 8) + (!{state.ms_var}! / 7)\" & i^f !{state.aux_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 839:
        cmds.append(f"i^f !{state.fb_var}! G^TR 2499 ( i^f !{state.ms_var}! L^SS 3820 ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 840:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 841:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.fb_var}! * 4) + (!{state.cnt_var}! / 8)\" & i^f !{state.ds_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 842:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.aux_var}^=!{state.cnt_var}! + !{state.ds_var}! + {data_val}\", \"{state.cnt_var}^=!{state.aux_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 843:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.fb_var}! ^ !{state.cnt_var}!\", \"{state.cnt_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 844:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.rs_var}! + !{state.cnt_var}! + {data_val}\", \"{state.rs_var}^=!{state.aux_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 845:
        cmds.append(f"i^f !{state.fb_var}! G^TR 6806 ( i^f !{state.rs_var}! L^SS 6155 ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 846:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! * 4) + (!{state.ms_var}! / 2)\" & i^f !{state.fb_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 847:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.fb_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 848:
        cmds.append(f"i^f !{state.ms_var}! G^TR 6586 ( i^f !{state.last_rs_var}! L^SS 6128 ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 849:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.fb_var}^=!{state.cnt_var}! + !{state.ms_var}! + {data_val}\", \"{state.cnt_var}^=!{state.fb_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 850:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.fb_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 851:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 852:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ !{state.last_rs_var}!\", \"{state.rs_var}+=!{state.fb_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 853:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ !{state.cnt_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ !{state.cnt_var}!\", \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 854:
        cmds.append(f"i^f !{state.rs_var}! G^TR 6905 ( i^f !{state.fb_var}! L^SS 8900 ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 855:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! * 8) + (!{state.rs_var}! / 9)\" & i^f !{state.cnt_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 856:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ds_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 857:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.cnt_var}! + !{state.ds_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ms_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 858:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.aux_var}^=!{state.rs_var}! + !{state.ds_var}! + {data_val}\", \"{state.rs_var}^=!{state.aux_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 859:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.rs_var}! + !{state.cnt_var}! + {data_val}\", \"{state.rs_var}^=!{state.ms_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 860:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.fb_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 861:
        cmds.append(f"i^f !{state.rs_var}! G^TR 3281 ( i^f !{state.aux_var}! L^SS 3764 ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 862:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.cnt_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 863:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.rs_var}! * 9) + (!{state.ds_var}! / 3)\" & i^f !{state.fb_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 864:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.rs_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 865:
        cmds.append(f"i^f !{state.ms_var}! G^TR 2073 ( i^f !{state.ds_var}! L^SS 4923 ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 866:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.last_rs_var}^=!{state.ms_var}! + !{state.aux_var}! + {data_val}\", \"{state.ms_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 867:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ !{state.aux_var}!\", \"{state.ds_var}+=!{state.rs_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 868:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 869:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 870:
        cmds.append(f"i^f !{state.aux_var}! G^TR 4076 ( i^f !{state.fb_var}! L^SS 5217 ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 871:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.rs_var}^=!{state.aux_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 872:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.rs_var}^=!{state.ds_var}! + !{state.ds_var}! + {data_val}\", \"{state.ds_var}^=!{state.rs_var}! + !{state.ds_var}! + {idx_val}\" ) )\n")
    if choice == 873:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.last_rs_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 874:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ !{state.ms_var}!\", \"{state.cnt_var}+=!{state.fb_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 875:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.rs_var}^=!{state.last_rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.rs_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 876:
        cmds.append(f"i^f !{state.ms_var}! G^TR 2436 ( i^f !{state.ds_var}! L^SS 7733 ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 877:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.rs_var}^=!{state.ms_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 878:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.aux_var}! * 3) + (!{state.fb_var}! / 4)\" & i^f !{state.ds_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {idx_val}\" )\n")
    if choice == 879:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.cnt_var}^=!{state.ms_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 880:
        cmds.append(f"i^f !{state.fb_var}! G^TR 1999 ( i^f !{state.ms_var}! L^SS 7638 ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 881:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.fb_var}! * 5) + (!{state.ds_var}! / 10)\" & i^f !{state.ms_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 882:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ms_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ms_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 883:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ !{state.last_rs_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 884:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.rs_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.fb_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 885:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.fb_var}^=!{state.aux_var}! + !{state.aux_var}! + {data_val}\", \"{state.aux_var}^=!{state.fb_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 886:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! * 8) + (!{state.ds_var}! / 5)\" & i^f !{state.cnt_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 887:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.fb_var}^=!{state.ds_var}! + !{state.ms_var}! + {data_val}\", \"{state.ds_var}^=!{state.fb_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 888:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ !{state.rs_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 889:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 890:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 891:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.cnt_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.cnt_var}! + {idx_val}\" ) )\n")
    if choice == 892:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.fb_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 893:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 8919 ( i^f !{state.cnt_var}! L^SS 1286 ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 894:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.rs_var}! ^ !{state.aux_var}!\", \"{state.rs_var}+=!{state.fb_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 895:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ms_var}! * 6) + (!{state.last_rs_var}! / 3)\" & i^f !{state.fb_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 896:
        cmds.append(f"i^f !{state.ds_var}! G^TR 5107 ( i^f !{state.cnt_var}! L^SS 5133 ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 897:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.ds_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 898:
        cmds.append(f"i^f !{state.ds_var}! G^TR 2625 ( i^f !{state.fb_var}! L^SS 1681 ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 899:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.fb_var}! ^ !{state.aux_var}!\", \"{state.fb_var}+=!{state.cnt_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 900:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.fb_var}! * 10) + (!{state.ds_var}! / 4)\" & i^f !{state.ms_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 901:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.last_rs_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 902:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" )\n")
    if choice == 903:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.cnt_var}^=!{state.last_rs_var}! + !{state.ms_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.cnt_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 904:
        cmds.append(f"i^f !{state.ms_var}! G^TR 4312 ( i^f !{state.aux_var}! L^SS 2374 ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 905:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.rs_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 906:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.rs_var}! * 3) + (!{state.last_rs_var}! / 4)\" & i^f !{state.cnt_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 907:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ !{state.fb_var}!\", \"{state.ds_var}+=!{state.rs_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 908:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ds_var}^=!{state.aux_var}! + !{state.aux_var}! + {data_val}\", \"{state.aux_var}^=!{state.ds_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 909:
        cmds.append(f"i^f !{state.ds_var}! G^TR 4389 ( i^f !{state.fb_var}! L^SS 1378 ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 910:
        cmds.append(f"i^f !{state.fb_var}! G^TR 3062 ( i^f !{state.cnt_var}! L^SS 4834 ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 911:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.rs_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 912:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 913:
        cmds.append(f"i^f !{state.ms_var}! G^TR 1178 ( i^f !{state.ds_var}! L^SS 6075 ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 914:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 915:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.cnt_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 916:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ds_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 917:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 6588 ( i^f !{state.aux_var}! L^SS 7971 ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 918:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ !{state.aux_var}!\", \"{state.rs_var}+=!{state.ds_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 919:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.cnt_var}! * 3) + (!{state.ms_var}! / 2)\" & i^f !{state.aux_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 920:
        cmds.append(f"i^f !{state.fb_var}! G^TR 4052 ( i^f !{state.last_rs_var}! L^SS 2005 ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 921:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.fb_var}! + !{state.rs_var}! + {data_val}\", \"{state.fb_var}^=!{state.aux_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 922:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.rs_var}! * 7) + (!{state.aux_var}! / 4)\" & i^f !{state.ms_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 923:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.cnt_var}^=!{state.aux_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.aux_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 924:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ !{state.rs_var}!\", \"{state.cnt_var}+=!{state.ds_var}! ^ !{state.rs_var}!\", \"{state.rs_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 925:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.rs_var}^=!{state.ds_var}! + !{state.rs_var}! + {data_val}\", \"{state.ds_var}^=!{state.rs_var}! + !{state.rs_var}! + {idx_val}\" ) )\n")
    if choice == 926:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! * 9) + (!{state.fb_var}! / 5)\" & i^f !{state.cnt_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 927:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 4304 ( i^f !{state.rs_var}! L^SS 4282 ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 928:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! * 7) + (!{state.rs_var}! / 7)\" & i^f !{state.cnt_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 929:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 930:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 8552 ( i^f !{state.cnt_var}! L^SS 4154 ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 931:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 8888 ( i^f !{state.last_rs_var}! L^SS 2159 ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 932:
        cmds.append(f"i^f !{state.fb_var}! G^TR 5678 ( i^f !{state.cnt_var}! L^SS 3279 ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 933:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.fb_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 934:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ !{state.fb_var}!\", \"{state.ms_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 935:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.aux_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 936:
        cmds.append(f"i^f !{state.aux_var}! G^TR 7844 ( i^f !{state.rs_var}! L^SS 6593 ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 937:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 2945 ( i^f !{state.ms_var}! L^SS 5350 ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 938:
        cmds.append(f"i^f !{state.aux_var}! G^TR 6290 ( i^f !{state.rs_var}! L^SS 6048 ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 939:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 940:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ !{state.fb_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 941:
        cmds.append(f"i^f !{state.rs_var}! G^TR 8695 ( i^f !{state.last_rs_var}! L^SS 1747 ( s^et /a \"{state.aux_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.last_rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 942:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.last_rs_var}^=!{state.cnt_var}! + !{state.aux_var}! + {data_val}\", \"{state.cnt_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 943:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.ms_var}^=!{state.fb_var}! + !{state.fb_var}! + {data_val}\", \"{state.fb_var}^=!{state.ms_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 944:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.fb_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.ds_var}+={data_val}\"\n")
    if choice == 945:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.last_rs_var}+=!{state.fb_var}! ^ !{state.ds_var}!\", \"{state.fb_var}+=!{state.last_rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" )\n")
    if choice == 946:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.rs_var}! * 2) + (!{state.cnt_var}! / 8)\" & i^f !{state.last_rs_var}! G^TR !{state.ds_var}! ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 947:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ !{state.fb_var}!\", \"{state.cnt_var}+=!{state.aux_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 948:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.rs_var}! * 9) + (!{state.ms_var}! / 9)\" & i^f !{state.aux_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 949:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.aux_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.last_rs_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 950:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ !{state.last_rs_var}!\", \"{state.aux_var}+=!{state.cnt_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.cnt_var}! ^ {data_val}\" )\n")
    if choice == 951:
        cmds.append(f"f^or /L %%a in (1,1,2) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.cnt_var}^=!{state.last_rs_var}! + !{state.last_rs_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.cnt_var}! + !{state.last_rs_var}! + {idx_val}\" ) )\n")
    if choice == 952:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.aux_var}! %% 7) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 953:
        cmds.append(f"s^et /a \"{state.fb_var}=(!{state.ds_var}! * 4) + (!{state.aux_var}! / 5)\" & i^f !{state.fb_var}! G^TR !{state.ms_var}! ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ {idx_val}\" )\n")
    if choice == 954:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.cnt_var}! * 3) + (!{state.aux_var}! / 3)\" & i^f !{state.ms_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 955:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.aux_var}!\", \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.aux_var}!\", \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 956:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.cnt_var}! %% 10) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 957:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.rs_var}! %% 9) + 1\" & f^or /L %%x in (1,1,!{state.aux_var}!) do s^et /a \"{state.cnt_var}+={data_val}\"\n")
    if choice == 958:
        cmds.append(f"i^f !{state.ms_var}! G^TR 3071 ( i^f !{state.rs_var}! L^SS 5141 ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 959:
        cmds.append(f"i^f !{state.rs_var}! G^TR 1306 ( i^f !{state.cnt_var}! L^SS 6305 ( s^et /a \"{state.ms_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 960:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.fb_var}+=!{state.ds_var}! ^ !{state.last_rs_var}!\", \"{state.ds_var}+=!{state.fb_var}! ^ !{state.last_rs_var}!\", \"{state.last_rs_var}+=!{state.fb_var}! ^ {data_val}\" )\n")
    if choice == 961:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! * 10) + (!{state.fb_var}! / 3)\" & i^f !{state.cnt_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 962:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,3) do ( s^et /a \"{state.rs_var}^=!{state.aux_var}! + !{state.ms_var}! + {data_val}\", \"{state.aux_var}^=!{state.rs_var}! + !{state.ms_var}! + {idx_val}\" ) )\n")
    if choice == 963:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ms_var}! * 10) + (!{state.ds_var}! / 8)\" & i^f !{state.last_rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ms_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 964:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.aux_var}! * 5) + (!{state.ds_var}! / 6)\" & i^f !{state.ms_var}! G^TR !{state.cnt_var}! ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.ms_var}! ^ {idx_val}\" )\n")
    if choice == 965:
        cmds.append(f"i^f !{state.rs_var}! G^TR 3544 ( i^f !{state.ds_var}! L^SS 6959 ( s^et /a \"{state.last_rs_var}+=!{state.ms_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ms_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 966:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.rs_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 967:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! %% 9) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 968:
        cmds.append(f"i^f !{state.last_rs_var}! G^TR 4014 ( i^f !{state.ds_var}! L^SS 8540 ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.last_rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.ds_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 969:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.aux_var}! * 8) + (!{state.ds_var}! / 3)\" & i^f !{state.rs_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ {idx_val}\" )\n")
    if choice == 970:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ds_var}! * 8) + (!{state.last_rs_var}! / 4)\" & i^f !{state.cnt_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 971:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 1078 ( i^f !{state.rs_var}! L^SS 5643 ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 972:
        cmds.append(f"s^et /a \"{state.aux_var}=(!{state.last_rs_var}! * 7) + (!{state.ds_var}! / 5)\" & i^f !{state.aux_var}! G^TR !{state.fb_var}! ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.aux_var}! ^ {idx_val}\" )\n")
    if choice == 973:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.aux_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.rs_var}+=!{state.aux_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.aux_var}! ^ {data_val}\" )\n")
    if choice == 974:
        cmds.append(f"i^f !{state.fb_var}! G^TR 7527 ( i^f !{state.ms_var}! L^SS 1623 ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.ms_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 975:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.rs_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 976:
        cmds.append(f"i^f !{state.ms_var}! G^TR 4585 ( i^f !{state.aux_var}! L^SS 2915 ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.rs_var}+=!{state.ms_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 977:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.ms_var}!\", \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 978:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ !{state.ds_var}!\", \"{state.cnt_var}+=!{state.rs_var}! ^ !{state.ds_var}!\", \"{state.ds_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 979:
        cmds.append(f"i^f !{state.cnt_var}! G^TR 3486 ( i^f !{state.aux_var}! L^SS 7289 ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.aux_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 980:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ds_var}! + !{state.aux_var}! + {data_val}\", \"{state.ds_var}^=!{state.aux_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 981:
        cmds.append(f"i^f !{state.ds_var}! G^TR 3252 ( i^f !{state.fb_var}! L^SS 1101 ( s^et /a \"{state.cnt_var}+=!{state.rs_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.cnt_var}+=!{state.ds_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.rs_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 982:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.ms_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.aux_var}+={data_val}\"\n")
    if choice == 983:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.ds_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 984:
        cmds.append(f"s^et /a \"{state.last_rs_var}=(!{state.ds_var}! * 4) + (!{state.cnt_var}! / 9)\" & i^f !{state.last_rs_var}! G^TR !{state.aux_var}! ( s^et /a \"{state.ds_var}+=!{state.cnt_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ {idx_val}\" )\n")
    if choice == 985:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! * 6) + (!{state.ds_var}! / 9)\" & i^f !{state.cnt_var}! G^TR !{state.last_rs_var}! ( s^et /a \"{state.aux_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 986:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! * 7) + (!{state.fb_var}! / 6)\" & i^f !{state.cnt_var}! G^TR !{state.rs_var}! ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.cnt_var}! ^ {idx_val}\" )\n")
    if choice == 987:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.aux_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 988:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.aux_var}! %% 5) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 989:
        cmds.append(f"i^f !{state.aux_var}! G^TR 2074 ( i^f !{state.cnt_var}! L^SS 3772 ( s^et /a \"{state.aux_var}+=!{state.fb_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.aux_var}+=!{state.aux_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.fb_var}+=!{state.cnt_var}! ^ ({data_val} + {idx_val}) \" )\n")
    if choice == 990:
        cmds.append(f"s^et /a \"{state.ds_var}=(!{state.last_rs_var}! %% 9) + 1\" & f^or /L %%x in (1,1,!{state.ds_var}!) do s^et /a \"{state.ms_var}+={data_val}\"\n")
    if choice == 991:
        cmds.append(f"s^et /a \"{state.ms_var}=(!{state.ds_var}! %% 8) + 1\" & f^or /L %%x in (1,1,!{state.ms_var}!) do s^et /a \"{state.last_rs_var}+={data_val}\"\n")
    if choice == 992:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.ds_var}^=!{state.last_rs_var}! + !{state.fb_var}! + {data_val}\", \"{state.last_rs_var}^=!{state.ds_var}! + !{state.fb_var}! + {idx_val}\" ) )\n")
    if choice == 993:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.ds_var}! + !{state.aux_var}! + {data_val}\", \"{state.ds_var}^=!{state.aux_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 994:
        cmds.append(f"s^et /a \"{state.cnt_var}=(!{state.aux_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.cnt_var}!) do s^et /a \"{state.rs_var}+={data_val}\"\n")
    if choice == 995:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.rs_var}+=!{state.cnt_var}! ^ !{state.ms_var}!\", \"{state.cnt_var}+=!{state.rs_var}! ^ !{state.ms_var}!\", \"{state.ms_var}+=!{state.rs_var}! ^ {data_val}\" )\n")
    if choice == 996:
        cmds.append(f"f^or /L %%i in (1,1,3) do ( s^et /a \"{state.ds_var}+=!{state.last_rs_var}! ^ !{state.fb_var}!\", \"{state.last_rs_var}+=!{state.ds_var}! ^ !{state.fb_var}!\", \"{state.fb_var}+=!{state.ds_var}! ^ {data_val}\" )\n")
    if choice == 997:
        cmds.append(f"f^or /L %%a in (1,1,3) do ( f^or /L %%b in (1,1,2) do ( s^et /a \"{state.aux_var}^=!{state.cnt_var}! + !{state.aux_var}! + {data_val}\", \"{state.cnt_var}^=!{state.aux_var}! + !{state.aux_var}! + {idx_val}\" ) )\n")
    if choice == 998:
        cmds.append(f"s^et /a \"{state.rs_var}=(!{state.aux_var}! %% 6) + 1\" & f^or /L %%x in (1,1,!{state.rs_var}!) do s^et /a \"{state.fb_var}+={data_val}\"\n")
    if choice == 999:
        cmds.append(f"i^f !{state.rs_var}! G^TR 2836 ( i^f !{state.fb_var}! L^SS 6017 ( s^et /a \"{state.last_rs_var}+=!{state.ds_var}! ^ {data_val}\" ) e^lse ( s^et /a \"{state.last_rs_var}+=!{state.rs_var}! ^ {idx_val}\" ) ) e^lse ( s^et /a \"{state.ds_var}+=!{state.fb_var}! ^ ({data_val} + {idx_val}) \" )\n")
    return cmds, choice

def simulate_advanced_junk(state, data_val, idx_val, choice):
    if choice == 0:
        state.fb_val = to_int32((state.aux_val ^ state.rs_val) + to_int32(state.last_rs_val * 23))
    if choice == 1:
        state.cnt_val = to_int32((state.aux_val ^ state.fb_val) + to_int32(state.last_rs_val * 55))
    if choice == 2:
        state.fb_val = to_int32((state.cnt_val ^ state.rs_val) + to_int32(state.last_rs_val * 29))
    if choice == 3:
        state.last_rs_val = to_int32((state.cnt_val ^ state.rs_val) + to_int32(state.aux_val * 98))
    if choice == 4:
        state.last_rs_val = to_int32((state.cnt_val ^ state.fb_val) + to_int32(state.rs_val * 86))
    if choice == 5:
        state.aux_val = to_int32((state.fb_val ^ state.rs_val) + to_int32(state.last_rs_val * 96))
    if choice == 6:
        state.rs_val = to_int32((state.cnt_val ^ state.fb_val) + to_int32(state.aux_val * 23))
    if choice == 7:
        state.last_rs_val = to_int32((state.cnt_val ^ state.fb_val) + to_int32(state.rs_val * 1))
    if choice == 8:
        state.cnt_val = to_int32((state.rs_val ^ state.fb_val) + to_int32(state.aux_val * 80))
    if choice == 9:
        state.fb_val = to_int32((state.rs_val ^ state.last_rs_val) + to_int32(state.aux_val * 21))
    if choice == 10:
        state.last_rs_val = to_int32((state.aux_val ^ state.fb_val) + to_int32(state.rs_val * 88))
    if choice == 11:
        state.cnt_val = to_int32((state.aux_val ^ state.last_rs_val) + to_int32(state.rs_val * 17))
    if choice == 12:
        state.cnt_val = to_int32((state.rs_val ^ state.fb_val) + to_int32(state.aux_val * 11))
    if choice == 13:
        state.last_rs_val = to_int32((state.rs_val ^ state.fb_val) + to_int32(state.cnt_val * 39))
    if choice == 14:
        state.rs_val = to_int32((state.fb_val ^ state.cnt_val) + to_int32(state.last_rs_val * 16))
    if choice == 15:
        state.aux_val = to_int32((state.cnt_val ^ state.last_rs_val) + to_int32(state.rs_val * 67))
    if choice == 16:
        state.last_rs_val = to_int32((state.cnt_val ^ state.rs_val) + to_int32(state.fb_val * 61))
    if choice == 17:
        state.last_rs_val = to_int32((state.fb_val ^ state.aux_val) + to_int32(state.cnt_val * 9))
    if choice == 18:
        state.rs_val = to_int32((state.last_rs_val ^ state.cnt_val) + to_int32(state.aux_val * 8))
    if choice == 19:
        state.fb_val = to_int32((state.rs_val ^ state.aux_val) + to_int32(state.last_rs_val * 51))
    if choice == 20:
        state.fb_val = to_int32((state.rs_val ^ state.aux_val) + to_int32(state.last_rs_val * 98))
    if choice == 21:
        state.rs_val = to_int32((state.aux_val ^ state.fb_val) + to_int32(state.cnt_val * 57))
    if choice == 22:
        state.cnt_val = to_int32((state.aux_val ^ state.last_rs_val) + to_int32(state.fb_val * 91))
    if choice == 23:
        state.aux_val = to_int32((state.last_rs_val ^ state.rs_val) + to_int32(state.cnt_val * 2))
    if choice == 24:
        state.last_rs_val = to_int32((state.aux_val ^ state.rs_val) + to_int32(state.fb_val * 55))
    if choice == 25:
        state.cnt_val = to_int32((state.aux_val ^ state.rs_val) + to_int32(state.last_rs_val * 1))
    if choice == 26:
        state.fb_val = to_int32((state.last_rs_val ^ state.cnt_val) + to_int32(state.rs_val * 44))
    if choice == 27:
        state.cnt_val = to_int32((state.aux_val ^ state.rs_val) + to_int32(state.last_rs_val * 64))
    if choice == 28:
        state.fb_val = to_int32((state.cnt_val ^ state.aux_val) + to_int32(state.rs_val * 25))
    if choice == 29:
        state.fb_val = to_int32((state.aux_val ^ state.last_rs_val) + to_int32(state.rs_val * 11))
    if choice == 30:
        if state.aux_val > 1246: state.fb_val = to_int32(state.fb_val + 45)
        else: state.fb_val = to_int32(state.fb_val - 7)
    if choice == 31:
        if state.rs_val > 1546: state.aux_val = to_int32(state.aux_val + 18)
        else: state.aux_val = to_int32(state.aux_val - 24)
    if choice == 32:
        if state.cnt_val > 4964: state.last_rs_val = to_int32(state.last_rs_val + 7)
        else: state.last_rs_val = to_int32(state.last_rs_val - 40)
    if choice == 33:
        if state.rs_val > 3755: state.last_rs_val = to_int32(state.last_rs_val + 5)
        else: state.last_rs_val = to_int32(state.last_rs_val - 49)
    if choice == 34:
        if state.fb_val > 2225: state.rs_val = to_int32(state.rs_val + 32)
        else: state.rs_val = to_int32(state.rs_val - 26)
    if choice == 35:
        if state.cnt_val > 3103: state.last_rs_val = to_int32(state.last_rs_val + 42)
        else: state.last_rs_val = to_int32(state.last_rs_val - 44)
    if choice == 36:
        if state.cnt_val > 3063: state.last_rs_val = to_int32(state.last_rs_val + 9)
        else: state.last_rs_val = to_int32(state.last_rs_val - 13)
    if choice == 37:
        if state.last_rs_val > 4190: state.cnt_val = to_int32(state.cnt_val + 17)
        else: state.cnt_val = to_int32(state.cnt_val - 14)
    if choice == 38:
        if state.rs_val > 1970: state.rs_val = to_int32(state.rs_val + 29)
        else: state.rs_val = to_int32(state.rs_val - 6)
    if choice == 39:
        if state.last_rs_val > 1589: state.fb_val = to_int32(state.fb_val + 12)
        else: state.fb_val = to_int32(state.fb_val - 10)
    if choice == 40:
        if state.rs_val > 1127: state.cnt_val = to_int32(state.cnt_val + 4)
        else: state.cnt_val = to_int32(state.cnt_val - 4)
    if choice == 41:
        if state.cnt_val > 2755: state.fb_val = to_int32(state.fb_val + 28)
        else: state.fb_val = to_int32(state.fb_val - 29)
    if choice == 42:
        if state.rs_val > 1009: state.aux_val = to_int32(state.aux_val + 37)
        else: state.aux_val = to_int32(state.aux_val - 42)
    if choice == 43:
        if state.cnt_val > 4701: state.aux_val = to_int32(state.aux_val + 12)
        else: state.aux_val = to_int32(state.aux_val - 17)
    if choice == 44:
        if state.rs_val > 4279: state.aux_val = to_int32(state.aux_val + 11)
        else: state.aux_val = to_int32(state.aux_val - 50)
    if choice == 45:
        if state.fb_val > 708: state.last_rs_val = to_int32(state.last_rs_val + 22)
        else: state.last_rs_val = to_int32(state.last_rs_val - 45)
    if choice == 46:
        if state.rs_val > 2021: state.aux_val = to_int32(state.aux_val + 47)
        else: state.aux_val = to_int32(state.aux_val - 50)
    if choice == 47:
        if state.cnt_val > 1495: state.rs_val = to_int32(state.rs_val + 6)
        else: state.rs_val = to_int32(state.rs_val - 15)
    if choice == 48:
        if state.fb_val > 2994: state.rs_val = to_int32(state.rs_val + 25)
        else: state.rs_val = to_int32(state.rs_val - 18)
    if choice == 49:
        if state.last_rs_val > 3803: state.rs_val = to_int32(state.rs_val + 31)
        else: state.rs_val = to_int32(state.rs_val - 27)
    if choice == 50:
        if state.rs_val > 4497: state.fb_val = to_int32(state.fb_val + 13)
        else: state.fb_val = to_int32(state.fb_val - 1)
    if choice == 51:
        if state.cnt_val > 1391: state.rs_val = to_int32(state.rs_val + 1)
        else: state.rs_val = to_int32(state.rs_val - 5)
    if choice == 52:
        if state.aux_val > 3199: state.last_rs_val = to_int32(state.last_rs_val + 18)
        else: state.last_rs_val = to_int32(state.last_rs_val - 10)
    if choice == 53:
        if state.rs_val > 3416: state.cnt_val = to_int32(state.cnt_val + 34)
        else: state.cnt_val = to_int32(state.cnt_val - 49)
    if choice == 54:
        if state.fb_val > 2744: state.last_rs_val = to_int32(state.last_rs_val + 18)
        else: state.last_rs_val = to_int32(state.last_rs_val - 36)
    if choice == 55:
        if state.last_rs_val > 3583: state.cnt_val = to_int32(state.cnt_val + 15)
        else: state.cnt_val = to_int32(state.cnt_val - 19)
    if choice == 56:
        if state.rs_val > 1687: state.aux_val = to_int32(state.aux_val + 39)
        else: state.aux_val = to_int32(state.aux_val - 12)
    if choice == 57:
        if state.rs_val > 2570: state.last_rs_val = to_int32(state.last_rs_val + 29)
        else: state.last_rs_val = to_int32(state.last_rs_val - 22)
    if choice == 58:
        if state.cnt_val > 3582: state.cnt_val = to_int32(state.cnt_val + 12)
        else: state.cnt_val = to_int32(state.cnt_val - 43)
    if choice == 59:
        if state.cnt_val > 3844: state.fb_val = to_int32(state.fb_val + 15)
        else: state.fb_val = to_int32(state.fb_val - 39)
    if choice == 60:
        for _ in range(3): state.aux_val = to_int32(state.aux_val + state.fb_val + 4)
    if choice == 61:
        for _ in range(4): state.cnt_val = to_int32(state.cnt_val + state.fb_val + 3)
    if choice == 62:
        for _ in range(2): state.aux_val = to_int32(state.aux_val + state.rs_val + 1)
    if choice == 63:
        for _ in range(3): state.aux_val = to_int32(state.aux_val + state.last_rs_val + 5)
    if choice == 64:
        for _ in range(2): state.aux_val = to_int32(state.aux_val + state.last_rs_val + 9)
    if choice == 65:
        for _ in range(4): state.last_rs_val = to_int32(state.last_rs_val + state.rs_val + 4)
    if choice == 66:
        for _ in range(2): state.last_rs_val = to_int32(state.last_rs_val + state.cnt_val + 2)
    if choice == 67:
        for _ in range(2): state.fb_val = to_int32(state.fb_val + state.rs_val + 9)
    if choice == 68:
        for _ in range(4): state.aux_val = to_int32(state.aux_val + state.last_rs_val + 2)
    if choice == 69:
        for _ in range(4): state.rs_val = to_int32(state.rs_val + state.fb_val + 6)
    if choice == 70:
        for _ in range(2): state.rs_val = to_int32(state.rs_val + state.last_rs_val + 1)
    if choice == 71:
        for _ in range(3): state.fb_val = to_int32(state.fb_val + state.cnt_val + 3)
    if choice == 72:
        for _ in range(3): state.last_rs_val = to_int32(state.last_rs_val + state.aux_val + 8)
    if choice == 73:
        for _ in range(2): state.rs_val = to_int32(state.rs_val + state.last_rs_val + 4)
    if choice == 74:
        for _ in range(3): state.last_rs_val = to_int32(state.last_rs_val + state.rs_val + 2)
    if choice == 75:
        for _ in range(2): state.fb_val = to_int32(state.fb_val + state.cnt_val + 1)
    if choice == 76:
        for _ in range(2): state.rs_val = to_int32(state.rs_val + state.cnt_val + 2)
    if choice == 77:
        for _ in range(3): state.fb_val = to_int32(state.fb_val + state.cnt_val + 6)
    if choice == 78:
        for _ in range(3): state.rs_val = to_int32(state.rs_val + state.fb_val + 1)
    if choice == 79:
        for _ in range(2): state.rs_val = to_int32(state.rs_val + state.last_rs_val + 3)
    if choice == 80:
        for _ in range(3): state.last_rs_val = to_int32(state.last_rs_val + state.aux_val + 9)
    if choice == 81:
        for _ in range(3): state.fb_val = to_int32(state.fb_val + state.cnt_val + 7)
    if choice == 82:
        for _ in range(2): state.fb_val = to_int32(state.fb_val + state.aux_val + 2)
    if choice == 83:
        for _ in range(2): state.rs_val = to_int32(state.rs_val + state.aux_val + 10)
    if choice == 84:
        for _ in range(4): state.cnt_val = to_int32(state.cnt_val + state.rs_val + 4)
    if choice == 85:
        for _ in range(4): state.rs_val = to_int32(state.rs_val + state.cnt_val + 7)
    if choice == 86:
        for _ in range(2): state.last_rs_val = to_int32(state.last_rs_val + state.fb_val + 1)
    if choice == 87:
        for _ in range(3): state.aux_val = to_int32(state.aux_val + state.rs_val + 5)
    if choice == 88:
        for _ in range(3): state.aux_val = to_int32(state.aux_val + state.rs_val + 2)
    if choice == 89:
        for _ in range(2): state.cnt_val = to_int32(state.cnt_val + state.last_rs_val + 2)
    if choice == 90:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 27)
    if choice == 91:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 65)
    if choice == 92:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 36)
    if choice == 93:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 59)
    if choice == 94:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 12)
    if choice == 95:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 72)
    if choice == 96:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 86)
    if choice == 97:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 96)
    if choice == 98:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 46)
    if choice == 99:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 96)
    if choice == 100:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 89)
    if choice == 101:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 59)
    if choice == 102:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 20)
    if choice == 103:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 27)
    if choice == 104:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 83)
    if choice == 105:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 89)
    if choice == 106:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 39)
    if choice == 107:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 49)
    if choice == 108:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 97)
    if choice == 109:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 71)
    if choice == 110:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 30)
    if choice == 111:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 29)
    if choice == 112:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 36)
    if choice == 113:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 70)
    if choice == 114:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 63)
    if choice == 115:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 58)
    if choice == 116:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 79)
    if choice == 117:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 39)
    if choice == 118:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 29)
    if choice == 119:
        state.last_rs_val = state.rs_val
        state.rs_val = to_int32(state.aux_val ^ state.fb_val)
        state.aux_val = to_int32(state.cnt_val + 42)
    if choice == 120:
        state.rs_val = to_int32((to_int32(state.fb_val + data_val) ^ to_int32(state.last_rs_val - idx_val)) + 35)
    if choice == 121:
        state.fb_val = to_int32((to_int32(state.cnt_val + data_val) ^ to_int32(state.last_rs_val - idx_val)) + 21)
    if choice == 122:
        state.last_rs_val = to_int32((to_int32(state.cnt_val + data_val) ^ to_int32(state.rs_val - idx_val)) + 19)
    if choice == 123:
        state.fb_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.cnt_val - idx_val)) + 49)
    if choice == 124:
        state.cnt_val = to_int32((to_int32(state.fb_val + data_val) ^ to_int32(state.rs_val - idx_val)) + 49)
    if choice == 125:
        state.fb_val = to_int32((to_int32(state.rs_val + data_val) ^ to_int32(state.cnt_val - idx_val)) + 36)
    if choice == 126:
        state.fb_val = to_int32((to_int32(state.aux_val + data_val) ^ to_int32(state.cnt_val - idx_val)) + 2)
    if choice == 127:
        state.fb_val = to_int32((to_int32(state.rs_val + data_val) ^ to_int32(state.cnt_val - idx_val)) + 10)
    if choice == 128:
        state.cnt_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.aux_val - idx_val)) + 50)
    if choice == 129:
        state.fb_val = to_int32((to_int32(state.cnt_val + data_val) ^ to_int32(state.last_rs_val - idx_val)) + 47)
    if choice == 130:
        state.fb_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.cnt_val - idx_val)) + 21)
    if choice == 131:
        state.rs_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.fb_val - idx_val)) + 45)
    if choice == 132:
        state.cnt_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.rs_val - idx_val)) + 19)
    if choice == 133:
        state.aux_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.rs_val - idx_val)) + 13)
    if choice == 134:
        state.rs_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.cnt_val - idx_val)) + 3)
    if choice == 135:
        state.aux_val = to_int32((to_int32(state.rs_val + data_val) ^ to_int32(state.fb_val - idx_val)) + 28)
    if choice == 136:
        state.aux_val = to_int32((to_int32(state.cnt_val + data_val) ^ to_int32(state.fb_val - idx_val)) + 50)
    if choice == 137:
        state.last_rs_val = to_int32((to_int32(state.cnt_val + data_val) ^ to_int32(state.fb_val - idx_val)) + 15)
    if choice == 138:
        state.aux_val = to_int32((to_int32(state.rs_val + data_val) ^ to_int32(state.last_rs_val - idx_val)) + 30)
    if choice == 139:
        state.fb_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.aux_val - idx_val)) + 17)
    if choice == 140:
        state.rs_val = to_int32((to_int32(state.aux_val + data_val) ^ to_int32(state.fb_val - idx_val)) + 14)
    if choice == 141:
        state.fb_val = to_int32((to_int32(state.aux_val + data_val) ^ to_int32(state.rs_val - idx_val)) + 5)
    if choice == 142:
        state.last_rs_val = to_int32((to_int32(state.rs_val + data_val) ^ to_int32(state.aux_val - idx_val)) + 25)
    if choice == 143:
        state.rs_val = to_int32((to_int32(state.fb_val + data_val) ^ to_int32(state.aux_val - idx_val)) + 10)
    if choice == 144:
        state.fb_val = to_int32((to_int32(state.rs_val + data_val) ^ to_int32(state.aux_val - idx_val)) + 45)
    if choice == 145:
        state.fb_val = to_int32((to_int32(state.aux_val + data_val) ^ to_int32(state.last_rs_val - idx_val)) + 14)
    if choice == 146:
        state.aux_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.fb_val - idx_val)) + 15)
    if choice == 147:
        state.last_rs_val = to_int32((to_int32(state.aux_val + data_val) ^ to_int32(state.fb_val - idx_val)) + 26)
    if choice == 148:
        state.fb_val = to_int32((to_int32(state.last_rs_val + data_val) ^ to_int32(state.rs_val - idx_val)) + 22)
    if choice == 149:
        state.aux_val = to_int32((to_int32(state.rs_val + data_val) ^ to_int32(state.last_rs_val - idx_val)) + 8)
    if choice == 150:
        state.ms_val = to_int32((state.fb_val ^ state.ds_val) + to_int32(state.rs_val * 3))
    if choice == 151:
        state.ds_val = to_int32((state.ms_val ^ state.aux_val) + to_int32(state.cnt_val * 7))
    if choice == 152:
        state.rs_val = to_int32((state.ds_val ^ state.last_rs_val) + to_int32(state.ms_val * 2))
    if choice == 153:
        state.fb_val = to_int32((state.ms_val ^ state.cnt_val) + to_int32(state.ds_val * 5))
    if choice == 154:
        state.cnt_val = to_int32((state.ds_val ^ state.rs_val) + to_int32(state.aux_val * 4))
    if choice == 155:
        state.aux_val = to_int32((state.ms_val ^ state.fb_val) + to_int32(state.last_rs_val * 9))
    if choice == 156:
        state.last_rs_val = to_int32((state.ds_val ^ state.ms_val) + to_int32(state.fb_val * 6))
    if choice == 157:
        state.ms_val = to_int32((state.rs_val ^ state.aux_val) + to_int32(state.ds_val * 8))
    if choice == 158:
        state.ds_val = to_int32((state.fb_val ^ state.last_rs_val) + to_int32(state.rs_val * 1))
    if choice == 159:
        state.rs_val = to_int32((state.ms_val ^ state.cnt_val) + to_int32(state.aux_val * 10))
    if choice == 160:
        state.fb_val = to_int32((state.ds_val ^ state.ms_val) + to_int32(state.cnt_val * 11))
    if choice == 161:
        state.ms_val = to_int32((state.aux_val ^ state.rs_val) + to_int32(state.ds_val * 12))
    if choice == 162:
        state.ds_val = to_int32((state.cnt_val ^ state.fb_val) + to_int32(state.ms_val * 13))
    if choice == 163:
        state.cnt_val = to_int32((state.last_rs_val ^ state.ds_val) + to_int32(state.aux_val * 14))
    if choice == 164:
        state.aux_val = to_int32((state.ms_val ^ state.rs_val) + to_int32(state.fb_val * 15))
    if choice == 165:
        state.last_rs_val = to_int32((state.ds_val ^ state.cnt_val) + to_int32(state.ms_val * 16))
    if choice == 166:
        state.rs_val = to_int32((state.ms_val ^ state.fb_val) + to_int32(state.ds_val * 17))
    if choice == 167:
        state.fb_val = to_int32((state.aux_val ^ state.ms_val) + to_int32(state.rs_val * 18))
    if choice == 168:
        state.ds_val = to_int32((state.cnt_val ^ state.rs_val) + to_int32(state.last_rs_val * 19))
    if choice == 169:
        state.ms_val = to_int32((state.fb_val ^ state.ds_val) + to_int32(state.aux_val * 20))
    if choice == 170:
        state.ms_val = to_int32(to_int32((state.ds_val ^ state.rs_val) + (state.fb_val ^ state.aux_val)) ^ state.cnt_val)
    if choice == 171:
        state.ds_val = to_int32(to_int32((state.ms_val ^ state.fb_val) + (state.rs_val ^ state.last_rs_val)) ^ state.aux_val)
    if choice == 172:
        state.rs_val = to_int32(to_int32((state.ds_val ^ state.aux_val) + (state.ms_val ^ state.cnt_val)) ^ state.fb_val)
    if choice == 173:
        state.fb_val = to_int32(to_int32((state.ms_val ^ state.cnt_val) + (state.ds_val ^ state.rs_val)) ^ state.last_rs_val)
    if choice == 174:
        state.cnt_val = to_int32(to_int32((state.ds_val ^ state.last_rs_val) + (state.ms_val ^ state.fb_val)) ^ state.rs_val)
    if choice == 175:
        state.aux_val = to_int32(to_int32((state.ms_val ^ state.rs_val) + (state.ds_val ^ state.cnt_val)) ^ state.fb_val)
    if choice == 176:
        state.last_rs_val = to_int32(to_int32((state.ds_val ^ state.fb_val) + (state.ms_val ^ state.aux_val)) ^ state.cnt_val)
    if choice == 177:
        state.ms_val = to_int32(to_int32((state.rs_val ^ state.aux_val) + (state.ds_val ^ state.last_rs_val)) ^ state.fb_val)
    if choice == 178:
        state.ds_val = to_int32(to_int32((state.fb_val ^ state.last_rs_val) + (state.rs_val ^ state.ms_val)) ^ state.cnt_val)
    if choice == 179:
        state.rs_val = to_int32(to_int32((state.ms_val ^ state.cnt_val) + (state.aux_val ^ state.fb_val)) ^ state.ds_val)
    if choice == 180:
        state.ms_val = to_int32(to_int32(state.ds_val * 3) + to_int32(batch_div(state.fb_val, 2)) - to_int32(batch_mod(state.rs_val, 5)))
    if choice == 181:
        state.ds_val = to_int32(to_int32(state.ms_val * 2) + to_int32(batch_div(state.aux_val, 3)) - to_int32(batch_mod(state.cnt_val, 4)))
    if choice == 182:
        state.rs_val = to_int32(to_int32(state.ds_val * 4) + to_int32(batch_div(state.last_rs_val, 5)) - to_int32(batch_mod(state.ms_val, 7)))
    if choice == 183:
        state.fb_val = to_int32(to_int32(state.ms_val * 5) + to_int32(batch_div(state.cnt_val, 4)) - to_int32(batch_mod(state.ds_val, 6)))
    if choice == 184:
        state.cnt_val = to_int32(to_int32(state.ds_val * 6) + to_int32(batch_div(state.rs_val, 7)) - to_int32(batch_mod(state.aux_val, 2)))
    if choice == 185:
        state.aux_val = to_int32(to_int32(state.ms_val * 7) + to_int32(batch_div(state.fb_val, 6)) - to_int32(batch_mod(state.last_rs_val, 3)))
    if choice == 186:
        state.last_rs_val = to_int32(to_int32(state.ds_val * 2) + to_int32(batch_div(state.ms_val, 4)) - to_int32(batch_mod(state.fb_val, 8)))
    if choice == 187:
        state.ms_val = to_int32(to_int32(state.rs_val * 3) + to_int32(batch_div(state.aux_val, 2)) - to_int32(batch_mod(state.ds_val, 9)))
    if choice == 188:
        state.ds_val = to_int32(to_int32(state.fb_val * 4) + to_int32(batch_div(state.last_rs_val, 3)) - to_int32(batch_mod(state.rs_val, 5)))
    if choice == 189:
        state.rs_val = to_int32(to_int32(state.ms_val * 5) + to_int32(batch_div(state.cnt_val, 5)) - to_int32(batch_mod(state.aux_val, 4)))
    if choice == 190:
        if data_val > 50: state.ds_val = to_int32(state.ds_val + idx_val)
        else: state.ds_val = to_int32(state.ds_val - idx_val)
    if choice == 191:
        if idx_val < 20: state.ms_val = to_int32(state.ms_val + data_val)
        else: state.ms_val = to_int32(state.ms_val - data_val)
    if choice == 192:
        if data_val == idx_val: state.rs_val = to_int32(state.ds_val * 2)
        else: state.rs_val = to_int32(state.ms_val * 2)
    if choice == 193:
        if state.rs_val > data_val: state.fb_val = to_int32(state.fb_val + idx_val)
        else: state.fb_val = to_int32(state.fb_val - idx_val)
    if choice == 194:
        if state.ms_val < idx_val: state.cnt_val = to_int32(state.cnt_val + data_val)
        else: state.cnt_val = to_int32(state.cnt_val - data_val)
    if choice == 195:
        if state.ds_val > state.ms_val: state.aux_val = to_int32(state.aux_val + 1)
        else: state.aux_val = to_int32(state.aux_val - 1)
    if choice == 196:
        if state.fb_val < state.cnt_val: state.last_rs_val = to_int32(state.last_rs_val + 2)
        else: state.last_rs_val = to_int32(state.last_rs_val - 2)
    if choice == 197:
        if data_val > 100: state.ms_val = to_int32(state.ms_val ^ idx_val)
        else: state.ms_val = to_int32(state.ms_val + idx_val)
    if choice == 198:
        if idx_val > 50: state.ds_val = to_int32(state.ds_val * (data_val % 5 + 1))
        else: state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 199:
        if state.rs_val == state.aux_val: state.ms_val = to_int32(state.fb_val + 1)
        else: state.ms_val = to_int32(state.cnt_val + 1)
    if choice == 200:
        if data_val > idx_val: state.ds_val = to_int32(state.ms_val ^ state.rs_val)
        else: state.ds_val = to_int32(state.ms_val + state.rs_val)
    if choice == 201:
        if idx_val > data_val: state.rs_val = to_int32(state.fb_val ^ state.aux_val)
        else: state.rs_val = to_int32(state.fb_val + state.aux_val)
    if choice == 202:
        if state.cnt_val > 5000: state.ms_val = to_int32(batch_div(state.ds_val, 2))
        else: state.ms_val = to_int32(state.ds_val * 2)
    if choice == 203:
        if state.last_rs_val < 1000: state.ds_val = to_int32(state.ms_val + data_val)
        else: state.ds_val = to_int32(state.ms_val - data_val)
    if choice == 204:
        if state.fb_val > state.rs_val: state.ms_val = to_int32(state.ms_val + idx_val)
        else: state.ms_val = to_int32(state.ms_val ^ idx_val)
    if choice == 205:
        if data_val < 30: state.rs_val = to_int32(state.rs_val + 1)
        else: state.rs_val = to_int32(state.rs_val + 2)
    if choice == 206:
        if idx_val > 70: state.fb_val = to_int32(state.fb_val - 1)
        else: state.fb_val = to_int32(state.fb_val - 2)
    if choice == 207:
        if state.aux_val > state.cnt_val: state.ds_val = to_int32(state.ds_val ^ state.ms_val)
        else: state.ds_val = to_int32(state.ds_val + 1)
    if choice == 208:
        if state.ms_val < state.ds_val: state.rs_val = to_int32(state.rs_val + state.fb_val)
        else: state.rs_val = to_int32(state.rs_val ^ state.fb_val)
    if choice == 209:
        if data_val == 0: state.ms_val = 1
        else: state.ms_val = to_int32(state.ms_val + 1)
    if choice == 210:
        if data_val > 10: state.ds_val = to_int32(state.ds_val + state.ms_val)
        else: state.ds_val = to_int32(state.ds_val - state.ms_val)
    if choice == 211:
        if idx_val < 80: state.rs_val = to_int32(state.rs_val ^ state.fb_val)
        else: state.rs_val = to_int32(state.rs_val + state.fb_val)
    if choice == 212:
        if state.ms_val > state.ds_val: state.fb_val = to_int32(state.fb_val + idx_val)
        else: state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 213:
        if state.rs_val < state.aux_val: state.cnt_val = to_int32(state.cnt_val + 1)
        else: state.cnt_val = to_int32(state.cnt_val - 1)
    if choice == 214:
        if state.fb_val > state.cnt_val: state.ms_val = to_int32(state.ms_val + data_val)
        else: state.ms_val = to_int32(state.ms_val + idx_val)
    if choice == 215:
        if data_val < idx_val: state.ds_val = to_int32(state.ds_val * 2)
        else: state.ds_val = to_int32(batch_div(state.ds_val, 2))
    if choice == 216:
        if idx_val > data_val: state.rs_val = to_int32(state.rs_val + 5)
        else: state.rs_val = to_int32(state.rs_val - 5)
    if choice == 217:
        if state.aux_val == state.fb_val: state.ms_val = 0
        else: state.ms_val = to_int32(state.ms_val ^ 0xFF)
    if choice == 218:
        if state.cnt_val > state.last_rs_val: state.ds_val = to_int32(state.ds_val + 1)
        else: state.ds_val = to_int32(state.ds_val - 1)
    if choice == 219:
        if state.ms_val < 0: state.ms_val = 1
        else: state.ms_val = to_int32(state.ms_val + 1)
    if choice == 220:
        if data_val > 200: state.rs_val = to_int32(state.rs_val ^ 0xAA)
        else: state.rs_val = to_int32(state.rs_val ^ 0x55)
    if choice == 221:
        if idx_val > 50: state.ds_val = to_int32(state.ds_val * (batch_mod(data_val, 5) + 1))
        else: state.ds_val = to_int32(state.ds_val + 20)
    if choice == 222:
        if state.rs_val > 1000: state.ms_val = to_int32(state.ms_val + 1)
        else: state.ms_val = to_int32(state.ms_val - 1)
    if choice == 223:
        if state.fb_val < 500: state.ds_val = to_int32(state.ds_val ^ state.ms_val)
        else: state.ds_val = to_int32(state.ds_val + state.ms_val)
    if choice == 224:
        if state.cnt_val == 0: state.cnt_val = 1
        else: state.cnt_val = to_int32(state.cnt_val * 2)
    if choice == 225:
        if data_val > 128: state.ms_val = to_int32(state.ms_val + 1)
        else: state.ms_val = to_int32(state.ms_val - 1)
    if choice == 226:
        if idx_val < 128: state.ds_val = to_int32(state.ds_val + 1)
        else: state.ds_val = to_int32(state.ds_val - 1)
    if choice == 227:
        if state.aux_val > 100: state.rs_val = to_int32(state.rs_val + 1)
        else: state.rs_val = to_int32(state.rs_val - 1)
    if choice == 228:
        if state.fb_val < 100: state.cnt_val = to_int32(state.cnt_val + 1)
        else: state.cnt_val = to_int32(state.cnt_val - 1)
    if choice == 229:
        if state.ms_val == state.ds_val: state.rs_val = to_int32(state.rs_val + 1)
        else: state.rs_val = to_int32(state.rs_val - 1)
    if choice == 230:
        for i in range(1, 3):
            if data_val > 50: state.ms_val = to_int32(state.ms_val + i)
    if choice == 231:
        for i in range(1, 3):
            if idx_val < 50: state.ds_val = to_int32(state.ds_val + i)
    if choice == 232:
        for i in range(1, 3):
            if state.rs_val > 1000: state.fb_val = to_int32(state.fb_val + i)
    if choice == 233:
        for i in range(1, 3):
            if state.cnt_val < 5000: state.aux_val = to_int32(state.aux_val + i)
    if choice == 234:
        for i in range(1, 3):
            if state.ms_val == state.ds_val: state.last_rs_val = to_int32(state.last_rs_val + i)
    if choice == 235:
        for _ in range(1, 3):
            for _ in range(1, 3): state.ms_val = to_int32(state.ms_val + 1)
    if choice == 236:
        for _ in range(1, 3):
            for _ in range(1, 3): state.ds_val = to_int32(state.ds_val + 1)
    if choice == 237:
        for _ in range(1, 3):
            for _ in range(1, 3): state.rs_val = to_int32(state.rs_val + 1)
    if choice == 238:
        for _ in range(1, 3):
            for _ in range(1, 3): state.fb_val = to_int32(state.fb_val + 1)
    if choice == 239:
        for _ in range(1, 3):
            for _ in range(1, 3): state.cnt_val = to_int32(state.cnt_val + 1)
    if choice == 240:
        if data_val > 10:
            for i in range(1, 4): state.ms_val = to_int32(state.ms_val + i)
    if choice == 241:
        if idx_val < 90:
            for i in range(1, 4): state.ds_val = to_int32(state.ds_val + i)
    if choice == 242:
        if state.ms_val > state.ds_val:
            for i in range(1, 3): state.rs_val = to_int32(state.rs_val + i)
    if choice == 243:
        if state.fb_val < state.cnt_val:
            for i in range(1, 3): state.aux_val = to_int32(state.aux_val + i)
    if choice == 244:
        if state.last_rs_val > 0:
            for i in range(1, 3): state.ms_val = to_int32(state.ms_val + i)
    if choice == 245:
        for _ in range(1, 6):
            state.ds_val = to_int32(state.ds_val + 1)
            if state.ds_val > 10000: state.ds_val = 0
    if choice == 246:
        for _ in range(1, 6):
            state.ms_val = to_int32(state.ms_val + 1)
            if state.ms_val > 10000: state.ms_val = 0
    if choice == 247:
        for _ in range(1, 6):
            state.rs_val = to_int32(state.rs_val + 1)
            if state.rs_val > 10000: state.rs_val = 0
    if choice == 248:
        for _ in range(1, 6):
            state.fb_val = to_int32(state.fb_val + 1)
            if state.fb_val > 10000: state.fb_val = 0
    if choice == 249:
        for _ in range(1, 6):
            state.cnt_val = to_int32(state.cnt_val + 1)
            if state.cnt_val > 10000: state.cnt_val = 0
    if choice == 250:
        state.ms_val = 0
        for _ in range(1, 5): state.ms_val = to_int32(state.ms_val + batch_mod(state.ds_val, 10))
    if choice == 251:
        state.ds_val = 0
        for _ in range(1, 5): state.ds_val = to_int32(state.ds_val + batch_mod(state.ms_val, 10))
    if choice == 252:
        state.rs_val = 0
        for _ in range(1, 5): state.rs_val = to_int32(state.rs_val + batch_mod(state.fb_val, 10))
    if choice == 253:
        state.fb_val = 0
        for _ in range(1, 5): state.fb_val = to_int32(state.fb_val + batch_mod(state.rs_val, 10))
    if choice == 254:
        state.cnt_val = 0
        for _ in range(1, 5): state.cnt_val = to_int32(state.cnt_val + batch_mod(state.aux_val, 10))
    if choice == 255:
        for i in range(1, 4):
            state.ms_val = to_int32(state.ms_val + i)
            state.ds_val = to_int32(state.ds_val - i)
    if choice == 256:
        for i in range(1, 4):
            state.rs_val = to_int32(state.rs_val + i)
            state.fb_val = to_int32(state.fb_val - i)
    if choice == 257:
        for i in range(1, 4):
            state.cnt_val = to_int32(state.cnt_val + i)
            state.aux_val = to_int32(state.aux_val - i)
    if choice == 258:
        for i in range(1, 4):
            state.last_rs_val = to_int32(state.last_rs_val + i)
            state.ms_val = to_int32(state.ms_val - i)
    if choice == 259:
        for i in range(1, 4):
            state.ds_val = to_int32(state.ds_val + i)
            state.rs_val = to_int32(state.rs_val - i)
    if choice == 260:
        if state.ms_val > state.ds_val:
            if state.rs_val > state.fb_val: state.ms_val = to_int32(state.ms_val + 1)
    if choice == 261:
        if state.ds_val < state.ms_val:
            if state.fb_val < state.rs_val: state.ds_val = to_int32(state.ds_val + 1)
    if choice == 262:
        if state.rs_val > state.fb_val:
            if state.ms_val > state.ds_val: state.rs_val = to_int32(state.rs_val + 1)
    if choice == 263:
        if state.fb_val < state.rs_val:
            if state.ds_val < state.ms_val: state.fb_val = to_int32(state.fb_val + 1)
    if choice == 264:
        if state.cnt_val > state.aux_val:
            if state.ms_val > state.ds_val: state.cnt_val = to_int32(state.cnt_val + 1)
    if choice == 265:
        for _ in range(1, 2):
            if 1 == 1:
                for _ in range(1, 2): state.ms_val = to_int32(state.ms_val + 1)
    if choice == 266:
        for _ in range(1, 2):
            if 1 == 1:
                for _ in range(1, 2): state.ds_val = to_int32(state.ds_val + 1)
    if choice == 267:
        for _ in range(1, 2):
            if 1 == 1:
                for _ in range(1, 2): state.rs_val = to_int32(state.rs_val + 1)
    if choice == 268:
        for _ in range(1, 2):
            if 1 == 1:
                for _ in range(1, 2): state.fb_val = to_int32(state.fb_val + 1)
    if choice == 269:
        for _ in range(1, 2):
            if 1 == 1:
                for _ in range(1, 2): state.cnt_val = to_int32(state.cnt_val + 1)
    if choice == 270:
        if 1 == 1: state.ms_val = to_int32(state.ms_val + 1)
        else: state.ms_val = 0
    if choice == 271:
        if not 1 == 0: state.ds_val = to_int32(state.ds_val + 1)
        else: state.ds_val = 0
    if choice == 272:
        if random.random() > -1: state.rs_val = to_int32(state.rs_val + 1)
        else: state.rs_val = 0
    if choice == 273:
        if True: state.fb_val = to_int32(state.fb_val + 1)
        else: state.fb_val = 0
    if choice == 274:
        if True: state.cnt_val = to_int32(state.cnt_val + 1)
        else: state.cnt_val = 0
    if choice == 275:
        if state.ms_val > -2147483648: state.ms_val = to_int32(state.ms_val + 1)
        else: state.ms_val = 0
    if choice == 276:
        if state.ds_val < 2147483647: state.ds_val = to_int32(state.ds_val + 1)
        else: state.ds_val = 0
    if choice == 277:
        if 1 < 2: state.rs_val = to_int32(state.rs_val + 1)
        else: state.rs_val = 0
    if choice == 278:
        if 2 > 1: state.fb_val = to_int32(state.fb_val + 1)
        else: state.fb_val = 0
    if choice == 279:
        if "a" == "a": state.cnt_val = to_int32(state.cnt_val + 1)
        else: state.cnt_val = 0
    if choice == 280:
        if not "a" == "b": state.ms_val = to_int32(state.ms_val + 1)
        else: state.ms_val = 0
    if choice == 281:
        if 0 == 0: state.ds_val = to_int32(state.ds_val + 1)
        else: state.ds_val = 0
    if choice == 282:
        if True: state.rs_val = to_int32(state.rs_val + 1)
        else: state.rs_val = 0
    if choice == 283:
        if True: state.fb_val = to_int32(state.fb_val + 1)
        else: state.fb_val = to_int32(state.fb_val + 1)
    if choice == 284:
        if True: state.cnt_val = to_int32(state.cnt_val + 1)
        else: state.cnt_val = 0
    if choice == 285:
        if 1 == 1:
            if 2 == 2: state.ms_val = to_int32(state.ms_val + 1)
    if choice == 286:
        if 1 == 1:
            if 2 == 2: state.ds_val = to_int32(state.ds_val + 1)
    if choice == 287:
        if 1 == 1:
            if 2 == 2: state.rs_val = to_int32(state.rs_val + 1)
    if choice == 288:
        if 1 == 1:
            if 2 == 2: state.fb_val = to_int32(state.fb_val + 1)
    if choice == 289:
        if 1 == 1:
            if 2 == 2: state.cnt_val = to_int32(state.cnt_val + 1)
    if choice == 290:
        for a in [1]:
            if a == 1: state.ms_val = to_int32(state.ms_val + 1)
    if choice == 291:
        for a in [1]:
            if a == 1: state.ds_val = to_int32(state.ds_val + 1)
    if choice == 292:
        for a in [1]:
            if a == 1: state.rs_val = to_int32(state.rs_val + 1)
    if choice == 293:
        for a in [1]:
            if a == 1: state.fb_val = to_int32(state.fb_val + 1)
    if choice == 294:
        for a in [1]:
            if a == 1: state.cnt_val = to_int32(state.cnt_val + 1)
    if choice == 295:
        if 1 == 1: state.ms_val = to_int32(state.ms_val + 1)
        if 1 == 1: state.ds_val = to_int32(state.ds_val + 1)
    if choice == 296:
        if 1 == 1: state.rs_val = to_int32(state.rs_val + 1)
        if 1 == 1: state.fb_val = to_int32(state.fb_val + 1)
    if choice == 297:
        if 1 == 1: state.cnt_val = to_int32(state.cnt_val + 1)
        if 1 == 1: state.last_rs_val = to_int32(state.last_rs_val + 1)
    if choice == 298:
        if 1 == 1: state.ms_val = to_int32(state.ms_val + 1)
        if 1 == 1: state.aux_val = to_int32(state.aux_val + 1)
    if choice == 299:
        if 1 == 1: state.ds_val = to_int32(state.ds_val + 1)
        if 1 == 1: state.rs_val = to_int32(state.rs_val + 1)
    if choice == 300:
        state.ds_val = to_int32(to_int32(to_int32(state.cnt_val ^ state.aux_val) * 47) + to_int32(to_int32(state.last_rs_val ^ state.ms_val) * 13))
        state.ds_val = to_int32(state.ds_val ^ to_int32(state.fb_val + data_val))
    if choice == 301:
        state.last_rs_val = to_int32(to_int32(to_int32(state.cnt_val ^ state.aux_val) * 13) + to_int32(to_int32(state.rs_val ^ state.fb_val) * 30))
        state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.ds_val + data_val))
    if choice == 302:
        state.fb_val = to_int32(to_int32(to_int32(state.aux_val ^ state.ds_val) * 26) + to_int32(to_int32(state.ms_val ^ state.last_rs_val) * 47))
        state.fb_val = to_int32(state.fb_val ^ to_int32(state.rs_val + data_val))
    if choice == 303:
        state.rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.ms_val) * 39) + to_int32(to_int32(state.aux_val ^ state.fb_val) * 11))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.last_rs_val + data_val))
    if choice == 304:
        state.rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.last_rs_val) * 5) + to_int32(to_int32(state.fb_val ^ state.ms_val) * 28))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.aux_val + data_val))
    if choice == 305:
        state.aux_val = to_int32(to_int32(to_int32(state.fb_val ^ state.ms_val) * 18) + to_int32(to_int32(state.last_rs_val ^ state.rs_val) * 45))
        state.aux_val = to_int32(state.aux_val ^ to_int32(state.ds_val + data_val))
    if choice == 306:
        state.rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.cnt_val) * 31) + to_int32(to_int32(state.aux_val ^ state.fb_val) * 9))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.last_rs_val + data_val))
    if choice == 307:
        state.fb_val = to_int32(to_int32(to_int32(state.cnt_val ^ state.aux_val) * 44) + to_int32(to_int32(state.rs_val ^ state.last_rs_val) * 26))
        state.fb_val = to_int32(state.fb_val ^ to_int32(state.ds_val + data_val))
    if choice == 308:
        state.ds_val = to_int32(to_int32(to_int32(state.last_rs_val ^ state.aux_val) * 10) + to_int32(to_int32(state.rs_val ^ state.fb_val) * 43))
        state.ds_val = to_int32(state.ds_val ^ to_int32(state.cnt_val + data_val))
    if choice == 309:
        state.rs_val = to_int32(to_int32(to_int32(state.fb_val ^ state.ms_val) * 23) + to_int32(to_int32(state.last_rs_val ^ state.aux_val) * 7))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.cnt_val + data_val))
    if choice == 310:
        state.rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.aux_val) * 36) + to_int32(to_int32(state.fb_val ^ state.last_rs_val) * 24))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.ms_val + data_val))
    if choice == 311:
        state.fb_val = to_int32(to_int32(to_int32(state.last_rs_val ^ state.aux_val) * 2) + to_int32(to_int32(state.cnt_val ^ state.ms_val) * 41))
        state.fb_val = to_int32(state.fb_val ^ to_int32(state.ds_val + data_val))
    if choice == 312:
        state.last_rs_val = to_int32(to_int32(to_int32(state.fb_val ^ state.ms_val) * 15) + to_int32(to_int32(state.aux_val ^ state.rs_val) * 5))
        state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.ds_val + data_val))
    if choice == 313:
        state.rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.aux_val) * 28) + to_int32(to_int32(state.last_rs_val ^ state.ms_val) * 22))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.fb_val + data_val))
    if choice == 314:
        state.ds_val = to_int32(to_int32(to_int32(state.fb_val ^ state.ms_val) * 41) + to_int32(to_int32(state.last_rs_val ^ state.aux_val) * 39))
        state.ds_val = to_int32(state.ds_val ^ to_int32(state.cnt_val + data_val))
    if choice == 315:
        state.aux_val = to_int32(to_int32(to_int32(state.rs_val ^ state.fb_val) * 7) + to_int32(to_int32(state.ds_val ^ state.cnt_val) * 3))
        state.aux_val = to_int32(state.aux_val ^ to_int32(state.ms_val + data_val))
    if choice == 316:
        state.aux_val = to_int32(to_int32(to_int32(state.ms_val ^ state.last_rs_val) * 20) + to_int32(to_int32(state.rs_val ^ state.cnt_val) * 20))
        state.aux_val = to_int32(state.aux_val ^ to_int32(state.ds_val + data_val))
    if choice == 317:
        state.last_rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.cnt_val) * 33) + to_int32(to_int32(state.fb_val ^ state.aux_val) * 37))
        state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.rs_val + data_val))
    if choice == 318:
        state.aux_val = to_int32(to_int32(to_int32(state.cnt_val ^ state.ds_val) * 46) + to_int32(to_int32(state.ms_val ^ state.fb_val) * 1))
        state.aux_val = to_int32(state.aux_val ^ to_int32(state.last_rs_val + data_val))
    if choice == 319:
        state.last_rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.rs_val) * 12) + to_int32(to_int32(state.ms_val ^ state.cnt_val) * 18))
        state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.fb_val + data_val))
    if choice == 320:
        state.rs_val = to_int32(to_int32(to_int32(state.ms_val ^ state.ds_val) * 25) + to_int32(to_int32(state.last_rs_val ^ state.fb_val) * 35))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.cnt_val + data_val))
    if choice == 321:
        state.fb_val = to_int32(to_int32(to_int32(state.rs_val ^ state.aux_val) * 38) + to_int32(to_int32(state.last_rs_val ^ state.ms_val) * 52))
        state.fb_val = to_int32(state.fb_val ^ to_int32(state.ds_val + data_val))
    if choice == 322:
        state.fb_val = to_int32(to_int32(to_int32(state.ds_val ^ state.rs_val) * 4) + to_int32(to_int32(state.aux_val ^ state.ms_val) * 16))
        state.fb_val = to_int32(state.fb_val ^ to_int32(state.cnt_val + data_val))
    if choice == 323:
        state.aux_val = to_int32(to_int32(to_int32(state.rs_val ^ state.last_rs_val) * 17) + to_int32(to_int32(state.fb_val ^ state.ms_val) * 33))
        state.aux_val = to_int32(state.aux_val ^ to_int32(state.ds_val + data_val))
    if choice == 324:
        state.rs_val = to_int32(to_int32(to_int32(state.ds_val ^ state.aux_val) * 30) + to_int32(to_int32(state.ms_val ^ state.cnt_val) * 50))
        state.rs_val = to_int32(state.rs_val ^ to_int32(state.last_rs_val + data_val))
    if choice == 325:
        for i_loop in range(1, 4 + 1):
            state.fb_val = to_int32(state.fb_val + to_int32(state.last_rs_val + i_loop))
            state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.rs_val + state.aux_val) + idx_val))
    if choice == 326:
        for i_loop in range(1, 5 + 1):
            state.rs_val = to_int32(state.rs_val + to_int32(state.ds_val + i_loop))
            state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.fb_val + state.aux_val) + idx_val))
    if choice == 327:
        for i_loop in range(1, 3 + 1):
            state.last_rs_val = to_int32(state.last_rs_val + to_int32(state.ds_val + i_loop))
            state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.fb_val + state.rs_val) + idx_val))
    if choice == 328:
        for i_loop in range(1, 4 + 1):
            state.rs_val = to_int32(state.rs_val + to_int32(state.fb_val + i_loop))
            state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.aux_val + state.ds_val) + idx_val))
    if choice == 329:
        for i_loop in range(1, 5 + 1):
            state.cnt_val = to_int32(state.cnt_val + to_int32(state.aux_val + i_loop))
            state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ms_val + state.fb_val) + idx_val))
    if choice == 330:
        for i_loop in range(1, 3 + 1):
            state.ms_val = to_int32(state.ms_val + to_int32(state.rs_val + i_loop))
            state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.cnt_val + state.fb_val) + idx_val))
    if choice == 331:
        for i_loop in range(1, 4 + 1):
            state.fb_val = to_int32(state.fb_val + to_int32(state.ms_val + i_loop))
            state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.aux_val) + idx_val))
    if choice == 332:
        for i_loop in range(1, 5 + 1):
            state.ds_val = to_int32(state.ds_val + to_int32(state.rs_val + i_loop))
            state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.aux_val + state.cnt_val) + idx_val))
    if choice == 333:
        for i_loop in range(1, 3 + 1):
            state.ms_val = to_int32(state.ms_val + to_int32(state.last_rs_val + i_loop))
            state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 334:
        for i_loop in range(1, 4 + 1):
            state.ds_val = to_int32(state.ds_val + to_int32(state.cnt_val + i_loop))
            state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.aux_val + state.fb_val) + idx_val))
    if choice == 335:
        for i_loop in range(1, 5 + 1):
            state.cnt_val = to_int32(state.cnt_val + to_int32(state.ds_val + i_loop))
            state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.fb_val + state.rs_val) + idx_val))
    if choice == 336:
        for i_loop in range(1, 3 + 1):
            state.fb_val = to_int32(state.fb_val + to_int32(state.ms_val + i_loop))
            state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 337:
        for i_loop in range(1, 4 + 1):
            state.fb_val = to_int32(state.fb_val + to_int32(state.ds_val + i_loop))
            state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.aux_val) + idx_val))
    if choice == 338:
        for i_loop in range(1, 5 + 1):
            state.aux_val = to_int32(state.aux_val + to_int32(state.rs_val + i_loop))
            state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.cnt_val + state.fb_val) + idx_val))
    if choice == 339:
        for i_loop in range(1, 3 + 1):
            state.ms_val = to_int32(state.ms_val + to_int32(state.cnt_val + i_loop))
            state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + idx_val))
    if choice == 340:
        for i_loop in range(1, 4 + 1):
            state.cnt_val = to_int32(state.cnt_val + to_int32(state.ms_val + i_loop))
            state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + idx_val))
    if choice == 341:
        for i_loop in range(1, 5 + 1):
            state.cnt_val = to_int32(state.cnt_val + to_int32(state.ms_val + i_loop))
            state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + idx_val))
    if choice == 342:
        for i_loop in range(1, 3 + 1):
            state.ds_val = to_int32(state.ds_val + to_int32(state.ms_val + i_loop))
            state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.aux_val) + idx_val))
    if choice == 343:
        for i_loop in range(1, 4 + 1):
            state.rs_val = to_int32(state.rs_val + to_int32(state.last_rs_val + i_loop))
            state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.cnt_val) + idx_val))
    if choice == 344:
        for i_loop in range(1, 5 + 1):
            state.ds_val = to_int32(state.ds_val + to_int32(state.ms_val + i_loop))
            state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 345:
        for i_loop in range(1, 3 + 1):
            state.cnt_val = to_int32(state.cnt_val + to_int32(state.ms_val + i_loop))
            state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.rs_val) + idx_val))
    if choice == 346:
        for i_loop in range(1, 4 + 1):
            state.aux_val = to_int32(state.aux_val + to_int32(state.ds_val + i_loop))
            state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.rs_val + state.fb_val) + idx_val))
    if choice == 347:
        for i_loop in range(1, 5 + 1):
            state.cnt_val = to_int32(state.cnt_val + to_int32(state.fb_val + i_loop))
            state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.last_rs_val + state.rs_val) + idx_val))
    if choice == 348:
        for i_loop in range(1, 3 + 1):
            state.aux_val = to_int32(state.aux_val + to_int32(state.rs_val + i_loop))
            state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ms_val + state.ds_val) + idx_val))
    if choice == 349:
        for i_loop in range(1, 4 + 1):
            state.cnt_val = to_int32(state.cnt_val + to_int32(state.last_rs_val + i_loop))
            state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.fb_val) + idx_val))
    if choice == 350:
        if state.cnt_val > 3850:
            if state.ms_val < 2650:
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.aux_val + data_val))
            else:
                state.last_rs_val = to_int32(state.last_rs_val + to_int32(state.rs_val ^ idx_val))
        else:
            state.last_rs_val = to_int32(state.fb_val * 2)
    if choice == 351:
        if state.ms_val > 3861:
            if state.rs_val < 2669:
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.ds_val + data_val))
            else:
                state.cnt_val = to_int32(state.cnt_val + to_int32(state.aux_val ^ idx_val))
        else:
            state.cnt_val = to_int32(state.last_rs_val * 2)
    if choice == 352:
        if state.fb_val > 3872:
            if state.ds_val < 2688:
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.ms_val + data_val))
            else:
                state.aux_val = to_int32(state.aux_val + to_int32(state.rs_val ^ idx_val))
        else:
            state.aux_val = to_int32(state.last_rs_val * 2)
    if choice == 353:
        if state.ds_val > 3883:
            if state.rs_val < 2707:
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.last_rs_val + data_val))
            else:
                state.cnt_val = to_int32(state.cnt_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.cnt_val = to_int32(state.aux_val * 2)
    if choice == 354:
        if state.fb_val > 3894:
            if state.ds_val < 2726:
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.aux_val + data_val))
            else:
                state.rs_val = to_int32(state.rs_val + to_int32(state.ms_val ^ idx_val))
        else:
            state.rs_val = to_int32(state.last_rs_val * 2)
    if choice == 355:
        if state.cnt_val > 3905:
            if state.ds_val < 2745:
                state.fb_val = to_int32(state.fb_val ^ to_int32(state.rs_val + data_val))
            else:
                state.fb_val = to_int32(state.fb_val + to_int32(state.last_rs_val ^ idx_val))
        else:
            state.fb_val = to_int32(state.aux_val * 2)
    if choice == 356:
        if state.ds_val > 3916:
            if state.ms_val < 2764:
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.cnt_val + data_val))
            else:
                state.aux_val = to_int32(state.aux_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.aux_val = to_int32(state.last_rs_val * 2)
    if choice == 357:
        if state.cnt_val > 3927:
            if state.last_rs_val < 2783:
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.ms_val + data_val))
            else:
                state.ds_val = to_int32(state.ds_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.ds_val = to_int32(state.rs_val * 2)
    if choice == 358:
        if state.last_rs_val > 3938:
            if state.rs_val < 2802:
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.aux_val + data_val))
            else:
                state.ms_val = to_int32(state.ms_val + to_int32(state.ds_val ^ idx_val))
        else:
            state.ms_val = to_int32(state.fb_val * 2)
    if choice == 359:
        if state.last_rs_val > 3949:
            if state.ds_val < 2821:
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.cnt_val + data_val))
            else:
                state.aux_val = to_int32(state.aux_val + to_int32(state.ms_val ^ idx_val))
        else:
            state.aux_val = to_int32(state.fb_val * 2)
    if choice == 360:
        if state.ds_val > 3960:
            if state.fb_val < 2840:
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.last_rs_val + data_val))
            else:
                state.ms_val = to_int32(state.ms_val + to_int32(state.cnt_val ^ idx_val))
        else:
            state.ms_val = to_int32(state.rs_val * 2)
    if choice == 361:
        if state.ms_val > 3971:
            if state.last_rs_val < 2859:
                state.fb_val = to_int32(state.fb_val ^ to_int32(state.aux_val + data_val))
            else:
                state.fb_val = to_int32(state.fb_val + to_int32(state.ds_val ^ idx_val))
        else:
            state.fb_val = to_int32(state.rs_val * 2)
    if choice == 362:
        if state.aux_val > 3982:
            if state.cnt_val < 2878:
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.ms_val + data_val))
            else:
                state.rs_val = to_int32(state.rs_val + to_int32(state.last_rs_val ^ idx_val))
        else:
            state.rs_val = to_int32(state.ds_val * 2)
    if choice == 363:
        if state.cnt_val > 3993:
            if state.ms_val < 2897:
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.last_rs_val + data_val))
            else:
                state.rs_val = to_int32(state.rs_val + to_int32(state.aux_val ^ idx_val))
        else:
            state.rs_val = to_int32(state.fb_val * 2)
    if choice == 364:
        if state.ds_val > 4:
            if state.ms_val < 2916:
                state.fb_val = to_int32(state.fb_val ^ to_int32(state.last_rs_val + data_val))
            else:
                state.fb_val = to_int32(state.fb_val + to_int32(state.aux_val ^ idx_val))
        else:
            state.fb_val = to_int32(state.rs_val * 2)
    if choice == 365:
        if state.aux_val > 15:
            if state.ds_val < 2935:
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.last_rs_val + data_val))
            else:
                state.rs_val = to_int32(state.rs_val + to_int32(state.ms_val ^ idx_val))
        else:
            state.rs_val = to_int32(state.cnt_val * 2)
    if choice == 366:
        if state.fb_val > 26:
            if state.rs_val < 2954:
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.cnt_val + data_val))
            else:
                state.aux_val = to_int32(state.aux_val + to_int32(state.last_rs_val ^ idx_val))
        else:
            state.aux_val = to_int32(state.ds_val * 2)
    if choice == 367:
        if state.rs_val > 37:
            if state.cnt_val < 2973:
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.aux_val + data_val))
            else:
                state.ds_val = to_int32(state.ds_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.ds_val = to_int32(state.last_rs_val * 2)
    if choice == 368:
        if state.last_rs_val > 48:
            if state.cnt_val < 2992:
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.rs_val + data_val))
            else:
                state.ds_val = to_int32(state.ds_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.ds_val = to_int32(state.ms_val * 2)
    if choice == 369:
        if state.rs_val > 59:
            if state.fb_val < 3011:
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.cnt_val + data_val))
            else:
                state.aux_val = to_int32(state.aux_val + to_int32(state.ms_val ^ idx_val))
        else:
            state.aux_val = to_int32(state.last_rs_val * 2)
    if choice == 370:
        if state.fb_val > 70:
            if state.rs_val < 3030:
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.aux_val + data_val))
            else:
                state.last_rs_val = to_int32(state.last_rs_val + to_int32(state.cnt_val ^ idx_val))
        else:
            state.last_rs_val = to_int32(state.ds_val * 2)
    if choice == 371:
        if state.last_rs_val > 81:
            if state.cnt_val < 3049:
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.rs_val + data_val))
            else:
                state.aux_val = to_int32(state.aux_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.aux_val = to_int32(state.ds_val * 2)
    if choice == 372:
        if state.cnt_val > 92:
            if state.rs_val < 3068:
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.aux_val + data_val))
            else:
                state.last_rs_val = to_int32(state.last_rs_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.last_rs_val = to_int32(state.ms_val * 2)
    if choice == 373:
        if state.aux_val > 103:
            if state.ds_val < 3087:
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.cnt_val + data_val))
            else:
                state.last_rs_val = to_int32(state.last_rs_val + to_int32(state.fb_val ^ idx_val))
        else:
            state.last_rs_val = to_int32(state.ms_val * 2)
    if choice == 374:
        if state.cnt_val > 114:
            if state.fb_val < 3106:
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.last_rs_val + data_val))
            else:
                state.ds_val = to_int32(state.ds_val + to_int32(state.aux_val ^ idx_val))
        else:
            state.ds_val = to_int32(state.rs_val * 2)
    if choice == 375:
        state.cnt_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.ds_val ^ state.rs_val) + to_int32(state.aux_val ^ state.ms_val)) - to_int32(state.fb_val ^ state.last_rs_val)) + data_val) + idx_val)
    if choice == 376:
        state.ds_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.last_rs_val ^ state.cnt_val) + to_int32(state.fb_val ^ state.aux_val)) - to_int32(state.rs_val ^ state.ms_val)) + data_val) + idx_val)
    if choice == 377:
        state.ms_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.rs_val ^ state.fb_val) + to_int32(state.ds_val ^ state.aux_val)) - to_int32(state.last_rs_val ^ state.cnt_val)) + data_val) + idx_val)
    if choice == 378:
        state.last_rs_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.ms_val ^ state.ds_val) + to_int32(state.aux_val ^ state.cnt_val)) - to_int32(state.rs_val ^ state.fb_val)) + data_val) + idx_val)
    if choice == 379:
        state.cnt_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.rs_val ^ state.last_rs_val) + to_int32(state.aux_val ^ state.ds_val)) - to_int32(state.ms_val ^ state.fb_val)) + data_val) + idx_val)
    if choice == 380:
        state.ms_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.aux_val ^ state.rs_val) + to_int32(state.last_rs_val ^ state.ds_val)) - to_int32(state.fb_val ^ state.cnt_val)) + data_val) + idx_val)
    if choice == 381:
        state.last_rs_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.cnt_val ^ state.ds_val) + to_int32(state.aux_val ^ state.ms_val)) - to_int32(state.fb_val ^ state.rs_val)) + data_val) + idx_val)
    if choice == 382:
        state.cnt_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.last_rs_val ^ state.rs_val) + to_int32(state.ds_val ^ state.ms_val)) - to_int32(state.fb_val ^ state.aux_val)) + data_val) + idx_val)
    if choice == 383:
        state.ms_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.aux_val ^ state.last_rs_val) + to_int32(state.fb_val ^ state.ds_val)) - to_int32(state.rs_val ^ state.cnt_val)) + data_val) + idx_val)
    if choice == 384:
        state.last_rs_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.cnt_val ^ state.aux_val) + to_int32(state.ms_val ^ state.rs_val)) - to_int32(state.ds_val ^ state.fb_val)) + data_val) + idx_val)
    if choice == 385:
        state.aux_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.rs_val ^ state.cnt_val) + to_int32(state.ms_val ^ state.last_rs_val)) - to_int32(state.fb_val ^ state.ds_val)) + data_val) + idx_val)
    if choice == 386:
        state.last_rs_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.rs_val ^ state.ds_val) + to_int32(state.aux_val ^ state.ms_val)) - to_int32(state.fb_val ^ state.cnt_val)) + data_val) + idx_val)
    if choice == 387:
        state.ms_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.aux_val ^ state.fb_val) + to_int32(state.cnt_val ^ state.last_rs_val)) - to_int32(state.rs_val ^ state.ds_val)) + data_val) + idx_val)
    if choice == 388:
        state.ds_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.fb_val ^ state.last_rs_val) + to_int32(state.cnt_val ^ state.ms_val)) - to_int32(state.rs_val ^ state.aux_val)) + data_val) + idx_val)
    if choice == 389:
        state.ds_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.aux_val ^ state.rs_val) + to_int32(state.ms_val ^ state.cnt_val)) - to_int32(state.last_rs_val ^ state.fb_val)) + data_val) + idx_val)
    if choice == 390:
        state.cnt_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.fb_val ^ state.aux_val) + to_int32(state.ds_val ^ state.last_rs_val)) - to_int32(state.rs_val ^ state.ms_val)) + data_val) + idx_val)
    if choice == 391:
        state.ms_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.last_rs_val ^ state.ds_val) + to_int32(state.fb_val ^ state.rs_val)) - to_int32(state.aux_val ^ state.cnt_val)) + data_val) + idx_val)
    if choice == 392:
        state.cnt_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.ms_val ^ state.aux_val) + to_int32(state.rs_val ^ state.fb_val)) - to_int32(state.last_rs_val ^ state.ds_val)) + data_val) + idx_val)
    if choice == 393:
        state.cnt_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.ds_val ^ state.aux_val) + to_int32(state.rs_val ^ state.ms_val)) - to_int32(state.fb_val ^ state.last_rs_val)) + data_val) + idx_val)
    if choice == 394:
        state.ds_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.last_rs_val ^ state.aux_val) + to_int32(state.cnt_val ^ state.rs_val)) - to_int32(state.ms_val ^ state.fb_val)) + data_val) + idx_val)
    if choice == 395:
        state.rs_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.cnt_val ^ state.aux_val) + to_int32(state.fb_val ^ state.ds_val)) - to_int32(state.ms_val ^ state.last_rs_val)) + data_val) + idx_val)
    if choice == 396:
        state.fb_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.aux_val ^ state.ms_val) + to_int32(state.rs_val ^ state.cnt_val)) - to_int32(state.last_rs_val ^ state.ds_val)) + data_val) + idx_val)
    if choice == 397:
        state.last_rs_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.aux_val ^ state.ms_val) + to_int32(state.fb_val ^ state.ds_val)) - to_int32(state.rs_val ^ state.cnt_val)) + data_val) + idx_val)
    if choice == 398:
        state.last_rs_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.ds_val ^ state.aux_val) + to_int32(state.cnt_val ^ state.rs_val)) - to_int32(state.fb_val ^ state.ms_val)) + data_val) + idx_val)
    if choice == 399:
        state.ds_val = to_int32(to_int32(to_int32(to_int32(to_int32(state.cnt_val ^ state.fb_val) + to_int32(state.rs_val ^ state.ms_val)) - to_int32(state.aux_val ^ state.last_rs_val)) + data_val) + idx_val)

    if choice == 500:
        state.aux_val = batch_mod(state.cnt_val, 5) + 1
        for _ in range(state.aux_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 501:
        if state.ms_val > 3265:
            if state.cnt_val < 3508: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 502:
        if state.ms_val > 8259:
            if state.ds_val < 1361: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 503:
        for _ in range(2):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.cnt_val + state.ms_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.fb_val + state.ms_val) + idx_val))
    if choice == 504:
        for _ in range(2):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.last_rs_val + state.last_rs_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.fb_val + state.last_rs_val) + idx_val))
    if choice == 505:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.ms_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.ms_val) + idx_val))
    if choice == 506:
        for _ in range(2):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.cnt_val + state.aux_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + idx_val))
    if choice == 507:
        state.ds_val = to_int32(to_int32(state.aux_val * 4) + batch_div(state.ms_val, 3))
        if state.ds_val > state.rs_val:
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ idx_val))
    if choice == 508:
        state.cnt_val = to_int32(to_int32(state.ds_val * 3) + batch_div(state.ms_val, 9))
        if state.cnt_val > state.last_rs_val:
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ idx_val))
    if choice == 509:
        state.fb_val = to_int32(to_int32(state.last_rs_val * 8) + batch_div(state.aux_val, 2))
        if state.fb_val > state.rs_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ idx_val))
    if choice == 510:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ state.ms_val))
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
    if choice == 511:
        state.aux_val = to_int32(to_int32(state.ds_val * 9) + batch_div(state.rs_val, 5))
        if state.aux_val > state.last_rs_val:
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ idx_val))
    if choice == 512:
        for _ in range(3):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.last_rs_val + state.ds_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.fb_val + state.ds_val) + idx_val))
    if choice == 513:
        state.rs_val = to_int32(to_int32(state.fb_val * 7) + batch_div(state.last_rs_val, 10))
        if state.rs_val > state.ds_val:
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ idx_val))
    if choice == 514:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.last_rs_val))
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
    if choice == 515:
        state.aux_val = batch_mod(state.fb_val, 8) + 1
        for _ in range(state.aux_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 516:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
    if choice == 517:
        state.ds_val = to_int32(to_int32(state.ms_val * 5) + batch_div(state.fb_val, 6))
        if state.ds_val > state.aux_val:
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ idx_val))
    if choice == 518:
        state.fb_val = batch_mod(state.ds_val, 5) + 1
        for _ in range(state.fb_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 519:
        if state.cnt_val > 7526:
            if state.ds_val < 3661: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 520:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.fb_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
    if choice == 521:
        state.cnt_val = batch_mod(state.ds_val, 5) + 1
        for _ in range(state.cnt_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 522:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ state.ds_val))
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 523:
        state.cnt_val = batch_mod(state.rs_val, 10) + 1
        for _ in range(state.cnt_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 524:
        for _ in range(2):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.ds_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.ds_val) + idx_val))
    if choice == 525:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ state.cnt_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.cnt_val))
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
    if choice == 526:
        state.last_rs_val = batch_mod(state.ms_val, 8) + 1
        for _ in range(state.last_rs_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 527:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
    if choice == 528:
        state.aux_val = to_int32(to_int32(state.ms_val * 9) + batch_div(state.rs_val, 3))
        if state.aux_val > state.last_rs_val:
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ idx_val))
    if choice == 529:
        for _ in range(2):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.rs_val + state.last_rs_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.last_rs_val + state.last_rs_val) + idx_val))
    if choice == 530:
        state.ds_val = to_int32(to_int32(state.cnt_val * 4) + batch_div(state.last_rs_val, 6))
        if state.ds_val > state.rs_val:
            state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ data_val))
        else:
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ idx_val))
    if choice == 531:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ state.fb_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
    if choice == 532:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.ds_val + state.rs_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.ms_val + state.rs_val) + idx_val))
    if choice == 533:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ state.cnt_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ state.cnt_val))
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
    if choice == 534:
        for _ in range(3):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.rs_val + state.aux_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + idx_val))
    if choice == 535:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.fb_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ms_val + state.fb_val) + idx_val))
    if choice == 536:
        for _ in range(2):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.fb_val + state.aux_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + idx_val))
    if choice == 537:
        if state.cnt_val > 8389:
            if state.rs_val < 7613: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 538:
        for _ in range(3):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.rs_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 539:
        if state.ms_val > 2015:
            if state.ds_val < 6995: state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 540:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.fb_val + state.fb_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + idx_val))
    if choice == 541:
        if state.cnt_val > 2682:
            if state.fb_val < 3767: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 542:
        if state.cnt_val > 7802:
            if state.aux_val < 8587: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.cnt_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 543:
        state.rs_val = batch_mod(state.aux_val, 8) + 1
        for _ in range(state.rs_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 544:
        state.aux_val = to_int32(to_int32(state.last_rs_val * 10) + batch_div(state.cnt_val, 3))
        if state.aux_val > state.fb_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ idx_val))
    if choice == 545:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ state.ds_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
    if choice == 546:
        state.aux_val = to_int32(to_int32(state.ms_val * 3) + batch_div(state.fb_val, 5))
        if state.aux_val > state.last_rs_val:
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ idx_val))
    if choice == 547:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + idx_val))
    if choice == 548:
        state.ms_val = batch_mod(state.last_rs_val, 6) + 1
        for _ in range(state.ms_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 549:
        for _ in range(2):
            for _ in range(3):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.rs_val + state.cnt_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.fb_val + state.cnt_val) + idx_val))
    if choice == 550:
        for _ in range(3):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.fb_val + state.ds_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.last_rs_val + state.ds_val) + idx_val))
    if choice == 551:
        for _ in range(2):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ms_val + state.cnt_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.cnt_val) + idx_val))
    if choice == 552:
        for _ in range(3):
            for _ in range(3):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.last_rs_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.last_rs_val) + idx_val))
    if choice == 553:
        state.fb_val = to_int32(to_int32(state.rs_val * 10) + batch_div(state.ms_val, 3))
        if state.fb_val > state.cnt_val:
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ idx_val))
    if choice == 554:
        state.fb_val = batch_mod(state.ms_val, 5) + 1
        for _ in range(state.fb_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 555:
        state.fb_val = to_int32(to_int32(state.ds_val * 2) + batch_div(state.last_rs_val, 3))
        if state.fb_val > state.cnt_val:
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
    if choice == 556:
        state.fb_val = batch_mod(state.ms_val, 8) + 1
        for _ in range(state.fb_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 557:
        if state.last_rs_val > 6603:
            if state.rs_val < 1276: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 558:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ state.ms_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ data_val))
    if choice == 559:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ state.rs_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
    if choice == 560:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
    if choice == 561:
        if state.aux_val > 3362:
            if state.cnt_val < 1708: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.aux_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 562:
        if state.fb_val > 5751:
            if state.aux_val < 2950: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.fb_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 563:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ state.rs_val))
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
    if choice == 564:
        state.ds_val = batch_mod(state.rs_val, 9) + 1
        for _ in range(state.ds_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 565:
        for _ in range(3):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.fb_val + state.fb_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + idx_val))
    if choice == 566:
        if state.aux_val > 2332:
            if state.ds_val < 5325: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 567:
        for _ in range(3):
            for _ in range(3):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.fb_val + state.last_rs_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.cnt_val + state.last_rs_val) + idx_val))
    if choice == 568:
        if state.rs_val > 7917:
            if state.ds_val < 6786: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 569:
        for _ in range(2):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + idx_val))
    if choice == 570:
        if state.ms_val > 3918:
            if state.ds_val < 5965: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 571:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + idx_val))
    if choice == 572:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.rs_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ data_val))
    if choice == 573:
        state.ms_val = batch_mod(state.rs_val, 5) + 1
        for _ in range(state.ms_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 574:
        state.ds_val = to_int32(to_int32(state.cnt_val * 6) + batch_div(state.rs_val, 5))
        if state.ds_val > state.aux_val:
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
        else:
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ idx_val))
    if choice == 575:
        state.fb_val = to_int32(to_int32(state.ms_val * 4) + batch_div(state.cnt_val, 7))
        if state.fb_val > state.last_rs_val:
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
    if choice == 576:
        state.ds_val = to_int32(to_int32(state.fb_val * 6) + batch_div(state.cnt_val, 6))
        if state.ds_val > state.last_rs_val:
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ idx_val))
    if choice == 577:
        state.aux_val = to_int32(to_int32(state.ds_val * 5) + batch_div(state.cnt_val, 8))
        if state.aux_val > state.rs_val:
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ idx_val))
    if choice == 578:
        state.aux_val = batch_mod(state.cnt_val, 8) + 1
        for _ in range(state.aux_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 579:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ state.ds_val))
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
    if choice == 580:
        if state.fb_val > 5920:
            if state.ds_val < 8126: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 581:
        if state.ds_val > 1877:
            if state.ms_val < 3395: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.ds_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 582:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ state.cnt_val))
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ state.cnt_val))
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
    if choice == 583:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ state.aux_val))
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
    if choice == 584:
        if state.ds_val > 7022:
            if state.rs_val < 6425: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 585:
        state.rs_val = batch_mod(state.ds_val, 8) + 1
        for _ in range(state.rs_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 586:
        state.aux_val = to_int32(to_int32(state.ms_val * 5) + batch_div(state.cnt_val, 3))
        if state.aux_val > state.last_rs_val:
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ idx_val))
    if choice == 587:
        if state.ms_val > 2990:
            if state.aux_val < 6953: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 588:
        for _ in range(3):
            for _ in range(3):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.rs_val + state.aux_val) + idx_val))
    if choice == 589:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 9) + batch_div(state.rs_val, 4))
        if state.last_rs_val > state.fb_val:
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 590:
        state.aux_val = batch_mod(state.fb_val, 6) + 1
        for _ in range(state.aux_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 591:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 4) + batch_div(state.ds_val, 2))
        if state.last_rs_val > state.aux_val:
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 592:
        state.fb_val = batch_mod(state.rs_val, 5) + 1
        for _ in range(state.fb_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 593:
        state.ms_val = batch_mod(state.ds_val, 7) + 1
        for _ in range(state.ms_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 594:
        if state.cnt_val > 6385:
            if state.aux_val < 1028: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 595:
        for _ in range(2):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.rs_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ms_val + state.rs_val) + idx_val))
    if choice == 596:
        if state.cnt_val > 8325:
            if state.ms_val < 5756: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.cnt_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 597:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ms_val + state.fb_val) + idx_val))
    if choice == 598:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ state.cnt_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ state.cnt_val))
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
    if choice == 599:
        state.last_rs_val = batch_mod(state.rs_val, 8) + 1
        for _ in range(state.last_rs_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 600:
        if state.aux_val > 5320:
            if state.cnt_val < 1764: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 601:
        for _ in range(2):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.last_rs_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ms_val + state.last_rs_val) + idx_val))
    if choice == 602:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.fb_val + state.fb_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.rs_val + state.fb_val) + idx_val))
    if choice == 603:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 9) + batch_div(state.rs_val, 5))
        if state.last_rs_val > state.fb_val:
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 604:
        state.aux_val = batch_mod(state.rs_val, 6) + 1
        for _ in range(state.aux_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 605:
        if state.cnt_val > 7157:
            if state.fb_val < 5105: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 606:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ state.last_rs_val))
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
    if choice == 607:
        for _ in range(2):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.cnt_val + state.ds_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.fb_val + state.ds_val) + idx_val))
    if choice == 608:
        if state.rs_val > 3867:
            if state.cnt_val < 4716: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 609:
        for _ in range(2):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.aux_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + idx_val))
    if choice == 610:
        state.rs_val = to_int32(to_int32(state.fb_val * 8) + batch_div(state.last_rs_val, 8))
        if state.rs_val > state.ds_val:
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ idx_val))
    if choice == 611:
        state.cnt_val = batch_mod(state.aux_val, 7) + 1
        for _ in range(state.cnt_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 612:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.ms_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.ms_val) + idx_val))
    if choice == 613:
        if state.ds_val > 8566:
            if state.rs_val < 3814: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 614:
        if state.fb_val > 7714:
            if state.rs_val < 6503: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 615:
        if state.fb_val > 8360:
            if state.cnt_val < 8665: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 616:
        state.cnt_val = batch_mod(state.ms_val, 5) + 1
        for _ in range(state.cnt_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 617:
        if state.rs_val > 6549:
            if state.last_rs_val < 1927: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 618:
        if state.fb_val > 7609:
            if state.ds_val < 7701: state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 619:
        for _ in range(2):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.fb_val + state.aux_val) + idx_val))
    if choice == 620:
        state.cnt_val = batch_mod(state.fb_val, 9) + 1
        for _ in range(state.cnt_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 621:
        if state.aux_val > 7188:
            if state.last_rs_val < 8575: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 622:
        state.cnt_val = batch_mod(state.ds_val, 7) + 1
        for _ in range(state.cnt_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 623:
        state.cnt_val = batch_mod(state.ds_val, 6) + 1
        for _ in range(state.cnt_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 624:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ms_val + state.rs_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.rs_val) + idx_val))
    if choice == 625:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.aux_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
    if choice == 626:
        state.last_rs_val = batch_mod(state.rs_val, 6) + 1
        for _ in range(state.last_rs_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 627:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.cnt_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.cnt_val) + idx_val))
    if choice == 628:
        state.fb_val = batch_mod(state.ds_val, 6) + 1
        for _ in range(state.fb_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 629:
        if state.aux_val > 3092:
            if state.ms_val < 8247: state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 630:
        state.ms_val = batch_mod(state.aux_val, 8) + 1
        for _ in range(state.ms_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 631:
        state.cnt_val = to_int32(to_int32(state.ms_val * 10) + batch_div(state.aux_val, 4))
        if state.cnt_val > state.ds_val:
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ idx_val))
    if choice == 632:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ state.rs_val))
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
    if choice == 633:
        if state.cnt_val > 5417:
            if state.fb_val < 8775: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 634:
        if state.cnt_val > 5934:
            if state.rs_val < 5725: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 635:
        state.last_rs_val = to_int32(to_int32(state.fb_val * 9) + batch_div(state.cnt_val, 9))
        if state.last_rs_val > state.aux_val:
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ idx_val))
    if choice == 636:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ state.last_rs_val))
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
    if choice == 637:
        state.cnt_val = batch_mod(state.rs_val, 7) + 1
        for _ in range(state.cnt_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 638:
        state.ds_val = batch_mod(state.ms_val, 7) + 1
        for _ in range(state.ds_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 639:
        state.fb_val = batch_mod(state.aux_val, 7) + 1
        for _ in range(state.fb_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 640:
        if state.cnt_val > 2891:
            if state.aux_val < 7479: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 641:
        state.ds_val = batch_mod(state.cnt_val, 5) + 1
        for _ in range(state.ds_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 642:
        for _ in range(2):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.rs_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.rs_val) + idx_val))
    if choice == 643:
        for _ in range(3):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ms_val + state.rs_val) + idx_val))
    if choice == 644:
        for _ in range(3):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.aux_val + state.cnt_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ms_val + state.cnt_val) + idx_val))
    if choice == 645:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ state.ms_val))
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
    if choice == 646:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ state.ds_val))
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 647:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ms_val + state.aux_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + idx_val))
    if choice == 648:
        state.ms_val = to_int32(to_int32(state.last_rs_val * 3) + batch_div(state.cnt_val, 8))
        if state.ms_val > state.rs_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ idx_val))
    if choice == 649:
        for _ in range(3):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.fb_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + idx_val))
    if choice == 650:
        state.cnt_val = to_int32(to_int32(state.aux_val * 7) + batch_div(state.rs_val, 6))
        if state.cnt_val > state.ds_val:
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
    if choice == 651:
        state.last_rs_val = to_int32(to_int32(state.rs_val * 9) + batch_div(state.aux_val, 2))
        if state.last_rs_val > state.cnt_val:
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ idx_val))
    if choice == 652:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 9) + batch_div(state.ds_val, 8))
        if state.last_rs_val > state.fb_val:
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 653:
        if state.aux_val > 4503:
            if state.last_rs_val < 5496: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 654:
        state.rs_val = batch_mod(state.cnt_val, 10) + 1
        for _ in range(state.rs_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 655:
        state.last_rs_val = batch_mod(state.aux_val, 5) + 1
        for _ in range(state.last_rs_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 656:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.rs_val + state.last_rs_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ds_val + state.last_rs_val) + idx_val))
    if choice == 657:
        state.rs_val = batch_mod(state.fb_val, 10) + 1
        for _ in range(state.rs_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 658:
        state.cnt_val = batch_mod(state.fb_val, 10) + 1
        for _ in range(state.cnt_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 659:
        state.rs_val = to_int32(to_int32(state.aux_val * 2) + batch_div(state.fb_val, 6))
        if state.rs_val > state.ds_val:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
    if choice == 660:
        for _ in range(2):
            for _ in range(3):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.fb_val) + idx_val))
    if choice == 661:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
    if choice == 662:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ state.fb_val))
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
    if choice == 663:
        state.ms_val = to_int32(to_int32(state.last_rs_val * 8) + batch_div(state.rs_val, 8))
        if state.ms_val > state.cnt_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ idx_val))
    if choice == 664:
        state.fb_val = to_int32(to_int32(state.ms_val * 2) + batch_div(state.last_rs_val, 2))
        if state.fb_val > state.rs_val:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
    if choice == 665:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ state.last_rs_val))
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
    if choice == 666:
        if state.last_rs_val > 1692:
            if state.rs_val < 8105: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 667:
        state.last_rs_val = to_int32(to_int32(state.aux_val * 2) + batch_div(state.ds_val, 6))
        if state.last_rs_val > state.ms_val:
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ idx_val))
    if choice == 668:
        for _ in range(2):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.rs_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.rs_val) + idx_val))
    if choice == 669:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.fb_val + state.ds_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.aux_val + state.ds_val) + idx_val))
    if choice == 670:
        if state.last_rs_val > 6294:
            if state.ms_val < 8868: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 671:
        if state.rs_val > 4026:
            if state.last_rs_val < 7311: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 672:
        state.ds_val = to_int32(to_int32(state.fb_val * 5) + batch_div(state.rs_val, 8))
        if state.ds_val > state.ms_val:
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ idx_val))
    if choice == 673:
        for _ in range(3):
            for _ in range(3):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ms_val + state.aux_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.aux_val) + idx_val))
    if choice == 674:
        for _ in range(3):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.ms_val + state.rs_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.ds_val + state.rs_val) + idx_val))
    if choice == 675:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.ms_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
    if choice == 676:
        if state.ms_val > 3462:
            if state.cnt_val < 4427: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 677:
        state.fb_val = to_int32(to_int32(state.ds_val * 8) + batch_div(state.aux_val, 5))
        if state.fb_val > state.rs_val:
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
    if choice == 678:
        for _ in range(2):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.ds_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.last_rs_val + state.ds_val) + idx_val))
    if choice == 679:
        state.rs_val = batch_mod(state.aux_val, 10) + 1
        for _ in range(state.rs_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 680:
        state.last_rs_val = batch_mod(state.fb_val, 8) + 1
        for _ in range(state.last_rs_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 681:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ state.ms_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ data_val))
    if choice == 682:
        for _ in range(2):
            for _ in range(3):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.rs_val + state.aux_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.fb_val + state.aux_val) + idx_val))
    if choice == 683:
        for _ in range(2):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.fb_val + state.fb_val) + idx_val))
    if choice == 684:
        state.cnt_val = to_int32(to_int32(state.ds_val * 4) + batch_div(state.aux_val, 6))
        if state.cnt_val > state.ms_val:
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ idx_val))
    if choice == 685:
        state.last_rs_val = to_int32(to_int32(state.fb_val * 10) + batch_div(state.rs_val, 10))
        if state.last_rs_val > state.aux_val:
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ idx_val))
    if choice == 686:
        state.last_rs_val = batch_mod(state.fb_val, 9) + 1
        for _ in range(state.last_rs_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 687:
        if state.last_rs_val > 8709:
            if state.fb_val < 1320: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 688:
        state.rs_val = to_int32(to_int32(state.ds_val * 9) + batch_div(state.ms_val, 6))
        if state.rs_val > state.fb_val:
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ idx_val))
    if choice == 689:
        state.last_rs_val = batch_mod(state.cnt_val, 10) + 1
        for _ in range(state.last_rs_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 690:
        if state.aux_val > 1223:
            if state.cnt_val < 5576: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 691:
        state.rs_val = batch_mod(state.ms_val, 7) + 1
        for _ in range(state.rs_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 692:
        state.ms_val = batch_mod(state.aux_val, 7) + 1
        for _ in range(state.ms_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 693:
        for _ in range(3):
            for _ in range(3):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ds_val + state.ms_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.rs_val + state.ms_val) + idx_val))
    if choice == 694:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.fb_val))
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
    if choice == 695:
        state.cnt_val = batch_mod(state.aux_val, 8) + 1
        for _ in range(state.cnt_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 696:
        for _ in range(3):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ms_val + state.aux_val) + idx_val))
    if choice == 697:
        for _ in range(3):
            for _ in range(3):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.aux_val + state.cnt_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.fb_val + state.cnt_val) + idx_val))
    if choice == 698:
        if state.cnt_val > 1872:
            if state.aux_val < 7941: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 699:
        for _ in range(2):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.ms_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.ms_val) + idx_val))
    if choice == 700:
        if state.fb_val > 1398:
            if state.ms_val < 6160: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 701:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.ms_val + state.fb_val) + idx_val))
    if choice == 702:
        if state.cnt_val > 8145:
            if state.ms_val < 5807: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.cnt_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 703:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
    if choice == 704:
        for _ in range(2):
            for _ in range(3):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.rs_val + state.ds_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.aux_val + state.ds_val) + idx_val))
    if choice == 705:
        if state.rs_val > 8037:
            if state.cnt_val < 3686: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 706:
        if state.ms_val > 4060:
            if state.aux_val < 7453: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 707:
        state.fb_val = to_int32(to_int32(state.aux_val * 7) + batch_div(state.ms_val, 5))
        if state.fb_val > state.cnt_val:
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ idx_val))
    if choice == 708:
        for _ in range(3):
            for _ in range(3):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.ds_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.ds_val) + idx_val))
    if choice == 709:
        if state.ms_val > 2667:
            if state.aux_val < 6342: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 710:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.ds_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 711:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.rs_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.rs_val) + idx_val))
    if choice == 712:
        state.ds_val = to_int32(to_int32(state.fb_val * 7) + batch_div(state.ms_val, 4))
        if state.ds_val > state.rs_val:
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ idx_val))
    if choice == 713:
        for _ in range(3):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.rs_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 714:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ state.ds_val))
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
    if choice == 715:
        state.ds_val = batch_mod(state.ms_val, 6) + 1
        for _ in range(state.ds_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 716:
        state.aux_val = batch_mod(state.fb_val, 9) + 1
        for _ in range(state.aux_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 717:
        for _ in range(3):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.fb_val + state.cnt_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.rs_val + state.cnt_val) + idx_val))
    if choice == 718:
        if state.ms_val > 8101:
            if state.ds_val < 8783: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 719:
        for _ in range(2):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.fb_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + idx_val))
    if choice == 720:
        if state.ms_val > 4434:
            if state.last_rs_val < 1525: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 721:
        if state.ms_val > 8406:
            if state.fb_val < 5181: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 722:
        state.aux_val = to_int32(to_int32(state.fb_val * 9) + batch_div(state.last_rs_val, 4))
        if state.aux_val > state.ms_val:
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
    if choice == 723:
        if state.rs_val > 2778:
            if state.aux_val < 8626: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 724:
        state.last_rs_val = batch_mod(state.cnt_val, 5) + 1
        for _ in range(state.last_rs_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 725:
        if state.ms_val > 1033:
            if state.cnt_val < 8716: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 726:
        state.rs_val = to_int32(to_int32(state.ms_val * 5) + batch_div(state.cnt_val, 5))
        if state.rs_val > state.aux_val:
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ idx_val))
    if choice == 727:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.ms_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
    if choice == 728:
        if state.last_rs_val > 2675:
            if state.ds_val < 8966: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 729:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.aux_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
    if choice == 730:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ state.ds_val))
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
    if choice == 731:
        for _ in range(3):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.last_rs_val + state.last_rs_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.last_rs_val) + idx_val))
    if choice == 732:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ state.aux_val))
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
    if choice == 733:
        state.fb_val = batch_mod(state.ds_val, 10) + 1
        for _ in range(state.fb_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 734:
        for _ in range(2):
            for _ in range(2):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.cnt_val + state.aux_val) + idx_val))
    if choice == 735:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ state.rs_val))
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ data_val))
    if choice == 736:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ state.last_rs_val))
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ data_val))
    if choice == 737:
        state.ds_val = batch_mod(state.rs_val, 10) + 1
        for _ in range(state.ds_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 738:
        if state.ms_val > 5741:
            if state.aux_val < 7850: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.ms_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 739:
        state.aux_val = to_int32(to_int32(state.fb_val * 10) + batch_div(state.ds_val, 7))
        if state.aux_val > state.rs_val:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
    if choice == 740:
        for _ in range(2):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.ms_val + state.last_rs_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.ds_val + state.last_rs_val) + idx_val))
    if choice == 741:
        if state.fb_val > 1224:
            if state.rs_val < 8301: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 742:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 743:
        for _ in range(3):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.last_rs_val + state.rs_val) + idx_val))
    if choice == 744:
        if state.aux_val > 2937:
            if state.ds_val < 6828: state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.aux_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 745:
        state.last_rs_val = batch_mod(state.rs_val, 5) + 1
        for _ in range(state.last_rs_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 746:
        for _ in range(3):
            for _ in range(3):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + idx_val))
    if choice == 747:
        state.fb_val = to_int32(to_int32(state.ms_val * 9) + batch_div(state.ds_val, 5))
        if state.fb_val > state.cnt_val:
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
    if choice == 748:
        state.fb_val = batch_mod(state.aux_val, 5) + 1
        for _ in range(state.fb_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 749:
        if state.cnt_val > 3763:
            if state.last_rs_val < 2432: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 750:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ state.ds_val))
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
    if choice == 751:
        state.ms_val = to_int32(to_int32(state.cnt_val * 8) + batch_div(state.fb_val, 9))
        if state.ms_val > state.last_rs_val:
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
        else:
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ idx_val))
    if choice == 752:
        if state.ms_val > 7099:
            if state.cnt_val < 8486: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 753:
        state.ms_val = to_int32(to_int32(state.rs_val * 3) + batch_div(state.aux_val, 3))
        if state.ms_val > state.fb_val:
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ idx_val))
    if choice == 754:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.rs_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ data_val))
    if choice == 755:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ state.rs_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ data_val))
    if choice == 756:
        if state.ms_val > 6709:
            if state.rs_val < 2810: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 757:
        if state.rs_val > 7637:
            if state.aux_val < 1533: state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 758:
        state.ms_val = to_int32(to_int32(state.ds_val * 3) + batch_div(state.last_rs_val, 10))
        if state.ms_val > state.rs_val:
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
    if choice == 759:
        state.fb_val = batch_mod(state.ms_val, 7) + 1
        for _ in range(state.fb_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 760:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ state.ds_val))
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
    if choice == 761:
        if state.aux_val > 8059:
            if state.cnt_val < 5505: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.aux_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 762:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 5) + batch_div(state.rs_val, 9))
        if state.last_rs_val > state.fb_val:
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 763:
        if state.last_rs_val > 4639:
            if state.ms_val < 8055: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 764:
        state.aux_val = to_int32(to_int32(state.fb_val * 8) + batch_div(state.rs_val, 8))
        if state.aux_val > state.last_rs_val:
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
    if choice == 765:
        state.aux_val = batch_mod(state.fb_val, 7) + 1
        for _ in range(state.aux_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 766:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ state.cnt_val))
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ state.cnt_val))
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
    if choice == 767:
        state.ds_val = batch_mod(state.last_rs_val, 8) + 1
        for _ in range(state.ds_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 768:
        for _ in range(3):
            for _ in range(3):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.cnt_val + state.cnt_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.aux_val + state.cnt_val) + idx_val))
    if choice == 769:
        if state.ms_val > 2239:
            if state.fb_val < 8116: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 770:
        state.rs_val = to_int32(to_int32(state.aux_val * 9) + batch_div(state.fb_val, 9))
        if state.rs_val > state.ms_val:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
    if choice == 771:
        state.cnt_val = batch_mod(state.aux_val, 10) + 1
        for _ in range(state.cnt_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 772:
        state.cnt_val = batch_mod(state.fb_val, 8) + 1
        for _ in range(state.cnt_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 773:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.fb_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + idx_val))
    if choice == 774:
        for _ in range(2):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.fb_val + state.ds_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.ms_val + state.ds_val) + idx_val))
    if choice == 775:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 776:
        state.ds_val = batch_mod(state.rs_val, 6) + 1
        for _ in range(state.ds_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 777:
        state.rs_val = batch_mod(state.ms_val, 10) + 1
        for _ in range(state.rs_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 778:
        if state.ds_val > 3941:
            if state.fb_val < 3674: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 779:
        state.aux_val = batch_mod(state.fb_val, 10) + 1
        for _ in range(state.aux_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 780:
        state.aux_val = to_int32(to_int32(state.ds_val * 7) + batch_div(state.cnt_val, 9))
        if state.aux_val > state.fb_val:
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ idx_val))
    if choice == 781:
        state.fb_val = to_int32(to_int32(state.aux_val * 8) + batch_div(state.ds_val, 3))
        if state.fb_val > state.ms_val:
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ idx_val))
    if choice == 782:
        for _ in range(2):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.cnt_val + state.ds_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ds_val + state.ds_val) + idx_val))
    if choice == 783:
        if state.aux_val > 6357:
            if state.ms_val < 2066: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 784:
        for _ in range(3):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.last_rs_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.last_rs_val) + idx_val))
    if choice == 785:
        state.ms_val = to_int32(to_int32(state.last_rs_val * 7) + batch_div(state.aux_val, 10))
        if state.ms_val > state.cnt_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ idx_val))
    if choice == 786:
        state.ms_val = to_int32(to_int32(state.rs_val * 5) + batch_div(state.ds_val, 9))
        if state.ms_val > state.fb_val:
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ idx_val))
    if choice == 787:
        if state.cnt_val > 4491:
            if state.ds_val < 7788: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 788:
        for _ in range(3):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.ms_val + state.fb_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.fb_val + state.fb_val) + idx_val))
    if choice == 789:
        if state.ds_val > 7788:
            if state.ms_val < 7942: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 790:
        if state.last_rs_val > 1651:
            if state.rs_val < 8380: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 791:
        state.rs_val = to_int32(to_int32(state.aux_val * 10) + batch_div(state.fb_val, 2))
        if state.rs_val > state.ms_val:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
    if choice == 792:
        state.ds_val = batch_mod(state.rs_val, 10) + 1
        for _ in range(state.ds_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 793:
        state.fb_val = batch_mod(state.aux_val, 8) + 1
        for _ in range(state.fb_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 794:
        if state.ms_val > 3302:
            if state.ds_val < 5234: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 795:
        state.rs_val = batch_mod(state.fb_val, 5) + 1
        for _ in range(state.rs_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 796:
        if state.last_rs_val > 1896:
            if state.cnt_val < 4724: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 797:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.fb_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
    if choice == 798:
        state.ms_val = to_int32(to_int32(state.aux_val * 2) + batch_div(state.cnt_val, 3))
        if state.ms_val > state.ds_val:
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ idx_val))
    if choice == 799:
        state.fb_val = batch_mod(state.cnt_val, 8) + 1
        for _ in range(state.fb_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 800:
        state.last_rs_val = to_int32(to_int32(state.aux_val * 2) + batch_div(state.rs_val, 5))
        if state.last_rs_val > state.cnt_val:
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ idx_val))
    if choice == 801:
        for _ in range(2):
            for _ in range(3):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.fb_val + state.rs_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.cnt_val + state.rs_val) + idx_val))
    if choice == 802:
        if state.last_rs_val > 2025:
            if state.ms_val < 7917: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 803:
        state.ds_val = batch_mod(state.last_rs_val, 7) + 1
        for _ in range(state.ds_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 804:
        if state.last_rs_val > 3139:
            if state.rs_val < 6860: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 805:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.ms_val + state.ms_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.ds_val + state.ms_val) + idx_val))
    if choice == 806:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.rs_val + state.rs_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 807:
        for _ in range(3):
            for _ in range(3):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.fb_val + state.fb_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.rs_val + state.fb_val) + idx_val))
    if choice == 808:
        if state.fb_val > 5937:
            if state.ms_val < 8999: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 809:
        for _ in range(2):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.ds_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.ds_val) + idx_val))
    if choice == 810:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.ds_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 811:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.last_rs_val + state.ms_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.ms_val) + idx_val))
    if choice == 812:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ state.rs_val))
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ data_val))
    if choice == 813:
        state.aux_val = to_int32(to_int32(state.fb_val * 2) + batch_div(state.ds_val, 9))
        if state.aux_val > state.rs_val:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
    if choice == 814:
        for _ in range(2):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.last_rs_val + state.rs_val) + idx_val))
    if choice == 815:
        state.ms_val = batch_mod(state.ds_val, 8) + 1
        for _ in range(state.ms_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 816:
        if state.fb_val > 3772:
            if state.last_rs_val < 6236: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.fb_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 817:
        for _ in range(3):
            for _ in range(3):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.fb_val + state.rs_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 818:
        state.cnt_val = batch_mod(state.ms_val, 6) + 1
        for _ in range(state.cnt_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 819:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ state.aux_val))
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
    if choice == 820:
        state.aux_val = batch_mod(state.cnt_val, 7) + 1
        for _ in range(state.aux_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 821:
        state.last_rs_val = batch_mod(state.ms_val, 5) + 1
        for _ in range(state.last_rs_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 822:
        if state.fb_val > 2811:
            if state.cnt_val < 4369: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 823:
        state.rs_val = to_int32(to_int32(state.fb_val * 7) + batch_div(state.aux_val, 4))
        if state.rs_val > state.last_rs_val:
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ idx_val))
    if choice == 824:
        state.fb_val = to_int32(to_int32(state.cnt_val * 9) + batch_div(state.rs_val, 2))
        if state.fb_val > state.aux_val:
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
        else:
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ idx_val))
    if choice == 825:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 5) + batch_div(state.rs_val, 6))
        if state.last_rs_val > state.fb_val:
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 826:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ state.last_rs_val))
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
    if choice == 827:
        for _ in range(3):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.fb_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.fb_val) + idx_val))
    if choice == 828:
        for _ in range(2):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.cnt_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.cnt_val) + idx_val))
    if choice == 829:
        state.ms_val = to_int32(to_int32(state.last_rs_val * 4) + batch_div(state.aux_val, 9))
        if state.ms_val > state.fb_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ idx_val))
    if choice == 830:
        for _ in range(3):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.aux_val + state.cnt_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.last_rs_val + state.cnt_val) + idx_val))
    if choice == 831:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
    if choice == 832:
        if state.aux_val > 8931:
            if state.cnt_val < 3827: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 833:
        state.ms_val = to_int32(to_int32(state.ds_val * 8) + batch_div(state.last_rs_val, 8))
        if state.ms_val > state.rs_val:
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
    if choice == 834:
        state.aux_val = to_int32(to_int32(state.last_rs_val * 6) + batch_div(state.rs_val, 8))
        if state.aux_val > state.ds_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ idx_val))
    if choice == 835:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ state.fb_val))
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
    if choice == 836:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 6) + batch_div(state.ds_val, 6))
        if state.last_rs_val > state.rs_val:
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 837:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ data_val))
    if choice == 838:
        state.aux_val = to_int32(to_int32(state.cnt_val * 8) + batch_div(state.ms_val, 7))
        if state.aux_val > state.ds_val:
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
        else:
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
    if choice == 839:
        if state.fb_val > 2499:
            if state.ms_val < 3820: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 840:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 841:
        state.ds_val = to_int32(to_int32(state.fb_val * 4) + batch_div(state.cnt_val, 8))
        if state.ds_val > state.aux_val:
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ idx_val))
    if choice == 842:
        for _ in range(3):
            for _ in range(3):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.cnt_val + state.ds_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.aux_val + state.ds_val) + idx_val))
    if choice == 843:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ state.cnt_val))
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
    if choice == 844:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.rs_val + state.cnt_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.aux_val + state.cnt_val) + idx_val))
    if choice == 845:
        if state.fb_val > 6806:
            if state.rs_val < 6155: state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.fb_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 846:
        state.fb_val = to_int32(to_int32(state.ds_val * 4) + batch_div(state.ms_val, 2))
        if state.fb_val > state.aux_val:
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
    if choice == 847:
        state.last_rs_val = batch_mod(state.fb_val, 5) + 1
        for _ in range(state.last_rs_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 848:
        if state.ms_val > 6586:
            if state.last_rs_val < 6128: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 849:
        for _ in range(3):
            for _ in range(3):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.cnt_val + state.ms_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.fb_val + state.ms_val) + idx_val))
    if choice == 850:
        state.ms_val = batch_mod(state.fb_val, 7) + 1
        for _ in range(state.ms_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 851:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
    if choice == 852:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ state.last_rs_val))
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
    if choice == 853:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ state.cnt_val))
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
    if choice == 854:
        if state.rs_val > 6905:
            if state.fb_val < 8900: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 855:
        state.cnt_val = to_int32(to_int32(state.ms_val * 8) + batch_div(state.rs_val, 9))
        if state.cnt_val > state.last_rs_val:
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ idx_val))
    if choice == 856:
        state.last_rs_val = batch_mod(state.ds_val, 6) + 1
        for _ in range(state.last_rs_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 857:
        for _ in range(3):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.ds_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.ds_val) + idx_val))
    if choice == 858:
        for _ in range(2):
            for _ in range(3):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.rs_val + state.ds_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.aux_val + state.ds_val) + idx_val))
    if choice == 859:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.cnt_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ms_val + state.cnt_val) + idx_val))
    if choice == 860:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.fb_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
    if choice == 861:
        if state.rs_val > 3281:
            if state.aux_val < 3764: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 862:
        state.last_rs_val = batch_mod(state.cnt_val, 10) + 1
        for _ in range(state.last_rs_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 863:
        state.fb_val = to_int32(to_int32(state.rs_val * 9) + batch_div(state.ds_val, 3))
        if state.fb_val > state.aux_val:
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ idx_val))
    if choice == 864:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.rs_val + state.fb_val) + idx_val))
    if choice == 865:
        if state.ms_val > 2073:
            if state.ds_val < 4923: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.ms_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 866:
        for _ in range(3):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ms_val + state.aux_val) + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + idx_val))
    if choice == 867:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ state.aux_val))
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ data_val))
    if choice == 868:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.ms_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
    if choice == 869:
        state.cnt_val = batch_mod(state.ms_val, 6) + 1
        for _ in range(state.cnt_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 870:
        if state.aux_val > 4076:
            if state.fb_val < 5217: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 871:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.rs_val + state.fb_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.aux_val + state.fb_val) + idx_val))
    if choice == 872:
        for _ in range(3):
            for _ in range(3):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ds_val + state.ds_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.rs_val + state.ds_val) + idx_val))
    if choice == 873:
        state.ds_val = batch_mod(state.last_rs_val, 5) + 1
        for _ in range(state.ds_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 874:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ state.ms_val))
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
    if choice == 875:
        for _ in range(2):
            for _ in range(3):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.last_rs_val + state.last_rs_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.rs_val + state.last_rs_val) + idx_val))
    if choice == 876:
        if state.ms_val > 2436:
            if state.ds_val < 7733: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 877:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.rs_val + state.last_rs_val) + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ms_val + state.last_rs_val) + idx_val))
    if choice == 878:
        state.ds_val = to_int32(to_int32(state.aux_val * 3) + batch_div(state.fb_val, 4))
        if state.ds_val > state.rs_val:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ idx_val))
    if choice == 879:
        for _ in range(3):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.cnt_val + state.last_rs_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.ms_val + state.last_rs_val) + idx_val))
    if choice == 880:
        if state.fb_val > 1999:
            if state.ms_val < 7638: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.fb_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 881:
        state.ms_val = to_int32(to_int32(state.fb_val * 5) + batch_div(state.ds_val, 10))
        if state.ms_val > state.rs_val:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ idx_val))
    if choice == 882:
        for _ in range(3):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ms_val + state.aux_val) + idx_val))
    if choice == 883:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ state.last_rs_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ data_val))
    if choice == 884:
        state.fb_val = batch_mod(state.rs_val, 10) + 1
        for _ in range(state.fb_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 885:
        for _ in range(2):
            for _ in range(3):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.fb_val + state.aux_val) + idx_val))
    if choice == 886:
        state.cnt_val = to_int32(to_int32(state.ms_val * 8) + batch_div(state.ds_val, 5))
        if state.cnt_val > state.rs_val:
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ idx_val))
    if choice == 887:
        for _ in range(3):
            for _ in range(3):
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.ds_val + state.ms_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.fb_val + state.ms_val) + idx_val))
    if choice == 888:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ state.rs_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ data_val))
    if choice == 889:
        state.cnt_val = batch_mod(state.ds_val, 8) + 1
        for _ in range(state.cnt_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 890:
        state.cnt_val = batch_mod(state.aux_val, 5) + 1
        for _ in range(state.cnt_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 891:
        for _ in range(3):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.cnt_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.cnt_val) + idx_val))
    if choice == 892:
        state.cnt_val = batch_mod(state.fb_val, 7) + 1
        for _ in range(state.cnt_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 893:
        if state.last_rs_val > 8919:
            if state.cnt_val < 1286: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 894:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ state.aux_val))
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
    if choice == 895:
        state.fb_val = to_int32(to_int32(state.ms_val * 6) + batch_div(state.last_rs_val, 3))
        if state.fb_val > state.rs_val:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
    if choice == 896:
        if state.ds_val > 5107:
            if state.cnt_val < 5133: state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 897:
        state.aux_val = batch_mod(state.ds_val, 10) + 1
        for _ in range(state.aux_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 898:
        if state.ds_val > 2625:
            if state.fb_val < 1681: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 899:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ state.aux_val))
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
    if choice == 900:
        state.ms_val = to_int32(to_int32(state.fb_val * 10) + batch_div(state.ds_val, 4))
        if state.ms_val > state.rs_val:
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
        else:
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ idx_val))
    if choice == 901:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ state.ds_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
    if choice == 902:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.ds_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
    if choice == 903:
        for _ in range(3):
            for _ in range(3):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.last_rs_val + state.ms_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.cnt_val + state.ms_val) + idx_val))
    if choice == 904:
        if state.ms_val > 4312:
            if state.aux_val < 2374: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 905:
        state.ds_val = batch_mod(state.rs_val, 10) + 1
        for _ in range(state.ds_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 906:
        state.cnt_val = to_int32(to_int32(state.rs_val * 3) + batch_div(state.last_rs_val, 4))
        if state.cnt_val > state.ms_val:
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ idx_val))
    if choice == 907:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ state.fb_val))
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
    if choice == 908:
        for _ in range(2):
            for _ in range(3):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + idx_val))
    if choice == 909:
        if state.ds_val > 4389:
            if state.fb_val < 1378: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 910:
        if state.fb_val > 3062:
            if state.cnt_val < 4834: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 911:
        state.cnt_val = batch_mod(state.rs_val, 7) + 1
        for _ in range(state.cnt_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 912:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.ms_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
    if choice == 913:
        if state.ms_val > 1178:
            if state.ds_val < 6075: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 914:
        state.last_rs_val = batch_mod(state.ms_val, 5) + 1
        for _ in range(state.last_rs_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 915:
        state.last_rs_val = batch_mod(state.cnt_val, 7) + 1
        for _ in range(state.last_rs_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 916:
        state.rs_val = batch_mod(state.ds_val, 10) + 1
        for _ in range(state.rs_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 917:
        if state.last_rs_val > 6588:
            if state.aux_val < 7971: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 918:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ state.aux_val))
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
    if choice == 919:
        state.aux_val = to_int32(to_int32(state.cnt_val * 3) + batch_div(state.ms_val, 2))
        if state.aux_val > state.rs_val:
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
        else:
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
    if choice == 920:
        if state.fb_val > 4052:
            if state.last_rs_val < 2005: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 921:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.fb_val + state.rs_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.aux_val + state.rs_val) + idx_val))
    if choice == 922:
        state.ms_val = to_int32(to_int32(state.rs_val * 7) + batch_div(state.aux_val, 4))
        if state.ms_val > state.ds_val:
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ idx_val))
    if choice == 923:
        for _ in range(3):
            for _ in range(2):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.aux_val + state.last_rs_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.cnt_val + state.last_rs_val) + idx_val))
    if choice == 924:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ state.rs_val))
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ state.rs_val))
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ data_val))
    if choice == 925:
        for _ in range(3):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.ds_val + state.rs_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.rs_val + state.rs_val) + idx_val))
    if choice == 926:
        state.cnt_val = to_int32(to_int32(state.ds_val * 9) + batch_div(state.fb_val, 5))
        if state.cnt_val > state.ms_val:
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ idx_val))
    if choice == 927:
        if state.cnt_val > 4304:
            if state.rs_val < 4282: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 928:
        state.cnt_val = to_int32(to_int32(state.aux_val * 7) + batch_div(state.rs_val, 7))
        if state.cnt_val > state.fb_val:
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
    if choice == 929:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.aux_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
    if choice == 930:
        if state.last_rs_val > 8552:
            if state.cnt_val < 4154: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 931:
        if state.cnt_val > 8888:
            if state.last_rs_val < 2159: state.ms_val = to_int32(state.ms_val + (state.aux_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 932:
        if state.fb_val > 5678:
            if state.cnt_val < 3279: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 933:
        state.last_rs_val = batch_mod(state.fb_val, 8) + 1
        for _ in range(state.last_rs_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 934:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
    if choice == 935:
        state.ms_val = batch_mod(state.aux_val, 6) + 1
        for _ in range(state.ms_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 936:
        if state.aux_val > 7844:
            if state.rs_val < 6593: state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.aux_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 937:
        if state.cnt_val > 2945:
            if state.ms_val < 5350: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 938:
        if state.aux_val > 6290:
            if state.rs_val < 6048: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 939:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.ms_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
    if choice == 940:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ state.fb_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
    if choice == 941:
        if state.rs_val > 8695:
            if state.last_rs_val < 1747: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 942:
        for _ in range(2):
            for _ in range(3):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.cnt_val + state.aux_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + idx_val))
    if choice == 943:
        for _ in range(2):
            for _ in range(3):
                state.ms_val = to_int32(state.ms_val ^ to_int32(to_int32(state.fb_val + state.fb_val) + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(to_int32(state.ms_val + state.fb_val) + idx_val))
    if choice == 944:
        state.rs_val = batch_mod(state.fb_val, 5) + 1
        for _ in range(state.rs_val):
            state.ds_val = to_int32(state.ds_val + data_val)
    if choice == 945:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.ds_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
    if choice == 946:
        state.last_rs_val = to_int32(to_int32(state.rs_val * 2) + batch_div(state.cnt_val, 8))
        if state.last_rs_val > state.ds_val:
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ idx_val))
    if choice == 947:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ state.fb_val))
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
    if choice == 948:
        state.aux_val = to_int32(to_int32(state.rs_val * 9) + batch_div(state.ms_val, 9))
        if state.aux_val > state.last_rs_val:
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ data_val))
        else:
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ idx_val))
    if choice == 949:
        state.last_rs_val = batch_mod(state.aux_val, 10) + 1
        for _ in range(state.last_rs_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 950:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ state.last_rs_val))
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
    if choice == 951:
        for _ in range(2):
            for _ in range(2):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.last_rs_val + state.last_rs_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.cnt_val + state.last_rs_val) + idx_val))
    if choice == 952:
        state.ds_val = batch_mod(state.aux_val, 7) + 1
        for _ in range(state.ds_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 953:
        state.fb_val = to_int32(to_int32(state.ds_val * 4) + batch_div(state.aux_val, 5))
        if state.fb_val > state.ms_val:
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
    if choice == 954:
        state.ms_val = to_int32(to_int32(state.cnt_val * 3) + batch_div(state.aux_val, 3))
        if state.ms_val > state.fb_val:
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
        else:
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ idx_val))
    if choice == 955:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.aux_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.aux_val))
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
    if choice == 956:
        state.aux_val = batch_mod(state.cnt_val, 10) + 1
        for _ in range(state.aux_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 957:
        state.aux_val = batch_mod(state.rs_val, 9) + 1
        for _ in range(state.aux_val):
            state.cnt_val = to_int32(state.cnt_val + data_val)
    if choice == 958:
        if state.ms_val > 3071:
            if state.rs_val < 5141: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.ms_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 959:
        if state.rs_val > 1306:
            if state.cnt_val < 6305: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 960:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ state.last_rs_val))
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ state.last_rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
    if choice == 961:
        state.cnt_val = to_int32(to_int32(state.aux_val * 10) + batch_div(state.fb_val, 3))
        if state.cnt_val > state.last_rs_val:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
    if choice == 962:
        for _ in range(3):
            for _ in range(3):
                state.rs_val = to_int32(state.rs_val ^ to_int32(to_int32(state.aux_val + state.ms_val) + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.rs_val + state.ms_val) + idx_val))
    if choice == 963:
        state.last_rs_val = to_int32(to_int32(state.ms_val * 10) + batch_div(state.ds_val, 8))
        if state.last_rs_val > state.aux_val:
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
        else:
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ idx_val))
    if choice == 964:
        state.ms_val = to_int32(to_int32(state.aux_val * 5) + batch_div(state.ds_val, 6))
        if state.ms_val > state.cnt_val:
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ idx_val))
    if choice == 965:
        if state.rs_val > 3544:
            if state.ds_val < 6959: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 966:
        state.cnt_val = batch_mod(state.rs_val, 8) + 1
        for _ in range(state.cnt_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 967:
        state.cnt_val = batch_mod(state.ds_val, 9) + 1
        for _ in range(state.cnt_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 968:
        if state.last_rs_val > 4014:
            if state.ds_val < 8540: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 969:
        state.rs_val = to_int32(to_int32(state.aux_val * 8) + batch_div(state.ds_val, 3))
        if state.rs_val > state.last_rs_val:
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
    if choice == 970:
        state.cnt_val = to_int32(to_int32(state.ds_val * 8) + batch_div(state.last_rs_val, 4))
        if state.cnt_val > state.aux_val:
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ idx_val))
    if choice == 971:
        if state.cnt_val > 1078:
            if state.rs_val < 5643: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 972:
        state.aux_val = to_int32(to_int32(state.last_rs_val * 7) + batch_div(state.ds_val, 5))
        if state.aux_val > state.fb_val:
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ data_val))
        else:
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ idx_val))
    if choice == 973:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ state.ds_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
    if choice == 974:
        if state.fb_val > 7527:
            if state.ms_val < 1623: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 975:
        state.cnt_val = batch_mod(state.rs_val, 8) + 1
        for _ in range(state.cnt_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 976:
        if state.ms_val > 4585:
            if state.aux_val < 2915: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 977:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.ms_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
    if choice == 978:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ state.ds_val))
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
    if choice == 979:
        if state.cnt_val > 3486:
            if state.aux_val < 7289: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 980:
        for _ in range(3):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + idx_val))
    if choice == 981:
        if state.ds_val > 3252:
            if state.fb_val < 1101: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 982:
        state.cnt_val = batch_mod(state.ms_val, 5) + 1
        for _ in range(state.cnt_val):
            state.aux_val = to_int32(state.aux_val + data_val)
    if choice == 983:
        state.rs_val = batch_mod(state.ds_val, 6) + 1
        for _ in range(state.rs_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 984:
        state.last_rs_val = to_int32(to_int32(state.ds_val * 4) + batch_div(state.cnt_val, 9))
        if state.last_rs_val > state.aux_val:
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
        else:
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ idx_val))
    if choice == 985:
        state.cnt_val = to_int32(to_int32(state.aux_val * 6) + batch_div(state.ds_val, 9))
        if state.cnt_val > state.last_rs_val:
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
    if choice == 986:
        state.cnt_val = to_int32(to_int32(state.aux_val * 7) + batch_div(state.fb_val, 6))
        if state.cnt_val > state.rs_val:
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
        else:
            state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
    if choice == 987:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.aux_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + idx_val))
    if choice == 988:
        state.ds_val = batch_mod(state.aux_val, 5) + 1
        for _ in range(state.ds_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 989:
        if state.aux_val > 2074:
            if state.cnt_val < 3772: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.aux_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 990:
        state.ds_val = batch_mod(state.last_rs_val, 9) + 1
        for _ in range(state.ds_val):
            state.ms_val = to_int32(state.ms_val + data_val)
    if choice == 991:
        state.ms_val = batch_mod(state.ds_val, 8) + 1
        for _ in range(state.ms_val):
            state.last_rs_val = to_int32(state.last_rs_val + data_val)
    if choice == 992:
        for _ in range(3):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.last_rs_val + state.fb_val) + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(to_int32(state.ds_val + state.fb_val) + idx_val))
    if choice == 993:
        for _ in range(3):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.ds_val + state.aux_val) + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + idx_val))
    if choice == 994:
        state.cnt_val = batch_mod(state.aux_val, 6) + 1
        for _ in range(state.cnt_val):
            state.rs_val = to_int32(state.rs_val + data_val)
    if choice == 995:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ state.ms_val))
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ state.ms_val))
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
    if choice == 996:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.fb_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.fb_val))
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
    if choice == 997:
        for _ in range(3):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(to_int32(state.cnt_val + state.aux_val) + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(to_int32(state.aux_val + state.aux_val) + idx_val))
    if choice == 998:
        state.rs_val = batch_mod(state.aux_val, 6) + 1
        for _ in range(state.rs_val):
            state.fb_val = to_int32(state.fb_val + data_val)
    if choice == 999:
        if state.rs_val > 2836:
            if state.fb_val < 6017: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 400:
        if state.ds_val > state.rs_val:
            if state.ms_val < state.last_rs_val: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 401:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ state.fb_val))
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ state.last_rs_val))
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ state.ms_val))
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
    if choice == 402:
        state.rs_val = to_int32(to_int32(state.ms_val * 19) + batch_div(state.cnt_val, 8))
        if state.rs_val > state.last_rs_val: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
        else: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ idx_val))
    if choice == 403:
        for _ in range(2):
            for _ in range(2):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.last_rs_val + state.fb_val + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.cnt_val + state.ds_val + idx_val))
    if choice == 404:
        if state.aux_val > state.ms_val:
            if state.cnt_val < state.last_rs_val: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 405:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ state.aux_val))
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ state.ms_val))
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ state.cnt_val))
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
    if choice == 406:
        state.ds_val = to_int32(to_int32(state.last_rs_val * 13) + batch_div(state.fb_val, 5))
        if state.ds_val > state.rs_val: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
    if choice == 407:
        for _ in range(2):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.rs_val + state.ms_val + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.ds_val + state.aux_val + idx_val))
    if choice == 408:
        if state.ms_val > state.rs_val:
            if state.last_rs_val < state.fb_val: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 409:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.cnt_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ state.ds_val))
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ state.last_rs_val))
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
    if choice == 410:
        state.fb_val = to_int32(to_int32(state.ds_val * 19) + batch_div(state.cnt_val, 5))
        if state.fb_val > state.aux_val: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
        else: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ idx_val))
    if choice == 411:
        for _ in range(2):
            for _ in range(2):
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.aux_val + state.rs_val + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.ds_val + state.last_rs_val + idx_val))
    if choice == 412:
        if state.aux_val > state.rs_val:
            if state.cnt_val < state.ds_val: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
            else: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ to_int32(data_val + idx_val)))
    if choice == 413:
        for _ in range(3):
            state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ state.cnt_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.rs_val))
            state.fb_val = to_int32(state.fb_val + (state.ms_val ^ state.aux_val))
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ data_val))
    if choice == 414:
        state.ds_val = to_int32(to_int32(state.fb_val * 18) + batch_div(state.last_rs_val, 9))
        if state.ds_val > state.ms_val: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ idx_val))
    if choice == 415:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.ms_val + state.ds_val + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.rs_val + state.aux_val + idx_val))
    if choice == 416:
        if state.fb_val > state.rs_val:
            if state.last_rs_val < state.ms_val: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 417:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ state.ds_val))
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ state.ms_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.fb_val ^ data_val))
    if choice == 418:
        state.aux_val = to_int32(to_int32(state.last_rs_val * 18) + batch_div(state.cnt_val, 3))
        if state.aux_val > state.ms_val: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ data_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ idx_val))
    if choice == 419:
        for _ in range(2):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.ds_val + state.aux_val + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.ms_val + state.cnt_val + idx_val))
    if choice == 420:
        if state.fb_val > state.ms_val:
            if state.rs_val < state.last_rs_val: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 421:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.cnt_val))
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ state.ds_val))
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ state.last_rs_val))
            state.cnt_val = to_int32(state.cnt_val + (state.aux_val ^ data_val))
    if choice == 422:
        state.ds_val = to_int32(to_int32(state.last_rs_val * 10) + batch_div(state.rs_val, 10))
        if state.ds_val > state.aux_val: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ data_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ idx_val))
    if choice == 423:
        for _ in range(2):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.fb_val + state.last_rs_val + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(state.ms_val + state.cnt_val + idx_val))
    if choice == 424:
        if state.last_rs_val > state.ds_val:
            if state.aux_val < state.ms_val: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 425:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ state.rs_val))
            state.ms_val = to_int32(state.ms_val + (state.fb_val ^ state.aux_val))
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ state.last_rs_val))
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ data_val))
    if choice == 426:
        state.rs_val = to_int32(to_int32(state.ms_val * 4) + batch_div(state.ds_val, 10))
        if state.rs_val > state.aux_val: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ data_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ idx_val))
    if choice == 427:
        for _ in range(2):
            for _ in range(2):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.aux_val + state.last_rs_val + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.cnt_val + state.fb_val + idx_val))
    if choice == 428:
        if state.cnt_val > state.last_rs_val:
            if state.ds_val < state.aux_val: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 429:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ state.ds_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
    if choice == 430:
        state.rs_val = to_int32(to_int32(state.last_rs_val * 19) + batch_div(state.aux_val, 9))
        if state.rs_val > state.cnt_val: state.ms_val = to_int32(state.ms_val + (state.ds_val ^ data_val))
        else: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
    if choice == 431:
        for _ in range(2):
            for _ in range(2):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.last_rs_val + state.ms_val + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.cnt_val + state.fb_val + idx_val))
    if choice == 432:
        if state.last_rs_val > state.fb_val:
            if state.rs_val < state.cnt_val: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.aux_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 433:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ state.ds_val))
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ state.aux_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.rs_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
    if choice == 434:
        state.ms_val = to_int32(to_int32(state.last_rs_val * 10) + batch_div(state.rs_val, 9))
        if state.ms_val > state.aux_val: state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
        else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ idx_val))
    if choice == 435:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.last_rs_val + state.fb_val + data_val))
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.aux_val + state.ms_val + idx_val))
    if choice == 436:
        if state.cnt_val > state.rs_val:
            if state.fb_val < state.aux_val: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 437:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ state.last_rs_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ state.cnt_val))
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ state.ms_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
    if choice == 438:
        state.rs_val = to_int32(to_int32(state.fb_val * 20) + batch_div(state.ms_val, 2))
        if state.rs_val > state.aux_val: state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
        else: state.ds_val = to_int32(state.ds_val + (state.last_rs_val ^ idx_val))
    if choice == 439:
        for _ in range(2):
            for _ in range(2):
                state.fb_val = to_int32(state.fb_val ^ to_int32(state.rs_val + state.last_rs_val + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.fb_val + state.ds_val + idx_val))
    if choice == 440:
        if state.cnt_val > state.aux_val:
            if state.last_rs_val < state.fb_val: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 441:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ state.ds_val))
            state.rs_val = to_int32(state.rs_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ state.last_rs_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
    if choice == 442:
        state.fb_val = to_int32(to_int32(state.cnt_val * 9) + batch_div(state.ms_val, 7))
        if state.fb_val > state.last_rs_val: state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ds_val ^ idx_val))
    if choice == 443:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.cnt_val + state.last_rs_val + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.aux_val + state.ds_val + idx_val))
    if choice == 444:
        if state.ds_val > state.rs_val:
            if state.cnt_val < state.fb_val: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 445:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ state.last_rs_val))
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ state.rs_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
    if choice == 446:
        state.ds_val = to_int32(to_int32(state.ms_val * 15) + batch_div(state.aux_val, 6))
        if state.ds_val > state.fb_val: state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ idx_val))
    if choice == 447:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.ms_val + state.aux_val + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.rs_val + state.last_rs_val + idx_val))
    if choice == 448:
        if state.ds_val > state.last_rs_val:
            if state.fb_val < state.ms_val: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ data_val))
            else: state.aux_val = to_int32(state.aux_val + (state.cnt_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.aux_val ^ to_int32(data_val + idx_val)))
    if choice == 449:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.ds_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ state.last_rs_val))
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ state.fb_val))
            state.cnt_val = to_int32(state.cnt_val + (state.rs_val ^ data_val))
    if choice == 450:
        state.cnt_val = to_int32(to_int32(state.rs_val * 9) + batch_div(state.aux_val, 3))
        if state.cnt_val > state.ds_val: state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ idx_val))
    if choice == 451:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.fb_val + state.last_rs_val + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(state.aux_val + state.cnt_val + idx_val))
    if choice == 452:
        if state.last_rs_val > state.rs_val:
            if state.cnt_val < state.ds_val: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 453:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ state.rs_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ state.aux_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.fb_val))
            state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ data_val))
    if choice == 454:
        state.cnt_val = to_int32(to_int32(state.last_rs_val * 8) + batch_div(state.aux_val, 8))
        if state.cnt_val > state.ds_val: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ data_val))
        else: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ idx_val))
    if choice == 455:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.ms_val + state.rs_val + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.aux_val + state.fb_val + idx_val))
    if choice == 456:
        if state.rs_val > state.ms_val:
            if state.aux_val < state.last_rs_val: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ idx_val))
        else: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 457:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.fb_val ^ state.last_rs_val))
            state.fb_val = to_int32(state.fb_val + (state.ds_val ^ state.ms_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ state.cnt_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ data_val))
    if choice == 458:
        state.fb_val = to_int32(to_int32(state.ms_val * 3) + batch_div(state.rs_val, 8))
        if state.fb_val > state.ds_val: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.aux_val ^ idx_val))
    if choice == 459:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.fb_val + state.ds_val + data_val))
                state.fb_val = to_int32(state.fb_val ^ to_int32(state.rs_val + state.aux_val + idx_val))
    if choice == 460:
        if state.ds_val > state.aux_val:
            if state.fb_val < state.last_rs_val: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 461:
        for _ in range(3):
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ state.last_rs_val))
            state.aux_val = to_int32(state.aux_val + (state.ds_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ state.rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ data_val))
    if choice == 462:
        state.cnt_val = to_int32(to_int32(state.last_rs_val * 19) + batch_div(state.ds_val, 2))
        if state.cnt_val > state.aux_val: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
        else: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ idx_val))
    if choice == 463:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.ms_val + state.cnt_val + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.aux_val + state.ds_val + idx_val))
    if choice == 464:
        if state.last_rs_val > state.ms_val:
            if state.cnt_val < state.ds_val: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
        else: state.rs_val = to_int32(state.rs_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 465:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ state.ds_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.rs_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.aux_val ^ data_val))
    if choice == 466:
        state.cnt_val = to_int32(to_int32(state.ms_val * 4) + batch_div(state.ds_val, 9))
        if state.cnt_val > state.rs_val: state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ data_val))
        else: state.fb_val = to_int32(state.fb_val + (state.aux_val ^ idx_val))
    if choice == 467:
        for _ in range(2):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.ds_val + state.fb_val + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.last_rs_val + state.cnt_val + idx_val))
    if choice == 468:
        if state.last_rs_val > state.cnt_val:
            if state.ds_val < state.rs_val: state.ms_val = to_int32(state.ms_val + (state.aux_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 469:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ state.fb_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ state.rs_val))
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.aux_val))
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
    if choice == 470:
        state.last_rs_val = to_int32(to_int32(state.cnt_val * 7) + batch_div(state.ms_val, 9))
        if state.last_rs_val > state.fb_val: state.aux_val = to_int32(state.aux_val + (state.ds_val ^ data_val))
        else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ idx_val))
    if choice == 471:
        for _ in range(2):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.aux_val + state.cnt_val + data_val))
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.last_rs_val + state.ds_val + idx_val))
    if choice == 472:
        if state.aux_val > state.last_rs_val:
            if state.rs_val < state.ds_val: state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ data_val))
            else: state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ to_int32(data_val + idx_val)))
    if choice == 473:
        for _ in range(3):
            state.aux_val = to_int32(state.aux_val + (state.fb_val ^ state.rs_val))
            state.fb_val = to_int32(state.fb_val + (state.last_rs_val ^ state.cnt_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.ms_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
    if choice == 474:
        state.ds_val = to_int32(to_int32(state.cnt_val * 19) + batch_div(state.ms_val, 9))
        if state.ds_val > state.rs_val: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
        else: state.aux_val = to_int32(state.aux_val + (state.fb_val ^ idx_val))
    if choice == 475:
        for _ in range(2):
            for _ in range(2):
                state.last_rs_val = to_int32(state.last_rs_val ^ to_int32(state.rs_val + state.cnt_val + data_val))
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.last_rs_val + state.ms_val + idx_val))
    if choice == 476:
        if state.last_rs_val > state.rs_val:
            if state.aux_val < state.ds_val: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
            else: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ idx_val))
        else: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ to_int32(data_val + idx_val)))
    if choice == 477:
        for _ in range(3):
            state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ state.aux_val))
            state.cnt_val = to_int32(state.cnt_val + (state.ms_val ^ state.fb_val))
            state.ms_val = to_int32(state.ms_val + (state.rs_val ^ state.ds_val))
            state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ data_val))
    if choice == 478:
        state.aux_val = to_int32(to_int32(state.ds_val * 14) + batch_div(state.last_rs_val, 2))
        if state.aux_val > state.cnt_val: state.ms_val = to_int32(state.ms_val + (state.rs_val ^ data_val))
        else: state.ms_val = to_int32(state.ms_val + (state.fb_val ^ idx_val))
    if choice == 479:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.ds_val + state.last_rs_val + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.rs_val + state.aux_val + idx_val))
    if choice == 480:
        if state.aux_val > state.last_rs_val:
            if state.ms_val < state.cnt_val: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 481:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.aux_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ state.cnt_val))
            state.ds_val = to_int32(state.ds_val + (state.rs_val ^ state.fb_val))
            state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
    if choice == 482:
        state.rs_val = to_int32(to_int32(state.ds_val * 3) + batch_div(state.fb_val, 2))
        if state.rs_val > state.cnt_val: state.aux_val = to_int32(state.aux_val + (state.ms_val ^ data_val))
        else: state.aux_val = to_int32(state.aux_val + (state.last_rs_val ^ idx_val))
    if choice == 483:
        for _ in range(2):
            for _ in range(2):
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.ms_val + state.rs_val + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.cnt_val + state.last_rs_val + idx_val))
    if choice == 484:
        if state.ds_val > state.rs_val:
            if state.fb_val < state.aux_val: state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ data_val))
            else: state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ idx_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ms_val ^ to_int32(data_val + idx_val)))
    if choice == 485:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.fb_val ^ state.ds_val))
            state.fb_val = to_int32(state.fb_val + (state.rs_val ^ state.ms_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.last_rs_val))
            state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
    if choice == 486:
        state.fb_val = to_int32(to_int32(state.rs_val * 20) + batch_div(state.aux_val, 5))
        if state.fb_val > state.ms_val: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.ds_val ^ idx_val))
    if choice == 487:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.ds_val + state.aux_val + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.rs_val + state.cnt_val + idx_val))
    if choice == 488:
        if state.fb_val > state.last_rs_val:
            if state.aux_val < state.rs_val: state.ds_val = to_int32(state.ds_val + (state.cnt_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.ms_val ^ idx_val))
        else: state.cnt_val = to_int32(state.cnt_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 489:
        for _ in range(3):
            state.ms_val = to_int32(state.ms_val + (state.last_rs_val ^ state.ds_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ state.cnt_val))
            state.rs_val = to_int32(state.rs_val + (state.aux_val ^ state.fb_val))
            state.ds_val = to_int32(state.ds_val + (state.ms_val ^ data_val))
    if choice == 490:
        state.ds_val = to_int32(to_int32(state.cnt_val * 16) + batch_div(state.last_rs_val, 8))
        if state.ds_val > state.aux_val: state.fb_val = to_int32(state.fb_val + (state.ms_val ^ data_val))
        else: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ idx_val))
    if choice == 491:
        for _ in range(2):
            for _ in range(2):
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.ds_val + state.fb_val + data_val))
                state.ds_val = to_int32(state.ds_val ^ to_int32(state.ms_val + state.aux_val + idx_val))
    if choice == 492:
        if state.aux_val > state.last_rs_val:
            if state.cnt_val < state.ms_val: state.ds_val = to_int32(state.ds_val + (state.fb_val ^ data_val))
            else: state.ds_val = to_int32(state.ds_val + (state.rs_val ^ idx_val))
        else: state.fb_val = to_int32(state.fb_val + (state.ds_val ^ to_int32(data_val + idx_val)))
    if choice == 493:
        for _ in range(3):
            state.rs_val = to_int32(state.rs_val + (state.last_rs_val ^ state.aux_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.ms_val))
            state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ state.ds_val))
            state.aux_val = to_int32(state.aux_val + (state.rs_val ^ data_val))
    if choice == 494:
        state.ms_val = to_int32(to_int32(state.aux_val * 18) + batch_div(state.ds_val, 5))
        if state.ms_val > state.last_rs_val: state.fb_val = to_int32(state.fb_val + (state.cnt_val ^ data_val))
        else: state.fb_val = to_int32(state.fb_val + (state.rs_val ^ idx_val))
    if choice == 495:
        for _ in range(2):
            for _ in range(2):
                state.rs_val = to_int32(state.rs_val ^ to_int32(state.cnt_val + state.last_rs_val + data_val))
                state.cnt_val = to_int32(state.cnt_val ^ to_int32(state.rs_val + state.ms_val + idx_val))
    if choice == 496:
        if state.ds_val > state.ms_val:
            if state.last_rs_val < state.fb_val: state.rs_val = to_int32(state.rs_val + (state.aux_val ^ data_val))
            else: state.rs_val = to_int32(state.rs_val + (state.cnt_val ^ idx_val))
        else: state.aux_val = to_int32(state.aux_val + (state.rs_val ^ to_int32(data_val + idx_val)))
    if choice == 497:
        for _ in range(3):
            state.cnt_val = to_int32(state.cnt_val + (state.last_rs_val ^ state.ms_val))
            state.last_rs_val = to_int32(state.last_rs_val + (state.fb_val ^ state.ds_val))
            state.fb_val = to_int32(state.fb_val + (state.aux_val ^ state.rs_val))
            state.ms_val = to_int32(state.ms_val + (state.cnt_val ^ data_val))
    if choice == 498:
        state.fb_val = to_int32(to_int32(state.ms_val * 16) + batch_div(state.aux_val, 6))
        if state.fb_val > state.ds_val: state.last_rs_val = to_int32(state.last_rs_val + (state.cnt_val ^ data_val))
        else: state.last_rs_val = to_int32(state.last_rs_val + (state.rs_val ^ idx_val))
    if choice == 499:
        for _ in range(2):
            for _ in range(2):
                state.aux_val = to_int32(state.aux_val ^ to_int32(state.ms_val + state.cnt_val + data_val))
                state.ms_val = to_int32(state.ms_val ^ to_int32(state.aux_val + state.rs_val + idx_val))
def generate_advanced_junk(state, data_hint=None, index_hint=None, commutative=False):
    if state is None: return ""
    cmds = []
    num_instr = random.randint(3, 5)
    data_val = data_hint if data_hint is not None else random.randint(0, 1000)
    idx_val = index_hint if index_hint is not None else random.randint(0, 1000)

    for _ in range(num_instr):
        if commutative:
            # Multi-domain commutative XOR mutations involving all state variables
            vars_to_mutate = [
                (state.rs_var, "rs_val"),
                (state.cnt_var, "cnt_val"),
                (state.aux_var, "aux_val"),
                (state.last_rs_var, "last_rs_val"),
                (state.fb_var, "fb_val"),
                (state.ds_var, "ds_val"),
                (state.ms_var, "ms_val")
            ]
            target_var_name, target_attr = random.choice(vars_to_mutate)
            other_var_name, other_attr = random.choice([v for v in vars_to_mutate if v[0] != target_var_name])
            val = random.randint(1, 255)
            if data_hint is not None: val ^= (data_hint % 256)
            if index_hint is not None: val ^= (index_hint % 256)

            cmds.append(f's^et /a "{target_var_name}^=({val} ^ !{other_var_name}!)"\n')
            current_val = getattr(state, target_attr)
            other_val = getattr(state, other_attr)
            setattr(state, target_attr, to_int32(current_val ^ (val ^ other_val)))
        else:
            c_cmds, choice = generate_advanced_junk_internal(state, data_val, idx_val)
            cmds.extend(c_cmds)
            simulate_advanced_junk(state, data_val, idx_val, choice)
    return "".join(cmds)

def generate_extraction(pool_var, index, target_var, used_vars, length=None, state_obj=None, commutative=False):
    idx_var = "_" + generate_random_name(10, used_vars)

    if state_obj:
        full_state = to_int32(state_obj.rs_val ^ state_obj.aux_val ^ state_obj.cnt_val ^ state_obj.last_rs_val ^ state_obj.fb_val ^ state_obj.ds_val ^ state_obj.ms_val)
        arith_idx = generate_arithmetic(to_int32(index ^ full_state))
        set_idx_cmd = f's^et /a "{idx_var}=({arith_idx}) ^ (!{state_obj.rs_var}! ^ !{state_obj.aux_var}! ^ !{state_obj.cnt_var}! ^ !{state_obj.last_rs_var}! ^ !{state_obj.fb_var}! ^ !{state_obj.ds_var}! ^ !{state_obj.ms_var}!)"\n'
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
    initial_cnt = state_obj.cnt_val
    initial_aux = state_obj.aux_val
    initial_last_rs = state_obj.last_rs_val
    initial_fb = state_obj.fb_val
    initial_ds = state_obj.ds_val
    initial_ms = state_obj.ms_val

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
    # random.shuffle(mapping_code) # Removed to prevent state drift during character mapping

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
        full_state = to_int32(state_obj.rs_val ^ state_obj.aux_val ^ state_obj.cnt_val ^ state_obj.last_rs_val ^ state_obj.fb_val ^ state_obj.ds_val ^ state_obj.ms_val)
        arith_next = generate_arithmetic(to_int32(next_id ^ full_state))
        obf_block.append(f's^et /a "{state_var}=({arith_next}) ^ (!{state_obj.rs_var}! ^ !{state_obj.aux_var}! ^ !{state_obj.cnt_var}! ^ !{state_obj.last_rs_var}! ^ !{state_obj.fb_var}! ^ !{state_obj.ds_var}! ^ !{state_obj.ms_var}!)"\n')
        obf_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    for _ in range(50):
        fid = random.randint(100, 999)
        obf_fake = [f":ID_{fid}\n"]
        obf_fake.append(state_obj.rehash()) # Entry sync
        obf_fake.append(generate_advanced_junk(state_obj))
        obf_fake.append(f's^et "{generate_random_name(10, used_vars)}={generate_unreadable_string(20)}"\n')
        target_id = random.choice(block_ids)
        full_state = to_int32(state_obj.rs_val ^ state_obj.aux_val ^ state_obj.cnt_val ^ state_obj.last_rs_val ^ state_obj.fb_val ^ state_obj.ds_val ^ state_obj.ms_val)
        arith_target = generate_arithmetic(to_int32(target_id ^ full_state))
        obf_fake.append(f's^et /a "{state_var}=({arith_target}) ^ (!{state_obj.rs_var}! ^ !{state_obj.aux_var}! ^ !{state_obj.cnt_var}! ^ !{state_obj.last_rs_var}! ^ !{state_obj.fb_var}! ^ !{state_obj.ds_var}! ^ !{state_obj.ms_var}!)"\n')
        obf_fake.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_fake)
    random.shuffle(flattened_blocks_data)

    final = [
        "@e^cho o^ff\n",
        "s^etlocal e^nabledelayedexpansion\n",
        # Fixed: Initialize with start values, not final values
        f's^et /a "{state_obj.rs_var}={initial_rs}", "{state_obj.cnt_var}={initial_cnt}", "{state_obj.aux_var}={initial_aux}", "{state_obj.last_rs_var}={initial_last_rs}", "{state_obj.fb_var}={initial_fb}", "{state_obj.ds_var}={initial_ds}", "{state_obj.ms_var}={initial_ms}"\n',
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
    full_state_start = to_int32(state_at_flow_start.rs_val ^ state_at_flow_start.aux_val ^ state_at_flow_start.cnt_val ^ state_at_flow_start.last_rs_val ^ state_at_flow_start.fb_val ^ state_at_flow_start.ds_val ^ state_at_flow_start.ms_val)
    arith_start = generate_arithmetic(to_int32(block_ids[0] ^ full_state_start))
    final.append(f's^et /a "{state_var}=({arith_start}) ^ (!{state_at_flow_start.rs_var}! ^ !{state_at_flow_start.aux_var}! ^ !{state_at_flow_start.cnt_var}! ^ !{state_at_flow_start.last_rs_var}! ^ !{state_at_flow_start.fb_var}! ^ !{state_at_flow_start.ds_var}! ^ !{state_at_flow_start.ms_var}!)"\n')
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
