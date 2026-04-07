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
        self.cnt_var = "_" + generate_random_name(10, used_vars)
        self.aux_var = "_" + generate_random_name(10, used_vars)
        self.last_rs_var = "_" + generate_random_name(10, used_vars)
        self.fb_var = "_" + generate_random_name(10, used_vars)

        self.rs_val = random.randint(100, 10000)
        self.cnt_val = random.randint(100, 10000)
        self.aux_val = random.randint(100, 10000)
        self.last_rs_val = random.randint(100, 10000)
        self.fb_val = random.randint(100, 10000)

    def rehash(self):
        self.rs_val = random.randint(100, 10000)
        self.cnt_val = random.randint(100, 10000)
        self.aux_val = random.randint(100, 10000)
        self.last_rs_val = random.randint(100, 10000)
        self.fb_val = random.randint(100, 10000)
        return f's^et /a "{self.rs_var}={self.rs_val}", "{self.cnt_var}={self.cnt_val}", "{self.aux_var}={self.aux_val}", "{self.last_rs_var}={self.last_rs_val}", "{self.fb_var}={self.fb_val}"\n'

def generate_advanced_junk_internal(state, data_val, idx_val):
    cmds = []
    choice = random.randint(0, 149)
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

def generate_advanced_junk(state, data_hint=None, index_hint=None, commutative=False):
    if state is None: return ""
    cmds = []
    num_instr = random.randint(3, 5)
    data_val = data_hint if data_hint is not None else random.randint(0, 1000)
    idx_val = index_hint if index_hint is not None else random.randint(0, 1000)

    for _ in range(num_instr):
        if commutative:
            # Fixed: Only use XOR and only RS to ensure true commutativity in shuffled sections
            op = '^'
            val = random.randint(1, 255)
            if data_hint is not None: val ^= (data_hint % 256)
            if index_hint is not None: val ^= (index_hint % 256)

            cmds.append(f's^et /a "{state.rs_var}{op}={val}"\n')
            state.rs_val = to_int32(state.rs_val ^ val)
        else:
            c_cmds, choice = generate_advanced_junk_internal(state, data_val, idx_val)
            cmds.extend(c_cmds)
            simulate_advanced_junk(state, data_val, idx_val, choice)
    return "".join(cmds)

def generate_extraction(pool_var, index, target_var, used_vars, length=None, state_obj=None, commutative=False):
    idx_var = "_" + generate_random_name(10, used_vars)

    if state_obj:
        full_state = to_int32(state_obj.rs_val ^ state_obj.aux_val ^ state_obj.cnt_val ^ state_obj.last_rs_val ^ state_obj.fb_val)
        arith_idx = generate_arithmetic(to_int32(index ^ full_state))
        set_idx_cmd = f's^et /a "{idx_var}=({arith_idx}) ^ (!{state_obj.rs_var}! ^ !{state_obj.aux_var}! ^ !{state_obj.cnt_var}! ^ !{state_obj.last_rs_var}! ^ !{state_obj.fb_var}!)"\n'
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
        full_state = to_int32(state_obj.rs_val ^ state_obj.aux_val ^ state_obj.cnt_val ^ state_obj.last_rs_val ^ state_obj.fb_val)
        arith_next = generate_arithmetic(to_int32(next_id ^ full_state))
        obf_block.append(f's^et /a "{state_var}=({arith_next}) ^ (!{state_obj.rs_var}! ^ !{state_obj.aux_var}! ^ !{state_obj.cnt_var}! ^ !{state_obj.last_rs_var}! ^ !{state_obj.fb_var}!)"\n')
        obf_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    for _ in range(50):
        fid = random.randint(100, 999)
        obf_fake = [f":ID_{fid}\n"]
        obf_fake.append(state_obj.rehash()) # Entry sync
        obf_fake.append(generate_advanced_junk(state_obj))
        obf_fake.append(f's^et "{generate_random_name(10, used_vars)}={generate_unreadable_string(20)}"\n')
        target_id = random.choice(block_ids)
        full_state = to_int32(state_obj.rs_val ^ state_obj.aux_val ^ state_obj.cnt_val ^ state_obj.last_rs_val ^ state_obj.fb_val)
        arith_target = generate_arithmetic(to_int32(target_id ^ full_state))
        obf_fake.append(f's^et /a "{state_var}=({arith_target}) ^ (!{state_obj.rs_var}! ^ !{state_obj.aux_var}! ^ !{state_obj.cnt_var}! ^ !{state_obj.last_rs_var}! ^ !{state_obj.fb_var}!)"\n')
        obf_fake.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_fake)
    random.shuffle(flattened_blocks_data)

    final = [
        "@e^cho o^ff\n",
        "s^etlocal e^nabledelayedexpansion\n",
        # Fixed: Initialize with start values, not final values
        f's^et /a "{state_obj.rs_var}={initial_rs}", "{state_obj.cnt_var}={initial_cnt}", "{state_obj.aux_var}={initial_aux}", "{state_obj.last_rs_var}={initial_last_rs}", "{state_obj.fb_var}={initial_fb}"\n',
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
    full_state_start = to_int32(state_at_flow_start.rs_val ^ state_at_flow_start.aux_val ^ state_at_flow_start.cnt_val ^ state_at_flow_start.last_rs_val ^ state_at_flow_start.fb_val)
    arith_start = generate_arithmetic(to_int32(block_ids[0] ^ full_state_start))
    final.append(f's^et /a "{state_var}=({arith_start}) ^ (!{state_at_flow_start.rs_var}! ^ !{state_at_flow_start.aux_var}! ^ !{state_at_flow_start.cnt_var}! ^ !{state_at_flow_start.last_rs_var}! ^ !{state_at_flow_start.fb_var}!)"\n')
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
