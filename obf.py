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

class RollingState:
    def __init__(self, used_vars):
        self.rs_var = "_" + generate_random_name(10, used_vars)
        self.aux_var = "_" + generate_random_name(10, used_vars)
        self.cnt_var = "_" + generate_random_name(10, used_vars)
        self.last_rs_var = "_" + generate_random_name(10, used_vars)
        self.rs = random.randint(1000, 0x7FFFFFFF)
        self.aux = random.randint(1000, 0x7FFFFFFF)
        self.cnt = random.randint(1, 100)
        self.last_rs = self.rs

    def rehash(self):
        self.last_rs = self.rs
        batch = f's^et /a "{self.last_rs_var}=!{self.rs_var}!"\n'
        self.rs = to_int32(self.rs ^ (self.cnt * 0x1337))
        batch += f's^et /a "{self.rs_var}=!{self.rs_var}! ^ (!{self.cnt_var}! * 4919)"\n'
        self.cnt = (self.cnt + 1) % 10000
        batch += f's^et /a "{self.cnt_var}=(!{self.cnt_var}! + 1) %% 10000"\n'
        return batch

def generate_junk_command():
    cmds = [
        "v^er >n^ul", "t^ype n^ul >n^ul", "v^ol >n^ul", "p^ath >n^ul",
        "s^et /a \"_dummy=%random% %% 10\" >n^ul",
        "i^f 1==1 r^em " + generate_unreadable_string(5),
        "f^or %%i in (1) do r^em"
    ]
    return random.choice(cmds)

def simulate_advanced_junk(case_idx, rs, aux, cnt, last_rs, data, idx):
    case_idx %= 100
    rs, aux, cnt, last_rs = (v & 0xFFFFFFFF for v in (rs, aux, cnt, last_rs))
    data &= 0xFFFFFFFF
    idx &= 0xFFFFFFFF
    v_const = (case_idx * 0x7FFFFFFF) & 0xFFFFFFFF

    if case_idx == 0: rs ^= data
    elif case_idx == 1: aux += rs
    elif case_idx == 2: rs -= idx
    elif case_idx == 3: cnt += 1
    elif case_idx == 4: aux ^= data + idx
    elif case_idx == 5: rs = rs * 3 + aux
    elif case_idx == 6: aux = aux * 2 - rs
    elif case_idx == 7: rs ^= last_rs
    elif case_idx == 8: aux += last_rs
    elif case_idx == 9: rs = ((rs << 1) | (rs >> 31)) & 0xFFFFFFFF
    elif case_idx == 10: rs = (rs ^ 0xAAAAAAAA) + (aux & 0xFFFF)
    elif case_idx == 11: aux = (aux ^ 0x55555555) - (rs & 0xFFFF)
    elif case_idx == 12: rs = (rs + data) ^ (idx * 0x1337)
    elif case_idx == 13: aux = (aux + idx) ^ (data * 0x7331)
    elif case_idx == 14: rs ^= (rs >> 16)
    elif case_idx == 15: aux ^= (aux >> 16)
    elif case_idx == 16: rs = to_int32(rs * 31 + cnt)
    elif case_idx == 17: aux = to_int32(aux * 37 + cnt)
    elif case_idx == 18: rs = (rs ^ aux) + data
    elif case_idx == 19: aux = (aux ^ rs) + idx
    elif case_idx == 20: rs = to_int32(rs + (aux >> 5))
    elif case_idx == 21: aux = to_int32(aux + (rs >> 5))
    elif case_idx == 22: rs = (rs ^ (data << 8)) + idx
    elif case_idx == 23: aux = (aux ^ (idx << 8)) + data
    elif case_idx == 24: rs = rs ^ (rs << 13)
    elif case_idx == 25: rs = rs ^ (rs >> 17)
    elif case_idx == 26: rs = rs ^ (rs << 5)
    elif case_idx == 27: aux = aux ^ (aux << 13)
    elif case_idx == 28: aux = aux ^ (aux >> 17)
    elif case_idx == 29: aux = aux ^ (aux << 5)
    elif case_idx == 30: rs = to_int32(rs + aux + data + idx + cnt)
    elif case_idx == 31: aux = to_int32(aux - rs - data - idx - cnt)
    elif case_idx == 32: rs ^= (aux ^ data)
    elif case_idx == 33: aux ^= (rs ^ idx)
    elif case_idx == 34: rs = to_int32(rs ^ (last_rs + data))
    elif case_idx == 35: aux = to_int32(aux ^ (last_rs + idx))
    elif case_idx == 36: rs = (rs >> 8) | (rs << 24)
    elif case_idx == 37: aux = (aux >> 8) | (aux << 24)
    elif case_idx == 38: rs = (rs ^ data) * 3
    elif case_idx == 39: aux = (aux ^ idx) * 3
    elif case_idx == 40: rs = (rs + aux) ^ (rs >> 4)
    elif case_idx == 41: aux = (aux + rs) ^ (aux >> 4)
    elif case_idx == 42: rs = to_int32(rs ^ (cnt * 0x1234567))
    elif case_idx == 43: aux = to_int32(aux ^ (cnt * 0x7654321))
    elif case_idx == 44: rs = to_int32((rs ^ data) - (aux ^ idx))
    elif case_idx == 45: aux = to_int32((aux ^ idx) - (rs ^ data))
    elif case_idx == 46: rs = rs ^ ~(aux & data)
    elif case_idx == 47: aux = aux ^ ~(rs & idx)
    elif case_idx == 48: rs = (rs + 0x1234) ^ (aux - 0x4321)
    elif case_idx == 49: aux = (aux + 0x5678) ^ (rs - 0x8765)
    elif case_idx == 50: rs = (rs ^ (rs >> 10)) * 0x2783f02b
    elif case_idx == 51: aux = (aux ^ (aux >> 10)) * 0x2783f02b
    elif case_idx == 52: rs = rs ^ (data >> 2)
    elif case_idx == 53: aux = aux ^ (idx >> 2)
    elif case_idx == 54: rs = to_int32(rs + (data ^ 0xFF))
    elif case_idx == 55: aux = to_int32(aux + (idx ^ 0xFF))
    elif case_idx == 56: rs = rs ^ (rs << 7) & 0x9d2c5680
    elif case_idx == 57: rs = rs ^ (rs << 15) & 0xefc60000
    elif case_idx == 58: aux = aux ^ (aux << 7) & 0x9d2c5680
    elif case_idx == 59: aux = aux ^ (aux << 15) & 0xefc60000
    elif case_idx == 60: rs = to_int32(rs + data) if rs % 2 == 0 else to_int32(rs ^ data)
    elif case_idx == 61: aux = to_int32(aux + idx) if aux % 2 == 0 else to_int32(aux ^ idx)
    elif case_idx == 62: rs = (rs ^ idx) + (aux ^ data)
    elif case_idx == 63: aux = (aux ^ data) + (rs ^ idx)
    elif case_idx == 64: rs ^= to_int32(aux * 13)
    elif case_idx == 65: aux ^= to_int32(rs * 17)
    elif case_idx == 66: rs = to_int32(rs + last_rs) ^ data
    elif case_idx == 67: aux = to_int32(aux + last_rs) ^ idx
    elif case_idx == 68: rs = (rs << 4) ^ (rs >> 28) ^ aux
    elif case_idx == 69: aux = (aux << 4) ^ (aux >> 28) ^ rs
    elif case_idx == 70: rs = rs ^ 0x12345678 ^ data
    elif case_idx == 71: aux = aux ^ 0x87654321 ^ idx
    elif case_idx == 72: rs = (rs ^ 0x55AA55AA) + (cnt << 2)
    elif case_idx == 73: aux = (aux ^ 0xAA55AA55) + (cnt << 2)
    elif case_idx == 74: rs = to_int32(rs * cnt + data)
    elif case_idx == 75: aux = to_int32(aux * cnt + idx)
    elif case_idx == 76: rs ^= (data << 16) | (idx & 0xFFFF)
    elif case_idx == 77: aux ^= (idx << 16) | (data & 0xFFFF)
    elif case_idx == 78: rs = rs ^ (rs >> 4) ^ (rs >> 7)
    elif case_idx == 79: aux = aux ^ (aux >> 4) ^ (aux >> 7)
    elif case_idx == 80: rs = to_int32(rs + (rs << 1)) ^ data
    elif case_idx == 81: aux = to_int32(aux + (aux << 1)) ^ idx
    elif case_idx == 82: rs = rs ^ (aux + data + idx)
    elif case_idx == 83: aux = aux ^ (rs + data + idx)
    elif case_idx == 84: rs = (rs ^ (rs << 1)) ^ (data << 2)
    elif case_idx == 85: aux = (aux ^ (aux << 1)) ^ (idx << 2)
    elif case_idx == 86: rs = rs ^ (cnt * 11) ^ 0x99999999
    elif case_idx == 87: aux = aux ^ (cnt * 13) ^ 0x66666666
    elif case_idx == 88: rs = (rs ^ data) + (rs & aux)
    elif case_idx == 89: aux = (aux ^ idx) + (rs & aux)
    elif case_idx == 90: rs = (rs ^ 0xFFFFFFFF) ^ data
    elif case_idx == 91: aux = (aux ^ 0xFFFFFFFF) ^ idx
    elif case_idx == 92: rs = to_int32(rs * 7 + aux * 3)
    elif case_idx == 93: aux = to_int32(aux * 7 + rs * 3)
    elif case_idx == 94: rs ^= (rs >> 1) ^ (rs >> 2)
    elif case_idx == 95: aux ^= (aux >> 1) ^ (aux >> 2)
    elif case_idx == 96: rs = (rs ^ 0x1234) + (data ^ 0x4321)
    elif case_idx == 97: aux = (aux ^ 0x5678) + (idx ^ 0x8765)
    elif case_idx == 98: rs = to_int32(rs ^ (cnt + data + idx + aux + last_rs))
    elif case_idx == 99: aux = to_int32(aux ^ (cnt + data + idx + rs + last_rs))

    return to_int32(rs), to_int32(aux), to_int32(cnt), to_int32(last_rs)

def generate_advanced_junk_internal(case_idx, rs_var, aux_var, cnt_var, last_rs_var, data_var, idx_var):
    case_idx %= 100
    if case_idx == 0: return f's^et /a "{rs_var}=!{rs_var}! ^ !{data_var}!"\n'
    elif case_idx == 1: return f's^et /a "{aux_var}=!{aux_var}! + !{rs_var}!"\n'
    elif case_idx == 2: return f's^et /a "{rs_var}=!{rs_var}! - !{idx_var}!"\n'
    elif case_idx == 3: return f's^et /a "{cnt_var}=!{cnt_var}! + 1"\n'
    elif case_idx == 4: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{data_var}! + !{idx_var}!)"\n'
    elif case_idx == 5: return f's^et /a "{rs_var}=!{rs_var}! * 3 + !{aux_var}!"\n'
    elif case_idx == 6: return f's^et /a "{aux_var}=!{aux_var}! * 2 - !{rs_var}!"\n'
    elif case_idx == 7: return f's^et /a "{rs_var}=!{rs_var}! ^ !{last_rs_var}!"\n'
    elif case_idx == 8: return f's^et /a "{aux_var}=!{aux_var}! + !{last_rs_var}!"\n'
    elif case_idx == 9: return f's^et /a "{rs_var}=(!{rs_var}! << 1) | ((!{rs_var}! >> 31) & 1)"\n'
    elif case_idx == 10: return f's^et /a "{rs_var}=(!{rs_var}! ^ 2863311530) + (!{aux_var}! & 65535)"\n'
    elif case_idx == 11: return f's^et /a "{aux_var}=(!{aux_var}! ^ 1431655765) - (!{rs_var}! & 65535)"\n'
    elif case_idx == 12: return f's^et /a "{rs_var}=(!{rs_var}! + !{data_var}!) ^ (!{idx_var}! * 4919)"\n'
    elif case_idx == 13: return f's^et /a "{aux_var}=(!{aux_var}! + !{idx_var}!) ^ (!{data_var}! * 29489)"\n'
    elif case_idx == 14: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! >> 16)"\n'
    elif case_idx == 15: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! >> 16)"\n'
    elif case_idx == 16: return f's^et /a "{rs_var}=!{rs_var}! * 31 + !{cnt_var}!"\n'
    elif case_idx == 17: return f's^et /a "{aux_var}=!{aux_var}! * 37 + !{cnt_var}!"\n'
    elif case_idx == 18: return f's^et /a "{rs_var}=(!{rs_var}! ^ !{aux_var}!) + !{data_var}!"\n'
    elif case_idx == 19: return f's^et /a "{aux_var}=(!{aux_var}! ^ !{rs_var}!) + !{idx_var}!"\n'
    elif case_idx == 20: return f's^et /a "{rs_var}=!{rs_var}! + (!{aux_var}! >> 5)"\n'
    elif case_idx == 21: return f's^et /a "{aux_var}=!{aux_var}! + (!{rs_var}! >> 5)"\n'
    elif case_idx == 22: return f's^et /a "{rs_var}=(!{rs_var}! ^ (!{data_var}! << 8)) + !{idx_var}!"\n'
    elif case_idx == 23: return f's^et /a "{aux_var}=(!{aux_var}! ^ (!{idx_var}! << 8)) + !{data_var}!"\n'
    elif case_idx == 24: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! << 13)"\n'
    elif case_idx == 25: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! >> 17)"\n'
    elif case_idx == 26: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! << 5)"\n'
    elif case_idx == 27: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! << 13)"\n'
    elif case_idx == 28: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! >> 17)"\n'
    elif case_idx == 29: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! << 5)"\n'
    elif case_idx == 30: return f's^et /a "{rs_var}=!{rs_var}! + !{aux_var}! + !{data_var}! + !{idx_var}! + !{cnt_var}!"\n'
    elif case_idx == 31: return f's^et /a "{aux_var}=!{aux_var}! - !{rs_var}! - !{data_var}! - !{idx_var}! - !{cnt_var}!"\n'
    elif case_idx == 32: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{aux_var}! ^ !{data_var}!)"\n'
    elif case_idx == 33: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{rs_var}! ^ !{idx_var}!)"\n'
    elif case_idx == 34: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{last_rs_var}! + !{data_var}!)"\n'
    elif case_idx == 35: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{last_rs_var}! + !{idx_var}!)"\n'
    elif case_idx == 36: return f's^et /a "{rs_var}=(!{rs_var}! >> 8) | (!{rs_var}! << 24)"\n'
    elif case_idx == 37: return f's^et /a "{aux_var}=(!{aux_var}! >> 8) | (!{aux_var}! << 24)"\n'
    elif case_idx == 38: return f's^et /a "{rs_var}=(!{rs_var}! ^ !{data_var}!) * 3"\n'
    elif case_idx == 39: return f's^et /a "{aux_var}=(!{aux_var}! ^ !{idx_var}!) * 3"\n'
    elif case_idx == 40: return f's^et /a "{rs_var}=(!{rs_var}! + !{aux_var}!) ^ (!{rs_var}! >> 4)"\n'
    elif case_idx == 41: return f's^et /a "{aux_var}=(!{aux_var}! + !{rs_var}!) ^ (!{aux_var}! >> 4)"\n'
    elif case_idx == 42: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{cnt_var}! * 19088743)"\n'
    elif case_idx == 43: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{cnt_var}! * 124090145)"\n'
    elif case_idx == 44: return f's^et /a "{rs_var}=(!{rs_var}! ^ !{data_var}!) - (!{aux_var}! ^ !{idx_var}!)"\n'
    elif case_idx == 45: return f's^et /a "{aux_var}=(!{aux_var}! ^ !{idx_var}!) - (!{rs_var}! ^ !{data_var}!)"\n'
    elif case_idx == 46: return f's^et /a "{rs_var}=!{rs_var}! ^ ~(!{aux_var}! & !{data_var}!)"\n'
    elif case_idx == 47: return f's^et /a "{aux_var}=!{aux_var}! ^ ~(!{rs_var}! & !{idx_var}!)"\n'
    elif case_idx == 48: return f's^et /a "{rs_var}=(!{rs_var}! + 4660) ^ (!{aux_var}! - 17185)"\n'
    elif case_idx == 49: return f's^et /a "{aux_var}=(!{aux_var}! + 22136) ^ (!{rs_var}! - 34661)"\n'
    elif case_idx == 50: return f's^et /a "{rs_var}=(!{rs_var}! ^ (!{rs_var}! >> 10)) * 662958123"\n'
    elif case_idx == 51: return f's^et /a "{aux_var}=(!{aux_var}! ^ (!{aux_var}! >> 10)) * 662958123"\n'
    elif case_idx == 52: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{data_var}! >> 2)"\n'
    elif case_idx == 53: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{idx_var}! >> 2)"\n'
    elif case_idx == 54: return f's^et /a "{rs_var}=!{rs_var}! + (!{data_var}! ^ 255)"\n'
    elif case_idx == 55: return f's^et /a "{aux_var}=!{aux_var}! + (!{idx_var}! ^ 255)"\n'
    elif case_idx == 56: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! << 7) & 2636928640"\n'
    elif case_idx == 57: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! << 15) & 4022730752"\n'
    elif case_idx == 58: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! << 7) & 2636928640"\n'
    elif case_idx == 59: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! << 15) & 4022730752"\n'
    elif case_idx == 60: return f's^et /a "_t=!{rs_var}! %% 2" \n i^f !_t!==0 (s^et /a "{rs_var}=!{rs_var}! + !{data_var}!") e^lse (s^et /a "{rs_var}=!{rs_var}! ^ !{data_var}!")\n'
    elif case_idx == 61: return f's^et /a "_t=!{aux_var}! %% 2" \n i^f !_t!==0 (s^et /a "{aux_var}=!{aux_var}! + !{idx_var}!") e^lse (s^et /a "{aux_var}=!{aux_var}! ^ !{idx_var}!")\n'
    elif case_idx == 62: return f's^et /a "{rs_var}=(!{rs_var}! ^ !{idx_var}!) + (!{aux_var}! ^ !{data_var}!)"\n'
    elif case_idx == 63: return f's^et /a "{aux_var}=(!{aux_var}! ^ !{data_var}!) + (!{rs_var}! ^ !{idx_var}!)"\n'
    elif case_idx == 64: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{aux_var}! * 13)"\n'
    elif case_idx == 65: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{rs_var}! * 17)"\n'
    elif case_idx == 66: return f's^et /a "{rs_var}=(!{rs_var}! + !{last_rs_var}!) ^ !{data_var}!"\n'
    elif case_idx == 67: return f's^et /a "{aux_var}=(!{aux_var}! + !{last_rs_var}!) ^ !{idx_var}!"\n'
    elif case_idx == 68: return f's^et /a "{rs_var}=(!{rs_var}! << 4) ^ (!{rs_var}! >> 28) ^ !{aux_var}!"\n'
    elif case_idx == 69: return f's^et /a "{aux_var}=(!{aux_var}! << 4) ^ (!{aux_var}! >> 28) ^ !{rs_var}!"\n'
    elif case_idx == 70: return f's^et /a "{rs_var}=!{rs_var}! ^ 305419896 ^ !{data_var}!"\n'
    elif case_idx == 71: return f's^et /a "{aux_var}=!{aux_var}! ^ 2271560481 ^ !{idx_var}!"\n'
    elif case_idx == 72: return f's^et /a "{rs_var}=(!{rs_var}! ^ 1437226410) + (!{cnt_var}! << 2)"\n'
    elif case_idx == 73: return f's^et /a "{aux_var}=(!{aux_var}! ^ 2857740885) + (!{cnt_var}! << 2)"\n'
    elif case_idx == 74: return f's^et /a "{rs_var}=!{rs_var}! * !{cnt_var}! + !{data_var}!"\n'
    elif case_idx == 75: return f's^et /a "{aux_var}=!{aux_var}! * !{cnt_var}! + !{idx_var}!"\n'
    elif case_idx == 76: return f's^et /a "{rs_var}=!{rs_var}! ^ ((!{data_var}! << 16) | (!{idx_var}! & 65535))"\n'
    elif case_idx == 77: return f's^et /a "{aux_var}=!{aux_var}! ^ ((!{idx_var}! << 16) | (!{data_var}! & 65535))"\n'
    elif case_idx == 78: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! >> 4) ^ (!{rs_var}! >> 7)"\n'
    elif case_idx == 79: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! >> 4) ^ (!{aux_var}! >> 7)"\n'
    elif case_idx == 80: return f's^et /a "{rs_var}=(!{rs_var}! + (!{rs_var}! << 1)) ^ !{data_var}!"\n'
    elif case_idx == 81: return f's^et /a "{aux_var}=(!{aux_var}! + (!{aux_var}! << 1)) ^ !{idx_var}!"\n'
    elif case_idx == 82: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{aux_var}! + !{data_var}! + !{idx_var}!)"\n'
    elif case_idx == 83: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{rs_var}! + !{data_var}! + !{idx_var}!)"\n'
    elif case_idx == 84: return f's^et /a "{rs_var}=(!{rs_var}! ^ (!{rs_var}! << 1)) ^ (!{data_var}! << 2)"\n'
    elif case_idx == 85: return f's^et /a "{aux_var}=(!{aux_var}! ^ (!{aux_var}! << 1)) ^ (!{idx_var}! << 2)"\n'
    elif case_idx == 86: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{cnt_var}! * 11) ^ 2576980377"\n'
    elif case_idx == 87: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{cnt_var}! * 13) ^ 1717986918"\n'
    elif case_idx == 88: return f's^et /a "{rs_var}=(!{rs_var}! ^ !{data_var}!) + (!{rs_var}! & !{aux_var}!)"\n'
    elif case_idx == 89: return f's^et /a "{aux_var}=(!{aux_var}! ^ !{idx_var}!) + (!{rs_var}! & !{aux_var}!)"\n'
    elif case_idx == 90: return f's^et /a "{rs_var}=(!{rs_var}! ^ 4294967295) ^ !{data_var}!"\n'
    elif case_idx == 91: return f's^et /a "{aux_var}=(!{aux_var}! ^ 4294967295) ^ !{idx_var}!"\n'
    elif case_idx == 92: return f's^et /a "{rs_var}=!{rs_var}! * 7 + !{aux_var}! * 3"\n'
    elif case_idx == 93: return f's^et /a "{aux_var}=!{aux_var}! * 7 + !{rs_var}! * 3"\n'
    elif case_idx == 94: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{rs_var}! >> 1) ^ (!{rs_var}! >> 2)"\n'
    elif case_idx == 95: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{aux_var}! >> 1) ^ (!{aux_var}! >> 2)"\n'
    elif case_idx == 96: return f's^et /a "{rs_var}=(!{rs_var}! ^ 4660) + (!{data_var}! ^ 17185)"\n'
    elif case_idx == 97: return f's^et /a "{aux_var}=(!{aux_var}! ^ 22136) + (!{idx_var}! ^ 34661)"\n'
    elif case_idx == 98: return f's^et /a "{rs_var}=!{rs_var}! ^ (!{cnt_var}! + !{data_var}! + !{idx_var}! + !{aux_var}! + !{last_rs_var}!)"\n'
    elif case_idx == 99: return f's^et /a "{aux_var}=!{aux_var}! ^ (!{cnt_var}! + !{data_var}! + !{idx_var}! + !{rs_var}! + !{last_rs_var}!)"\n'
    return ""

def tokenize_line(line):
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        if line[i] == '"':
            start = i
            i += 1
            while i < n and line[i] != '"':
                i += 1
            if i < n: i += 1
            tokens.append(line[start:i])
        elif line[i] == '^' and i + 1 < n:
            if line[i+1] == '^' and i + 2 < n and line[i+2] == '!':
                tokens.append('^^!')
                i += 3
            else:
                tokens.append(line[i:i+2])
                i += 2
        elif line[i] == '^': # Trailing caret
            tokens.append('^')
            i += 1
        elif i + 2 < n and line[i].isdigit() and line[i+1:i+3] == '>>':
            tokens.append(line[i:i+3])
            i += 3
        elif i + 1 < n and line[i].isdigit() and line[i+1] == '>':
            tokens.append(line[i:i+2])
            i += 2
        elif i + 1 < n and line[i:i+2] in ('&>', '>>', '<<', '&&', '||', '==', '+=', '-=', '*=', '/=', '%=', '&=', '^=', '|='):
            tokens.append(line[i:i+2])
            i += 2
        elif line[i] in '%!$':
            # Use regex for robust variable matching (Batch variables and MSBuild properties)
            var_pattern = r'(%%~[a-z]+|%%[a-z]|%~[a-z0-9]*[0-9*]|%[0-9*]|%[a-z0-9_#$@*-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^%]*))?%|![a-z0-9_#$@-]+(?::(?:~[0-9-]+,[0-9-]+|[^=]+=[^!]*))?!|\$\([a-z0-9_#$@.-]+\))'
            match = re.match(var_pattern, line[i:], re.IGNORECASE)
            if match:
                var_token = match.group(0)
                tokens.append(var_token)
                i += len(var_token)
            else:
                tokens.append(line[i])
                i += 1
        elif line[i] == ':':
            start = i
            i += 1
            while i < n and (line[i].isalnum() or line[i] in '_#$@*-'):
                i += 1
            tokens.append(line[start:i])
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
            while i < n and not line[i].isspace() and line[i] not in '"^()&|<>:=,;%!$':
                i += 1
            if start == i: # Safety advance
                tokens.append(line[i])
                i += 1
            else:
                tokens.append(line[start:i])
    return tokens

def generate_extraction(pool_var, index, target_var, used_vars, length=None, rs_obj=None):
    idx_var = "_" + generate_random_name(10, used_vars)

    if rs_obj:
        xor_key = random.randint(0, 0x7FFFFFFF)
        # index = (!rs_var! ^ !cnt_var! ^ xor_key) ^ (rs ^ cnt ^ xor_key ^ index)
        runtime_key = to_int32(rs_obj.rs ^ rs_obj.cnt ^ xor_key ^ index)
        arith_idx = f"(!{rs_obj.rs_var}! ^ !{rs_obj.cnt_var}! ^ {xor_key}) ^ {runtime_key}"
    else:
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
    rs_obj = RollingState(used_vars)
    # Save initial state for the first jump
    initial_rs  = rs_obj.rs
    initial_cnt = rs_obj.cnt

    unique_file_chars = set()
    label_map = {}
    for line in lines:
        unique_file_chars.update(line)
        stripped = line.lstrip()
        if stripped.startswith(":") and not stripped.startswith("::"):
            orig_label = stripped[1:].split()[0]
            if orig_label.lower() not in ["eof"]:
                if orig_label not in label_map:
                    label_map[orig_label] = "V_" + generate_random_name(8, used_vars)

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
            decoder_cmds.append(generate_extraction(pv, split, v_suffix, used_vars, rs_obj=rs_obj))
            decoder_cmds.append(generate_extraction(pv, 0, v_prefix, used_vars, length=split, rs_obj=rs_obj))
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
                        mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, rs_obj=rs_obj))
                elif method > 0.45:
                    mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, rs_obj=rs_obj))
                else:
                    v_link = "_" + generate_random_name(10, used_vars)
                    combined = generate_extraction(target_pv, char_idx, v_link, used_vars, length=1, rs_obj=rs_obj)
                    combined += f's^et "{var_name}=!{v_link}!"\n'
                    mapping_code.append(combined)
        char_map[char] = shadow_names
    random.shuffle(mapping_code)

    # Block splitter
    no_touch_kw  = {"if","for","do","in","exist","defined","not","errorlevel","else","equ","neq","lss","leq","gtr","geq"}
    caret_ok_kw  = {"echo","pause","exit","title","chcp","set","call","goto","rem","mkdir","copy","del","msbuild.exe","wscript.exe","timeout","wscript","msbuild"}
    all_keywords = no_touch_kw | caret_ok_kw

    blocks = []
    current_block = []
    nest_level = 0
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped: continue
        if stripped.lower().startswith("@echo off"): continue
        line_tokens = tokenize_line(line)
        if not (stripped.startswith("::") or stripped.lower().startswith("rem ")):
            for t in line_tokens:
                if t == '(': nest_level += 1
                elif t == ')': nest_level -= 1

        current_block.append(line)

        # Find next non-empty line for else check
        next_line_stripped = ""
        for i in range(idx + 1, len(lines)):
            ls = lines[i].lstrip().lower()
            if ls:
                next_line_stripped = ls
                break

        # Split block only if:
        # 1. Nest level is 0 (not inside a parenthesis block)
        # 2. Not about to start an ELSE (Batch requires ) ELSE ( to be contiguous)
        # 3. Not just finishing a line that opens a block
        if nest_level <= 0 and not stripped.rstrip().endswith("(") and not next_line_stripped.startswith("else") and not next_line_stripped.startswith(":"):
            if (stripped.startswith(":") and not stripped.startswith("::")) or \
               (random.random() < 0.25 and not stripped.lower().startswith("set ")):
                if current_block: blocks.append(current_block)
                current_block = []
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
    data_var = "_" + generate_random_name(10, used_vars)
    idx_var  = "_" + generate_random_name(10, used_vars)
    for idx, block in enumerate(blocks):
        b_id      = block_ids[idx]
        obf_block = [f":ID_{b_id}\n"]
        obf_block.append(rs_obj.rehash())

        for line_idx, line in enumerate(block):
            stripped = line.lstrip()
            if stripped.startswith(":") and not stripped.startswith("::"):
                orig_label = stripped[1:].split()[0]
                new_label = label_map.get(orig_label, orig_label)
                obf_block.append(f":{new_label}\n")
                continue

            tokens = tokenize_line(line)
            obf_line = ""

            skip_until = -1
            for t_idx, token in enumerate(tokens):
                if not token: continue
                if t_idx <= skip_until:
                    obf_line += token
                    continue
                tl = token.lower()

                # CMD line length limit is 8191. We stay safe under 8000.
                is_long = len(obf_line) > 1500 # Start tapering earlier

                if token.startswith('"') and token.endswith('"') and len(token) >= 2:
                    obf_line += token
                elif token.startswith('^') and len(token) >= 2:
                    obf_line += token
                elif tl in ('goto', 'call'):
                    prob = 0.0 if is_long else 0.55
                    obf_line += "".join("^" + c if random.random() < prob and c.isalnum() else c for c in token)
                    # Find and protect the label/target
                    for next_idx in range(t_idx + 1, len(tokens)):
                        nt = tokens[next_idx]
                        if nt.strip():
                            l_target = nt
                            if l_target.startswith(":"):
                                l_name = l_target[1:]
                                if l_name in label_map:
                                    l_target = ":" + label_map[l_name]
                            elif l_target.lower() == "/b": # Special case for exit /b
                                pass
                            else:
                                if l_target in label_map:
                                    l_target = label_map[l_target]

                            tokens[next_idx] = l_target
                            skip_until = next_idx
                            break
                elif tl in all_keywords:
                    prob = 0.0 if is_long else (0.25 if tl in no_touch_kw else 0.55)
                    obf_line += "".join(
                        "^" + c if random.random() < prob and c not in ('"', '!', '=', '%', '^', '&', '|', '<', '>', '$', '(', ')', '.', '_', '/', '\\', '[', ']', '{', '}', '+', '-', '*', ',', ';') and c.isalnum() and c != '^' and ord(c) < 127 else c
                        for c in token)
                elif re.match(r'^\s+$', token) or re.match(r'^[()&|<>:=,;\[\]{}+\-*]+$', token):
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
                                    if c in char_map and not is_long:
                                        frag += f"!{random.choice(char_map[c])}!"
                                    elif c == '!':
                                        frag += "!!" if is_long else "^^!"
                                    elif c == '^':
                                        frag += "^^"
                                    else:
                                        prob_c = 0.0 if is_long else 0.25
                                        if random.random() < prob_c and c not in ('"', '!', '=', '%', '^', '&', '|', '<', '>', '$', '(', ')', '.', '_', '/', '\\', '[', ']', '{', '}', '+', '-', '*', ',', ';') and c.isalnum() and c != '^' and ord(c) < 127:
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

                # Intersperse advanced junk
                if random.random() < 0.15:
                    case_idx = random.randint(0, 99)
                    data_val = random.randint(0, 0xFFFF)
                    obf_line += f'\ns^et /a "{data_var}={data_val}"\n'
                    obf_line += f's^et /a "{idx_var}={line_idx}"\n'
                    obf_line += generate_advanced_junk_internal(case_idx, rs_obj.rs_var, rs_obj.aux_var, rs_obj.cnt_var, rs_obj.last_rs_var, data_var, idx_var)
                    rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs = simulate_advanced_junk(case_idx, rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs, data_val, line_idx)
                    if random.random() < 0.3:
                        obf_line += generate_junk_command() + "\n"

            obf_block.append(obf_line + "\n")

        next_id = block_ids[idx+1] if idx+1 < len(blocks) else end_id
        # Couple next_id with rs and cnt
        xor_key = random.randint(0, 0x7FFFFFFF)
        runtime_next_id = to_int32(next_id ^ rs_obj.rs ^ rs_obj.cnt ^ xor_key)
        obf_block.append(f's^et /a "{state_var}=(!{rs_obj.rs_var}! ^ !{rs_obj.cnt_var}! ^ {xor_key}) ^ {runtime_next_id}"\n')
        obf_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    used_fids = set()
    for _ in range(20):
        while True:
            fid = random.randint(100, 999)
            if fid not in used_fids:
                used_fids.add(fid)
                break
        fake_next_id = random.choice(block_ids)
        xor_key = random.randint(0, 0x7FFFFFFF)
        runtime_fake_id = to_int32(fake_next_id ^ rs_obj.rs ^ rs_obj.cnt ^ xor_key)
        flattened_blocks_data.append([
            f":ID_{fid}\n",
            f's^et "{generate_random_name(10, used_vars)}={generate_unreadable_string(20)}"\n',
            f's^et /a "{state_var}=(!{rs_obj.rs_var}! ^ !{rs_obj.cnt_var}! ^ {xor_key}) ^ {runtime_fake_id}"\n',
            f"g^oto :{dispatcher_label}\n",
        ])
    random.shuffle(flattened_blocks_data)

    final = [
        "@e^cho o^ff\n",
        "s^etlocal e^nabledelayedexpansion\n",
        "c^hcp 6^5001 >n^ul\n",
        f's^et "{state_var}=0"\n',
        f's^et /a "{rs_obj.rs_var}={to_int32(rs_obj.rs)}"\n',
        f's^et /a "{rs_obj.aux_var}={to_int32(rs_obj.aux)}"\n',
        f's^et /a "{rs_obj.cnt_var}={to_int32(rs_obj.cnt)}"\n',
        f's^et /a "{rs_obj.last_rs_var}={to_int32(rs_obj.last_rs)}"\n',
        f's^et "{data_var}=0"\n',
        f's^et "{idx_var}=0"\n',
        f"g^oto :{setup_label}\n",
    ]
    for i, bl in enumerate(bridge_labels):
        target = bridge_labels[i+1] if i+1 < len(bridge_labels) else dispatcher_label
        final.append(f":{bl}\n")

        # Opaque predicates and dead paths
        if random.random() < 0.4:
            dead_target = dispatcher_label
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
    # Couple initial state_var
    xor_key = random.randint(0, 0x7FFFFFFF)
    runtime_block0_id = to_int32(block_ids[0] ^ initial_rs ^ initial_cnt ^ xor_key)
    final.append(f's^et /a "{state_var}=(!{rs_obj.rs_var}! ^ !{rs_obj.cnt_var}! ^ {xor_key}) ^ {runtime_block0_id}"\n')
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
