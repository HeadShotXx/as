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

        self.rs = random.randint(0, 0x7FFFFFFF)
        self.aux = random.randint(0, 0x7FFFFFFF)
        self.cnt = 0
        self.last_rs = self.rs

    def copy(self):
        new_obj = RollingState.__new__(RollingState)
        new_obj.rs_var = self.rs_var
        new_obj.aux_var = self.aux_var
        new_obj.cnt_var = self.cnt_var
        new_obj.last_rs_var = self.last_rs_var
        new_obj.rs = self.rs
        new_obj.aux = self.aux
        new_obj.cnt = self.cnt
        new_obj.last_rs = self.last_rs
        return new_obj

    def rehash(self):
        # Python Simulation (Fixed order)
        self.last_rs = self.rs
        self.rs = to_int32(self.rs ^ (self.aux + self.cnt))
        self.cnt = (self.cnt + 1) & 0x7FFFFFFF

        # Batch code generation (Matching fixed order to prevent state drift)
        return (
            f's^et /a "{self.last_rs_var}=!{self.rs_var}!"\n'
            f's^et /a "{self.rs_var}=(!{self.rs_var}! ^ (!{self.aux_var}! + !{self.cnt_var}!))"\n'
            f's^et /a "{self.cnt_var}=(!{self.cnt_var}! + 1) & 2147483647"\n'
        )

def simulate_advanced_junk(case, rs, aux, cnt, last_rs, data, idx):
    if case == 0: rs = to_int32(rs + data)
    elif case == 1: aux = to_int32(aux ^ (rs & 0xFFFF))
    elif case == 2: rs = to_int32(rs ^ (aux + idx))
    elif case == 3: aux = to_int32(aux + (data * 31))
    elif case == 4: rs = to_int32(rs ^ last_rs)
    elif case == 5: cnt = (cnt + (rs & 0xFF)) & 0x7FFFFFFF
    elif case == 6: aux = to_int32(aux - data)
    elif case == 7: rs = to_int32(rs * 3 + aux)
    elif case == 8: aux = to_int32(aux ^ (cnt + data))
    elif case == 9: rs = to_int32(rs ^ (data * idx))
    elif case == 10: aux = to_int32(aux + rs - last_rs)
    elif case == 11: rs = to_int32(rs ^ 0x7FFFFFFF)
    elif case == 12: aux = to_int32(aux | (data << 8))
    elif case == 13: rs = to_int32(rs & ~data)
    elif case == 14: aux = to_int32(aux ^ (idx * idx))
    elif case == 15: rs = to_int32(rs + (aux >> 4))
    elif case == 16: aux = to_int32(aux ^ 0x55555555)
    elif case == 17: rs = to_int32(rs - (cnt & 0x3FF))
    elif case == 18: aux = to_int32(aux + (last_rs & 0xFFF))
    elif case == 19: rs = to_int32(rs ^ (aux ^ data ^ idx))
    elif case == 20: rs = to_int32(rs + aux) if data > 128 else to_int32(rs - aux)
    elif case == 21: aux = to_int32(aux ^ cnt) if batch_mod(idx, 2) == 0 else to_int32(aux + cnt)
    elif case == 22: rs = to_int32((rs << 1) | (rs >> 31)) ^ data
    elif case == 23: aux = to_int32((aux >> 1) | (aux << 31)) + idx
    elif case == 24: rs = to_int32(rs ^ (aux & data))
    elif case == 25: aux = to_int32(aux + (rs | idx))
    elif case == 26: rs = to_int32(rs * (idx + 1))
    elif case == 27: aux = to_int32(aux ^ (last_rs >> 8))
    elif case == 28: rs = to_int32(rs ^ (cnt * data))
    elif case == 29: aux = to_int32(aux + (data ^ idx))
    elif case == 30: rs = to_int32(rs - (aux & cnt))
    elif case == 31: aux = to_int32(aux | (rs ^ data))
    elif case == 32: rs = to_int32(rs ^ to_int32(aux * data))
    elif case == 33: aux = to_int32(aux ^ to_int32(rs + idx))
    elif case == 34: rs = to_int32(rs + (cnt ^ data))
    elif case == 35: aux = to_int32(aux - (idx * 7))
    elif case == 36: rs = to_int32(rs ^ (aux + last_rs))
    elif case == 37: aux = to_int32(aux ^ (rs - data))
    elif case == 38: rs = to_int32(rs | (idx << 4))
    elif case == 39: aux = to_int32(aux & ~(cnt >> 2))
    elif case == 40: rs = to_int32(rs + (data * idx)) if rs > 0 else to_int32(rs - (data * idx))
    elif case == 41: aux = to_int32(aux ^ (rs + last_rs)) if aux > 0 else to_int32(aux - (rs + last_rs))
    elif case == 42: rs = to_int32(rs ^ (aux >> (cnt & 7)))
    elif case == 43: aux = to_int32(aux + (rs << (data & 3)))
    elif case == 44: rs = to_int32(rs ^ (data + idx + cnt))
    elif case == 45: aux = to_int32(aux ^ (last_rs - data - idx))
    elif case == 46: rs = to_int32(rs * 13 + aux)
    elif case == 47: aux = to_int32(aux * 17 - rs)
    elif case == 48: rs = to_int32(rs ^ (aux | data | idx | cnt))
    elif case == 49: aux = to_int32(aux ^ (rs & last_rs))
    elif case == 50: rs = to_int32(rs + aux + cnt + data + idx)
    elif case == 51: aux = to_int32(aux ^ rs ^ cnt ^ data ^ idx)
    elif case == 52: rs = to_int32((rs ^ 0xAAAAAAAA) + data)
    elif case == 53: aux = to_int32((aux ^ 0x55555555) - idx)
    elif case == 54: rs = to_int32(rs ^ (aux + (data << 2)))
    elif case == 55: aux = to_int32(aux + (rs ^ (idx >> 1)))
    elif case == 56: rs = to_int32(rs - (last_rs ^ cnt))
    elif case == 57: aux = to_int32(aux + (cnt ^ data))
    elif case == 58: rs = to_int32(rs ^ (idx * idx * idx))
    elif case == 59: aux = to_int32(aux ^ (data * data))
    elif case == 60: rs = to_int32(rs + 1) if batch_mod(data, 2) == 0 else to_int32(rs - 1)
    elif case == 61: aux = to_int32(aux + 1) if batch_mod(idx, 3) == 0 else to_int32(aux - 1)
    elif case == 62: rs = to_int32(rs ^ (aux + data)) if batch_mod(cnt, 4) == 0 else to_int32(rs ^ (aux - data))
    elif case == 63: aux = to_int32(aux ^ (rs + idx)) if batch_mod(last_rs, 5) == 0 else to_int32(aux ^ (rs - idx))
    elif case == 64: rs = to_int32(rs ^ (aux << 3))
    elif case == 65: aux = to_int32(aux ^ (rs >> 5))
    elif case == 66: rs = to_int32(rs + (data ^ 0xFF))
    elif case == 67: aux = to_int32(aux - (idx ^ 0x7F))
    elif case == 68: rs = to_int32(rs ^ (cnt + 0x1234))
    elif case == 69: aux = to_int32(aux ^ (last_rs - 0x4321))
    elif case == 70: rs = to_int32(rs + aux) if (rs ^ aux) > data else to_int32(rs ^ aux)
    elif case == 71: aux = to_int32(aux + rs) if (aux ^ rs) < idx else to_int32(aux ^ rs)
    elif case == 72: rs = to_int32(rs ^ (data * 3) + (idx * 5))
    elif case == 73: aux = to_int32(aux ^ (idx * 2) - (data * 4))
    elif case == 74: rs = to_int32(rs + (cnt & 15) - (idx & 15))
    elif case == 75: aux = to_int32(aux - (data & 15) + (cnt & 15))
    elif case == 76: rs = to_int32(rs ^ (aux + (last_rs >> 16)))
    elif case == 77: aux = to_int32(aux ^ (rs - (last_rs & 65535)))
    elif case == 78: rs = to_int32(rs + (data << (idx & 7)))
    elif case == 79: aux = to_int32(aux + (idx << (data & 3)))
    elif case == 80: rs = to_int32(rs ^ (aux + data + idx + cnt + last_rs))
    elif case == 81: aux = to_int32(aux + (rs ^ data ^ idx ^ cnt ^ last_rs))
    elif case == 82: rs = to_int32(rs ^ 305419896)
    elif case == 83: aux = to_int32(aux ^ 2271560481)
    elif case == 84: rs = to_int32(rs + (data * data) - (idx * idx))
    elif case == 85: aux = to_int32(aux - (data * data) + (idx * idx))
    elif case == 86: rs = to_int32(rs ^ (aux >> 1) ^ (cnt << 1))
    elif case == 87: aux = to_int32(aux ^ (rs << 2) ^ (idx >> 2))
    elif case == 88: rs = to_int32(rs + (last_rs ^ 65535))
    elif case == 89: aux = to_int32(aux - (last_rs ^ 43690))
    elif case == 90: rs = to_int32(rs ^ (data + idx)) if data > idx else to_int32(rs + (data ^ idx))
    elif case == 91: aux = to_int32(aux ^ (cnt + data)) if cnt > data else to_int32(aux + (cnt ^ data))
    elif case == 92: rs = to_int32(rs ^ (idx + cnt)) if idx > cnt else to_int32(rs + (idx ^ cnt))
    elif case == 93: aux = to_int32(aux ^ (last_rs + data)) if last_rs > data else to_int32(aux + (last_rs ^ data))
    elif case == 94: rs = to_int32(rs * 19)
    elif case == 95: aux = to_int32(aux * 23)
    elif case == 96: rs = to_int32(rs ^ (aux + (data & 127)))
    elif case == 97: aux = to_int32(aux ^ (rs - (idx & 127)))
    elif case == 98: rs = to_int32(rs + (cnt ^ 85))
    elif case == 99: aux = to_int32(aux ^ (last_rs | 1))
    return rs, aux, cnt, last_rs

def generate_advanced_junk_internal(case, rs_obj, data_val, idx_val):
    rv = rs_obj.rs_var
    av = rs_obj.aux_var
    cv = rs_obj.cnt_var
    lv = rs_obj.last_rs_var
    if case == 0: return f's^et /a "{rv}=!{rv}! + {data_val}"\n'
    elif case == 1: return f's^et /a "{av}=!{av}! ^ (!{rv}! & 65535)"\n'
    elif case == 2: return f's^et /a "{rv}=!{rv}! ^ (!{av}! + {idx_val})"\n'
    elif case == 3: return f's^et /a "{av}=!{av}! + ({data_val} * 31)"\n'
    elif case == 4: return f's^et /a "{rv}=!{rv}! ^ !{lv}!"\n'
    elif case == 5: return f's^et /a "{cv}=(!{cv}! + (!{rv}! & 255)) & 2147483647"\n'
    elif case == 6: return f's^et /a "{av}=!{av}! - {data_val}"\n'
    elif case == 7: return f's^et /a "{rv}=(!{rv}! * 3) + !{av}!"\n'
    elif case == 8: return f's^et /a "{av}=!{av}! ^ (!{cv}! + {data_val})"\n'
    elif case == 9: return f's^et /a "{rv}=!{rv}! ^ ({data_val} * {idx_val})"\n'
    elif case == 10: return f's^et /a "{av}=!{av}! + !{rv}! - !{lv}!"\n'
    elif case == 11: return f's^et /a "{rv}=!{rv}! ^ 2147483647"\n'
    elif case == 12: return f's^et /a "{av}=!{av}! | ({data_val} << 8)"\n'
    elif case == 13: return f's^et /a "{rv}=!{rv}! & ~{data_val}"\n'
    elif case == 14: return f's^et /a "{av}=!{av}! ^ ({idx_val} * {idx_val})"\n'
    elif case == 15: return f's^et /a "{rv}=!{rv}! + (!{av}! >> 4)"\n'
    elif case == 16: return f's^et /a "{av}=!{av}! ^ 1431655765"\n'
    elif case == 17: return f's^et /a "{rv}=!{rv}! - (!{cv}! & 1023)"\n'
    elif case == 18: return f's^et /a "{av}=!{av}! + (!{lv}! & 4095)"\n'
    elif case == 19: return f's^et /a "{rv}=!{rv}! ^ (!{av}! ^ {data_val} ^ {idx_val})"\n'
    elif case == 20: return f'i^f {data_val} g^tr 128 (s^et /a "{rv}=!{rv}! + !{av}!") e^lse (s^et /a "{rv}=!{rv}! - !{av}!")\n'
    elif case == 21: return f's^et /a "_T={idx_val} %% 2"\ni^f !_T! == 0 (s^et /a "{av}=!{av}! ^ !{cv}!") e^lse (s^et /a "{av}=!{av}! + !{cv}!")\n'
    elif case == 22: return f's^et /a "{rv}=((!{rv}! << 1) | (!{rv}! >> 31)) ^ {data_val}"\n'
    elif case == 23: return f's^et /a "{av}=((!{av}! >> 1) | (!{av}! << 31)) + {idx_val}"\n'
    elif case == 24: return f's^et /a "{rv}=!{rv}! ^ (!{av}! & {data_val})"\n'
    elif case == 25: return f's^et /a "{av}=!{av}! + (!{rv}! | {idx_val})"\n'
    elif case == 26: return f's^et /a "{rv}=!{rv}! * ({idx_val} + 1)"\n'
    elif case == 27: return f's^et /a "{av}=!{av}! ^ (!{lv}! >> 8)"\n'
    elif case == 28: return f's^et /a "{rv}=!{rv}! ^ (!{cv}! * {data_val})"\n'
    elif case == 29: return f's^et /a "{av}=!{av}! + ({data_val} ^ {idx_val})"\n'
    elif case == 30: return f's^et /a "{rv}=!{rv}! - (!{av}! & !{cv}!)"\n'
    elif case == 31: return f's^et /a "{av}=!{av}! | (!{rv}! ^ {data_val})"\n'
    elif case == 32: return f's^et /a "_T=!{av}! * {data_val}"\ns^et /a "{rv}=!{rv}! ^ !_T!"\n'
    elif case == 33: return f's^et /a "_T=!{rv}! + {idx_val}"\ns^et /a "{av}=!{av}! ^ !_T!"\n'
    elif case == 34: return f's^et /a "{rv}=!{rv}! + (!{cv}! ^ {data_val})"\n'
    elif case == 35: return f's^et /a "{av}=!{av}! - ({idx_val} * 7)"\n'
    elif case == 36: return f's^et /a "{rv}=!{rv}! ^ (!{av}! + !{lv}!)"\n'
    elif case == 37: return f's^et /a "{av}=!{av}! ^ (!{rv}! - {data_val})"\n'
    elif case == 38: return f's^et /a "{rv}=!{rv}! | ({idx_val} << 4)"\n'
    elif case == 39: return f's^et /a "{av}=!{av}! & ~(!{cv}! >> 2)"\n'
    elif case == 40: return f'i^f !{rv}! g^tr 0 (s^et /a "{rv}=!{rv}! + ({data_val} * {idx_val})") e^lse (s^et /a "{rv}=!{rv}! - ({data_val} * {idx_val})")\n'
    elif case == 41: return f'i^f !{av}! g^tr 0 (s^et /a "{av}=!{av}! ^ (!{rv}! + !{lv}!)") e^lse (s^et /a "{av}=!{av}! - (!{rv}! + !{lv}!)")\n'
    elif case == 42: return f's^et /a "_S=!{cv}! & 7"\ns^et /a "{rv}=!{rv}! ^ (!{av}! >> !_S!)"\n'
    elif case == 43: return f's^et /a "_S={data_val} & 3"\ns^et /a "{av}=!{av}! + (!{rv}! << !_S!)"\n'
    elif case == 44: return f's^et /a "{rv}=!{rv}! ^ ({data_val} + {idx_val} + !{cv}!)"\n'
    elif case == 45: return f's^et /a "{av}=!{av}! ^ (!{lv}! - {data_val} - {idx_val})"\n'
    elif case == 46: return f's^et /a "{rv}=(!{rv}! * 13) + !{av}!"\n'
    elif case == 47: return f's^et /a "{av}=(!{av}! * 17) - !{rv}!"\n'
    elif case == 48: return f's^et /a "{rv}=!{rv}! ^ (!{av}! | {data_val} | {idx_val} | !{cv}!)"\n'
    elif case == 49: return f's^et /a "{av}=!{av}! ^ (!{rv}! & !{lv}!)"\n'
    elif case == 50: return f's^et /a "{rv}=!{rv}! + !{av}! + !{cv}! + {data_val} + {idx_val}"\n'
    elif case == 51: return f's^et /a "{av}=!{av}! ^ !{rv}! ^ !{cv}! ^ {data_val} ^ {idx_val}"\n'
    elif case == 52: return f's^et /a "{rv}=(!{rv}! ^ 2863311530) + {data_val}"\n'
    elif case == 53: return f's^et /a "{av}=(!{av}! ^ 1431655765) - {idx_val}"\n'
    elif case == 54: return f's^et /a "{rv}=!{rv}! ^ (!{av}! + ({data_val} << 2))"\n'
    elif case == 55: return f's^et /a "{av}=!{av}! + (!{rv}! ^ ({idx_val} >> 1))"\n'
    elif case == 56: return f's^et /a "{rv}=!{rv}! - (!{lv}! ^ !{cv}!)"\n'
    elif case == 57: return f's^et /a "{av}=!{av}! + (!{cv}! ^ {data_val})"\n'
    elif case == 58: return f's^et /a "{rv}=!{rv}! ^ ({idx_val} * {idx_val} * {idx_val})"\n'
    elif case == 59: return f's^et /a "{av}=!{av}! ^ ({data_val} * {data_val})"\n'
    elif case == 60: return f's^et /a "_T={data_val} %% 2"\ni^f !_T! == 0 (s^et /a "{rv}=!{rv}! + 1") e^lse (s^et /a "{rv}=!{rv}! - 1")\n'
    elif case == 61: return f's^et /a "_T={idx_val} %% 3"\ni^f !_T! == 0 (s^et /a "{av}=!{av}! + 1") e^lse (s^et /a "{av}=!{av}! - 1")\n'
    elif case == 62: return f's^et /a "_T=!{cv}! %% 4"\ni^f !_T! == 0 (s^et /a "{rv}=!{rv}! ^ (!{av}! + {data_val})") e^lse (s^et /a "{rv}=!{rv}! ^ (!{av}! - {data_val})")\n'
    elif case == 63: return f's^et /a "_T=!{lv}! %% 5"\ni^f !_T! == 0 (s^et /a "{av}=!{av}! ^ (!{rv}! + {idx_val})") e^lse (s^et /a "{av}=!{av}! ^ (!{rv}! - {idx_val})")\n'
    elif case == 64: return f's^et /a "{rv}=!{rv}! ^ (!{av}! << 3)"\n'
    elif case == 65: return f's^et /a "{av}=!{av}! ^ (!{rv}! >> 5)"\n'
    elif case == 66: return f's^et /a "{rv}=!{rv}! + ({data_val} ^ 255)"\n'
    elif case == 67: return f's^et /a "{av}=!{av}! - ({idx_val} ^ 127)"\n'
    elif case == 68: return f's^et /a "{rv}=!{rv}! ^ (!{cv}! + 4660)"\n'
    elif case == 69: return f's^et /a "{av}=!{av}! ^ (!{lv}! - 17185)"\n'
    elif case == 70: return f's^et /a "_X=!{rv}! ^ !{av}!"\ni^f !_X! g^tr {data_val} (s^et /a "{rv}=!{rv}! + !{av}!") e^lse (s^et /a "{rv}=!{rv}! ^ !{av}!")\n'
    elif case == 71: return f's^et /a "_X=!{av}! ^ !{rv}!"\ni^f !_X! l^ss {idx_val} (s^et /a "{av}=!{av}! + !{rv}!") e^lse (s^et /a "{av}=!{av}! ^ !{rv}!")\n'
    elif case == 72: return f's^et /a "{rv}=!{rv}! ^ ({data_val} * 3) + ({idx_val} * 5)"\n'
    elif case == 73: return f's^et /a "{av}=!{av}! ^ ({idx_val} * 2) - ({data_val} * 4)"\n'
    elif case == 74: return f's^et /a "{rv}=!{rv}! + (!{cv}! & 15) - ({idx_val} & 15)"\n'
    elif case == 75: return f's^et /a "{av}=!{av}! - ({data_val} & 15) + (!{cv}! & 15)"\n'
    elif case == 76: return f's^et /a "{rv}=!{rv}! ^ (!{av}! + (!{lv}! >> 16))"\n'
    elif case == 77: return f's^et /a "{av}=!{av}! ^ (!{rv}! - (!{lv}! & 65535))"\n'
    elif case == 78: return f's^et /a "_S={idx_val} & 7"\ns^et /a "{rv}=!{rv}! + ({data_val} << !_S!)"\n'
    elif case == 79: return f's^et /a "_S={data_val} & 3"\ns^et /a "{av}=!{av}! + ({idx_val} << !_S!)"\n'
    elif case == 80: return f's^et /a "{rv}=!{rv}! ^ (!{av}! + {data_val} + {idx_val} + !{cv}! + !{lv}!)"\n'
    elif case == 81: return f's^et /a "{av}=!{av}! + (!{rv}! ^ {data_val} ^ {idx_val} ^ !{cv}! ^ !{lv}!)"\n'
    elif case == 82: return f's^et /a "{rv}=!{rv}! ^ 305419896"\n'
    elif case == 83: return f's^et /a "{av}=!{av}! ^ 2271560481"\n'
    elif case == 84: return f's^et /a "{rv}=!{rv}! + ({data_val} * {data_val}) - ({idx_val} * {idx_val})"\n'
    elif case == 85: return f's^et /a "{av}=!{av}! - ({data_val} * {data_val}) + ({idx_val} * {idx_val})"\n'
    elif case == 86: return f's^et /a "{rv}=!{rv}! ^ (!{av}! >> 1) ^ (!{cv}! << 1)"\n'
    elif case == 87: return f's^et /a "{av}=!{av}! ^ (!{rv}! << 2) ^ ({idx_val} >> 2)"\n'
    elif case == 88: return f's^et /a "{rv}=!{rv}! + (!{lv}! ^ 65535)"\n'
    elif case == 89: return f's^et /a "{av}=!{av}! - (!{lv}! ^ 43690)"\n'
    elif case == 90: return f'i^f {data_val} g^tr {idx_val} (s^et /a "{rv}=!{rv}! ^ ({data_val} + {idx_val})") e^lse (s^et /a "{rv}=!{rv}! + ({data_val} ^ {idx_val})")\n'
    elif case == 91: return f'i^f !{cv}! g^tr {data_val} (s^et /a "{av}=!{av}! ^ (!{cv}! + {data_val})") e^lse (s^et /a "{av}=!{av}! + (!{cv}! ^ {data_val})")\n'
    elif case == 92: return f'i^f {idx_val} g^tr !{cv}! (s^et /a "{rv}=!{rv}! ^ ({idx_val} + !{cv}!)") e^lse (s^et /a "{rv}=!{rv}! + ({idx_val} ^ !{cv}!)")\n'
    elif case == 93: return f'i^f !{lv}! g^tr {data_val} (s^et /a "{av}=!{av}! ^ (!{lv}! + {data_val})") e^lse (s^et /a "{av}=!{av}! + (!{lv}! ^ {data_val})")\n'
    elif case == 94: return f's^et /a "{rv}=!{rv}! * 19"\n'
    elif case == 95: return f's^et /a "{av}=!{av}! * 23"\n'
    elif case == 96: return f's^et /a "{rv}=!{rv}! ^ (!{av}! + ({data_val} & 127))"\n'
    elif case == 97: return f's^et /a "{av}=!{av}! ^ (!{rv}! - ({idx_val} & 127))"\n'
    elif case == 98: return f's^et /a "{rv}=!{rv}! + (!{cv}! ^ 85)"\n'
    elif case == 99: return f's^et /a "{av}=!{av}! ^ (!{lv}! | 1)"\n'
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
        xor_key = random.randint(0, 0xFFFF)
        runtime_key = to_int32(index ^ (rs_obj.rs ^ rs_obj.cnt ^ xor_key))
        arith_idx = f"((!{rs_obj.rs_var}! ^ !{rs_obj.cnt_var}! ^ {xor_key}) ^ {runtime_key})"
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
    used_vars.update([rs_obj.rs_var, rs_obj.aux_var, rs_obj.cnt_var, rs_obj.last_rs_var])

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

            # Junk integration
            case = random.randint(0, 99)
            data_val = random.randint(0, 255)
            idx_val = random.randint(0, 100)
            decoder_cmds.append(generate_advanced_junk_internal(case, rs_obj, data_val, idx_val))
            rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs = simulate_advanced_junk(case, rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs, data_val, idx_val)
            decoder_cmds.append(rs_obj.rehash())

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
                        # Junk integration
                        case = random.randint(0, 99)
                        data_val = ord(char)
                        idx_val = random.randint(0, 100)
                        mapping_code.append(generate_advanced_junk_internal(case, rs_obj, data_val, idx_val))
                        rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs = simulate_advanced_junk(case, rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs, data_val, idx_val)
                        mapping_code.append(rs_obj.rehash())

                        mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, rs_obj=rs_obj))
                elif method > 0.45:
                    # Junk integration
                    case = random.randint(0, 99)
                    data_val = ord(char)
                    idx_val = random.randint(0, 100)
                    mapping_code.append(generate_advanced_junk_internal(case, rs_obj, data_val, idx_val))
                    rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs = simulate_advanced_junk(case, rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs, data_val, idx_val)
                    mapping_code.append(rs_obj.rehash())

                    mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, rs_obj=rs_obj))
                else:
                    # Junk integration
                    case = random.randint(0, 99)
                    data_val = ord(char)
                    idx_val = random.randint(0, 100)
                    mapping_code.append(generate_advanced_junk_internal(case, rs_obj, data_val, idx_val))
                    rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs = simulate_advanced_junk(case, rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs, data_val, idx_val)
                    mapping_code.append(rs_obj.rehash())

                    v_link = "_" + generate_random_name(10, used_vars)
                    combined = generate_extraction(target_pv, char_idx, v_link, used_vars, length=1, rs_obj=rs_obj)
                    combined += f's^et "{var_name}=!{v_link}!"\n'
                    mapping_code.append(combined)
        char_map[char] = shadow_names
    # random.shuffle(mapping_code) # Disabled to maintain rolling state sequence

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
    for idx, block in enumerate(blocks):
        b_id      = block_ids[idx]
        obf_block = [f":ID_{b_id}\n"]

        # Junk integration
        case = random.randint(0, 99)
        data_val = b_id & 0xFF
        idx_val = idx
        obf_block.append(generate_advanced_junk_internal(case, rs_obj, data_val, idx_val))
        rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs = simulate_advanced_junk(case, rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs, data_val, idx_val)
        obf_block.append(rs_obj.rehash())

        for line in block:
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
                                    # Relocate fragments into current block
                                    obf_block.append(f'set "{fv}={frag}"\n')
                                    obf_line += f"!{fv}!"
                                else:
                                    obf_line += frag
                                i += sz

            obf_block.append(obf_line + "\n")

        next_id = block_ids[idx+1] if idx+1 < len(blocks) else end_id
        # State-coupled transition
        runtime_next_id = (next_id ^ rs_obj.rs) ^ rs_obj.cnt
        obf_block.append(f's^et /a "{state_var}=({runtime_next_id} ^ !{rs_obj.rs_var}!) ^ !{rs_obj.cnt_var}!"\n')
        obf_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    used_fids = set()
    for _ in range(20):
        while True:
            fid = random.randint(100, 999)
            if fid not in used_fids:
                used_fids.add(fid)
                break
        # State-machine synchronization for fake blocks
        case = random.randint(0, 99)
        data_val = fid & 0xFF
        idx_val = random.randint(0, 100)
        target_id = random.choice(block_ids)

        # Clone state for fake block to avoid drift
        fake_rs = rs_obj.copy()

        runtime_target_id = (target_id ^ fake_rs.rs) ^ fake_rs.cnt

        flattened_blocks_data.append([
            f":ID_{fid}\n",
            generate_advanced_junk_internal(case, fake_rs, data_val, idx_val),
            fake_rs.rehash(),
            f's^et "{generate_random_name(10, used_vars)}={generate_unreadable_string(20)}"\n',
            f's^et /a "{state_var}=({runtime_target_id} ^ !{fake_rs.rs_var}!) ^ !{fake_rs.cnt_var}!"\n',
            f"g^oto :{dispatcher_label}\n",
        ])
    random.shuffle(flattened_blocks_data)

    final = [
        "@e^cho o^ff\n",
        "s^etlocal e^nabledelayedexpansion\n",
        "c^hcp 6^5001 >n^ul\n",
        f's^et /a "{rs_obj.rs_var}={rs_obj.rs}"\n',
        f's^et /a "{rs_obj.aux_var}={rs_obj.aux}"\n',
        f's^et /a "{rs_obj.cnt_var}={rs_obj.cnt}"\n',
        f's^et /a "{rs_obj.last_rs_var}={rs_obj.last_rs}"\n',
        f's^et "{state_var}=0"\n',
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
