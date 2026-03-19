import sys
import random
import string
import os
import re

class RollingState:
    def __init__(self, rs=0, aux=0, cnt=0, last_rs=0):
        self.rs = to_int32(rs)
        self.aux = to_int32(aux)
        self.cnt = to_int32(cnt)
        self.last_rs = to_int32(last_rs)

    def copy(self):
        return RollingState(self.rs, self.aux, self.cnt, self.last_rs)

def simulate_advanced_junk(case, rs_obj, data_val=0, idx_val=0):
    rs, aux, cnt, last_rs = rs_obj.rs, rs_obj.aux, rs_obj.cnt, rs_obj.last_rs

    if case == 0: rs = to_int32(rs + aux)
    elif case == 1: aux = to_int32(aux ^ rs)
    elif case == 2: cnt = to_int32(cnt + 1)
    elif case == 3: rs = to_int32(rs ^ cnt)
    elif case == 4: aux = to_int32(aux + cnt)
    elif case == 5: rs = to_int32(rs * 3)
    elif case == 6: aux = to_int32(aux - rs)
    elif case == 7: rs = to_int32(rs ^ 0x55AA55AA)
    elif case == 8: aux = to_int32(aux + 0x12345678)
    elif case == 9: rs = to_int32(rs - cnt)
    elif case == 10: rs = to_int32(rs ^ (aux + cnt))
    elif case == 11: aux = to_int32(aux ^ (rs - cnt))
    elif case == 12: cnt = to_int32(cnt ^ (rs + aux))
    elif case == 13: rs = to_int32(rs + (aux ^ 0xFF))
    elif case == 14: aux = to_int32(aux - (rs ^ 0xAA))
    elif case == 15: rs = to_int32(rs * 5 + 1)
    elif case == 16: aux = to_int32(aux * 7 - 3)
    elif case == 17: rs = to_int32(rs ^ (rs >> 3))
    elif case == 18: aux = to_int32(aux ^ (aux << 5))
    elif case == 19: rs = to_int32(rs + (cnt * 11))
    elif case == 20: rs = to_int32(rs ^ 0xCAFEBABE)
    elif case == 21: aux = to_int32(aux ^ 0xDEADBEEF)
    elif case == 22: cnt = to_int32(cnt + rs)
    elif case == 23: rs = to_int32(rs - aux)
    elif case == 24: aux = to_int32(aux + rs + cnt)
    elif case == 25: rs = to_int32(rs ^ data_val)
    elif case == 26: aux = to_int32(aux + data_val)
    elif case == 27: rs = to_int32(rs + idx_val)
    elif case == 28: aux = to_int32(aux ^ idx_val)
    elif case == 29: rs = to_int32((rs ^ data_val) + idx_val)
    elif case == 30: aux = to_int32((aux + data_val) ^ idx_val)
    elif case == 31: rs = to_int32(rs ^ (data_val * 13))
    elif case == 32: aux = to_int32(aux + (idx_val * 17))
    elif case == 33: cnt = to_int32(cnt + data_val)
    elif case == 34: rs = to_int32(rs ^ (data_val + idx_val))
    elif case == 35: aux = to_int32(aux - (data_val ^ idx_val))
    elif case == 36: rs = to_int32(rs + (data_val & 0xFF))
    elif case == 37: aux = to_int32(aux ^ (idx_val | 0x0F))
    elif case == 38: rs = to_int32(rs * ( batch_mod(data_val, 3) + 2))
    elif case == 39: aux = to_int32(aux + ( batch_mod(idx_val, 5) + 1))
    elif case == 40: rs = to_int32(rs ^ (aux + data_val))
    elif case == 41: aux = to_int32(aux ^ (rs + idx_val))
    elif case == 42: rs = to_int32(rs - (cnt + data_val))
    elif case == 43: aux = to_int32(aux + (cnt ^ idx_val))
    elif case == 44: rs = to_int32(rs ^ ( (data_val ^ aux) + idx_val))
    elif case == 45: aux = to_int32(aux + ( (idx_val ^ rs) + data_val))
    elif case == 46: rs = to_int32(rs + (data_val ^ 0x7F))
    elif case == 47: aux = to_int32(aux ^ (idx_val + 0x3F))
    elif case == 48: rs = to_int32(rs ^ (data_val << 1))
    elif case == 49: aux = to_int32(aux + (idx_val >> 1))
    elif case == 50:
        if rs > 0: rs = to_int32(rs + 1)
        else: rs = to_int32(rs - 1)
    elif case == 51:
        if aux > 100: aux = to_int32(aux ^ 0xFF)
        else: aux = to_int32(aux + 0xFF)
    elif case == 52:
        if data_val > 10: rs = to_int32(rs + data_val)
        else: rs = to_int32(rs ^ data_val)
    elif case == 53:
        if batch_mod(idx_val, 2) == 0: aux = to_int32(aux + idx_val)
        else: aux = to_int32(aux - idx_val)
    elif case == 54:
        if (rs ^ aux) > 0: rs = to_int32(rs + cnt)
        else: aux = to_int32(aux + cnt)
    elif case == 55:
        for _ in range(3): rs = to_int32(rs + 1)
    elif case == 56:
        for _ in range(2): aux = to_int32(aux ^ 0x1)
    elif case == 57:
        if rs == 0: rs = 12345
        else: rs = to_int32(rs ^ 0x12345)
    elif case == 58:
        if aux == 0: aux = 54321
        else: aux = to_int32(aux + 0x54321)
    elif case == 59:
        if data_val == 0: rs = to_int32(rs + 10)
        else: rs = to_int32(rs ^ 10)
    elif case == 60:
        if rs > aux: rs = to_int32(rs - aux)
        else: aux = to_int32(aux - rs)
    elif case == 61:
        if rs < aux: rs = to_int32(rs + aux)
        else: aux = to_int32(aux + rs)
    elif case == 62:
        if batch_mod(rs + aux, 2) == 0: rs = to_int32(rs ^ 0xAAAA)
        else: rs = to_int32(rs + 0x5555)
    elif case == 63:
        if (rs ^ aux) < 0: aux = to_int32(aux + 0x1111)
        else: aux = to_int32(aux ^ 0x2222)
    elif case == 64:
        if cnt > 5: rs = to_int32(rs + 7)
        else: rs = to_int32(rs - 7)
    elif case == 65:
        if batch_mod(data_val, 3) == 0: aux = to_int32(aux * 2)
        else: aux = to_int32(aux + 2)
    elif case == 66:
        if batch_mod(idx_val, 4) == 0: rs = to_int32(rs ^ 0x44)
        else: rs = to_int32(rs + 0x44)
    elif case == 67:
        if rs != 0: rs = to_int32(rs ^ (batch_div(rs, 2) if rs > 0 else 0))
    elif case == 68:
        if aux != 0: aux = to_int32(aux + (batch_div(aux, 4) if aux > 0 else 0))
    elif case == 69:
        if (rs ^ data_val) > (aux ^ idx_val): rs = to_int32(rs + 1)
        else: aux = to_int32(aux + 1)
    elif case == 70:
        if rs & 1: rs = to_int32(rs + 3)
        else: rs = to_int32(rs ^ 3)
    elif case == 71:
        if aux & 1: aux = to_int32(aux - 5)
        else: aux = to_int32(aux ^ 5)
    elif case == 72:
        if batch_mod(data_val + idx_val, 2) == 0: cnt = to_int32(cnt + 2)
        else: cnt = to_int32(cnt + 1)
    elif case == 73:
        if rs > 1000: rs = to_int32(batch_mod(rs, 1000))
    elif case == 74:
        if aux > 1000: aux = to_int32(batch_mod(aux, 1000))
    elif case == 75: rs = to_int32(rs ^ last_rs)
    elif case == 76: aux = to_int32(aux + last_rs)
    elif case == 77: rs = to_int32(rs + (last_rs ^ rs))
    elif case == 78: aux = to_int32(aux ^ (last_rs + aux))
    elif case == 79: rs = to_int32(rs ^ (aux + last_rs + data_val))
    elif case == 80: aux = to_int32(aux + (rs ^ last_rs ^ idx_val))
    elif case == 81: rs = to_int32(rs + (last_rs * 2))
    elif case == 82: aux = to_int32(aux - (batch_div(last_rs, 2) if last_rs > 0 else 0))
    elif case == 83: rs = to_int32(rs ^ (last_rs ^ 0x33333333))
    elif case == 84: aux = to_int32(aux + (last_rs ^ 0xCCCCCCCC))
    elif case == 85: rs = to_int32(rs + ( (rs ^ last_rs) + (aux ^ data_val) ))
    elif case == 86: aux = to_int32(aux ^ ( (aux + last_rs) ^ (rs + idx_val) ))
    elif case == 87: rs = to_int32(rs ^ ( (cnt + last_rs) * 3 ))
    elif case == 88: aux = to_int32(aux + ( (cnt ^ last_rs) - 10 ))
    elif case == 89: rs = to_int32(rs + (data_val ^ last_rs))
    elif case == 90: aux = to_int32(aux ^ (idx_val + last_rs))
    elif case == 91: rs = to_int32(rs * ( batch_mod(last_rs, 3) + 1 ))
    elif case == 92: aux = to_int32(aux + ( batch_mod(last_rs, 4) + 2 ))
    elif case == 93:
        if last_rs > rs: rs = to_int32(rs + 5)
        else: rs = to_int32(rs - 5)
    elif case == 94:
        if last_rs < aux: aux = to_int32(aux ^ 0xF)
        else: aux = to_int32(aux + 0xF)
    elif case == 95: rs = to_int32(rs ^ (last_rs + cnt + data_val + idx_val))
    elif case == 96: aux = to_int32(aux + (last_rs ^ cnt ^ data_val ^ idx_val))
    elif case == 97: rs = to_int32(rs + ( (rs ^ 0x1) + (last_rs ^ 0x2) ))
    elif case == 98: aux = to_int32(aux ^ ( (aux + 0x3) ^ (last_rs + 0x4) ))
    elif case == 99: rs = to_int32(rs ^ (rs + aux + cnt + last_rs))

    rs_obj.last_rs = rs_obj.rs
    rs_obj.rs = rs
    rs_obj.aux = aux
    rs_obj.cnt = cnt
    return rs_obj

def generate_advanced_junk_internal(case, rs_var, aux_var, cnt_var, last_rs_var, data_var=None, idx_var=None, commutative=False):
    # Default data/idx if not provided (should not happen in real usage)
    dv = data_var if data_var else "!random!"
    iv = idx_var if idx_var else "!random!"

    if commutative:
        # Only XOR operations are commutative and safe to shuffle
        if case % 3 == 0: return f's^et /a "{rs_var}={rs_var} ^ {dv} ^ {iv}"\n'
        elif case % 3 == 1: return f's^et /a "{aux_var}={aux_var} ^ {dv} ^ {iv}"\n'
        else: return f's^et /a "{cnt_var}={cnt_var} ^ {dv} ^ {iv}"\n'

    if case == 0: return f's^et /a "{rs_var}={rs_var} + {aux_var}"\n'
    elif case == 1: return f's^et /a "{aux_var}={aux_var} ^ {rs_var}"\n'
    elif case == 2: return f's^et /a "{cnt_var}={cnt_var} + 1"\n'
    elif case == 3: return f's^et /a "{rs_var}={rs_var} ^ {cnt_var}"\n'
    elif case == 4: return f's^et /a "{aux_var}={aux_var} + {cnt_var}"\n'
    elif case == 5: return f's^et /a "{rs_var}={rs_var} * 3"\n'
    elif case == 6: return f's^et /a "{aux_var}={aux_var} - {rs_var}"\n'
    elif case == 7: return f's^et /a "{rs_var}={rs_var} ^ 0x55AA55AA"\n'
    elif case == 8: return f's^et /a "{aux_var}={aux_var} + 0x12345678"\n'
    elif case == 9: return f's^et /a "{rs_var}={rs_var} - {cnt_var}"\n'
    elif case == 10: return f's^et /a "{rs_var}={rs_var} ^ ({aux_var} + {cnt_var})"\n'
    elif case == 11: return f's^et /a "{aux_var}={aux_var} ^ ({rs_var} - {cnt_var})"\n'
    elif case == 12: return f's^et /a "{cnt_var}={cnt_var} ^ ({rs_var} + {aux_var})"\n'
    elif case == 13: return f's^et /a "{rs_var}={rs_var} + ({aux_var} ^ 0xFF)"\n'
    elif case == 14: return f's^et /a "{aux_var}={aux_var} - ({rs_var} ^ 0xAA)"\n'
    elif case == 15: return f's^et /a "{rs_var}={rs_var} * 5 + 1"\n'
    elif case == 16: return f's^et /a "{aux_var}={aux_var} * 7 - 3"\n'
    elif case == 17: return f's^et /a "{rs_var}={rs_var} ^ ({rs_var} >> 3)"\n'
    elif case == 18: return f's^et /a "{aux_var}={aux_var} ^ ({aux_var} << 5)"\n'
    elif case == 19: return f's^et /a "{rs_var}={rs_var} + ({cnt_var} * 11)"\n'
    elif case == 20: return f's^et /a "{rs_var}={rs_var} ^ 0xCAFEBABE"\n'
    elif case == 21: return f's^et /a "{aux_var}={aux_var} ^ 0xDEADBEEF"\n'
    elif case == 22: return f's^et /a "{cnt_var}={cnt_var} + {rs_var}"\n'
    elif case == 23: return f's^et /a "{rs_var}={rs_var} - {aux_var}"\n'
    elif case == 24: return f's^et /a "{aux_var}={aux_var} + {rs_var} + {cnt_var}"\n'
    elif case == 25: return f's^et /a "{rs_var}={rs_var} ^ {dv}"\n'
    elif case == 26: return f's^et /a "{aux_var}={aux_var} + {dv}"\n'
    elif case == 27: return f's^et /a "{rs_var}={rs_var} + {iv}"\n'
    elif case == 28: return f's^et /a "{aux_var}={aux_var} ^ {iv}"\n'
    elif case == 29: return f's^et /a "{rs_var}=({rs_var} ^ {dv}) + {iv}"\n'
    elif case == 30: return f's^et /a "{aux_var}=({aux_var} + {dv}) ^ {iv}"\n'
    elif case == 31: return f's^et /a "{rs_var}={rs_var} ^ ({dv} * 13)"\n'
    elif case == 32: return f's^et /a "{aux_var}={aux_var} + ({iv} * 17)"\n'
    elif case == 33: return f's^et /a "{cnt_var}={cnt_var} + {dv}"\n'
    elif case == 34: return f's^et /a "{rs_var}={rs_var} ^ ({dv} + {iv})"\n'
    elif case == 35: return f's^et /a "{aux_var}={aux_var} - ({dv} ^ {iv})"\n'
    elif case == 36: return f's^et /a "{rs_var}={rs_var} + ({dv} & 0xFF)"\n'
    elif case == 37: return f's^et /a "{aux_var}={aux_var} ^ ({iv} | 0x0F)"\n'
    elif case == 38: return f's^et /a "{rs_var}={rs_var} * ( ({dv} %% 3) + 2)"\n'
    elif case == 39: return f's^et /a "{aux_var}={aux_var} + ( ({iv} %% 5) + 1)"\n'
    elif case == 40: return f's^et /a "{rs_var}={rs_var} ^ ({aux_var} + {dv})"\n'
    elif case == 41: return f's^et /a "{aux_var}={aux_var} ^ ({rs_var} + {iv})"\n'
    elif case == 42: return f's^et /a "{rs_var}={rs_var} - ({cnt_var} + {dv})"\n'
    elif case == 43: return f's^et /a "{aux_var}={aux_var} + ({cnt_var} ^ {iv})"\n'
    elif case == 44: return f's^et /a "{rs_var}={rs_var} ^ ( ({dv} ^ {aux_var}) + {iv})"\n'
    elif case == 45: return f's^et /a "{aux_var}={aux_var} + ( ({iv} ^ {rs_var}) + {dv})"\n'
    elif case == 46: return f's^et /a "{rs_var}={rs_var} + ({dv} ^ 0x7F)"\n'
    elif case == 47: return f's^et /a "{aux_var}={aux_var} ^ ({iv} + 0x3F)"\n'
    elif case == 48: return f's^et /a "{rs_var}={rs_var} ^ ({dv} << 1)"\n'
    elif case == 49: return f's^et /a "{aux_var}={aux_var} + ({iv} >> 1)"\n'
    elif case == 50: return f'i^f !{rs_var}! g^tr 0 ( s^et /a "{rs_var}={rs_var} + 1" ) e^lse ( s^et /a "{rs_var}={rs_var} - 1" )\n'
    elif case == 51: return f'i^f !{aux_var}! g^tr 100 ( s^et /a "{aux_var}={aux_var} ^ 0xFF" ) e^lse ( s^et /a "{aux_var}={aux_var} + 0xFF" )\n'
    elif case == 52: return f'i^f !{dv}! g^tr 10 ( s^et /a "{rs_var}={rs_var} + {dv}" ) e^lse ( s^et /a "{rs_var}={rs_var} ^ {dv}" )\n'
    elif case == 53: return f's^et /a "_tmp_mod={iv} %% 2"\ni^f !_tmp_mod!==0 ( s^et /a "{aux_var}={aux_var} + {iv}" ) e^lse ( s^et /a "{aux_var}={aux_var} - {iv}" )\n'
    elif case == 54: return f's^et /a "_tmp_xor={rs_var} ^ {aux_var}"\ni^f !_tmp_xor! g^tr 0 ( s^et /a "{rs_var}={rs_var} + {cnt_var}" ) e^lse ( s^et /a "{aux_var}={aux_var} + {cnt_var}" )\n'
    elif case == 55: return f'f^or /l %%i in (1,1,3) do s^et /a "{rs_var}={rs_var} + 1"\n'
    elif case == 56: return f'f^or /l %%i in (1,1,2) do s^et /a "{aux_var}={aux_var} ^ 0x1"\n'
    elif case == 57: return f'i^f !{rs_var}!==0 ( s^et /a "{rs_var}=12345" ) e^lse ( s^et /a "{rs_var}={rs_var} ^ 0x12345" )\n'
    elif case == 58: return f'i^f !{aux_var}!==0 ( s^et /a "{aux_var}=54321" ) e^lse ( s^et /a "{aux_var}={aux_var} + 0x54321" )\n'
    elif case == 59: return f'i^f !{dv}!==0 ( s^et /a "{rs_var}={rs_var} + 10" ) e^lse ( s^et /a "{rs_var}={rs_var} ^ 10" )\n'
    elif case == 60: return f'i^f !{rs_var}! g^tr !{aux_var}! ( s^et /a "{rs_var}={rs_var} - {aux_var}" ) e^lse ( s^et /a "{aux_var}={aux_var} - {rs_var}" )\n'
    elif case == 61: return f'i^f !{rs_var}! l^ss !{aux_var}! ( s^et /a "{rs_var}={rs_var} + {aux_var}" ) e^lse ( s^et /a "{aux_var}={aux_var} + {rs_var}" )\n'
    elif case == 62: return f's^et /a "_tmp_sum={rs_var} + {aux_var}"\ns^et /a "_tmp_mod=_tmp_sum %% 2"\ni^f !_tmp_mod!==0 ( s^et /a "{rs_var}={rs_var} ^ 0xAAAA" ) e^lse ( s^et /a "{rs_var}={rs_var} + 0x5555" )\n'
    elif case == 63: return f's^et /a "_tmp_xor={rs_var} ^ {aux_var}"\ni^f !_tmp_xor! l^ss 0 ( s^et /a "{aux_var}={aux_var} + 0x1111" ) e^lse ( s^et /a "{aux_var}={aux_var} ^ 0x2222" )\n'
    elif case == 64: return f'i^f !{cnt_var}! g^tr 5 ( s^et /a "{rs_var}={rs_var} + 7" ) e^lse ( s^et /a "{rs_var}={rs_var} - 7" )\n'
    elif case == 65: return f's^et /a "_tmp_mod={dv} %% 3"\ni^f !_tmp_mod!==0 ( s^et /a "{aux_var}={aux_var} * 2" ) e^lse ( s^et /a "{aux_var}={aux_var} + 2" )\n'
    elif case == 66: return f's^et /a "_tmp_mod={iv} %% 4"\ni^f !_tmp_mod!==0 ( s^et /a "{rs_var}={rs_var} ^ 0x44" ) e^lse ( s^et /a "{rs_var}={rs_var} + 0x44" )\n'
    elif case == 67: return f'i^f not !{rs_var}!==0 ( s^et /a "_tmp_div={rs_var} / 2"\ni^f !{rs_var}! g^tr 0 ( s^et /a "{rs_var}={rs_var} ^ !_tmp_div!" ) )\n'
    elif case == 68: return f'i^f not !{aux_var}!==0 ( s^et /a "_tmp_div={aux_var} / 4"\ni^f !{aux_var}! g^tr 0 ( s^et /a "{aux_var}={aux_var} + !_tmp_div!" ) )\n'
    elif case == 69: return f's^et /a "_t1={rs_var} ^ {dv}"\ns^et /a "_t2={aux_var} ^ {iv}"\ni^f !_t1! g^tr !_t2! ( s^et /a "{rs_var}={rs_var} + 1" ) e^lse ( s^et /a "{aux_var}={aux_var} + 1" )\n'
    elif case == 70: return f's^et /a "_tmp_and={rs_var} & 1"\ni^f !_tmp_and!==1 ( s^et /a "{rs_var}={rs_var} + 3" ) e^lse ( s^et /a "{rs_var}={rs_var} ^ 3" )\n'
    elif case == 71: return f's^et /a "_tmp_and={aux_var} & 1"\ni^f !_tmp_and!==1 ( s^et /a "{aux_var}={aux_var} - 5" ) e^lse ( s^et /a "{aux_var}={aux_var} ^ 5" )\n'
    elif case == 72: return f's^et /a "_tmp_sum={dv} + {iv}"\ns^et /a "_tmp_mod=_tmp_sum %% 2"\ni^f !_tmp_mod!==0 ( s^et /a "{cnt_var}={cnt_var} + 2" ) e^lse ( s^et /a "{cnt_var}={cnt_var} + 1" )\n'
    elif case == 73: return f'i^f !{rs_var}! g^tr 1000 ( s^et /a "{rs_var}={rs_var} %% 1000" )\n'
    elif case == 74: return f'i^f !{aux_var}! g^tr 1000 ( s^et /a "{aux_var}={aux_var} %% 1000" )\n'
    elif case == 75: return f's^et /a "{rs_var}={rs_var} ^ {last_rs_var}"\n'
    elif case == 76: return f's^et /a "{aux_var}={aux_var} + {last_rs_var}"\n'
    elif case == 77: return f's^et /a "{rs_var}={rs_var} + ({last_rs_var} ^ {rs_var})"\n'
    elif case == 78: return f's^et /a "{aux_var}={aux_var} ^ ({last_rs_var} + {aux_var})"\n'
    elif case == 79: return f's^et /a "{rs_var}={rs_var} ^ ({aux_var} + {last_rs_var} + {dv})"\n'
    elif case == 80: return f's^et /a "{aux_var}={aux_var} + ({rs_var} ^ {last_rs_var} ^ {iv})"\n'
    elif case == 81: return f's^et /a "{rs_var}={rs_var} + ({last_rs_var} * 2)"\n'
    elif case == 82: return f's^et /a "_tmp_div={last_rs_var} / 2"\ni^f {last_rs_var} g^tr 0 ( s^et /a "{aux_var}={aux_var} - !_tmp_div!" )\n'
    elif case == 83: return f's^et /a "{rs_var}={rs_var} ^ ({last_rs_var} ^ 0x33333333)"\n'
    elif case == 84: return f's^et /a "{aux_var}={aux_var} + ({last_rs_var} ^ 0xCCCCCCCC)"\n'
    elif case == 85: return f's^et /a "{rs_var}={rs_var} + ( ({rs_var} ^ {last_rs_var}) + ({aux_var} ^ {dv}) )"\n'
    elif case == 86: return f's^et /a "{aux_var}={aux_var} ^ ( ({aux_var} + {last_rs_var}) ^ ({rs_var} + {iv}) )"\n'
    elif case == 87: return f's^et /a "{rs_var}={rs_var} ^ ( ({cnt_var} + {last_rs_var}) * 3 )"\n'
    elif case == 88: return f's^et /a "{aux_var}={aux_var} + ( ({cnt_var} ^ {last_rs_var}) - 10 )"\n'
    elif case == 89: return f's^et /a "{rs_var}={rs_var} + ({dv} ^ {last_rs_var})"\n'
    elif case == 90: return f's^et /a "{aux_var}={aux_var} ^ ({iv} + {last_rs_var})"\n'
    elif case == 91: return f's^et /a "_tmp_mod={last_rs_var} %% 3"\ns^et /a "_tmp_mod=_tmp_mod + 1"\ns^et /a "{rs_var}={rs_var} * !_tmp_mod!"\n'
    elif case == 92: return f's^et /a "_tmp_mod={last_rs_var} %% 4"\ns^et /a "_tmp_mod=_tmp_mod + 2"\ns^et /a "{aux_var}={aux_var} + !_tmp_mod!"\n'
    elif case == 93: return f'i^f !{last_rs_var}! g^tr !{rs_var}! ( s^et /a "{rs_var}={rs_var} + 5" ) e^lse ( s^et /a "{rs_var}={rs_var} - 5" )\n'
    elif case == 94: return f'i^f !{last_rs_var}! l^ss !{aux_var}! ( s^et /a "{aux_var}={aux_var} ^ 0xF" ) e^lse ( s^et /a "{aux_var}={aux_var} + 0xF" )\n'
    elif case == 95: return f's^et /a "{rs_var}={rs_var} ^ ({last_rs_var} + {cnt_var} + {dv} + {iv})"\n'
    elif case == 96: return f's^et /a "{aux_var}={aux_var} + ({last_rs_var} ^ {cnt_var} ^ {dv} ^ {iv})"\n'
    elif case == 97: return f's^et /a "{rs_var}={rs_var} + ( ({rs_var} ^ 0x1) + ({last_rs_var} ^ 0x2) )"\n'
    elif case == 98: return f's^et /a "{aux_var}={aux_var} ^ ( ({aux_var} + 0x3) ^ ({last_rs_var} + 0x4) )"\n'
    elif case == 99: return f's^et /a "{rs_var}={rs_var} ^ ({rs_var} + {aux_var} + {cnt_var} + {last_rs_var})"\n'
    return ""

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

def generate_extraction(pool_var, index, target_var, used_vars, length=None, rs_info=None):
    idx_var = "_" + generate_random_name(10, used_vars)

    if rs_info:
        rs_var, cnt_var, current_rs, current_cnt = rs_info
        xor_sum = to_int32(index ^ current_rs ^ current_cnt)
        arith_idx = f"(!{rs_var}! ^ !{cnt_var}! ^ {xor_sum})"
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

    rs_var = "_" + generate_random_name(6, used_vars)
    aux_var = "_" + generate_random_name(6, used_vars)
    cnt_var = "_" + generate_random_name(6, used_vars)
    last_rs_var = "_" + generate_random_name(6, used_vars)

    # Initialize rolling state
    rs_obj = RollingState(
        rs=random.randint(100000, 999999),
        aux=random.randint(100000, 999999),
        cnt=random.randint(1, 100),
        last_rs=random.randint(100000, 999999)
    )

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
            # NON-ISOLATABLE JUNK
            case = random.randint(0, 99)
            dv_val = pool_len
            iv_val = rot_amount
            decoder_cmds.append(generate_advanced_junk_internal(case, rs_var, aux_var, cnt_var, last_rs_var, data_var=str(dv_val), idx_var=str(iv_val)))
            simulate_advanced_junk(case, rs_obj, data_val=dv_val, idx_val=iv_val)

            rs_info = (rs_var, cnt_var, rs_obj.rs, rs_obj.cnt)

            # Undo left-rotation by rot_amount -> rotate right by rot_amount
            split    = (pool_len - rot_amount) % pool_len
            v_suffix = "_" + generate_random_name(8, used_vars)
            v_prefix = "_" + generate_random_name(8, used_vars)
            decoder_cmds.append(generate_extraction(pv, split, v_suffix, used_vars, rs_info=rs_info))
            decoder_cmds.append(generate_extraction(pv, 0, v_prefix, used_vars, length=split, rs_info=rs_info))
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
                # NON-ISOLATABLE JUNK
                case = random.randint(0, 99)
                dv_val = ord(char)
                iv_val = char_idx
                mapping_code.append(generate_advanced_junk_internal(case, rs_var, aux_var, cnt_var, last_rs_var, data_var=str(dv_val), idx_var=str(iv_val), commutative=True))
                # Update simulation for XOR-only logic
                if case % 3 == 0: rs_obj.rs = to_int32(rs_obj.rs ^ dv_val ^ iv_val)
                elif case % 3 == 1: rs_obj.aux = to_int32(rs_obj.aux ^ dv_val ^ iv_val)
                else: rs_obj.cnt = to_int32(rs_obj.cnt ^ dv_val ^ iv_val)

                rs_info = (rs_var, cnt_var, rs_obj.rs, rs_obj.cnt)

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
                        mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, rs_info=rs_info))
                elif method > 0.45:
                    mapping_code.append(generate_extraction(target_pv, char_idx, var_name, used_vars, length=1, rs_info=rs_info))
                else:
                    v_link = "_" + generate_random_name(10, used_vars)
                    combined = generate_extraction(target_pv, char_idx, v_link, used_vars, length=1, rs_info=rs_info)
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
    for idx, block in enumerate(blocks):
        b_id      = block_ids[idx]
        obf_block = [f":ID_{b_id}\n"]

        for line_idx, line in enumerate(block):
            # IN-BLOCK JUNK
            if random.random() < 0.3:
                case = random.randint(0, 99)
                dv_val = len(line)
                iv_val = line_idx
                obf_block.append(generate_advanced_junk_internal(case, rs_var, aux_var, cnt_var, last_rs_var, data_var=str(dv_val), idx_var=str(iv_val)))
                simulate_advanced_junk(case, rs_obj, data_val=dv_val, idx_val=iv_val)

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

            obf_block.append(obf_line + "\n")

        next_id = block_ids[idx+1] if idx+1 < len(blocks) else end_id
        xor_key = to_int32(next_id ^ rs_obj.rs ^ rs_obj.aux ^ rs_obj.cnt)
        obf_block.append(f's^et /a "{state_var}=({xor_key} ^ !{rs_var}! ^ !{aux_var}! ^ !{cnt_var}!)"\n')
        obf_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(obf_block)

    used_fids = set()
    for _ in range(20):
        while True:
            fid = random.randint(100, 999)
            if fid not in used_fids:
                used_fids.add(fid)
                break

        # Fake blocks also mutate state
        fake_block = [f":ID_{fid}\n"]
        for _ in range(random.randint(2, 5)):
            case = random.randint(0, 99)
            fake_block.append(generate_advanced_junk_internal(case, rs_var, aux_var, cnt_var, last_rs_var))

        fake_block.append(f's^et "{generate_random_name(10, used_vars)}={generate_unreadable_string(20)}"\n')
        fake_block.append(f's^et /a "{state_var}={generate_arithmetic(random.choice(block_ids))}"\n')
        fake_block.append(f"g^oto :{dispatcher_label}\n")
        flattened_blocks_data.append(fake_block)
    random.shuffle(flattened_blocks_data)

    final = [
        "@e^cho o^ff\n",
        "s^etlocal e^nabledelayedexpansion\n",
        "c^hcp 6^5001 >n^ul\n",
        f's^et /a "{rs_var}={rs_obj.rs}"\n',
        f's^et /a "{aux_var}={rs_obj.aux}"\n',
        f's^et /a "{cnt_var}={rs_obj.cnt}"\n',
        f's^et /a "{last_rs_var}={rs_obj.last_rs}"\n',
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

    # State-dependent initial jump
    xor_key_init = to_int32(block_ids[0] ^ rs_obj.rs ^ rs_obj.aux ^ rs_obj.cnt)
    final.append(f's^et /a "{state_var}=({xor_key_init} ^ !{rs_var}! ^ !{aux_var}! ^ !{cnt_var}!)"\n')

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
