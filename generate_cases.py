import random

def to_int32(n):
    n = n & 0xFFFFFFFF
    if n > 0x7FFFFFFF:
        n -= 0x100000000
    return n

def batch_div(a, b):
    if b == 0: return 0
    return int(float(a) / b)

state_vars = ['rs_var', 'cnt_var', 'aux_var', 'last_rs_var', 'fb_var', 'ds_var', 'ms_var']
state_vals = ['rs_val', 'cnt_val', 'aux_val', 'last_rs_val', 'fb_val', 'ds_val', 'ms_val']

def gen_case(choice):
    # This function generates both the cmds.append and the simulation logic
    cmd = ""
    sim = ""

    # Randomly pick some state variables
    v = random.sample(range(len(state_vars)), 4)
    v1, v2, v3, v4 = v[0], v[1], v[2], v[3]

    # Structurally different junk forms
    type = random.randint(0, 4)

    if type == 0: # Nested IFs
        th = random.randint(1000, 8000)
        cmd = f'    if choice == {choice}:\n'
        cmd += f'        cmds.append(f"i^f !{{state.{state_vars[v1]}}}! G^TR {th} ( i^f {{data_val}} L^SS {{idx_val}} ( s^et /a \\"{{state.{state_vars[v2]}}}+=!{{state.{state_vars[v3]}}}!\\" ) e^lse ( s^et /a \\"{{state.{state_vars[v2]}}}-=!{{state.{state_vars[v4]}}}!\\" ) ) e^lse ( s^et /a \\"{{state.{state_vars[v2]}}}={{data_val}} * {{idx_val}} ^ !{{state.{state_vars[v3]}}}!\\" )\\n")\n'

        sim = f'    if choice == {choice}:\n'
        sim += f'        if state.{state_vals[v1]} > {th}:\n'
        sim += f'            if data_val < idx_val:\n'
        sim += f'                state.{state_vals[v2]} = to_int32(state.{state_vals[v2]} + state.{state_vals[v3]})\n'
        sim += f'            else:\n'
        sim += f'                state.{state_vals[v2]} = to_int32(state.{state_vals[v2]} - state.{state_vals[v4]})\n'
        sim += f'        else:\n'
        sim += f'            state.{state_vals[v2]} = to_int32((data_val * idx_val) ^ state.{state_vals[v3]})\n'

    elif type == 1: # Double loops with cross-variable feedback
        it1 = random.randint(2, 3)
        it2 = random.randint(2, 2)
        cmd = f'    if choice == {choice}:\n'
        cmd += f'        cmds.append(f"f^or /L %%a in (1,1,{it1}) do f^or /L %%b in (1,1,{it2}) do s^et /a \\"{{state.{state_vars[v1]}}}+=!{{state.{state_vars[v2]}}}! ^ {{idx_val}}\\", \\"{{state.{state_vars[v3]}}}+=!{{state.{state_vars[v1]}}}! + {{data_val}}\\"\\n")\n'

        sim = f'    if choice == {choice}:\n'
        sim += f'        for _ in range({it1}):\n'
        sim += f'            for _ in range({it2}):\n'
        sim += f'                state.{state_vals[v1]} = to_int32(state.{state_vals[v1]} + (state.{state_vals[v2]} ^ idx_val))\n'
        sim += f'                state.{state_vals[v3]} = to_int32(state.{state_vals[v3]} + (state.{state_vals[v1]} + data_val))\n'

    elif type == 2: # State-dependent loop bounds
        mod = random.randint(3, 6)
        cmd = f'    if choice == {choice}:\n'
        cmd += f'        cmds.append(f"s^et /a \\"{{state.{state_vars[v4]}}}=!{{state.{state_vars[v1]}}}! %% {mod} + 2\\" & f^or /L %%i in (1,1,!{{state.{state_vars[v4]}}}!) do s^et /a \\"{{state.{state_vars[v2]}}}+=!{{state.{state_vars[v3]}}}! ^ {{data_val}}\\"\\n")\n'

        sim = f'    if choice == {choice}:\n'
        sim += f'        state.{state_vals[v4]} = (state.{state_vals[v1]} % {mod}) + 2\n'
        sim += f'        if state.{state_vals[v4]} < 0: state.{state_vals[v4]} = -state.{state_vals[v4]}\n' # Batch % can be negative
        sim += f'        for _ in range(state.{state_vals[v4]}):\n'
        sim += f'            state.{state_vals[v2]} = to_int32(state.{state_vals[v2]} + (state.{state_vals[v3]} ^ data_val))\n'

    elif type == 3: # Multi-variable arithmetic chain
        c1 = random.randint(1, 100)
        c2 = random.randint(1, 100)
        cmd = f'    if choice == {choice}:\n'
        cmd += f'        cmds.append(f"s^et /a \\"{{state.{state_vars[v1]}}}=(!{{state.{state_vars[v2]}}}! * {c1}) + (!{{state.{state_vars[v3]}}}! ^ {{data_val}})\\", \\"{{state.{state_vars[v4]}}}+=!{{state.{state_vars[v1]}}}! - ({c2} * {{idx_val}})\\"\\n")\n'

        sim = f'    if choice == {choice}:\n'
        sim += f'        state.{state_vals[v1]} = to_int32((state.{state_vals[v2]} * {c1}) + (state.{state_vals[v3]} ^ data_val))\n'
        sim += f'        state.{state_vals[v4]} = to_int32(state.{state_vals[v4]} + (state.{state_vals[v1]} - ({c2} * idx_val)))\n'

    elif type == 4: # Conditional arithmetic with multiple domains
        th1 = random.randint(2000, 5000)
        th2 = random.randint(2000, 5000)
        cmd = f'    if choice == {choice}:\n'
        cmd += f'        cmds.append(f"i^f !{{state.{state_vars[v1]}}}! L^SS {th1} ( s^et /a \\"{{state.{state_vars[v2]}}}^=!{{state.{state_vars[v3]}}}!\\" ) e^lse ( i^f !{{state.{state_vars[v4]}}}! G^TR {th2} ( s^et /a \\"{{state.{state_vars[v2]}}}+={{data_val}}\\" ) e^lse ( s^et /a \\"{{state.{state_vars[v2]}}}-={{idx_val}}\\" ) )\\n")\n'

        sim = f'    if choice == {choice}:\n'
        sim += f'        if state.{state_vals[v1]} < {th1}:\n'
        sim += f'            state.{state_vals[v2]} = to_int32(state.{state_vals[v2]} ^ state.{state_vals[v3]})\n'
        sim += f'        elif state.{state_vals[v4]} > {th2}:\n'
        sim += f'            state.{state_vals[v2]} = to_int32(state.{state_vals[v2]} + data_val)\n'
        sim += f'        else:\n'
        sim += f'            state.{state_vals[v2]} = to_int32(state.{state_vals[v2]} - idx_val)\n'

    return cmd, sim

all_cmds = []
all_sims = []
for i in range(1500, 2000):
    c, s = gen_case(i)
    all_cmds.append(c)
    all_sims.append(s)

with open('new_cmds.txt', 'w') as f:
    f.writelines(all_cmds)
with open('new_sims.txt', 'w') as f:
    f.writelines(all_sims)
