import random

state_vars = ["rs_var", "cnt_var", "aux_var", "last_rs_var", "fb_var", "ds_var", "ms_var"]
state_vals = ["rs_val", "cnt_val", "aux_val", "last_rs_val", "fb_val", "ds_val", "ms_val"]
var_to_val = {v: v.replace("_var", "_val") for v in state_vars}

def generate_logic():
    gen_code = []
    sim_code = []
    for choice in range(5000, 6000):
        gen_code.append(f"    if choice == {choice}:")
        sim_code.append(f"    if choice == {choice}:")

        type_choice = random.randint(0, 2)
        target_var = random.choice(state_vars)
        target_val = var_to_val[target_var]
        source_var = random.choice([v for v in state_vars if v != target_var])
        source_val = var_to_val[source_var]

        if type_choice == 0: # Loop
            steps = random.randint(1, 2)
            gen_code.append(f"        cmds.append(f'f^or /L %%j in (1,1,{steps+1}) do ( s^et /a \"{{state.{target_var}}}^=(!{{state.{source_var}}}! + {{data_val}} + %%j)\" )\\n')")
            sim_code.append(f"        for j in range(1, {steps+2}):")
            sim_code.append(f"            state.{target_val} = to_int32(state.{target_val} ^ to_int32(state.{source_val} + data_val + j))")

        elif type_choice == 1: # Branch
            threshold = random.randint(1000, 9000)
            gen_code.append(f"        cmds.append(f'i^f !{{state.{source_var}}}! G^TR {threshold} ( s^et /a \"{{state.{target_var}}}^=(!{{state.{source_var}}}! + {{data_val}})\" ) e^lse ( s^et /a \"{{state.{target_var}}}+=(!{{state.{source_var}}}! ^ {{idx_val}})\" )\\n')")
            sim_code.append(f"        if state.{source_val} > {threshold}:")
            sim_code.append(f"            state.{target_val} = to_int32(state.{target_val} ^ to_int32(state.{source_val} + data_val))")
            sim_code.append(f"        else:")
            sim_code.append(f"            state.{target_val} = to_int32(state.{target_val} + to_int32(state.{source_val} ^ idx_val))")

        else: # Dual mutation loop
            target2_var = random.choice([v for v in state_vars if v != target_var and v != source_var])
            target2_val = var_to_val[target2_var]
            gen_code.append(f"        cmds.append(f'f^or /L %%i in (1,1,2) do ( s^et /a \"{{state.{target_var}}}+=(!{{state.{target2_var}}}! ^ {{data_val}}) + %%i\", \"{{state.{target2_var}}}^=(!{{state.{target_var}}}! + {{idx_val}}) + %%i\" )\\n')")
            sim_code.append(f"        for i in range(1, 3):")
            sim_code.append(f"            state.{target_val} = to_int32(state.{target_val} + to_int32(to_int32(state.{target2_val} ^ data_val) + i))")
            sim_code.append(f"            state.{target2_val} = to_int32(state.{target2_val} ^ to_int32(to_int32(state.{target_val} + idx_val) + i))")

        # Mandatory coupling
        couple_target_var = random.choice(state_vars)
        couple_target_val = var_to_val[couple_target_var]
        gen_code.append(f"        cmds.append(f's^et /a \"{{state.{couple_target_var}}}^=(!{{state.rs_var}}! ^ !{{state.cnt_var}}! ^ !{{state.aux_var}}! ^ !{{state.last_rs_var}}! ^ !{{state.fb_var}}! ^ !{{state.ds_var}}! ^ !{{state.ms_var}}! ^ {{data_val}} ^ {{idx_val}})\\n')")
        sim_code.append(f"        state.{couple_target_val} = to_int32(state.{couple_target_val} ^ (state.rs_val ^ state.cnt_val ^ state.aux_val ^ state.last_rs_val ^ state.fb_val ^ state.ds_val ^ state.ms_val ^ data_val ^ idx_val))")

    return "\n".join(gen_code), "\n".join(sim_code)

gen, sim = generate_logic()
with open("gen_part.txt", "w") as f: f.write(gen)
with open("sim_part.txt", "w") as f: f.write(sim)
