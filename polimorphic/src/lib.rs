use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{thread_rng, Rng, seq::SliceRandom};
use proc_macro2::TokenStream as TokenStream2;

#[derive(Clone, Debug)]
enum PrimitiveStep {
    XorDec { acc: u128, cnt: u8, tid: usize, count: usize },
    Map { table: Vec<u8>, tid: usize, count: usize },
    BitUnpack { bits: u32, total_bits: u64, tid: usize, count: usize },
    SourceLoad { tid: usize, count: usize },
    Emit { tid: usize, count: usize },
    JunkUpdate { val: u32, tid: usize },
}

struct Task {
    layer_in: usize,
    layer_out: usize,
    step: PrimitiveStep,
}

fn encode_bits(data: &[u8], bits: u32) -> (Vec<u8>, u64) {
    let mut acc = 0u128;
    let mut cnt = 0u32;
    let mut out = Vec::new();
    let mask = (1u128 << bits) - 1;
    for &b in data {
        acc |= (b as u128) << cnt;
        cnt += 8;
        while cnt >= bits {
            out.push((acc & mask) as u8);
            acc >>= bits;
            cnt -= bits;
        }
    }
    if cnt > 0 { out.push((acc & mask) as u8); }
    (out, data.len() as u64 * 8)
}

fn generate_step_code(step: &PrimitiveStep, l_in: usize, l_out: usize) -> TokenStream2 {
    match step {
        PrimitiveStep::XorDec { tid, count, .. } => {
            quote! {
                {
                    while ctx.s[#l_in].tc[#tid] < #count {
                        if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                            let b = ctx.b[#l_in][ctx.s[#l_in].rp]; ctx.s[#l_in].rp += 1;
                            let key = (ctx.s[#l_in].acc >> (ctx.s[#l_in].cnt * 8)) as u8;
                            let v = b ^ key;
                            ctx.b[#l_out].push(v);
                            ctx.s[#l_in].acc = ctx.s[#l_in].acc.wrapping_add(v as u128).rotate_left(5);
                            ctx.s[#l_in].cnt = (ctx.s[#l_in].cnt + 1) % 16;
                            ctx.s[#l_in].tc[#tid] += 1;
                        } else { break; }
                    }
                    ctx.s[#l_in].tc[#tid] == #count
                }
            }
        },
        PrimitiveStep::Map { table, tid, count } => {
            let mut map = vec![0u8; 256];
            for (i, &v) in table.iter().enumerate() { map[v as usize] = i as u8; }
            let map_lit = quote! { [#(#map),*] };
            quote! {
                {
                    while ctx.s[#l_in].tc[#tid] < #count {
                        if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                            let b = ctx.b[#l_in][ctx.s[#l_in].rp]; ctx.s[#l_in].rp += 1;
                            ctx.b[#l_out].push((#map_lit)[b as usize]);
                            ctx.s[#l_in].tc[#tid] += 1;
                        } else { break; }
                    }
                    ctx.s[#l_in].tc[#tid] == #count
                }
            }
        },
        PrimitiveStep::BitUnpack { bits, total_bits, tid, count } => {
            quote! {
                {
                    while ctx.s[#l_in].tc[#tid] < #count {
                        if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                            let v = ctx.b[#l_in][ctx.s[#l_in].rp]; ctx.s[#l_in].rp += 1;
                            ctx.s[#l_in].acc |= (v as u128) << ctx.s[#l_in].cnt;
                            ctx.s[#l_in].cnt += #bits;
                            while ctx.s[#l_in].cnt >= 8 {
                                if ctx.s[#l_in].bc < #total_bits {
                                    let out_byte = (ctx.s[#l_in].acc & 0xFF) as u8;
                                    ctx.b[#l_out].push(out_byte);
                                    ctx.s[#l_in].acc >>= 8;
                                    ctx.s[#l_in].cnt -= 8;
                                    ctx.s[#l_in].bc += 8;
                                } else {
                                    ctx.s[#l_in].cnt = 0; ctx.s[#l_in].acc = 0; break;
                                }
                            }
                            ctx.s[#l_in].tc[#tid] += 1;
                        } else { break; }
                    }
                    ctx.s[#l_in].tc[#tid] == #count
                }
            }
        },
        PrimitiveStep::SourceLoad { count, tid } => {
            quote! {
                {
                    while ctx.s[#l_in].tc[#tid] < #count {
                        if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                            let v = ctx.b[#l_in][ctx.s[#l_in].rp]; ctx.s[#l_in].rp += 1;
                            ctx.b[#l_out].push(v);
                            ctx.s[#l_in].tc[#tid] += 1;
                        } else { break; }
                    }
                    ctx.s[#l_in].tc[#tid] == #count
                }
            }
        },
        PrimitiveStep::Emit { count, tid } => {
            quote! {
                {
                    while ctx.s[0].tc[#tid] < #count {
                        if ctx.b[0].len() > ctx.s[0].rp {
                            let v = ctx.b[0][ctx.s[0].rp]; ctx.s[0].rp += 1;
                            ctx.fb.push(v);
                            ctx.s[0].tc[#tid] += 1;
                        } else { break; }
                    }
                    ctx.s[0].tc[#tid] == #count
                }
            }
        },
        PrimitiveStep::JunkUpdate { val, tid } => {
            quote! {
                {
                    if ctx.s[0].tc[#tid] == 0 {
                        ctx.js = ctx.js.wrapping_add(#val).rotate_left(3);
                        ctx.s[0].tc[#tid] = 1;
                    }
                    true
                }
            }
        },
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let os = parse_macro_input!(input as LitStr).value();
    let mut rng = thread_rng();

    let xk = rng.gen::<u8>();
    let mut current_data = os.clone().into_bytes();
    let mut initial_xor_data = Vec::new();
    for &db in &current_data { initial_xor_data.push(db ^ xk); }
    current_data = initial_xor_data;

    let n_iters = rng.gen_range(2..4);
    let mut deobf_layers = Vec::new();

    for _ in 0..n_iters {
        match rng.gen_range(0..2) {
            0 => {
                let a_init = rng.gen::<u128>();
                let mut a = a_init;
                let mut cnt = 0u8;
                let mut out = Vec::new();
                for &p in &current_data {
                    let key = (a >> (cnt * 8)) as u8;
                    out.push(p ^ key);
                    a = a.wrapping_add(p as u128).rotate_left(5);
                    cnt = (cnt + 1) % 16;
                }
                deobf_layers.push(PrimitiveStep::XorDec { acc: a_init, cnt: 0, tid: 0, count: out.len() });
                current_data = out;
            },
            _ => {
                let bits = 5;
                let (indices, total_bits) = encode_bits(&current_data, bits);
                let mut alpha: Vec<u8> = (0..256).map(|x| x as u8).collect();
                alpha.shuffle(&mut rng);
                let mut out = Vec::new();
                for &idx in &indices { out.push(alpha[idx as usize]); }
                deobf_layers.push(PrimitiveStep::BitUnpack { bits, total_bits, tid: 0, count: indices.len() });
                deobf_layers.push(PrimitiveStep::Map { table: alpha, tid: 0, count: out.len() });
                current_data = out;
            }
        }
    }

    let eb = current_data;
    let mut simulation_layers = deobf_layers.clone();
    simulation_layers.reverse();

    let total_layers = simulation_layers.len();
    let max_l = total_layers + 1;
    let mut tasks = Vec::new();
    let mut cursors = vec![0usize; max_l + 1];

    {
        let tid = cursors[max_l]; cursors[max_l] += 1;
        tasks.push(Task { layer_in: max_l, layer_out: total_layers, step: PrimitiveStep::SourceLoad { tid, count: eb.len() } });
    }

    for (l_idx, mut s) in simulation_layers.into_iter().enumerate() {
        let l_in = total_layers - l_idx;
        let l_out = l_in - 1;
        let tid = cursors[l_in]; cursors[l_in] += 1;
        match &mut s {
            PrimitiveStep::XorDec { tid: t, .. } | PrimitiveStep::Map { tid: t, .. } | PrimitiveStep::BitUnpack { tid: t, .. } => *t = tid,
            _ => {}
        }
        tasks.push(Task { layer_in: l_in, layer_out: l_out, step: s });
    }

    {
        let tid = cursors[0]; cursors[0] += 1;
        tasks.push(Task { layer_in: 0, layer_out: 0, step: PrimitiveStep::Emit { tid, count: os.len() } });
    }

    for _ in 0..5 {
        let tid = cursors[0]; cursors[0] += 1;
        tasks.push(Task { layer_in: 0, layer_out: 0, step: PrimitiveStep::JunkUpdate { val: rng.gen(), tid } });
    }

    tasks.shuffle(&mut rng);

    let target_rs: u32 = {
        struct SimState { tc: [usize; 256], rp: usize, acc: u128, cnt: u32, bc: u64 }
        let mut sim_b: Vec<Vec<u8>> = (0..=max_l).map(|_| Vec::new()).collect();
        let mut sim_s: Vec<SimState> = (0..=max_l).map(|_| SimState { tc: [0; 256], rp: 0, acc: 0, cnt: 0, bc: 0 }).collect();
        let mut sim_fb = Vec::new();
        let mut sim_rs = 0u32;
        sim_b[max_l] = eb.clone();
        for t in &tasks { if let PrimitiveStep::XorDec { acc, cnt, .. } = t.step { sim_s[t.layer_in].acc = acc; sim_s[t.layer_in].cnt = cnt as u32; } }
        let mut finished = vec![false; tasks.len()];
        let mut completed = 0;
        for _ in 0..2000 {
            for (i, t) in tasks.iter().enumerate() {
                if finished[i] { continue; }
                let tid = match t.step { PrimitiveStep::XorDec { tid, .. } | PrimitiveStep::Map { tid, .. } | PrimitiveStep::BitUnpack { tid, .. } | PrimitiveStep::SourceLoad { tid, .. } | PrimitiveStep::Emit { tid, .. } | PrimitiveStep::JunkUpdate { tid, .. } => tid };
                if sim_s[t.layer_in].tc[255] == tid {
                    let ok = match &t.step {
                        PrimitiveStep::SourceLoad { count, .. } => { let mut c = 0; while c < *count && sim_b[t.layer_in].len() > sim_s[t.layer_in].rp { let val = sim_b[t.layer_in][sim_s[t.layer_in].rp]; sim_b[t.layer_out].push(val); sim_s[t.layer_in].rp += 1; c += 1; } c == *count },
                        PrimitiveStep::XorDec { count, .. } => { let mut c = 0; while c < *count && sim_b[t.layer_in].len() > sim_s[t.layer_in].rp { let b = sim_b[t.layer_in][sim_s[t.layer_in].rp]; sim_s[t.layer_in].rp += 1; let v = b ^ (sim_s[t.layer_in].acc >> (sim_s[t.layer_in].cnt * 8)) as u8; sim_b[t.layer_out].push(v); sim_s[t.layer_in].acc = sim_s[t.layer_in].acc.wrapping_add(v as u128).rotate_left(5); sim_s[t.layer_in].cnt = (sim_s[t.layer_in].cnt + 1) % 16; c += 1; } c == *count },
                        PrimitiveStep::Map { table, count, .. } => { let mut map = vec![0u8; 256]; for (j, &v) in table.iter().enumerate() { map[v as usize] = j as u8; } let mut c = 0; while c < *count && sim_b[t.layer_in].len() > sim_s[t.layer_in].rp { let val = sim_b[t.layer_in][sim_s[t.layer_in].rp]; sim_b[t.layer_out].push(map[val as usize]); sim_s[t.layer_in].rp += 1; c += 1; } c == *count },
                        PrimitiveStep::BitUnpack { bits, total_bits, count, .. } => { let mut c = 0; while c < *count && sim_b[t.layer_in].len() > sim_s[t.layer_in].rp { let val = sim_b[t.layer_in][sim_s[t.layer_in].rp]; sim_s[t.layer_in].acc |= (val as u128) << sim_s[t.layer_in].cnt; sim_s[t.layer_in].rp += 1; sim_s[t.layer_in].cnt += *bits; while sim_s[t.layer_in].cnt >= 8 { if sim_s[t.layer_in].bc < *total_bits { sim_b[t.layer_out].push((sim_s[t.layer_in].acc & 0xFF) as u8); sim_s[t.layer_in].acc >>= 8; sim_s[t.layer_in].cnt -= 8; sim_s[t.layer_in].bc += 8; } else { sim_s[t.layer_in].cnt = 0; break; } } c += 1; } c == *count },
                        PrimitiveStep::Emit { count, .. } => { let mut c = 0; while c < *count && sim_b[0].len() > sim_s[0].rp { sim_fb.push(sim_b[0][sim_s[0].rp]); sim_s[0].rp += 1; c += 1; } c == *count },
                        _ => true,
                    };
                    if ok { sim_s[t.layer_in].tc[255] += 1; finished[i] = true; completed += 1; let id = (i + 1) as u32; sim_rs = sim_rs.wrapping_add(id.wrapping_mul(0xDEADBEEF)); }
                }
            }
            if completed == tasks.len() { break; }
        }
        let mut rec = Vec::new(); for &b in &sim_fb { rec.push(b ^ xk); }
        assert_eq!(String::from_utf8_lossy(&rec), os, "Sim fail: {}", os);
        sim_rs
    };

    let mut vt_c = Vec::new();
    let mult = rng.gen::<u32>() | 1;
    let salt = rng.gen::<u32>();
    let mut inits = Vec::new();
    let mut ids = Vec::new();
    let tasks_count = tasks.len();

    for (idx, task) in tasks.iter().enumerate() {
        let id = (idx + 1) as u32;
        ids.push(id);
        let arm_key = id.wrapping_mul(mult) ^ salt;
        let l_in = task.layer_in;
        let l_out = task.layer_out;
        let tid = match task.step {
            PrimitiveStep::XorDec { tid, .. } | PrimitiveStep::Map { tid, .. } | PrimitiveStep::BitUnpack { tid, .. } |
            PrimitiveStep::SourceLoad { tid, .. } | PrimitiveStep::Emit { tid, .. } | PrimitiveStep::JunkUpdate { tid, .. } => tid,
        };
        if let PrimitiveStep::XorDec { acc, cnt, .. } = task.step {
            inits.push(quote! { ctx.s[#l_in].acc = #acc; ctx.s[#l_in].cnt = #cnt as u32; });
        }
        let step_code = generate_step_code(&task.step, l_in, l_out);
        vt_c.push(quote! { #arm_key => {
            if ctx.s[#l_in].tc[255] == #tid {
                if #step_code { ctx.s[#l_in].tc[255] += 1; true } else { false }
            } else { false }
        } });
    }

    let eb_lit = quote! { [#(#eb),*] };
    let ids_lit = quote! { [#(#ids),*] };

    let expanded = quote! {
        {
            struct Context { b: Vec<Vec<u8>>, s: Vec<State>, fb: Vec<u8>, rs: u32, js: u32 }
            struct State { tc: [usize; 256], rp: usize, acc: u128, cnt: u32, bc: u64 }
            impl State { fn new() -> Self { Self { tc: [0; 256], rp: 0, acc: 0, cnt: 0, bc: 0 } } }
            let mut ctx = Context { b: (0..=#max_l).map(|_| Vec::new()).collect(), s: (0..=#max_l).map(|_| State::new()).collect(), fb: Vec::new(), rs: 0, js: 0 };
            ctx.b[#max_l] = #eb_lit.to_vec();
            #(#inits)*
            let ids = #ids_lit;
            let mut finished = [false; #tasks_count];
            let mut completed = 0;
            for _ in 0..20000 {
                for i in 0..#tasks_count {
                    if !finished[i] && (match ids[i].wrapping_mul(#mult) ^ #salt { #(#vt_c)* _ => false }) {
                        finished[i] = true;
                        completed += 1;
                        let id = ids[i];
                        ctx.rs = ctx.rs.wrapping_add(id.wrapping_mul(0xDEADBEEF));
                    }
                }
                if completed == #tasks_count { break; }
            }
            let lock = (ctx.rs ^ (ctx.rs >> 13) ^ (ctx.rs >> 21)) as u8;
            let target_lock = (#target_rs ^ (#target_rs >> 13) ^ (#target_rs >> 21)) as u8;
            let mut res = Vec::new();
            for &b in &ctx.fb { res.push(b ^ #xk ^ lock ^ target_lock); }
            String::from_utf8_lossy(&res).into_owned()
        }
    };
    expanded.into()
}
