
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};

#[derive(Clone, Debug)]
enum PrimitiveStep {
    XorDec { key: u8, variant: u32, count: usize, tid: usize },
    Map { table: Vec<u8>, count: usize, tid: usize },
    BitUnpack { bits: u32, total_bits: u64, count: usize, tid: usize },
    BaseUnpack { base: u128, in_c: usize, out_c: usize, total_bytes: u64, count: usize, tid: usize },
    BigIntStep { base: u128, is_init: bool, is_last: bool, total_bytes: u64, count: usize, tid: usize },
    JunkUpdate { val: u32 },
}

#[derive(Clone, Debug)]
struct Task {
    layer_in: usize,
    layer_out: usize,
    step: PrimitiveStep,
}

struct Pipeline {
    encoder: Box<dyn Fn(&[u8]) -> (Vec<u8>, Vec<Vec<PrimitiveStep>>)>,
}

// --- BITSTREAM HELPERS ---

fn encode_bits(data: &[u8], bits: u32, alphabet: &[u8]) -> (Vec<u8>, u64) {
    let mut out = Vec::new();
    let mut acc = 0u128;
    let mut count = 0u32;
    for &b in data {
        acc = (acc << 8) | (b as u128);
        count += 8;
        while count >= bits {
            count -= bits;
            let idx = (acc >> count) & ((1 << bits) - 1);
            out.push(alphabet[idx as usize]);
            acc &= (1 << count) - 1;
        }
    }
    if count > 0 {
        let idx = (acc << (bits - count)) & ((1 << bits) - 1);
        out.push(alphabet[idx as usize]);
    }
    (out, data.len() as u64 * 8)
}

// --- BIGINT HELPERS ---

fn encode_bigint(data: &[u8], base: u128, alphabet: &[u8]) -> Vec<u8> {
    let mut leading_zeros = 0;
    for &b in data { if b == 0 { leading_zeros += 1; } else { break; } }
    let mut res = Vec::new();
    let mut bytes = data[leading_zeros..].to_vec();
    while !bytes.iter().all(|&b| b == 0) {
        let mut remainder = 0u64;
        for b in bytes.iter_mut() {
            let val = *b as u64 + (remainder * 256);
            *b = (val / base as u64) as u8;
            remainder = val % base as u64;
        }
        res.push(alphabet[remainder as usize]);
    }
    for _ in 0..leading_zeros {
        res.push(alphabet[0]);
    }
    res.reverse();
    res
}

// --- Z85 HELPERS ---

fn encode_z85_custom(data: &[u8], alphabet: &[u8]) -> (Vec<u8>, u64) {
    let mut d = data.to_vec();
    while d.len() % 4 != 0 {
        d.push(0);
    }
    let mut out = Vec::new();
    for chunk in d.chunks(4) {
        let mut val = 0u64;
        for &b in chunk { val = (val << 8) | b as u64; }
        let mut res = Vec::new();
        for _ in 0..5 {
            res.push(alphabet[(val % 85) as usize]);
            val /= 85;
        }
        res.reverse();
        out.extend(res);
    }
    (out, data.len() as u64)
}

fn get_pipelines() -> Vec<Pipeline> {
    let b64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes().to_vec();
    let b32_alpha = "abcdefghijklmnopqrstuvwxyz234567".as_bytes().to_vec();
    let b36_alpha = "0123456789abcdefghijklmnopqrstuvwxyz".as_bytes().to_vec();
    let z85_alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#".as_bytes().to_vec();
    let mut b91_alpha = Vec::new();
    for i in 33..127u8 {
        if i == b'\"' || i == b'\'' || i == b'\\' { continue; }
        b91_alpha.push(i);
    }

    let b32 = || {
        let alpha = b32_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bits) = encode_bits(data, 5, &alpha);
                let mut m_steps = Vec::new();
                let mut u_steps = Vec::new();
                let n = out.len();
                let frags = (n / 16).clamp(3, 8);
                for i in 0..frags {
                    let count = if i == frags - 1 { n - (i * (n / frags)) } else { n / frags };
                    m_steps.push(PrimitiveStep::Map { table: alpha.clone(), count, tid: i });
                    u_steps.push(PrimitiveStep::BitUnpack { bits: 5, total_bits, count, tid: i });
                }
                (out, vec![m_steps, u_steps])
            }),
        }
    };
    let b36 = || {
        let alpha = b36_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let out = encode_bigint(data, 36, &alpha);
                let mut m_steps = Vec::new();
                let mut u_steps = Vec::new();
                let n = out.len();
                let frags = (n / 16).clamp(3, 8);
                for i in 0..frags {
                    let count = if i == frags - 1 { n - (i * (n / frags)) } else { n / frags };
                    m_steps.push(PrimitiveStep::Map { table: alpha.clone(), count, tid: i });
                }
                u_steps.push(PrimitiveStep::BigIntStep { base: 36, is_init: true, is_last: false, total_bytes: data.len() as u64, count: 0, tid: 0 });
                for i in 0..frags {
                    let is_last = i == frags - 1;
                    let count = if is_last { n - (i * (n / frags)) } else { n / frags };
                    u_steps.push(PrimitiveStep::BigIntStep { base: 36, is_init: false, is_last, total_bytes: data.len() as u64, count, tid: i + 1 });
                }
                (out, vec![m_steps, u_steps])
            }),
        }
    };
    let b64 = || {
        let alpha = b64_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bits) = encode_bits(data, 6, &alpha);
                let mut m_steps = Vec::new();
                let mut u_steps = Vec::new();
                let n = out.len();
                let frags = (n / 16).clamp(3, 8);
                for i in 0..frags {
                    let count = if i == frags - 1 { n - (i * (n / frags)) } else { n / frags };
                    m_steps.push(PrimitiveStep::Map { table: alpha.clone(), count, tid: i });
                    u_steps.push(PrimitiveStep::BitUnpack { bits: 6, total_bits, count, tid: i });
                }
                (out, vec![m_steps, u_steps])
            }),
        }
    };
    let z85 = || {
        let alpha = z85_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bytes) = encode_z85_custom(data, &alpha);
                let mut m_steps = Vec::new();
                let mut u_steps = Vec::new();
                let n = out.len();
                let frags = (n / 16).clamp(3, 8);
                for i in 0..frags {
                    let count = if i == frags - 1 { n - (i * (n / frags)) } else { n / frags };
                    m_steps.push(PrimitiveStep::Map { table: alpha.clone(), count, tid: i });
                }
                let total_chunks = n / 5;
                for i in 0..frags {
                    let count = if i == frags - 1 { total_chunks - (i * (total_chunks / frags)) } else { total_chunks / frags };
                    u_steps.push(PrimitiveStep::BaseUnpack { base: 85, in_c: 5, out_c: 4, total_bytes, count, tid: i });
                }
                (out, vec![m_steps, u_steps])
            }),
        }
    };
    let b91 = || {
        let alpha = b91_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let out = encode_bigint(data, 91, &alpha);
                let mut m_steps = Vec::new();
                let mut u_steps = Vec::new();
                let n = out.len();
                let frags = (n / 16).clamp(3, 8);
                for i in 0..frags {
                    let count = if i == frags - 1 { n - (i * (n / frags)) } else { n / frags };
                    m_steps.push(PrimitiveStep::Map { table: alpha.clone(), count, tid: i });
                }
                u_steps.push(PrimitiveStep::BigIntStep { base: 91, is_init: true, is_last: false, total_bytes: data.len() as u64, count: 0, tid: 0 });
                for i in 0..frags {
                    let is_last = i == frags - 1;
                    let count = if is_last { n - (i * (n / frags)) } else { n / frags };
                    u_steps.push(PrimitiveStep::BigIntStep { base: 91, is_init: false, is_last, total_bytes: data.len() as u64, count, tid: i + 1 });
                }
                (out, vec![m_steps, u_steps])
            }),
        }
    };

    vec![b32(), b36(), b64(), z85(), b91()]
}

// --- HELPERS ---

fn compute_entropy(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| {
        acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555
    })
}

// --- GENERATORS ---

fn generate_step_map(alphabet: &[u8], l_in: usize, l_out: usize, count: usize, tid: usize, _rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);
    quote! {
        {
            while ctx.s[#l_in].tc[#tid] < #count {
                if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                    let b = ctx.b[#l_in][ctx.s[#l_in].rp];
                    ctx.s[#l_in].rp += 1;
                    let v = (#map_lit)[b as usize];
                    if v != 255 {
                        if #l_out == 0 { ctx.fb.push(vec![v]); }
                        else { ctx.b[#l_out].push(v); }
                    }
                    ctx.s[#l_in].tc[#tid] += 1;
                } else { break; }
            }
            ctx.s[#l_in].tc[#tid] == #count
        }
    }
}

fn generate_step_bit_unpack(bits: u32, total_bits: u64, l_in: usize, l_out: usize, count: usize, tid: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        {
            while ctx.s[#l_in].tc[#tid] < #count {
                if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                    let v = ctx.b[#l_in][ctx.s[#l_in].rp];
                    ctx.s[#l_in].rp += 1;
                    ctx.s[#l_in].acc = (ctx.s[#l_in].acc << #bits) | (v as u128);
                    ctx.s[#l_in].cnt += #bits;
                    while ctx.s[#l_in].cnt >= 8 {
                        ctx.s[#l_in].cnt -= 8;
                        if ctx.s[#l_in].bc < #total_bits {
                            let out_byte = (ctx.s[#l_in].acc >> ctx.s[#l_in].cnt) as u8;
                            if #l_out == 0 { ctx.fb.push(vec![out_byte]); }
                            else { ctx.b[#l_out].push(out_byte); }
                            ctx.s[#l_in].bc += 8;
                        }
                        ctx.s[#l_in].acc &= (1 << ctx.s[#l_in].cnt) - 1;
                    }
                    ctx.s[#l_in].tc[#tid] += 1;
                } else { break; }
            }
            ctx.s[#l_in].tc[#tid] == #count
        }
    }
}

fn generate_step_base_unpack(base: u128, in_c: usize, out_c: usize, total_bytes: u64, l_in: usize, l_out: usize, count: usize, tid: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        {
            while ctx.s[#l_in].tc[#tid] < #count {
                if ctx.b[#l_in].len() >= ctx.s[#l_in].rp + #in_c {
                    let chunk = &ctx.b[#l_in][ctx.s[#l_in].rp..ctx.s[#l_in].rp + #in_c];
                    ctx.s[#l_in].rp += #in_c;
                    let mut v = 0u128;
                    for &c in chunk { v = v * #base + (c as u128); }
                    for i in (0..#out_c).rev() {
                        if ctx.s[#l_in].bc < #total_bytes {
                            let out_byte = ((v >> (i * 8)) & 0xff) as u8;
                            if #l_out == 0 { ctx.fb.push(vec![out_byte]); }
                            else { ctx.b[#l_out].push(out_byte); }
                            ctx.s[#l_in].bc += 1;
                        }
                    }
                    ctx.s[#l_in].tc[#tid] += 1;
                } else { break; }
            }
            ctx.s[#l_in].tc[#tid] == #count
        }
    }
}

fn generate_step_bigint(base: u128, is_init: bool, is_last: bool, total_bytes: u64, l_in: usize, l_out: usize, count: usize, tid: usize, _rng: &mut impl Rng) -> TokenStream2 {
    if is_init {
        quote! { { ctx.s[#l_in].bi_res = vec![0u32]; ctx.s[#l_in].bi_lz = 0; ctx.s[#l_in].bi_started = false; true } }
    } else {
        quote! {
            {
                while ctx.s[#l_in].tc[#tid] < #count {
                    if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                        let v = ctx.b[#l_in][ctx.s[#l_in].rp];
                        ctx.s[#l_in].rp += 1;
                        if !ctx.s[#l_in].bi_started && v == 0 {
                            ctx.s[#l_in].bi_lz += 1;
                        } else {
                            ctx.s[#l_in].bi_started = true;
                            let mut carry = v as u64;
                            for digit in ctx.s[#l_in].bi_res.iter_mut() {
                                let prod = (*digit as u64) * (#base as u64) + carry;
                                *digit = prod as u32;
                                carry = prod >> 32;
                            }
                            while carry > 0 {
                                ctx.s[#l_in].bi_res.push(carry as u32);
                                carry >>= 32;
                            }
                        }
                        ctx.s[#l_in].tc[#tid] += 1;
                    } else { break; }
                }
                let done = ctx.s[#l_in].tc[#tid] == #count;
                if #is_last && done {
                    let mut out = vec![0u8; ctx.s[#l_in].bi_lz];
                    if !(ctx.s[#l_in].bi_res.len() == 1 && ctx.s[#l_in].bi_res[0] == 0) || ctx.s[#l_in].bi_res.len() == ctx.s[#l_in].bi_lz {
                        let rl = ctx.s[#l_in].bi_res.len();
                        let mut bytes_out = Vec::new();
                        for (idx, &val) in ctx.s[#l_in].bi_res.iter().enumerate().rev() {
                            let bytes = val.to_be_bytes();
                            if idx == rl - 1 {
                                 let mut skip = 0;
                                 while skip < 4 && bytes[skip] == 0 { skip += 1; }
                                 bytes_out.extend_from_slice(&bytes[skip..]);
                            } else { bytes_out.extend_from_slice(&bytes); }
                        }
                        out.extend(bytes_out);
                    }
                    let final_bytes = &out[..(#total_bytes as usize).min(out.len())];
                    for &b in final_bytes {
                        if #l_out == 0 { ctx.fb.push(vec![b]); }
                        else { ctx.b[#l_out].push(b); }
                    }
                }
                done
            }
        }
    }
}


fn generate_step_xor_dec(_key: u8, variant: u32, l_in: usize, l_out: usize, count: usize, tid: usize, _rng: &mut impl Rng) -> TokenStream2 {
    let u_l = match variant {
        0 => quote! { ctx.s[#l_in].acc = (ctx.s[#l_in].acc as u8).wrapping_add(b) as u128; },
        1 => quote! { ctx.s[#l_in].acc = (ctx.s[#l_in].acc as u8).wrapping_sub(b) as u128; },
        _ => quote! { ctx.s[#l_in].acc = (ctx.s[#l_in].acc as u8).rotate_left(3) as u128; },
    };
    quote! {
        {
            while ctx.s[#l_in].tc[#tid] < #count {
                if ctx.b[#l_in].len() > ctx.s[#l_in].rp {
                    let b = ctx.b[#l_in][ctx.s[#l_in].rp];
                    ctx.s[#l_in].rp += 1;
                    let db = b ^ (ctx.s[#l_in].acc as u8);
                    #u_l
                    if #l_out == 0 { ctx.fb.push(vec![db]); }
                    else { ctx.b[#l_out].push(db); }
                    ctx.s[#l_in].tc[#tid] += 1;
                } else { break; }
            }
            ctx.s[#l_in].tc[#tid] == #count
        }
    }
}


fn generate_fragmented_string_recovery(target_rs: u32, rng: &mut impl Rng) -> TokenStream2 {
    let s_n = Ident::new(&format!("S_{}", rng.gen::<u32>()), Span::call_site());

    quote! {
        {
            struct #s_n(Vec<Vec<u8>>, u32, u32);
            impl ::std::fmt::Display for #s_n {
                fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    if self.1 != #target_rs { return Ok(()); }
                    let temp_rs = self.1;
                    let temp_js = self.2;
                    let lock = (temp_rs ^ (temp_rs >> 13) ^ (temp_rs >> 21)) as u8;
                    for chunk in &self.0 {
                        let db_vec: Vec<u8> = chunk.iter().map(|&b| {
                            let db = b ^ lock;
                            let _ = temp_js.wrapping_add(db as u32);
                            db
                        }).collect();
                        f.write_str(&String::from_utf8_lossy(&db_vec))?;
                    }
                    Ok(())
                }
            }
            #s_n(ctx.fb.clone(), ctx.rs, ctx.js).to_string()
        }
    }
}

fn generate_polymorphic_decode_chain(
    transform_ids: &[u32],
    dispatch_name: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let target_rs = transform_ids.iter().fold(0u32, |acc, &x| acc ^ x);
    let fr = generate_fragmented_string_recovery(target_rs, rng);
    let ids_lit = transform_ids.iter().map(|&id| Literal::u32_unsuffixed(id)).collect::<Vec<_>>();
    let tasks_count = transform_ids.len();

    match rng.gen_range(0..2) {
        0 => { // State machine with retry loop
            quote! {
                let mut tasks_done = [false; #tasks_count];
                let mut done_count = 0;
                let ids = [#(#ids_lit),*];
                while done_count < #tasks_count {
                    for i in 0..#tasks_count {
                        if !tasks_done[i] {
                            if #dispatch_name(ids[i], &mut ctx) {
                                tasks_done[i] = true;
                                done_count += 1;
                            }
                        }
                    }
                }
                #fr
            }
        },
        _ => { // Nested blocks with inner loop
            quote! {
                let mut tasks_done = [false; #tasks_count];
                let mut done_count = 0;
                let ids = [#(#ids_lit),*];
                loop {
                    for i in 0..#tasks_count {
                        if !tasks_done[i] {
                            if #dispatch_name(ids[i], &mut ctx) {
                                tasks_done[i] = true;
                                done_count += 1;
                            }
                        }
                    }
                    if done_count == #tasks_count { break; }
                }
                #fr
            }
        }
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let os = lit_str.value();
    let entropy = compute_entropy(os.as_bytes());
    let mut rng = thread_rng();
    let pl = get_pipelines();
    let num_layers = ((entropy % 3) + 4) as usize; // 4 to 6 layers
    let mut current_data = os.clone().into_bytes();
    let mut all_layer_steps = Vec::new();

    let mut pipelines_layers = Vec::new();
    for _ in 0..num_layers {
        let idx = rng.gen_range(0..pl.len());
        let (encoded, layers) = (pl[idx].encoder)(&current_data);
        current_data = encoded;
        pipelines_layers.push(layers);
    }
    pipelines_layers.reverse();
    for layers in pipelines_layers {
        all_layer_steps.extend(layers);
    }

    let xk = rng.gen::<u8>();
    let ev = rng.gen_range(0..3u32);
    let mut key = xk;
    let mut eb = Vec::with_capacity(current_data.len());
    for &ob in &current_data {
        let eb_b = ob ^ key;
        eb.push(eb_b);
        match ev {
            0 => key = key.wrapping_add(eb_b),
            1 => key = key.wrapping_sub(eb_b),
            _ => key = key.rotate_left(3),
        };
    }

    // Add XOR Layer
    let mut xor_steps = Vec::new();
    let n = eb.len();
    let frags = (n / 16).clamp(3, 8);
    for i in 0..frags {
        let count = if i == frags - 1 { n - (i * (n / frags)) } else { n / frags };
        xor_steps.push(PrimitiveStep::XorDec { key: xk, variant: ev, count, tid: i });
    }
    all_layer_steps.insert(0, xor_steps);

    let actual_layers = all_layer_steps.len(); // XOR + N layers
    let mut tasks = Vec::new();
    let mut layer_task_counters = vec![0usize; actual_layers + 1];
    for (l_idx, steps) in all_layer_steps.into_iter().enumerate() {
        let l_in = actual_layers - l_idx;
        let l_out = l_in - 1;
        for mut step in steps {
            let tid = layer_task_counters[l_in];
            layer_task_counters[l_in] += 1;
            match &mut step {
                PrimitiveStep::XorDec { tid: t, .. } |
                PrimitiveStep::Map { tid: t, .. } |
                PrimitiveStep::BitUnpack { tid: t, .. } |
                PrimitiveStep::BaseUnpack { tid: t, .. } |
                PrimitiveStep::BigIntStep { tid: t, .. } => *t = tid,
                _ => {}
            }
            tasks.push(Task { layer_in: l_in, layer_out: l_out, step });
        }
    }

    // Randomized Task Interleaving (Unifies Space)
    let mut ordered_tasks = Vec::new();
    let mut layer_cursors = vec![0usize; actual_layers + 1]; // cursor for each layer
    let mut layer_tasks: Vec<Vec<Task>> = vec![Vec::new(); actual_layers + 1];
    for t in &tasks {
        layer_tasks[t.layer_in].push(t.clone());
    }

    let mut layer_produced = vec![0usize; actual_layers + 1];
    layer_produced[actual_layers] = current_data.len(); // Initial encoded string length

    // We also need to track how many items are currently 'available' in each buffer
    // since we are simulating the process.
    let mut buffer_available = vec![0usize; actual_layers + 1];
    buffer_available[actual_layers] = current_data.len();

    while (1..=actual_layers).any(|l| layer_cursors[l] < layer_tasks[l].len()) {
        let mut ready_layers = Vec::new();
        for l in 1..=actual_layers {
            if layer_cursors[l] < layer_tasks[l].len() {
                ready_layers.push(l);
            }
        }

        if ready_layers.is_empty() { break; }
        let l = ready_layers[rng.gen_range(0..ready_layers.len())];
        let task = &layer_tasks[l][layer_cursors[l]];

        ordered_tasks.push(task.clone());
        layer_cursors[l] += 1;

        // Interject Junk tasks (Bounded Ratio)
        if rng.gen_bool(0.1) {
            ordered_tasks.push(Task { layer_in: 0, layer_out: 0, step: PrimitiveStep::JunkUpdate { val: rng.gen() } });
        }
    }

    let mut vt_c = Vec::new();
    let mut rids = Vec::new();
    let salt = rng.gen::<u32>();
    let mult = rng.gen::<u32>() | 1;
    for task in ordered_tasks {
        let step_code = match task.step {
            PrimitiveStep::XorDec { key, variant, count, tid } => generate_step_xor_dec(key, variant, task.layer_in, task.layer_out, count, tid, &mut rng),
            PrimitiveStep::Map { ref table, count, tid } => generate_step_map(table, task.layer_in, task.layer_out, count, tid, &mut rng),
            PrimitiveStep::BitUnpack { bits, total_bits, count, tid } => generate_step_bit_unpack(bits, total_bits, task.layer_in, task.layer_out, count, tid, &mut rng),
            PrimitiveStep::BaseUnpack { base, in_c, out_c, total_bytes, count, tid } => generate_step_base_unpack(base, in_c, out_c, total_bytes, task.layer_in, task.layer_out, count, tid, &mut rng),
            PrimitiveStep::BigIntStep { base, is_init, is_last, total_bytes, count, tid } => generate_step_bigint(base, is_init, is_last, total_bytes, task.layer_in, task.layer_out, count, tid, &mut rng),
            PrimitiveStep::JunkUpdate { val } => quote! { { ctx.js = ctx.js.wrapping_add(#val).rotate_left(3); true } },
        };

        let id_val = rng.gen::<u32>();
        let arm_key = id_val.wrapping_mul(mult) ^ salt;

        let tid_check = match task.step {
            PrimitiveStep::XorDec { tid, .. } |
            PrimitiveStep::Map { tid, .. } |
            PrimitiveStep::BitUnpack { tid, .. } |
            PrimitiveStep::BaseUnpack { tid, .. } |
            PrimitiveStep::BigIntStep { tid, .. } => {
                let l_in = task.layer_in;
                quote! { ctx.s[#l_in].next_tid == #tid }
            },
            _ => quote! { true },
        };
        let tid_inc = match task.step {
            PrimitiveStep::XorDec { .. } |
            PrimitiveStep::Map { .. } |
            PrimitiveStep::BitUnpack { .. } |
            PrimitiveStep::BaseUnpack { .. } |
            PrimitiveStep::BigIntStep { .. } => {
                let l_in = task.layer_in;
                quote! { ctx.s[#l_in].next_tid += 1; }
            },
            _ => quote! {},
        };

        vt_c.push(quote! {
            #arm_key => {
                if #tid_check {
                    let progress = { #step_code };
                    if progress {
                        #tid_inc
                        ctx.rs ^= #id_val;
                    }
                    progress
                } else { false }
            }
        });
        rids.push(id_val);
    }

    let s_n = Ident::new(&format!("O_{}", rng.gen::<u32>()), Span::call_site());
    let m_n = Ident::new(&format!("r_{}", rng.gen::<u32>()), Span::call_site());
    let d_n = Ident::new(&format!("d_{}", rng.gen::<u32>()), Span::call_site());
    let dc = generate_polymorphic_decode_chain(&rids, &d_n, &mut rng);
    let (df, di, rl_v) = match rng.gen_range(0..3) {
        0 => {
            let dl = Literal::byte_string(&eb);
            (quote! { d: &'a [u8], }, quote! { d: #dl, }, quote! { self.d.to_vec() })
        },
        1 => {
            let even: Vec<u8> = eb.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = eb.iter().skip(1).step_by(2).cloned().collect();
            let el = Literal::byte_string(&even);
            let ol = Literal::byte_string(&odd);
            (quote! { e: &'a [u8], o: &'a [u8], }, quote! { e: #el, o: #ol, },
             quote! {
                {
                    let mut rd = Vec::new();
                    let mut ei = self.e.iter();
                    let mut oi = self.o.iter();
                    loop {
                        match (ei.next(), oi.next()) {
                            (Some(ev), Some(ov)) => { rd.push(*ev); rd.push(*ov); },
                            (Some(ev), None) => { rd.push(*ev); break; },
                            _ => break,
                        }
                    }
                    rd
                }
             })
        },
        _ => {
            let ji: Vec<u8> = eb.iter().flat_map(|&b| vec![b, rng.gen()]).collect();
            let dl = Literal::byte_string(&ji);
            (quote! { j: &'a [u8], }, quote! { j: #dl, }, quote! { self.j.iter().step_by(2).cloned().collect::<Vec<u8>>() })
        }
    };
    let expanded = quote! {{
        const MAX_LAYERS: usize = #actual_layers;
        #[derive(Clone)]
        struct LayerState {
            rp: usize,
            acc: u128,
            cnt: u32,
            bc: u64,
            bi_res: Vec<u32>,
            bi_lz: usize,
            bi_started: bool,
            tc: [usize; 32], // Task cursors
            next_tid: usize,
        }
        struct Context {
            b: Vec<Vec<u8>>,
            s: Vec<LayerState>,
            fb: Vec<Vec<u8>>,
            rs: u32,
            js: u32,
        }
        struct #s_n<'a> { #df key_ignored: u8, }
        impl<'a> #s_n<'a> {
            fn #m_n(&mut self) -> String {
                let mut ctx = Context {
                    b: vec![Vec::new(); MAX_LAYERS + 1],
                    s: vec![LayerState {
                        rp: 0, acc: 0, cnt: 0, bc: 0, bi_res: Vec::new(), bi_lz: 0, bi_started: false,
                        tc: [0; 32], next_tid: 0,
                    }; MAX_LAYERS + 1],
                    fb: Vec::new(),
                    rs: 0,
                    js: 0,
                };

                let rd = #rl_v;
                // Initial input in b[MAX_LAYERS]
                ctx.b[MAX_LAYERS] = rd;
                // Initialize XOR layer key
                ctx.s[MAX_LAYERS].acc = #xk as u128;

                let mut #d_n = |id: u32, ctx: &mut Context| -> bool {
                    let lock_in = (ctx.rs ^ (ctx.rs >> 13) ^ (ctx.rs >> 21)) as u8;
                    for l in 0..=MAX_LAYERS {
                        for b in ctx.b[l].iter_mut() { *b ^= lock_in; }
                    }
                    for f in ctx.fb.iter_mut() {
                        for b in f.iter_mut() { *b ^= lock_in; }
                    }

                    let res = match (id.wrapping_mul(#mult) ^ #salt) {
                        #(#vt_c)*
                        _ => false
                    };

                    let lock_out = (ctx.rs ^ (ctx.rs >> 13) ^ (ctx.rs >> 21)) as u8;
                    for l in 0..=MAX_LAYERS {
                        for b in ctx.b[l].iter_mut() { *b ^= lock_out; }
                    }
                    for f in ctx.fb.iter_mut() {
                        for b in f.iter_mut() { *b ^= lock_out; }
                    }
                    res
                };

                #dc
            }
        }
        let mut inst = #s_n { #di key_ignored: 0, };
        inst.#m_n()
    }};
    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_random_pipelines() {
        let mut rng = thread_rng();
        let originals = vec![
            b"Simple Calculator".to_vec(),
            vec![0, 0, 1, 2, 3],
            vec![1, 2, 3, 0, 0],
            vec![0, 1, 0, 2, 0],
            b"A".to_vec(),
            b"".to_vec(),
            vec![0],
            vec![0, 0, 0],
        ];
        let pl = get_pipelines();
        for original in originals {
            for _ in 0..50 {
                let num_layers = rng.gen_range(1..=4);
                let mut current_data = original.clone();
                let mut all_layer_steps = Vec::new();
                let mut pipelines_layers = Vec::new();
                for _ in 0..num_layers {
                    let idx = rng.gen_range(0..pl.len());
                    let (encoded, layers) = (pl[idx].encoder)(&current_data);
                    current_data = encoded;
                    pipelines_layers.push(layers);
                }
                pipelines_layers.reverse();
                for layers in pipelines_layers {
                    all_layer_steps.extend(layers);
                }

                let actual_layers = all_layer_steps.len();
                let mut tasks = Vec::new();
                for (l_idx, steps) in all_layer_steps.into_iter().enumerate() {
                    let l_in = actual_layers - l_idx;
                    let l_out = l_in - 1;
                    for step in steps {
                        tasks.push(Task { layer_in: l_in, layer_out: l_out, step });
                    }
                }

                let mut b = vec![Vec::new(); actual_layers + 1];
                let mut s = vec![LayerStateManual::new(); actual_layers + 1];
                let mut fb = Vec::new();
                b[actual_layers] = current_data.clone();

                let mut tasks_done = vec![false; tasks.len()];
                let mut done_count = 0;
                while done_count < tasks.len() {
                    let mut progress = false;
                    for i in 0..tasks.len() {
                        if !tasks_done[i] {
                            let t = &tasks[i];
                            let old_rp = s[t.layer_in].rp;
                            let old_fb_len = fb.len();
                            let old_out_len = if t.layer_out > 0 { b[t.layer_out].len() } else { 0 };

                            let success = execute_step_manual(t, &mut b, &mut s, &mut fb);

                            let new_rp = s[t.layer_in].rp;
                            let new_fb_len = fb.len();
                            let new_out_len = if t.layer_out > 0 { b[t.layer_out].len() } else { 0 };

                            if new_rp > old_rp || new_fb_len > old_fb_len || new_out_len > old_out_len || success {
                                progress = true;
                            }

                            if success {
                                tasks_done[i] = true;
                                done_count += 1;
                            }
                        }
                    }
                    if !progress && done_count < tasks.len() {
                        panic!("Deadlock in test! done={}/{}", done_count, tasks.len());
                    }
                }

                let mut recovered = Vec::new();
                for chunk in fb { recovered.extend(chunk); }
                assert_eq!(recovered, original);
            }
        }
    }

    #[derive(Clone, Default)]
    struct LayerStateManual {
        rp: usize,
        acc: u128,
        cnt: u32,
        bc: u64,
        bi_res: Vec<u32>,
        bi_lz: usize,
        bi_started: bool,
        tc: [usize; 32],
        next_tid: usize,
    }
    impl LayerStateManual { fn new() -> Self { Self::default() } }

    fn execute_step_manual(task: &Task, b: &mut [Vec<u8>], s: &mut [LayerStateManual], fb: &mut Vec<Vec<u8>>) -> bool {
        let l_in = task.layer_in;
        let l_out = task.layer_out;

        let tid_val = match &task.step {
            PrimitiveStep::XorDec { tid, .. } |
            PrimitiveStep::Map { tid, .. } |
            PrimitiveStep::BitUnpack { tid, .. } |
            PrimitiveStep::BaseUnpack { tid, .. } |
            PrimitiveStep::BigIntStep { tid, .. } => Some(*tid),
            _ => None,
        };

        if let Some(t) = tid_val {
            if s[l_in].next_tid != t { return false; }
        }

        let res = match &task.step {
            PrimitiveStep::XorDec { key: _key, variant, count, tid } => {
                let mut progress = false;
                while s[l_in].tc[*tid] < *count {
                    if b[l_in].len() > s[l_in].rp {
                        let b_val = b[l_in][s[l_in].rp];
                        s[l_in].rp += 1;
                        let db = b_val ^ (s[l_in].acc as u8);
                        match variant {
                            0 => s[l_in].acc = (s[l_in].acc as u8).wrapping_add(b_val) as u128,
                            1 => s[l_in].acc = (s[l_in].acc as u8).wrapping_sub(b_val) as u128,
                            _ => s[l_in].acc = (s[l_in].acc as u8).rotate_left(3) as u128,
                        }
                        if l_out == 0 { fb.push(vec![db]); }
                        else { b[l_out].push(db); }
                        s[l_in].tc[*tid] += 1;
                        progress = true;
                    } else { break; }
                }
                s[l_in].tc[*tid] == *count
            },
            PrimitiveStep::Map { table, count, tid } => {
                let mut progress = false;
                while s[l_in].tc[*tid] < *count {
                    if b[l_in].len() > s[l_in].rp {
                        let val = b[l_in][s[l_in].rp];
                        s[l_in].rp += 1;
                        let mut map = vec![255u8; 256];
                        for (i, &c) in table.iter().enumerate() { map[c as usize] = i as u8; }
                        let v = map[val as usize];
                        if v != 255 {
                            if l_out == 0 { fb.push(vec![v]); }
                            else { b[l_out].push(v); }
                        }
                    s[l_in].tc[*tid] += 1;
                        progress = true;
                    } else { break; }
                }
            s[l_in].tc[*tid] == *count
            },
        PrimitiveStep::BitUnpack { bits, total_bits, count, tid } => {
                let mut progress = false;
            while s[l_in].tc[*tid] < *count {
                    if b[l_in].len() > s[l_in].rp {
                        let v = b[l_in][s[l_in].rp];
                        s[l_in].rp += 1;
                        s[l_in].acc = (s[l_in].acc << bits) | (v as u128);
                        s[l_in].cnt += bits;
                        while s[l_in].cnt >= 8 {
                            s[l_in].cnt -= 8;
                            if s[l_in].bc < *total_bits {
                                let out_byte = (s[l_in].acc >> s[l_in].cnt) as u8;
                                if l_out == 0 { fb.push(vec![out_byte]); }
                                else { b[l_out].push(out_byte); }
                                s[l_in].bc += 8;
                            }
                            s[l_in].acc &= (1 << s[l_in].cnt) - 1;
                        }
                    s[l_in].tc[*tid] += 1;
                        progress = true;
                    } else { break; }
                }
            s[l_in].tc[*tid] == *count
            },
        PrimitiveStep::BaseUnpack { base, in_c, out_c, total_bytes, count, tid } => {
                let mut progress = false;
            while s[l_in].tc[*tid] < *count {
                    if b[l_in].len() >= s[l_in].rp + in_c {
                        let chunk = &b[l_in][s[l_in].rp..s[l_in].rp + in_c];
                        s[l_in].rp += in_c;
                        let mut v = 0u128;
                        for &c in chunk { v = v * base + (c as u128); }
                        for i in (0..*out_c).rev() {
                            if s[l_in].bc < *total_bytes {
                                let out_byte = ((v >> (i * 8)) & 0xff) as u8;
                                if l_out == 0 { fb.push(vec![out_byte]); }
                                else { b[l_out].push(out_byte); }
                                s[l_in].bc += 1;
                            }
                        }
                s[l_in].tc[*tid] += 1;
                        progress = true;
                    } else { break; }
                }
        s[l_in].tc[*tid] == *count
            },
    PrimitiveStep::BigIntStep { base, is_init, is_last, total_bytes, count, tid } => {
                if *is_init {
                    s[l_in].bi_res = vec![0u32];
                    s[l_in].bi_lz = 0;
                    s[l_in].bi_started = false;
                    true
                } else {
                    let mut progress = false;
                    while s[l_in].tc[*tid] < *count {
                        if b[l_in].len() > s[l_in].rp {
                            let v = b[l_in][s[l_in].rp];
                            s[l_in].rp += 1;
                            if !s[l_in].bi_started && v == 0 {
                                s[l_in].bi_lz += 1;
                            } else {
                                s[l_in].bi_started = true;
                                let mut carry = v as u64;
                                for digit in s[l_in].bi_res.iter_mut() {
                                    let prod = (*digit as u64) * (*base as u64) + carry;
                                    *digit = prod as u32;
                                    carry = prod >> 32;
                                }
                                while carry > 0 {
                                    s[l_in].bi_res.push(carry as u32);
                                    carry >>= 32;
                                }
                            }
                            s[l_in].tc[*tid] += 1;
                            progress = true;
                        } else { break; }
                    }
                    let done = s[l_in].tc[*tid] == *count;
                    if *is_last && done {
                        let mut out = vec![0u8; s[l_in].bi_lz];
                        if !(s[l_in].bi_res.len() == 1 && s[l_in].bi_res[0] == 0) || s[l_in].bi_res.len() == s[l_in].bi_lz {
                            let rl = s[l_in].bi_res.len();
                            let mut bytes_out = Vec::new();
                            for (idx, &val) in s[l_in].bi_res.iter().enumerate().rev() {
                                let bytes = val.to_be_bytes();
                                if idx == rl - 1 {
                                     let mut skip = 0;
                                     while skip < 4 && bytes[skip] == 0 { skip += 1; }
                                     bytes_out.extend_from_slice(&bytes[skip..]);
                                } else { bytes_out.extend_from_slice(&bytes); }
                            }
                            out.extend(bytes_out);
                        }
                        let final_bytes = &out[..(*total_bytes as usize).min(out.len())];
                        for &b_val in final_bytes {
                            if l_out == 0 { fb.push(vec![b_val]); }
                            else { b[l_out].push(b_val); }
                        }
                    }
                        done
                }
            },
            _ => true,
        };

        if res {
            if let Some(_) = tid_val {
                s[l_in].next_tid += 1;
            }
        }
        res
    }
}
