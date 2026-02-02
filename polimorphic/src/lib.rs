extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::{parse_macro_input, LitStr};
use rand::{Rng, SeedableRng, rngs::StdRng};
use proc_macro2::{TokenStream as TokenStream2, Ident, Literal};

#[derive(Clone, Debug)]
enum Primitive {
    Map(Vec<u8>),
    BitLoad { _bits: u32 },
    BitEmit { bits: u32, total_bits: u64 },
    BaseLoad { _base: u128, _in_c: usize },
    BaseEmit { base: u128, in_c: usize, out_c: usize, total_bytes: u64 },
    BigIntInit,
    BigIntPush { base: u128 },
    BigIntEmit { _total_bytes: u64 },
    ArithmeticChain(Vec<(u8, u32)>),
    Rotate { val: u32, is_left: bool },
    Noop { val: u32 },
    Sync,
}

struct Pipeline {
    encoder: Box<dyn Fn(&[u8]) -> (Vec<u8>, Vec<Primitive>)>,
}

// --- HELPERS ---

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
    for _ in 0..leading_zeros { res.push(alphabet[0]); }
    res.reverse();
    res
}

fn encode_z85_custom(data: &[u8], alphabet: &[u8]) -> (Vec<u8>, u64) {
    let mut d = data.to_vec();
    while d.len() % 4 != 0 { d.push(0); }
    let mut out = Vec::new();
    for chunk in d.chunks(4) {
        let mut val = 0u64;
        for &b in chunk { val = (val << 8) | b as u64; }
        let mut res = Vec::new();
        for _ in 0..5 { res.push(alphabet[(val % 85) as usize]); val /= 85; }
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

    let b32 = || {
        let alpha = b32_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bits) = encode_bits(data, 5, &alpha);
                (out, vec![Primitive::Map(alpha.clone()), Primitive::BitLoad { _bits: 5 }, Primitive::BitEmit { bits: 5, total_bits }])
            }),
        }
    };
    let b64 = || {
        let alpha = b64_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bits) = encode_bits(data, 6, &alpha);
                (out, vec![Primitive::Map(alpha.clone()), Primitive::BitLoad { _bits: 6 }, Primitive::BitEmit { bits: 6, total_bits }])
            }),
        }
    };
    let b36 = || {
        let alpha = b36_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let out = encode_bigint(data, 36, &alpha);
                (out, vec![Primitive::Map(alpha.clone()), Primitive::BigIntInit, Primitive::BigIntPush { base: 36 }, Primitive::BigIntEmit { _total_bytes: data.len() as u64 }])
            }),
        }
    };
    let z85 = || {
        let alpha = z85_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bytes) = encode_z85_custom(data, &alpha);
                (out, vec![Primitive::Map(alpha.clone()), Primitive::BaseLoad { _base: 85, _in_c: 5 }, Primitive::Sync, Primitive::BaseEmit { base: 85, in_c: 5, out_c: 4, total_bytes }])
            }),
        }
    };
    let arith = || {
        Pipeline {
            encoder: Box::new(|data| {
                let val = rand::thread_rng().gen::<u8>();
                let op = rand::thread_rng().gen_range(0..3);
                let encoded = data.iter().map(|&b| match op {
                    0 => b.wrapping_add(val),
                    1 => b.wrapping_sub(val),
                    _ => b ^ val,
                }).collect();
                let dec_op = match op { 0 => 0, 1 => 1, _ => 2 };
                (encoded, vec![Primitive::ArithmeticChain(vec![(dec_op, val as u32)])])
            }),
        }
    };
    let rot = || {
        Pipeline {
            encoder: Box::new(|data| {
                let shift = rand::thread_rng().gen_range(1..8);
                let encoded = data.iter().map(|&b| b.rotate_right(shift)).collect();
                (encoded, vec![Primitive::Rotate { val: shift, is_left: true }])
            }),
        }
    };

    vec![b32(), b64(), b36(), z85(), arith(), rot()]
}

fn compute_entropy(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555)
}

// --- GENERATORS ---

fn generate_obfuscated_map(alphabet: &[u8], rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let m_l = Literal::byte_string(&map);
    if rng.gen_bool(0.5) {
        quote! { for b in data.iter_mut() { *b = (#m_l)[*b as usize]; } }
    } else {
        quote! { data = data.into_iter().map(|b| (#m_l)[b as usize]).collect(); }
    }
}

fn generate_junk_logic(rng: &mut impl Rng, rs_var: &Ident, rs_compile: &mut u32) -> TokenStream2 {
    let mut code = Vec::new();
    for _ in 0..rng.gen_range(1..=2) {
        match rng.gen_range(0..3) {
            0 => { let v = rng.gen::<u32>(); *rs_compile = rs_compile.wrapping_add(v); code.push(quote! { #rs_var = #rs_var.wrapping_add(#v); }); }
            1 => { let v = rng.gen_range(1..31); *rs_compile = rs_compile.rotate_left(v); code.push(quote! { #rs_var = #rs_var.rotate_left(#v); }); }
            _ => { let v = rng.gen::<u32>(); *rs_compile ^= v; code.push(quote! { #rs_var ^= #v; }); }
        }
    }
    quote! { #(#code)* }
}

fn generate_obfuscated_decrypt(input_expr: TokenStream2, output_var: &Ident, rs_var: &Ident, rs_compile: &mut u32, rng: &mut impl Rng, variant: u32) -> TokenStream2 {
    let k_n = format_ident!("k_{}", rng.gen::<u32>());
    let b_n = format_ident!("b_{}", rng.gen::<u32>());
    let u_l = match variant {
        0 => quote! { #k_n = #k_n.wrapping_add(#b_n); },
        1 => quote! { #k_n = #k_n.wrapping_sub(#b_n); },
        _ => quote! { #k_n = #k_n.rotate_left(3); },
    };
    let junk = generate_junk_logic(rng, rs_var, rs_compile);
    quote! {
        let mut #k_n = self.key;
        let mut #output_var = Vec::with_capacity(#input_expr.len());
        for byte in #input_expr.iter() {
            let #b_n = *byte;
            #output_var.push(#b_n ^ #k_n);
            #u_l
        }
        #junk
        let l_o_j = (#rs_var ^ (#rs_var >> 13) ^ (#rs_var >> 21)) as u8;
        for b in #output_var.iter_mut() { *b ^= l_o_j; }
    }
}

fn generate_fragmented_string_recovery(bytes_var: &Ident, rs_var: &Ident) -> TokenStream2 {
    quote! {
        {
            let lock = (#rs_var ^ (#rs_var >> 13) ^ (#rs_var >> 21)) as u8;
            let unlocked: Vec<u8> = #bytes_var.iter().map(|&b| b ^ lock).collect();
            String::from_utf8(unlocked).expect("R1")
        }
    }
}

// --- MACRO ---

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let input_str = parse_macro_input!(input as LitStr);
    let os = input_str.value();
    let suffix = rand::thread_rng().gen::<u32>();
    let entropy = compute_entropy(os.as_bytes());
    let mut rng = StdRng::from_entropy();
    let pl = get_pipelines();
    let num_layers = ((entropy % 3) + 4) as usize;

    #[derive(Clone)]
    struct LayerConfig {
        seed_sc: u32, seed_corr: u32, mask_corr: u8, primitives: Vec<Primitive>,
        id_val: u32, rs_salt: u32, arm_junk_ops: Vec<(u8, u32)>, rs_in: u32, rs_out: u32, p_idx: usize,
    }

    let mut layers = Vec::new();
    for _ in 0..num_layers {
        layers.push(LayerConfig {
            seed_sc: rng.gen(), seed_corr: rng.gen(), mask_corr: rng.gen(), id_val: rng.gen(), rs_salt: rng.gen(),
            arm_junk_ops: (0..rng.gen_range(1..=3)).map(|_| (rng.gen_range(0..4), rng.gen())).collect(),
            primitives: Vec::new(), rs_in: 0, rs_out: 0, p_idx: rng.gen_range(0..pl.len()),
        });
    }

    let mut decode_order = layers.clone(); decode_order.reverse();
    let mut curr_rs = 0u32;
    for config in decode_order.iter_mut() {
        config.rs_in = curr_rs;
        let mut next_rs = curr_rs.wrapping_add(config.id_val).rotate_left(5) ^ config.rs_salt;
        apply_junk_compile(&mut next_rs, &config.arm_junk_ops);
        config.rs_out = next_rs; curr_rs = next_rs;
    }

    let mut cd = os.clone().into_bytes();
    let final_rs = decode_order.last().unwrap().rs_out;
    let final_lock = (final_rs ^ (final_rs >> 13) ^ (final_rs >> 21)) as u8;
    for b in cd.iter_mut() { *b ^= final_lock; }

    for i in (0..num_layers).rev() {
        let config = &mut decode_order[i];
        let lock_in = (config.rs_in ^ (config.rs_in >> 13) ^ (config.rs_in >> 21)) as u8;
        let lock_out = (config.rs_out ^ (config.rs_out >> 13) ^ (config.rs_out >> 21)) as u8;
        for b in cd.iter_mut() { *b ^= lock_out; }
        apply_scramble_compile(&mut cd, config.seed_sc);
        apply_state_corruption_compile(&mut cd, config.seed_corr, config.mask_corr);
        let (encoded, primitives) = (pl[config.p_idx].encoder)(&cd);
        cd = encoded; config.primitives = primitives;
        apply_unscramble_compile(&mut cd, config.seed_sc);
        for b in cd.iter_mut() { *b ^= lock_in; }
    }

    let xk = rng.gen::<u8>(); let ev = rng.gen_range(0..3u32); let mut key = xk;
    let mut rs_junk_compile = 0u32; let rs_j_n = format_ident!("rs_j_{}", suffix);
    let d_b_i = format_ident!("db_{}", suffix);
    let dl_c = generate_obfuscated_decrypt(quote! { rd }, &d_b_i, &rs_j_n, &mut rs_junk_compile, &mut rng, ev);
    let lock_junk = (rs_junk_compile ^ (rs_junk_compile >> 13) ^ (rs_junk_compile >> 21)) as u8;

    let mut eb = Vec::with_capacity(cd.len());
    for &ob in &cd {
        let eb_b = (ob ^ lock_junk) ^ key; eb.push(eb_b);
        match ev { 0 => key = key.wrapping_add(eb_b), 1 => key = key.wrapping_sub(eb_b), _ => key = key.rotate_left(3), };
    }

    let mut arms = Vec::new();
    for config in &decode_order {
        let mut codes = Vec::new();
        let s_s = config.seed_sc;
        codes.push(quote! {
            let mut s_k = #s_s;
            for _ in 0..data.len() {
                let i = (s_k as usize) % data.len(); let j = (s_k.wrapping_add(13) as usize) % data.len();
                data.swap(i, j); s_k = s_k.wrapping_mul(1103515245).wrapping_add(12345);
            }
        });
        for p in &config.primitives {
            match p {
                Primitive::Map(m) => codes.push(generate_obfuscated_map(m, &mut rng)),
                Primitive::BitLoad { .. } | Primitive::BaseLoad { .. } => codes.push(quote! { aux.extend_from_slice(&data); data.clear(); }),
                Primitive::BitEmit { bits, total_bits } => {
                    codes.push(quote! {
                        let mut out = Vec::new(); let mut acc = 0u128; let mut count = 0u32; let mut bc = 0u64;
                        for &v in aux.iter() {
                            acc = (acc << #bits) | (v as u128); count += #bits;
                            while count >= 8 {
                                count -= 8; if bc < #total_bits { out.push((acc >> count) as u8); bc += 8; }
                                acc &= (1 << count) - 1;
                            }
                        }
                        data = out; aux.clear();
                    });
                },
                Primitive::BaseEmit { base, in_c, out_c, total_bytes } => {
                    codes.push(quote! {
                        let mut out = Vec::new(); let mut len_v = 0u64;
                        for chunk in aux.chunks(#in_c) {
                            if chunk.len() < #in_c { continue; }
                            let mut v = 0u128; for &c in chunk { v = v * #base + (c as u128); }
                            for i in (0..#out_c).rev() { if len_v < #total_bytes { out.push(((v >> (i * 8)) & 0xff) as u8); len_v += 1; } }
                        }
                        data = out; aux.clear();
                    });
                },
                Primitive::Sync => codes.push(quote! { let mut data = data; }),
                Primitive::BigIntInit => codes.push(quote! { aux.clear(); aux.extend_from_slice(&0u32.to_ne_bytes()); }),
                Primitive::BigIntPush { base } => {
                    codes.push(quote! {
                        let mut lz = 0; for &v in &data { if v == 0 { lz += 1; } else { break; } }
                        let mut res = Vec::new(); for chunk in aux.chunks_exact(4) {
                            let mut bytes = [0u8; 4]; bytes.copy_from_slice(chunk); res.push(u32::from_ne_bytes(bytes));
                        }
                        for &v in &data[lz..] {
                            let mut carry = v as u64; for digit in res.iter_mut() {
                                let prod = (*digit as u64) * (#base as u64) + carry; *digit = prod as u32; carry = prod >> 32;
                            }
                            while carry > 0 { res.push(carry as u32); carry >>= 32; }
                        }
                        aux.clear(); for val in res { aux.extend_from_slice(&val.to_ne_bytes()); }
                        let mut next_aux = (lz as u64).to_ne_bytes().to_vec(); next_aux.extend_from_slice(&aux);
                        aux.clear(); aux.extend(next_aux);
                    });
                },
                Primitive::BigIntEmit { .. } => {
                    codes.push(quote! {
                        if aux.len() >= 8 {
                            let mut lz_bytes = [0u8; 8]; lz_bytes.copy_from_slice(&aux[0..8]); let lz = u64::from_ne_bytes(lz_bytes) as usize;
                            let mut res = Vec::new(); for chunk in aux[8..].chunks_exact(4) {
                                let mut bytes = [0u8; 4]; bytes.copy_from_slice(chunk); res.push(u32::from_ne_bytes(bytes));
                            }
                            let mut out = vec![0u8; lz]; if !(res.len() == 1 && res[0] == 0) || (aux.len() - 8) / 4 == lz {
                                let mut bytes_out = Vec::new(); let rl = res.len();
                                for (idx, &val) in res.iter().enumerate().rev() {
                                    let bytes = val.to_be_bytes();
                                    if idx == rl - 1 {
                                        let mut skip = 0; while skip < 4 && bytes[skip] == 0 { skip += 1; }
                                        bytes_out.extend_from_slice(&bytes[skip..]);
                                    } else { bytes_out.extend_from_slice(&bytes); }
                                }
                                out.extend(bytes_out);
                            }
                            data = out;
                        } else { data = Vec::new(); }
                        aux.clear();
                    });
                },
                Primitive::ArithmeticChain(ops) => {
                    for (op, val) in ops {
                        match op {
                            0 => codes.push(quote! { for b in data.iter_mut() { *b = b.wrapping_sub(#val as u8); } }),
                            1 => codes.push(quote! { for b in data.iter_mut() { *b = b.wrapping_add(#val as u8); } }),
                            _ => codes.push(quote! { for b in data.iter_mut() { *b ^= (#val as u8); } }),
                        }
                    }
                },
                Primitive::Rotate { val, is_left } => {
                    if *is_left { codes.push(quote! { for b in data.iter_mut() { *b = b.rotate_left(#val); } }); }
                    else { codes.push(quote! { for b in data.iter_mut() { *b = b.rotate_right(#val); } }); }
                },
                Primitive::Noop { val } => codes.push(quote! { let _ = #val; }),
                _ => {}
            }
        }
        let m_c = config.mask_corr;
        codes.push(quote! { for b in data.iter_mut() { *b ^= #m_c; } });
        codes.push(quote! {
            let mut u_k = #s_s;
            let mut sw = Vec::new();
            for _ in 0..data.len() {
                let i = (u_k as usize) % data.len(); let j = (u_k.wrapping_add(13) as usize) % data.len();
                sw.push((i, j)); u_k = u_k.wrapping_mul(1103515245).wrapping_add(12345);
            }
            for (i, j) in sw.into_iter().rev() { data.swap(i, j); }
        });

        let mut aj = Vec::new();
        for (op, val) in &config.arm_junk_ops {
            match op {
                0 => aj.push(quote! { rs = rs.wrapping_add(#val); }),
                1 => aj.push(quote! { rs = rs.rotate_left(#val); }),
                2 => aj.push(quote! { rs ^= #val; }),
                _ => aj.push(quote! { aux2.push((rs.wrapping_add(#val) as u8)); }),
            }
        }
        let ak = ((config.id_val ^ config.rs_in).wrapping_mul(13371337) ^ 0xDEADBEEF).rotate_left((config.rs_in & 0x7) as u32 + 1) ^ config.rs_in;
        let id_v = config.id_val; let rs_s = config.rs_salt;
        arms.push(quote! {
            #ak => {
                let mut data = data.to_vec(); let mut rs = rs_in;
                let l_i = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= l_i; }
                #(#codes)*
                rs = rs.wrapping_add(#id_v).rotate_left(5) ^ #rs_s; #(#aj)*
                let l_o = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= l_o; }
                (data, rs)
            }
        });
    }

    let s_n = format_ident!("O_{}", suffix); let m_n = format_ident!("r_{}", suffix);
    let d_n = format_ident!("d_{}", suffix); let i_v = format_ident!("ds_{}", suffix);
    let a_v = format_ident!("aux_{}", suffix); let a2_v = format_ident!("aux2_{}", suffix);
    let rs_n = format_ident!("rs_{}", suffix);
    
    let (df, di, rl) = match rng.gen_range(0..3) {
        0 => { let dl = Literal::byte_string(&eb); (quote! { d: &'a [u8], }, quote! { d: #dl, }, quote! { let mut rd = self.d.to_vec(); }) },
        1 => {
            let even: Vec<u8> = eb.iter().step_by(2).cloned().collect(); let odd: Vec<u8> = eb.iter().skip(1).step_by(2).cloned().collect();
            let el = Literal::byte_string(&even); let ol = Literal::byte_string(&odd);
            (quote! { e: &'a [u8], o: &'a [u8], }, quote! { e: #el, o: #ol, }, quote! {
                let mut rd = Vec::new(); let mut ei = self.e.iter(); let mut oi = self.o.iter();
                loop { match (ei.next(), oi.next()) { (Some(ev), Some(ov)) => { rd.push(*ev); rd.push(*ov); }, (Some(ev), None) => { rd.push(*ev); break; }, _ => break, } }
            })
        },
        _ => {
            let ji: Vec<u8> = eb.iter().flat_map(|&b| vec![b, rng.gen()]).collect(); let dl = Literal::byte_string(&ji);
            (quote! { j: &'a [u8], }, quote! { j: #dl, }, quote! { let mut rd: Vec<u8> = self.j.iter().step_by(2).cloned().collect(); })
        }
    };
    
    let rids_l = layers.iter().map(|c| c.id_val).collect::<Vec<_>>();
    let rids_q = rids_l.iter().rev().map(|&id| quote! { #id });
    let fr = generate_fragmented_string_recovery(&i_v, &rs_n);

    let expanded = quote! {
        {
            struct #s_n<'a> { #df key: u8, }
            impl<'a> #s_n<'a> {
                fn #m_n(&mut self) -> String {
                    let mut #d_n = |id: u32, data: &[u8], rs_in: u32, aux: &mut Vec<u8>, aux2: &mut Vec<u8>| -> (Vec<u8>, u32) {
                        let k = ((id ^ rs_in).wrapping_mul(13371337) ^ 0xDEADBEEF).rotate_left((rs_in & 0x7) as u32 + 1) ^ rs_in;
                        match k { #(#arms),* _ => (data.to_vec(), rs_in.wrapping_add(id)) }
                    };
                    let mut #a_v = Vec::new(); let mut #a2_v = Vec::new();
                    let mut #rs_j_n = 0u32; let mut #d_b_i = { #rl #dl_c #d_b_i };
                    let mut #i_v = #d_b_i; let mut #rs_n = 0u32;
                    for id in vec![#(#rids_q),*] {
                        let (nd, nr) = #d_n(id, &#i_v, #rs_n, &mut #a_v, &mut #a2_v);
                        #i_v = nd; #rs_n = nr;
                    }
                    #fr
                }
            }
            let mut inst = #s_n { #di key: #xk, }; inst.#m_n()
        }
    };
    expanded.into()
}

fn apply_scramble_compile(data: &mut Vec<u8>, seed: u32) {
    let mut s_k = seed; for _ in 0..data.len() {
        let i = (s_k as usize) % data.len(); let j = (s_k.wrapping_add(13) as usize) % data.len();
        data.swap(i, j); s_k = s_k.wrapping_mul(1103515245).wrapping_add(12345);
    }
}
fn apply_unscramble_compile(data: &mut Vec<u8>, seed: u32) {
    let mut u_k = seed; let mut sw = Vec::new(); for _ in 0..data.len() {
        let i = (u_k as usize) % data.len(); let j = (u_k.wrapping_add(13) as usize) % data.len();
        sw.push((i, j)); u_k = u_k.wrapping_mul(1103515245).wrapping_add(12345);
    }
    for (i, j) in sw.into_iter().rev() { data.swap(i, j); }
}
fn apply_state_corruption_compile(data: &mut Vec<u8>, _seed: u32, mask: u8) { for b in data.iter_mut() { *b ^= mask; } }
fn apply_junk_compile(rs: &mut u32, ops: &Vec<(u8, u32)>) {
    for (op, val) in ops { match op { 0 => *rs = rs.wrapping_add(*val), 1 => *rs = rs.rotate_left(*val), 2 => *rs ^= *val, _ => {} } }
}
