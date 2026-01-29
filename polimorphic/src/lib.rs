extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};
use rand::RngCore;
use rand::prelude::StdRng;
use rand::SeedableRng;

#[derive(Clone, Debug)]
enum Primitive {
    Map(Vec<u8>, u32),
    BitLoad { bits: u32 },
    BitEmit { bits: u32, total_bits: u64, seed: u32 },
    BaseLoad { base: u128, in_c: usize },
    BaseEmit { base: u128, in_c: usize, out_c: usize, total_bytes: u64, seed: u32 },
    BigIntInit,
    BigIntPush { base: u128 },
    BigIntEmit { total_bytes: u64, seed: u32 },
    Noop { val: u32 },
    Sync,
    StateShift,
}

struct Pipeline {
    encoder: Box<dyn Fn(&[u8], &mut u32, &mut dyn RngCore) -> (Vec<u8>, Vec<Primitive>)>,
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

fn get_loop_junk_params(seed: u32) -> (usize, u32, u32) {
    let mut p_rng = StdRng::seed_from_u64(seed as u64);
    (p_rng.gen_range(0..5), p_rng.gen::<u32>(), p_rng.gen_range(1..31))
}

fn apply_rs_junk_fixed(rs: &mut u32, op_idx: usize, val: u32, rot: u32) {
    match op_idx {
        0 => *rs = rs.wrapping_add(val),
        1 => *rs = rs.rotate_left(rot),
        2 => *rs ^= val,
        3 => *rs = rs.wrapping_mul(val | 1),
        _ => *rs = rs.wrapping_sub(val).rotate_right(3),
    }
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
            encoder: Box::new(move |data, rs, rng| {
                let seed = rng.gen::<u32>();
                let seed_map = rng.gen::<u32>();
                let (op_idx, val, rot) = get_loop_junk_params(seed);
                let (op_idx_map, val_map, rot_map) = get_loop_junk_params(seed_map);
                let (out, total_bits) = encode_bits(data, 5, &alpha);
                for _ in 0..out.len() { apply_rs_junk_fixed(rs, op_idx_map, val_map, rot_map); }
                for _ in 0..out.len() { apply_rs_junk_fixed(rs, op_idx, val, rot); }
                (out, vec![
                    Primitive::Map(alpha.clone(), seed_map),
                    Primitive::BitLoad { bits: 5 },
                    Primitive::BitEmit { bits: 5, total_bits, seed }
                ])
            }),
        }
    };
    let b64 = || {
        let alpha = b64_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data, rs, rng| {
                let seed = rng.gen::<u32>();
                let seed_map = rng.gen::<u32>();
                let (op_idx, val, rot) = get_loop_junk_params(seed);
                let (op_idx_map, val_map, rot_map) = get_loop_junk_params(seed_map);
                let (out, total_bits) = encode_bits(data, 6, &alpha);
                for _ in 0..out.len() { apply_rs_junk_fixed(rs, op_idx_map, val_map, rot_map); }
                for _ in 0..out.len() { apply_rs_junk_fixed(rs, op_idx, val, rot); }
                (out, vec![
                    Primitive::Map(alpha.clone(), seed_map),
                    Primitive::BitLoad { bits: 6 },
                    Primitive::BitEmit { bits: 6, total_bits, seed }
                ])
            }),
        }
    };
    let z85 = || {
        let alpha = z85_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data, rs, rng| {
                let seed = rng.gen::<u32>();
                let seed_map = rng.gen::<u32>();
                let (op_idx, val, rot) = get_loop_junk_params(seed);
                let (op_idx_map, val_map, rot_map) = get_loop_junk_params(seed_map);
                let (out, total_bytes) = encode_z85_custom(data, &alpha);
                for _ in 0..out.len() { apply_rs_junk_fixed(rs, op_idx_map, val_map, rot_map); }
                for _ in 0..(out.len() / 5) { apply_rs_junk_fixed(rs, op_idx, val, rot); }
                (out, vec![
                    Primitive::Map(alpha.clone(), seed_map),
                    Primitive::BaseLoad { base: 85, in_c: 5 },
                    Primitive::Sync,
                    Primitive::BaseEmit { base: 85, in_c: 5, out_c: 4, total_bytes, seed }
                ])
            }),
        }
    };

    vec![b32(), b64(), z85()]
}

// --- GENERATORS ---

fn generate_obfuscated_map(alphabet: &[u8], seed: u32, rs_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);
    let (op_idx, val, rot) = get_loop_junk_params(seed);
    let loop_junk = generate_junk_fixed(rs_var, op_idx, val, rot);
    let out_v = Ident::new(&format!("out_{}", rng.gen::<u32>()), Span::call_site());
    quote! {
        let mut #out_v = Vec::with_capacity(data.len());
        for &b in &data {
            #loop_junk
            let v = (#map_lit)[b as usize];
            if v != 255 { #out_v.push(v); }
        }
        data = #out_v;
    }
}

fn generate_bit_load() -> TokenStream2 {
    quote! { aux.extend_from_slice(&data); data.clear(); }
}

fn generate_bit_emit(bits: u32, total_bits: u64, seed: u32, rs_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let (op_idx, val, rot) = get_loop_junk_params(seed);
    let loop_junk = generate_junk_fixed(rs_var, op_idx, val, rot);
    let out_v = Ident::new(&format!("out_{}", rng.gen::<u32>()), Span::call_site());
    quote! {
        let mut #out_v = Vec::new();
        let mut acc = 0u128;
        let mut count = 0u32;
        let mut bc = 0u64;
        for &v in aux.iter() {
            #loop_junk
            acc = (acc << #bits) | (v as u128);
            count += #bits;
            while count >= 8 {
                count -= 8;
                if bc < #total_bits {
                    #out_v.push((acc >> count) as u8);
                    bc += 8;
                }
                acc &= (1 << count) - 1;
            }
        }
        data = #out_v;
        aux.clear();
    }
}

fn generate_base_load() -> TokenStream2 {
    quote! { aux.extend_from_slice(&data); data.clear(); }
}

fn generate_base_emit(base: u128, in_c: usize, out_c: usize, total_bytes: u64, seed: u32, rs_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let (op_idx, val, rot) = get_loop_junk_params(seed);
    let loop_junk = generate_junk_fixed(rs_var, op_idx, val, rot);
    let out_v = Ident::new(&format!("out_{}", rng.gen::<u32>()), Span::call_site());
    quote! {
        let mut #out_v = Vec::new();
        let mut len_v = 0u64;
        for chunk in aux.chunks(#in_c) {
            #loop_junk
            if chunk.len() < #in_c { continue; }
            let mut v = 0u128;
            for &c in chunk { v = v * #base + (c as u128); }
            for i in (0..#out_c).rev() {
                if len_v < #total_bytes {
                    #out_v.push(((v >> (i * 8)) & 0xff) as u8);
                    len_v += 1;
                }
            }
        }
        data = #out_v;
        aux.clear();
    }
}

fn generate_junk_fixed(rs_var: &Ident, op_idx: usize, val: u32, rot: u32) -> TokenStream2 {
    match op_idx {
        0 => quote! { #rs_var = #rs_var.wrapping_add(#val); },
        1 => quote! { #rs_var = #rs_var.rotate_left(#rot); },
        2 => quote! { #rs_var ^= #val; },
        3 => quote! { #rs_var = #rs_var.wrapping_mul(#val | 1); },
        _ => quote! { #rs_var = #rs_var.wrapping_sub(#val).rotate_right(3); },
    }
}

fn generate_junk_logic(rng: &mut impl Rng, rs_var: &Ident, rs_compile: &mut u32) -> TokenStream2 {
    let mut code = Vec::new();
    for _ in 0..rng.gen_range(1..=3) {
        let op_idx = rng.gen_range(0..5);
        let val = rng.gen::<u32>();
        let rot = rng.gen_range(1..31);
        apply_rs_junk_fixed(rs_compile, op_idx, val, rot);
        code.push(generate_junk_fixed(rs_var, op_idx, val, rot));
    }
    quote! { #(#code)* }
}

fn generate_state_corruption(seed: u32, mask: u8, rng: &mut impl Rng) -> (TokenStream2, TokenStream2) {
    let offset_var = Ident::new(&format!("offset_{}", rng.gen::<u32>()), Span::call_site());
    let init = quote! { let mut #offset_var = #seed.wrapping_mul(0x9E3779B9); };
    let apply = quote! {
        for (i, b) in data.iter_mut().enumerate() {
            let idx_mask = ((i as u32).wrapping_add(#offset_var) & 0x7) as u8;
            *b = b.wrapping_sub(idx_mask ^ #mask);
        }
    };
    (init, apply)
}

fn apply_state_corruption_compile(data: &mut Vec<u8>, seed: u32, mask: u8) {
    let offset = seed.wrapping_mul(0x9E3779B9);
    for (i, b) in data.iter_mut().enumerate() {
        let idx_mask = ((i as u32).wrapping_add(offset) & 0x7) as u8;
        *b = b.wrapping_add(idx_mask ^ mask);
    }
}

fn generate_index_scrambler(seed: u32, rng: &mut impl Rng) -> (TokenStream2, TokenStream2) {
    let out_v = Ident::new(&format!("out_s_{}", rng.gen::<u32>()), Span::call_site());
    let scramble = quote! {
        {
            let mut #out_v = Vec::with_capacity(data.len());
            let mut scramble_idx = #seed;
            for &b in data.iter() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                #out_v.push(b.wrapping_add((scramble_idx & 0x3) as u8));
            }
            data = #out_v;
        }
    };
    let out_v2 = Ident::new(&format!("out_u_{}", rng.gen::<u32>()), Span::call_site());
    let unscramble = quote! {
        {
            let mut #out_v2 = Vec::with_capacity(data.len());
            let mut scramble_idx = #seed;
            for &b in data.iter() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                #out_v2.push(b.wrapping_sub((scramble_idx & 0x3) as u8));
            }
            data = #out_v2;
        }
    };
    (scramble, unscramble)
}

fn apply_scramble_compile(data: &mut Vec<u8>, seed: u32) {
    let mut scramble_idx = seed;
    for b in data.iter_mut() {
        scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
        *b = b.wrapping_add((scramble_idx & 0x3) as u8);
    }
}

fn generate_obfuscated_decrypt(input_expr: TokenStream2, output_var: &Ident, rs_var: &Ident, rs_compile: &mut u32, rng: &mut impl Rng, variant: u32, use_lock: bool) -> TokenStream2 {
    let k_n = Ident::new(&format!("k_{}", rng.gen::<u32>()), Span::call_site());
    let b_n = Ident::new(&format!("b_{}", rng.gen::<u32>()), Span::call_site());
    let br_n = Ident::new(&format!("br_{}", rng.gen::<u32>()), Span::call_site());
    let u_l = match variant {
        0 => quote! { #k_n = #k_n.wrapping_add(#b_n); },
        1 => quote! { #k_n = #k_n.wrapping_sub(#b_n); },
        _ => quote! { #k_n = #k_n.rotate_left(3); },
    };
    let junk = generate_junk_logic(rng, rs_var, rs_compile);
    let core = match rng.gen_range(0..3) {
        0 => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Vec::with_capacity(#input_expr.len());
            for byte in #input_expr.iter() {
                let #b_n = *byte; #output_var.push(#b_n ^ #k_n); #u_l
            }
            #junk
        },
        1 => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Vec::new();
            let mut i = 0;
            while i < #input_expr.len() {
                let #b_n = #input_expr[i]; #output_var.push(#b_n ^ #k_n); #u_l; i += 1;
            }
            #junk
        },
        _ => quote! {
            let mut #k_n = self.key;
            let mut #output_var: Vec<u8> = #input_expr.iter().map(|#br_n| {
                let #b_n = *#br_n; let db = #b_n ^ #k_n; #u_l; db
            }).collect();
            #junk
        },
    };
    if use_lock {
        quote! {
            #core
            let lock_out_junk = (#rs_var ^ (#rs_var >> 13) ^ (#rs_var >> 21)) as u8;
            for b in #output_var.iter_mut() { *b ^= lock_out_junk; }
            #output_var
        }
    } else {
        quote! { #core #output_var }
    }
}

fn generate_fragmented_string_recovery(bytes_var: &Ident, rs_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let s_n = Ident::new(&format!("S_{}", rng.gen::<u32>()), Span::call_site());
    let chunk_size = rng.gen_range(3usize..=10usize);
    quote! {
        {
            struct #s_n(Vec<u8>, u32);
            impl ::std::fmt::Display for #s_n {
                fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    let mut trs = self.1;
                    let lock = (trs ^ (trs >> 13) ^ (trs >> 21)) as u8;
                    let unlocked: Vec<u8> = self.0.iter().map(|&b| b ^ lock).collect();
                    for chunk in unlocked.chunks(#chunk_size) {
                        let s: String = chunk.iter().map(|&b| { trs = trs.wrapping_add(b as u32).rotate_left(3); b as char }).collect();
                        f.write_str(&s)?;
                    }
                    Ok(())
                }
            }
            #s_n(#bytes_var, #rs_var).to_string()
        }
    }
}

fn generate_polymorphic_decode_chain(
    transform_ids: &[u32], initial_input_var: &Ident,
    dispatch_name: &Ident, aux_var: &Ident, rng: &mut impl Rng, rs_var: &Ident,
    mult: u32, salt: u32
) -> TokenStream2 {
    let last_idx = transform_ids.len() - 1;
    let last_id = transform_ids[last_idx];
    let last_input = Ident::new(&format!("nd_{}", last_idx), Span::call_site());
    let last_bytes = Ident::new(&format!("lb_{}", rng.gen::<u32>()), Span::call_site());
    let nr_n = Ident::new(&format!("nr_l_{}", rng.gen::<u32>()), Span::call_site());
    let fr = generate_fragmented_string_recovery(&last_bytes, &nr_n, rng);
    let mut nl = quote! {
        {
            let (res_data, next_rs) = #dispatch_name((#last_id ^ #rs_var).wrapping_mul(#mult) ^ #salt, &#last_input, #rs_var, &mut #aux_var);
            let #last_bytes = res_data; let #nr_n = next_rs; #fr
        }
    };
    for i in (0..last_idx).rev() {
        let id = transform_ids[i];
        let ci = Ident::new(&format!("nd_{}", i), Span::call_site());
        let ni = Ident::new(&format!("nd_{}", i + 1), Span::call_site());
        let ob = Ident::new(&format!("nb_{}", i), Span::call_site());
        nl = quote! {
            {
                let (res_data, nrs) = #dispatch_name((#id ^ #rs_var).wrapping_mul(#mult) ^ #salt, &#ci, #rs_var, &mut #aux_var);
                let mut #rs_var = nrs; let #ob = res_data; let mut #ni = #ob; #nl
            }
        };
    }
    let fv = Ident::new("nd_0", Span::call_site());
    quote! { { let mut #fv = #initial_input_var.clone(); let mut #rs_var = 0u32; #nl } }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let os = lit_str.value();
    let mut rng = thread_rng();
    let pl = get_pipelines();
    let num_layers = (os.len() % 3 + 2) as usize; // 2 to 4 layers
    let mut cd = os.clone().into_bytes();
    let mut layers_params = Vec::new();
    let mut cd_lengths = Vec::new();

    for _ in 0..num_layers {
        cd_lengths.push(cd.len());
        let idx = rng.gen_range(0..pl.len());
        let e_seed = rng.gen::<u64>();
        let mut e_rng = StdRng::seed_from_u64(e_seed);
        let mut dummy_rs = 0u32;
        let (encoded, primitives) = (pl[idx].encoder)(&cd, &mut dummy_rs, &mut e_rng);
        cd = encoded;
        layers_params.push((rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u8>(), primitives, idx, e_seed));
    }
    cd_lengths.push(cd.len());

    let mut rs_starts = vec![0u32; num_layers];
    let mut arm_ids_salts = vec![(0u32, 0u32); num_layers];
    let mut rs_curr = 0u32;
    let mut vt_c = Vec::new();
    let rs_v = Ident::new("rs", Span::call_site());
    let salt = rng.gen::<u32>();
    let mult = rng.gen::<u32>() | 1;

    for i in (0..num_layers).rev() {
        rs_starts[i] = rs_curr;
        let (seed_sc, seed_corr, mask_corr, primitives, _, _) = &layers_params[i];
        let cd_len = cd_lengths[i+1];
        let mut layer_code = quote! { let mut data = data; };
        let (_, unscramble) = generate_index_scrambler(*seed_sc, &mut rng);
        let (init_corr, apply_corr) = generate_state_corruption(*seed_corr, *mask_corr, &mut rng);
        for p in primitives {
            let step = match p {
                Primitive::Map(t, s) => {
                    let (o, v, r) = get_loop_junk_params(*s);
                    for _ in 0..cd_len { apply_rs_junk_fixed(&mut rs_curr, o, v, r); }
                    generate_obfuscated_map(t, *s, &rs_v, &mut rng)
                },
                Primitive::BitLoad { .. } => generate_bit_load(),
                Primitive::BitEmit { bits, total_bits, seed } => {
                    let (o, v, r) = get_loop_junk_params(*seed);
                    for _ in 0..cd_len { apply_rs_junk_fixed(&mut rs_curr, o, v, r); }
                    generate_bit_emit(*bits, *total_bits, *seed, &rs_v, &mut rng)
                },
                Primitive::BaseLoad { .. } => generate_base_load(),
                Primitive::BaseEmit { base, in_c, out_c, total_bytes, seed } => {
                    let (o, v, r) = get_loop_junk_params(*seed);
                    for _ in 0..(cd_len / in_c) { apply_rs_junk_fixed(&mut rs_curr, o, v, r); }
                    generate_base_emit(*base, *in_c, *out_c, *total_bytes, *seed, &rs_v, &mut rng)
                },
                Primitive::Sync => quote! { let mut data = data; },
                Primitive::StateShift => { rs_curr = rs_curr.rotate_left(1); quote! { rs = rs.rotate_left(1); } },
                _ => quote! {},
            };
            layer_code = quote! { #layer_code #step };
        }
        layer_code = quote! { #layer_code #init_corr #apply_corr #unscramble };
        let id_val = rng.gen::<u32>(); let rs_salt = rng.gen::<u32>();
        arm_ids_salts[i] = (id_val, rs_salt);
        rs_curr = rs_curr.wrapping_add(id_val).rotate_left(5) ^ rs_salt;
        let arm_junk = generate_junk_logic(&mut rng, &rs_v, &mut rs_curr);
        let arm_key = (id_val ^ rs_starts[i]).wrapping_mul(mult) ^ salt;
        vt_c.push(quote! {
            #arm_key => {
                let mut data = data.to_vec(); let mut rs = rs_in;
                let lock = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock; }
                #layer_code
                rs = rs.wrapping_add(#id_val).rotate_left(5) ^ #rs_salt; #arm_junk
                (data, rs)
            }
        });
    }

    cd = os.into_bytes();
    let lock_final = (rs_curr ^ (rs_curr >> 13) ^ (rs_curr >> 21)) as u8;
    for b in cd.iter_mut() { *b ^= lock_final; }
    for i in 0..num_layers {
        let (seed_sc, seed_corr, mask_corr, _, idx, e_seed) = layers_params[i];
        apply_scramble_compile(&mut cd, seed_sc);
        apply_state_corruption_compile(&mut cd, seed_corr, mask_corr);
        let (enc, _) = (pl[idx].encoder)(&cd, &mut 0u32, &mut StdRng::seed_from_u64(e_seed));
        cd = enc;
        let lock = (rs_starts[i] ^ (rs_starts[i] >> 13) ^ (rs_starts[i] >> 21)) as u8;
        for b in cd.iter_mut() { *b ^= lock; }
    }
    let mut eb = cd;
    let xk = rng.gen::<u8>(); let ev = rng.gen_range(0..3u32); let mut key = xk;
    let mut eb_final = Vec::new();
    for &b in &eb { let eb_b = b ^ key; eb_final.push(eb_b); match ev { 0 => key = key.wrapping_add(eb_b), 1 => key = key.wrapping_sub(eb_b), _ => key = key.rotate_left(3) } }
    eb = eb_final;

    let mut rids = Vec::new();
    for i in (0..num_layers).rev() { rids.push(arm_ids_salts[i].0); }

    let suffix = rng.gen::<u32>();
    let s_n = Ident::new(&format!("O_{}", suffix), Span::call_site());
    let m_n = Ident::new(&format!("r_{}", suffix), Span::call_site());
    let d_n = Ident::new(&format!("d_{}", suffix), Span::call_site());
    let i_v = Ident::new(&format!("ds_{}", suffix), Span::call_site());
    let a_v = Ident::new(&format!("aux_{}", suffix), Span::call_site());
    let rs_j_v = Ident::new(&format!("rs_j_{}", suffix), Span::call_site());
    let d_b_i = Ident::new(&format!("db_{}", suffix), Span::call_site());
    let dc = generate_polymorphic_decode_chain(&rids, &i_v, &d_n, &a_v, &mut rng, &rs_v, mult, salt);
    let dl_c = generate_obfuscated_decrypt(quote! { rd }, &d_b_i, &rs_j_v, &mut 0u32, &mut rng, ev, false);
    let (df, di, rl) = match rng.gen_range(0..3) {
        0 => { let dl = Literal::byte_string(&eb); (quote! { d: &'a [u8], }, quote! { d: #dl, }, quote! { let mut rd = self.d.to_vec(); }) },
        1 => {
            let ev_b: Vec<u8> = eb.iter().step_by(2).cloned().collect();
            let od_b: Vec<u8> = eb.iter().skip(1).step_by(2).cloned().collect();
            let el = Literal::byte_string(&ev_b); let ol = Literal::byte_string(&od_b);
            (quote! { e: &'a [u8], o: &'a [u8], }, quote! { e: #el, o: #ol, }, quote! { let mut rd = Vec::new(); let mut ei = self.e.iter(); let mut oi = self.o.iter(); loop { match (ei.next(), oi.next()) { (Some(e), Some(o)) => { rd.push(*e); rd.push(*o); }, (Some(e), None) => { rd.push(*e); break; }, _ => break } } })
        },
        _ => { let ji: Vec<u8> = eb.iter().flat_map(|&b| vec![b, rng.gen::<u8>()]).collect(); let li = Literal::byte_string(&ji); (quote! { j: &'a [u8], }, quote! { j: #li, }, quote! { let mut rd: Vec<u8> = self.j.iter().step_by(2).cloned().collect(); }) }
    };

    let expanded = quote! { {
        struct #s_n<'a> { #df key: u8, }
        impl<'a> #s_n<'a> {
            fn #m_n(&mut self) -> String {
                let mut #d_n = |arm_id: u32, data: &[u8], rs_in: u32, aux: &mut Vec<u8>| -> (Vec<u8>, u32) {
                    let mut rs = rs_in;
                    match arm_id { #(#vt_c)* _ => (data.to_vec(), rs) }
                };
                let mut #a_v = Vec::new(); let mut #rs_j_v = 0u32;
                let mut #i_v = { #rl; #dl_c };
                #dc
            }
        }
        let mut inst = #s_n { #di key: #xk, }; inst.#m_n()
    } };
    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_random_pipelines() {
        let mut rng = thread_rng();
        let originals = vec![b"Simple Calculator".to_vec(), vec![0, 0, 1, 2, 3]];
        let pl = get_pipelines();
        for original in originals {
            for _ in 0..10 {
                let mut data = original.clone();
                let mut layer_prims = Vec::new();
                for _ in 0..2 {
                    let idx = rng.gen_range(0..pl.len());
                    let (encoded, primitives) = (pl[idx].encoder)(&data, &mut 0u32, &mut rng);
                    data = encoded; layer_prims.push(primitives);
                }
                layer_prims.reverse();
                let mut b_data = data; let mut aux = Vec::new();
                for primitives in layer_prims {
                    for p in primitives {
                        match p {
                            Primitive::Map(alpha, _) => {
                                let mut map = [255u8; 256]; for (j, &c) in alpha.iter().enumerate() { map[c as usize] = j as u8; }
                                let mut out = Vec::new(); for &b in &b_data { let v = map[b as usize]; if v != 255 { out.push(v); } }
                                b_data = out;
                            },
                            Primitive::BitLoad { .. } | Primitive::BaseLoad { .. } => { aux.extend_from_slice(&b_data); b_data.clear(); },
                            Primitive::BitEmit { bits, total_bits, .. } => {
                                let mut out = Vec::new(); let mut acc = 0u128; let mut count = 0u32; let mut bc = 0u64;
                                for &v in aux.iter() { acc = (acc << bits) | (v as u128); count += bits; while count >= 8 { count -= 8; if bc < total_bits { out.push((acc >> count) as u8); bc += 8; } acc &= (1 << count) - 1; } }
                                b_data = out; aux.clear();
                            },
                            Primitive::BaseEmit { base, in_c, out_c, total_bytes, .. } => {
                                let mut out = Vec::new(); let mut len_v = 0u64;
                                for chunk in aux.chunks(in_c) { if chunk.len() < in_c { continue; } let mut v = 0u128; for &c in chunk { v = v * base + (c as u128); } for i in (0..out_c).rev() { if len_v < total_bytes { out.push(((v >> (i * 8)) & 0xff) as u8); len_v += 1; } } }
                                b_data = out; aux.clear();
                            },
                            _ => {}
                        }
                    }
                }
                assert_eq!(b_data, original);
            }
        }
    }
}
