extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};

#[derive(Clone, Debug)]
enum Primitive {
    Map(Vec<u8>),
    BitLoad { bits: u32 },
    BitEmit { bits: u32, total_bits: u64 },
    BitUnpack { bits: u32, total_bits: u64 },
    BaseLoad { base: u128, in_c: usize },
    BaseEmit { base: u128, in_c: usize, out_c: usize, total_bytes: u64 },
    BigIntInit,
    BigIntPush { base: u128, use_be: bool },
    BigIntEmit { total_bytes: u64, use_be: bool },
    BigIntDecode { base: u128, total_bytes: u64 },
    Noop { val: u32 },
    Sync,
}

struct Pipeline {
    encoder: Box<dyn Fn(&[u8]) -> (Vec<u8>, Vec<Primitive>)>,
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
                let mut rng = thread_rng();
                let (out, total_bits) = encode_bits(data, 5, &alpha);
                let primitives = if rng.gen_bool(0.5) {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitLoad { bits: 5 },
                        Primitive::Noop { val: rng.gen() },
                        Primitive::BitEmit { bits: 5, total_bits }
                    ]
                } else {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitUnpack { bits: 5, total_bits }
                    ]
                };
                (out, primitives)
            }),
        }
    };
    let b36 = || {
        let alpha = b36_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let out = encode_bigint(data, 36, &alpha);
                let primitives = if rng.gen_bool(0.5) {
                    let use_be = rng.gen_bool(0.5);
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntInit,
                        Primitive::BigIntPush { base: 36, use_be },
                        Primitive::BigIntEmit { total_bytes: data.len() as u64, use_be }
                    ]
                } else {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntDecode { base: 36, total_bytes: data.len() as u64 }
                    ]
                };
                (out, primitives)
            }),
        }
    };
    let b64 = || {
        let alpha = b64_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let (out, total_bits) = encode_bits(data, 6, &alpha);
                let primitives = if rng.gen_bool(0.5) {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitLoad { bits: 6 },
                        Primitive::BitEmit { bits: 6, total_bits }
                    ]
                } else {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitUnpack { bits: 6, total_bits }
                    ]
                };
                (out, primitives)
            }),
        }
    };
    let z85 = || {
        let alpha = z85_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bytes) = encode_z85_custom(data, &alpha);
                (out, vec![
                    Primitive::Map(alpha.clone()),
                    Primitive::BaseLoad { base: 85, in_c: 5 },
                    Primitive::Sync,
                    Primitive::BaseEmit { base: 85, in_c: 5, out_c: 4, total_bytes }
                ])
            }),
        }
    };
    let b91 = || {
        let alpha = b91_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let out = encode_bigint(data, 91, &alpha);
                let primitives = if rng.gen_bool(0.5) {
                    let use_be = rng.gen_bool(0.5);
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntInit,
                        Primitive::BigIntPush { base: 91, use_be },
                        Primitive::BigIntEmit { total_bytes: data.len() as u64, use_be }
                    ]
                } else {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntDecode { base: 91, total_bytes: data.len() as u64 }
                    ]
                };
                (out, primitives)
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

fn generate_obfuscated_map(alphabet: &[u8], rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }

    match rng.gen_range(0..3) {
        0 => {
            let map_lit = Literal::byte_string(&map);
            quote! {
                let mut out = Vec::with_capacity(data.len());
                for &b in &data {
                    let v = (#map_lit)[b as usize];
                    if v != 255 { out.push(v); }
                }
                data = out;
            }
        },
        1 => {
            let mut arms = Vec::new();
            for (i, &c) in alphabet.iter().enumerate() {
                let cu = c as usize;
                let iu = i as u8;
                arms.push(quote! { #cu => out.push(#iu), });
            }
            quote! {
                let mut out = Vec::with_capacity(data.len());
                for &b in &data {
                    match b as usize {
                        #(#arms)*
                        _ => {}
                    }
                }
                data = out;
            }
        },
        _ => {
            let xor_key = rng.gen::<u8>();
            let mut xored_map = vec![0u8; 256];
            let mut found = vec![0u8; 256];
            for (i, &c) in alphabet.iter().enumerate() {
                xored_map[c as usize] = (i as u8) ^ xor_key;
                found[c as usize] = 1;
            }
            let map_lit = Literal::byte_string(&xored_map);
            let found_lit = Literal::byte_string(&found);
            quote! {
                let mut out = Vec::with_capacity(data.len());
                for &b in &data {
                    if (#found_lit)[b as usize] != 0 {
                        let v = (#map_lit)[b as usize];
                        out.push(v ^ #xor_key);
                    }
                }
                data = out;
            }
        }
    }
}

fn generate_bit_load(_bits: u32, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.extend_from_slice(&data);
        data.clear();
    }
}

fn generate_bit_emit(bits: u32, total_bits: u64, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
        0 => quote! {
            let mut out = Vec::new();
            let mut acc = 0u128;
            let mut count = 0u32;
            let mut bc = 0u64;
            for &v in aux.iter() {
                acc = (acc << #bits) | (v as u128);
                count += #bits;
                while count >= 8 {
                    count -= 8;
                    if bc < #total_bits {
                        out.push((acc >> count) as u8);
                        bc += 8;
                    }
                    acc &= (1 << count) - 1;
                }
            }
            data = out;
            aux.clear();
        },
        _ => quote! {
            let mut out = Vec::new();
            let mut acc = 0u128;
            let mut count = 0u32;
            let mut bc = 0u64;
            let mut i = 0;
            while i < aux.len() {
                let v = aux[i];
                acc = (acc << #bits) | (v as u128);
                count += #bits;
                while count >= 8 {
                    count -= 8;
                    if bc < #total_bits {
                        out.push((acc >> count) as u8);
                        bc += 8;
                    }
                    acc &= (1 << count) - 1;
                }
                i += 1;
            }
            data = out;
            aux.clear();
        }
    }
}

fn generate_bit_unpack(bits: u32, total_bits: u64, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
        0 => quote! {
            let mut out = Vec::new();
            let mut acc = 0u128;
            let mut count = 0u32;
            let mut bc = 0u64;
            for &v in data.iter() {
                acc = (acc << #bits) | (v as u128);
                count += #bits;
                while count >= 8 {
                    count -= 8;
                    if bc < #total_bits {
                        out.push((acc >> count) as u8);
                        bc += 8;
                    }
                    acc &= (1 << count) - 1;
                }
            }
            data = out;
        },
        _ => quote! {
            let mut out = Vec::with_capacity(data.len());
            let mut acc = 0u128;
            let mut count = 0u32;
            let mut bc = 0u64;
            let mut it = data.iter();
            while let Some(&v) = it.next() {
                acc = (acc << #bits) | (v as u128);
                count += #bits;
                while count >= 8 {
                    count -= 8;
                    if bc < #total_bits {
                        out.push((acc >> count) as u8);
                        bc += 8;
                    }
                    acc &= (1 << count) - 1;
                }
            }
            data = out;
        }
    }
}

fn generate_base_load(_base: u128, _in_c: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.extend_from_slice(&data);
        data.clear();
    }
}

fn generate_base_emit(base: u128, in_c: usize, out_c: usize, total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        let mut out = Vec::new();
        let mut len_v = 0u64;
        for chunk in aux.chunks(#in_c) {
            if chunk.len() < #in_c { continue; }
            let mut v = 0u128;
            for &c in chunk { v = v * #base + (c as u128); }
            for i in (0..#out_c).rev() {
                if len_v < #total_bytes {
                    out.push(((v >> (i * 8)) & 0xff) as u8);
                    len_v += 1;
                }
            }
        }
        data = out;
        aux.clear();
    }
}

fn generate_bigint_init(_rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.clear();
        aux.extend_from_slice(&0u32.to_ne_bytes());
    }
}

fn generate_bigint_push(base: u128, use_be: bool, _rng: &mut impl Rng) -> TokenStream2 {
    let push_digit = if use_be {
        quote! { for val in res { aux.extend_from_slice(&val.to_be_bytes()); } }
    } else {
        quote! { for val in res { aux.extend_from_slice(&val.to_ne_bytes()); } }
    };
    let read_digit = if use_be {
        quote! { u32::from_be_bytes(bytes) }
    } else {
        quote! { u32::from_ne_bytes(bytes) }
    };

    quote! {
        let mut leading_zeros = 0;
        for &v in &data { if v == 0 { leading_zeros += 1; } else { break; } }
        let mut res = Vec::new();
        for chunk in aux.chunks_exact(4) {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(chunk);
            res.push(#read_digit);
        }

        for &v in &data[leading_zeros..] {
            let mut carry = v as u64;
            for digit in res.iter_mut() {
                let prod = (*digit as u64) * (#base as u64) + carry;
                *digit = prod as u32;
                carry = prod >> 32;
            }
            while carry > 0 {
                res.push(carry as u32);
                carry >>= 32;
            }
        }

        aux.clear();
        #push_digit
        let lz = leading_zeros as u64;
        let mut next_aux = lz.to_ne_bytes().to_vec();
        next_aux.extend_from_slice(&aux);
        aux.clear();
        aux.extend(next_aux);
    }
}

fn generate_bigint_emit(_total_bytes: u64, use_be: bool, _rng: &mut impl Rng) -> TokenStream2 {
    let read_digit = if use_be {
        quote! { u32::from_be_bytes(bytes) }
    } else {
        quote! { u32::from_ne_bytes(bytes) }
    };

    quote! {
        if aux.len() >= 8 {
            let mut lz_bytes = [0u8; 8];
            lz_bytes.copy_from_slice(&aux[0..8]);
            let lz = u64::from_ne_bytes(lz_bytes) as usize;

            let mut res = Vec::new();
            for chunk in aux[8..].chunks_exact(4) {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(chunk);
                res.push(#read_digit);
            }

            let mut out = vec![0u8; lz];
            if !(res.len() == 1 && res[0] == 0) || (aux.len() - 8) / 4 == lz {
                let mut bytes_out = Vec::new();
                let rl = res.len();
                for (idx, &val) in res.iter().enumerate().rev() {
                    let bytes = val.to_be_bytes();
                    if idx == rl - 1 {
                         let mut skip = 0;
                         while skip < 4 && bytes[skip] == 0 { skip += 1; }
                         bytes_out.extend_from_slice(&bytes[skip..]);
                    } else { bytes_out.extend_from_slice(&bytes); }
                }
                out.extend(bytes_out);
            }
            data = out;
        } else {
            data = Vec::new();
        }
        aux.clear();
    }
}

fn generate_bigint_decode(base: u128, _total_bytes: u64, rng: &mut impl Rng) -> TokenStream2 {
    let loop_style = rng.gen_range(0..2);
    let core = if loop_style == 0 {
        quote! {
            for &v in &data[leading_zeros..] {
                let mut carry = v as u64;
                for digit in res.iter_mut() {
                    let prod = (*digit as u64) * (#base as u64) + carry;
                    *digit = prod as u32;
                    carry = prod >> 32;
                }
                while carry > 0 {
                    res.push(carry as u32);
                    carry >>= 32;
                }
            }
        }
    } else {
        quote! {
            let mut i = leading_zeros;
            while i < data.len() {
                let v = data[i];
                let mut carry = v as u64;
                let mut j = 0;
                while j < res.len() {
                    let prod = (res[j] as u64) * (#base as u64) + carry;
                    res[j] = prod as u32;
                    carry = prod >> 32;
                    j += 1;
                }
                while carry > 0 {
                    res.push(carry as u32);
                    carry >>= 32;
                }
                i += 1;
            }
        }
    };

    quote! {
        let mut leading_zeros = 0;
        for &v in &data { if v == 0 { leading_zeros += 1; } else { break; } }
        let mut res = vec![0u32; 0];
        #core
        let mut out = vec![0u8; leading_zeros];
        let rl = res.len();
        if rl > 0 {
            for (idx, &val) in res.iter().enumerate().rev() {
                let bytes = val.to_be_bytes();
                if idx == rl - 1 {
                     let mut skip = 0;
                     while skip < 4 && bytes[skip] == 0 { skip += 1; }
                     out.extend_from_slice(&bytes[skip..]);
                } else { out.extend_from_slice(&bytes); }
            }
        }
        data = out;
    }
}

// Enhanced junk logic that is semantically required
fn generate_junk_logic(rng: &mut impl Rng, _real_var: Option<&Ident>, rs_var: Option<&Ident>, rs_compile: &mut u32) -> TokenStream2 {
    let mut code = Vec::new();
    if let Some(rsv) = rs_var {
        for _ in 0..rng.gen_range(2..=4) {
             match rng.gen_range(0..5) {
                0 => {
                    let val = rng.gen::<u32>();
                    *rs_compile = rs_compile.wrapping_add(val);
                    code.push(quote! { #rsv = #rsv.wrapping_add(#val); });
                },
                1 => {
                    let val = rng.gen_range(1..31);
                    *rs_compile = rs_compile.rotate_left(val);
                    code.push(quote! { #rsv = #rsv.rotate_left(#val); });
                },
                2 => {
                    let val = rng.gen::<u32>();
                    *rs_compile ^= val;
                    code.push(quote! { #rsv ^= #val; });
                },
                3 => {
                    let val = rng.gen::<u32>();
                    *rs_compile = rs_compile.wrapping_mul(val | 1);
                    code.push(quote! { #rsv = #rsv.wrapping_mul(#val | 1); });
                },
                _ => {
                    let val = rng.gen::<u32>();
                    *rs_compile = rs_compile.wrapping_sub(val);
                    code.push(quote! { #rsv = #rsv.wrapping_sub(#val); });
                }
            }
        }
    }

    if code.is_empty() {
        let j_v = Ident::new(&format!("j_{}", rng.gen::<u32>()), Span::call_site());
        let j_val = rng.gen::<u32>();
        quote! { let #j_v = #j_val; }
    } else {
        quote! { #(#code)* }
    }
}

fn apply_state_corruption_compile(data: &mut Vec<u8>, seed: u32, mask: u8) {
    let offset = seed.wrapping_mul(0x9E3779B9);
    for (i, b) in data.iter_mut().enumerate() {
        let idx_mask = ((i as u32).wrapping_add(offset) & 0x7) as u8;
        *b = b.wrapping_add(idx_mask ^ mask); // Use addition to reverse the subtraction in decoder
    }
}

// Generate semantically required state modifiers
fn generate_state_corruption(seed: u32, mask: u8, rng: &mut impl Rng) -> (TokenStream2, TokenStream2) {
    let offset_var = Ident::new(&format!("offset_{}", rng.gen::<u32>()), Span::call_site());
    
    // State initialization
    let init = quote! {
        let mut #offset_var = #seed.wrapping_mul(0x9E3779B9);
    };
    
    // State application - SUBTRACT to reverse the operation
    let apply = quote! {
        for (i, b) in data.iter_mut().enumerate() {
            let idx_mask = ((i as u32).wrapping_add(#offset_var) & 0x7) as u8;
            *b = b.wrapping_sub(idx_mask ^ #mask);
        }
    };
    
    (init, apply)
}

fn apply_scramble_compile(data: &mut Vec<u8>, seed: u32) {
    let mut scramble_idx = seed;
    for b in data.iter_mut() {
        scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
        let offset = (scramble_idx & 0x3) as u8;
        *b = b.wrapping_add(offset);
    }
}

fn apply_unscramble_compile(data: &mut Vec<u8>, seed: u32) {
    let mut scramble_idx = seed;
    for b in data.iter_mut() {
        scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
        let offset = (scramble_idx & 0x3) as u8;
        *b = b.wrapping_sub(offset);
    }
}

// Generate index scrambling that must be reversed
fn generate_index_scrambler(seed: u32, _rng: &mut impl Rng) -> (TokenStream2, TokenStream2) {
    let scramble_seed = seed;
    
    let scramble = quote! {
        {
            let mut out_sc = Vec::with_capacity(data.len());
            let mut scramble_idx = #scramble_seed;
            for &b in data.iter() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (scramble_idx & 0x3) as u8;
                out_sc.push(b.wrapping_add(offset));
            }
            data = out_sc;
        }
    };
    
    let unscramble = quote! {
        {
            let mut out_un = Vec::with_capacity(data.len());
            let mut scramble_idx = #scramble_seed;
            for &b in data.iter() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (scramble_idx & 0x3) as u8;
                out_un.push(b.wrapping_sub(offset));
            }
            data = out_un;
        }
    };
    
    (scramble, unscramble)
}

fn generate_obfuscated_decrypt(input_expr: TokenStream2, output_var: &Ident, rs_var: &Ident, rs_compile: &mut u32, rng: &mut impl Rng, variant: u32) -> TokenStream2 {
    let k_n = Ident::new(&format!("k_{}", rng.gen::<u32>()), Span::call_site());
    let b_n = Ident::new(&format!("b_{}", rng.gen::<u32>()), Span::call_site());
    let br_n = Ident::new(&format!("br_{}", rng.gen::<u32>()), Span::call_site());
    
    let u_l = match variant {
        0 => quote! { #k_n = #k_n.wrapping_add(#b_n); },
        1 => quote! { #k_n = #k_n.wrapping_sub(#b_n); },
        _ => quote! { #k_n = #k_n.rotate_left(3); },
    };
    
    let junk = generate_junk_logic(rng, Some(output_var), Some(rs_var), rs_compile);
    
    let core = match rng.gen_range(0..3) {
        0 => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Vec::with_capacity(#input_expr.len());
            for byte in #input_expr.iter() {
                let #b_n = *byte;
                #output_var.push(#b_n ^ #k_n);
                #u_l
            }
            #junk
        },
        1 => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Vec::new();
            let mut i = 0;
            while i < #input_expr.len() {
                let #b_n = #input_expr[i];
                #output_var.push(#b_n ^ #k_n);
                #u_l
                i += 1;
            }
            #junk
        },
        _ => quote! {
            let mut #k_n = self.key;
            let mut #output_var: Vec<u8> = #input_expr.iter().map(|#br_n| {
                let #b_n = *#br_n;
                let db = #b_n ^ #k_n;
                #u_l
                db
            }).collect();
            #junk
        },
    };
    
    quote! {
        #core
        let lock_out_junk = (#rs_var ^ (#rs_var >> 13) ^ (#rs_var >> 21)) as u8;
        for b in #output_var.iter_mut() { *b ^= lock_out_junk; }
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
                    let mut temp_rs = self.1;
                    let lock = (temp_rs ^ (temp_rs >> 13) ^ (temp_rs >> 21)) as u8;
                    let unlocked: Vec<u8> = self.0.iter().map(|&b| b ^ lock).collect();
                    for chunk in unlocked.chunks(#chunk_size) {
                        let s: String = chunk.iter().map(|&b| {
                            temp_rs = temp_rs.wrapping_add(b as u32).rotate_left(3);
                            b as char
                        }).collect();
                        f.write_str(&s)?;
                    }
                    let _ = temp_rs;
                    Ok(())
                }
            }
            #s_n(#bytes_var, #rs_var).to_string()
        }
    }
}

fn generate_polymorphic_decode_chain(
    transform_ids: &[u32],
    junk_tokens: &[TokenStream2],
    initial_input_var: &Ident,
    dispatch_name: &Ident,
    aux_var: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let rs_n = Ident::new("rs", Span::call_site());
    
    match rng.gen_range(0..3) {
        0 => { // State machine
            let mut arms = Vec::new();
            let s_n = Ident::new("s", Span::call_site());
            let m_n = Ident::new("m", Span::call_site());
            
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                let i_u = i as usize;
                
                if i < transform_ids.len() - 1 {
                    arms.push(quote! {
                        #i_u => {
                            let (res_data, next_rs) = #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var);
                            #m_n = res_data;
                            #rs_n = next_rs;
                            #s_n += 1;
                            #junk
                        }
                    });
                } else {
                    let fb_n = Ident::new("fb", Span::call_site());
                    let nr_n = Ident::new("nr", Span::call_site());
                    let fr = generate_fragmented_string_recovery(&fb_n, &nr_n, rng);
                    arms.push(quote! {
                        #i_u => {
                            let (res_data, next_rs) = #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var);
                            let #fb_n = res_data;
                            let #nr_n = next_rs;
                            let fv = #fr;
                            break fv;
                        }
                    });
                }
            }
            arms.push(quote! { _ => break String::new(), });
            
            quote! {
                let mut #s_n = 0usize;
                let mut #m_n = #initial_input_var.clone();
                let mut #rs_n = 0u32;
                loop { match #s_n { #(#arms)* } }
            }
        },
        1 => { // Nested blocks
            if transform_ids.is_empty() { return quote! { String::new() }; }
            
            let last_idx = transform_ids.len() - 1;

            let last_id = transform_ids[last_idx];
            let last_input = Ident::new(&format!("nd_{}", last_idx), Span::call_site());
            let last_bytes = Ident::new("lb", Span::call_site());
            let nr_n = Ident::new("nr_last", Span::call_site());
            let fr = generate_fragmented_string_recovery(&last_bytes, &nr_n, rng);
            
            let mut nl = quote! { 
                { 
                    let (res_data, next_rs) = #dispatch_name(#last_id ^ #rs_n, &#last_input, #rs_n, &mut #aux_var); 
                    let #last_bytes = res_data; 
                    let #nr_n = next_rs; 
                    #fr 
                } 
            };
            
            for i in (0..last_idx).rev() {
                let id = transform_ids[i];
                let ci = Ident::new(&format!("nd_{}", i), Span::call_site());
                let ni = Ident::new(&format!("nd_{}", i + 1), Span::call_site());
                let ob = Ident::new(&format!("nb_{}", i), Span::call_site());
                let junk = &junk_tokens[i];
                
                nl = quote! { 
                    { 
                        let (res_data, next_rs_val) = #dispatch_name(#id ^ #rs_n, &#ci, #rs_n, &mut #aux_var); 
                        let mut #rs_n = next_rs_val; 
                        let #ob = res_data; 
                        #junk 
                        let mut #ni = #ob; 
                        #nl 
                    } 
                };
            }
            
            let fv = Ident::new("nd_0", Span::call_site());
            quote! { { let mut #fv = #initial_input_var.clone(); let mut #rs_n = 0u32; #nl } }
        },
        _ => { // Linear
            let mut st = Vec::new();
            let cv = Ident::new("cv", Span::call_site());
            
            st.push(quote! { let mut #cv = #initial_input_var.clone(); });
            st.push(quote! { let mut #rs_n = 0u32; });
            
            for (i, &id) in transform_ids.iter().enumerate() {
                let nb = Ident::new(&format!("b_{}", i), Span::call_site());
                let rd_v = Ident::new(&format!("rd_{}", i), Span::call_site());
                let nr_v = Ident::new(&format!("nr_{}", i), Span::call_site());
                
                st.push(quote! { 
                    let (#rd_v, #nr_v) = #dispatch_name(#id ^ #rs_n, &#cv, #rs_n, &mut #aux_var); 
                    let #nb = #rd_v; 
                    #rs_n = #nr_v; 
                });
                
                let junk = &junk_tokens[i];
                st.push(quote! { #junk });
                
                if i < transform_ids.len() - 1 {
                    st.push(quote! { #cv = #nb; });
                } else {
                    let fvb = Ident::new("fv", Span::call_site());
                    st.push(quote! { let mut #fvb = #nb; });
                    let fr = generate_fragmented_string_recovery(&fvb, &rs_n, rng);
                    st.push(quote! { let frs = #fr; });
                }
            }
            
            quote! { { #(#st)* frs } }
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
    
    let mut cd = os.clone().into_bytes();
    let mut layers_data = Vec::new();
    
    for _ in 0..num_layers {
        let seed_sc = rng.gen::<u32>();
        let seed_corr = rng.gen::<u32>();
        let mask_corr = rng.gen::<u8>();

        apply_scramble_compile(&mut cd, seed_sc);
        apply_state_corruption_compile(&mut cd, seed_corr, mask_corr);

        let idx = rng.gen_range(0..pl.len());
        let (encoded, primitives) = (pl[idx].encoder)(&cd);
        cd = encoded;

        apply_unscramble_compile(&mut cd, seed_sc);
        layers_data.push((seed_sc, seed_corr, mask_corr, primitives));
    }
    layers_data.reverse();

    let xk = rng.gen::<u8>();
    let ev = rng.gen_range(0..3u32);
    let mut key = xk;
    
    let mut rs_junk_compile = 0u32;
    let d_b_i = Ident::new("db", Span::call_site());
    let dl_c = generate_obfuscated_decrypt(quote! { rd }, &d_b_i, &Ident::new("rs_junk", Span::call_site()), &mut rs_junk_compile, &mut rng, ev);
    let lock_junk = (rs_junk_compile ^ (rs_junk_compile >> 13) ^ (rs_junk_compile >> 21)) as u8;

    let mut eb = Vec::with_capacity(cd.len());
    for &ob in &cd {
        let eb_b = (ob ^ lock_junk) ^ key;
        eb.push(eb_b);
        match ev {
            0 => key = key.wrapping_add(eb_b),
            1 => key = key.wrapping_sub(eb_b),
            _ => key = key.rotate_left(3),
        };
    }

    let mut vt_c = Vec::new();
    let mut rids = Vec::new();
    let mut dc_junks = Vec::new();
    let salt = rng.gen::<u32>();
    let mult = rng.gen::<u32>() | 1;
    let mut rs = 0u32;

    #[derive(Clone, Debug)]
    enum TaskInternal {
        Scramble(u32),
        Unscramble(u32),
        StateCorruption(u32, u8),
        Primitive(Primitive),
    }

    let mut all_tasks = Vec::new();
    for (seed_sc, seed_corr, mask_corr, primitives) in layers_data {
        all_tasks.push(TaskInternal::Scramble(seed_sc));
        for p in primitives {
            all_tasks.push(TaskInternal::Primitive(p));
        }
        all_tasks.push(TaskInternal::StateCorruption(seed_corr, mask_corr));
        all_tasks.push(TaskInternal::Unscramble(seed_sc));
    }

    let mut task_idx = 0;
    while task_idx < all_tasks.len() {
        let n = rng.gen_range(1..=3);
        let group = &all_tasks[task_idx..std::cmp::min(task_idx + n, all_tasks.len())];
        task_idx += n;

        let mut group_code = Vec::new();
        for task in group {
            let task_code = match task {
                TaskInternal::Scramble(seed) => {
                    let (scramble, _) = generate_index_scrambler(*seed, &mut rng);
                    quote! { #scramble }
                },
                TaskInternal::Unscramble(seed) => {
                    let (_, unscramble) = generate_index_scrambler(*seed, &mut rng);
                    quote! { #unscramble }
                },
                TaskInternal::StateCorruption(seed, mask) => {
                    let (init, apply) = generate_state_corruption(*seed, *mask, &mut rng);
                    quote! { #init #apply }
                },
                TaskInternal::Primitive(p) => {
                    match p {
                        Primitive::Map(table) => generate_obfuscated_map(&table, &mut rng),
                        Primitive::BitLoad { bits } => generate_bit_load(*bits, &mut rng),
                        Primitive::BitEmit { bits, total_bits } => generate_bit_emit(*bits, *total_bits, &mut rng),
                        Primitive::BitUnpack { bits, total_bits } => generate_bit_unpack(*bits, *total_bits, &mut rng),
                        Primitive::BaseLoad { base, in_c } => generate_base_load(*base, *in_c, &mut rng),
                        Primitive::BaseEmit { base, in_c, out_c, total_bytes } => generate_base_emit(*base, *in_c, *out_c, *total_bytes, &mut rng),
                        Primitive::BigIntInit => generate_bigint_init(&mut rng),
                        Primitive::BigIntPush { base, use_be } => generate_bigint_push(*base, *use_be, &mut rng),
                        Primitive::BigIntEmit { total_bytes, use_be } => generate_bigint_emit(*total_bytes, *use_be, &mut rng),
                        Primitive::BigIntDecode { base, total_bytes } => generate_bigint_decode(*base, *total_bytes, &mut rng),
                        Primitive::Noop { val } => quote! { let _ = #val; },
                        Primitive::Sync => quote! {  },
                    }
                }
            };
            group_code.push(task_code);
        }

        let id_val = rng.gen::<u32>();
        let mut arm_rs = rs;
        let rs_salt = rng.gen::<u32>();
        arm_rs = arm_rs.wrapping_add(id_val).rotate_left(5) ^ rs_salt;
        
        let core_rs_update = quote! {
            rs = rs.wrapping_add(#id_val).rotate_left(5) ^ #rs_salt;
        };
        
        let arm_junk = generate_junk_logic(&mut rng, None, Some(&Ident::new("rs", Span::call_site())), &mut arm_rs);
        let arm_key = (id_val ^ rs).wrapping_mul(mult) ^ salt;
        
        vt_c.push(quote! {
            #arm_key => {
                let mut data = data.to_vec();
                let mut rs = rs_in;
                let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock_in; }
                #(#group_code)*
                #core_rs_update
                #arm_junk
                let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock_out; }
                (data, rs)
            }
        });
        
        let mut dummy_rs = 0u32;
        let dc_junk = generate_junk_logic(&mut rng, None, None, &mut dummy_rs);
        dc_junks.push(dc_junk);

        rids.push(id_val);
        rs = arm_rs;
    }

    let s_n = Ident::new(&format!("O_{}", rng.gen::<u32>()), Span::call_site());
    let m_n = Ident::new(&format!("r_{}", rng.gen::<u32>()), Span::call_site());
    let d_n = Ident::new(&format!("d_{}", rng.gen::<u32>()), Span::call_site());
    let i_v = Ident::new("ds", Span::call_site());
    let a_v = Ident::new("aux", Span::call_site());
    
    let dc = generate_polymorphic_decode_chain(&rids, &dc_junks, &i_v, &d_n, &a_v, &mut rng);
    
    let (df, di, rl) = match rng.gen_range(0..3) {
        0 => {
            let dl = Literal::byte_string(&eb);
            (quote! { d: &'a [u8], }, quote! { d: #dl, }, quote! { let mut rd = self.d.to_vec(); })
        },
        1 => {
            let even: Vec<u8> = eb.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = eb.iter().skip(1).step_by(2).cloned().collect();
            let el = Literal::byte_string(&even);
            let ol = Literal::byte_string(&odd);
            (quote! { e: &'a [u8], o: &'a [u8], }, quote! { e: #el, o: #ol, },
             quote! {
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
             })
        },
        _ => {
            let ji: Vec<u8> = eb.iter().flat_map(|&b| vec![b, rng.gen()]).collect();
            let dl = Literal::byte_string(&ji);
            (quote! { j: &'a [u8], }, quote! { j: #dl, }, quote! { let mut rd: Vec<u8> = self.j.iter().step_by(2).cloned().collect(); })
        }
    };
    
    let expanded = quote! {{
        struct #s_n<'a> { #df key: u8, }
        impl<'a> #s_n<'a> {
            fn #m_n(&mut self) -> String {
                let mut #d_n = |id: u32, data: &[u8], rs_in: u32, aux: &mut Vec<u8>| -> (Vec<u8>, u32) {
                    match (id.wrapping_mul(#mult) ^ #salt) {
                        #(#vt_c)*
                        _ => (data.to_vec(), rs_in)
                    }
                };
                let mut #a_v = Vec::new();
                let mut rs_junk = 0u32;
                let mut #d_b_i = { #rl #dl_c db };
                let mut #i_v = #d_b_i;
                #dc
            }
        }
        let mut inst = #s_n { #di key: #xk, };
        inst.#m_n()
    }};
    
    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_bits_manual(data: &[u8], bits: u32, total_bits: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc = 0u128;
        let mut count = 0u32;
        let mut bc = 0u64;
        for &v in data {
            acc = (acc << bits) | (v as u128);
            count += bits;
            while count >= 8 {
                count -= 8;
                if bc < total_bits {
                    out.push((acc >> count) as u8);
                    bc += 8;
                }
                acc &= (1 << count) - 1;
            }
        }
        out
    }

    fn decode_z85_manual(data: &[u8], base: u128, in_c: usize, out_c: usize, total_bytes: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut len_v = 0u64;
        for chunk in data.chunks(in_c) {
            if chunk.len() < in_c { continue; }
            let mut val = 0u128;
            for &c in chunk { val = val * base + (c as u128); }
            for i in (0..out_c).rev() {
                if len_v < total_bytes {
                    out.push(((val >> (i * 8)) & 0xff) as u8);
                    len_v += 1;
                }
            }
        }
        out
    }

    fn decode_bigint_manual_from_aux(aux: &[u8]) -> Vec<u8> {
        if aux.len() < 8 { return Vec::new(); }
        let mut lz_bytes = [0u8; 8];
        lz_bytes.copy_from_slice(&aux[0..8]);
        let lz = u64::from_ne_bytes(lz_bytes) as usize;
        let mut res = Vec::new();
        for chunk in aux[8..].chunks_exact(4) {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(chunk);
            res.push(u32::from_ne_bytes(bytes));
        }
        let mut out = vec![0u8; lz];
        if !(res.len() == 1 && res[0] == 0) || (aux.len() - 8) / 4 == lz {
            let mut bytes_out = Vec::new();
            let rl = res.len();
            for (idx, &val) in res.iter().enumerate().rev() {
                let bytes = val.to_be_bytes();
                if idx == rl - 1 {
                     let mut skip = 0;
                     while skip < 4 && bytes[skip] == 0 { skip += 1; }
                     bytes_out.extend_from_slice(&bytes[skip..]);
                } else { bytes_out.extend_from_slice(&bytes); }
            }
            out.extend(bytes_out);
        }
        out
    }

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
            for _ in 0..100 {
                let num_layers = rng.gen_range(1..=5);
                let mut data = original.clone();
                let mut layer_prims = Vec::new();
                for _ in 0..num_layers {
                    let idx = rng.gen_range(0..pl.len());
                    let (encoded, primitives) = (pl[idx].encoder)(&data);
                    data = encoded;
                    layer_prims.push(primitives);
                }
                layer_prims.reverse();
                let mut b_data = data;
                let mut aux = Vec::new();
                for primitives in layer_prims {
                    for p in primitives {
                        match p {
                            Primitive::Map(alphabet) => {
                                let mut map = [255u8; 256];
                                for (j, &c) in alphabet.iter().enumerate() { map[c as usize] = j as u8; }
                                let mut out = Vec::new();
                                for &b in &b_data { let v = map[b as usize]; if v != 255 { out.push(v); } }
                                b_data = out;
                            },
                            Primitive::BitLoad { .. } | Primitive::BaseLoad { .. } => {
                                aux.extend_from_slice(&b_data);
                                b_data.clear();
                            },
                            Primitive::BitEmit { bits, total_bits } => {
                                b_data = decode_bits_manual(&aux, bits, total_bits);
                                aux.clear();
                            },
                            Primitive::BitUnpack { bits, total_bits } => {
                                b_data = decode_bits_manual(&b_data, bits, total_bits);
                            },
                            Primitive::BaseEmit { base, in_c, out_c, total_bytes } => {
                                b_data = decode_z85_manual(&aux, base, in_c, out_c, total_bytes);
                                aux.clear();
                            },
                            Primitive::BigIntInit => {
                                aux.clear();
                                aux.extend_from_slice(&0u32.to_ne_bytes());
                            },
                            Primitive::BigIntPush { base, use_be } => {
                                let mut res = Vec::new();
                                let mut lz = 0;
                                if aux.len() >= 8 {
                                    for chunk in aux[8..].chunks_exact(4) {
                                        let mut bytes = [0u8; 4];
                                        bytes.copy_from_slice(chunk);
                                        res.push(if use_be { u32::from_be_bytes(bytes) } else { u32::from_ne_bytes(bytes) });
                                    }
                                } else {
                                    for chunk in aux.chunks_exact(4) {
                                        let mut bytes = [0u8; 4];
                                        bytes.copy_from_slice(chunk);
                                        res.push(if use_be { u32::from_be_bytes(bytes) } else { u32::from_ne_bytes(bytes) });
                                    }
                                }
                                for &v in &b_data { if v == 0 { lz += 1; } else { break; } }
                                for &v in &b_data[lz..] {
                                    let mut carry = v as u64;
                                    for digit in res.iter_mut() {
                                        let prod = (*digit as u64) * (base as u64) + carry;
                                        *digit = prod as u32;
                                        carry = prod >> 32;
                                    }
                                    while carry > 0 { res.push(carry as u32); carry >>= 32; }
                                }
                                aux.clear();
                                aux.extend_from_slice(&(lz as u64).to_ne_bytes());
                                for val in res {
                                    let b = if use_be { val.to_be_bytes() } else { val.to_ne_bytes() };
                                    aux.extend_from_slice(&b);
                                }
                            },
                            Primitive::BigIntEmit { use_be, .. } => {
                                if aux.len() >= 8 {
                                    let mut lz_bytes = [0u8; 8];
                                    lz_bytes.copy_from_slice(&aux[0..8]);
                                    let lz = u64::from_ne_bytes(lz_bytes) as usize;
                                    let mut res = Vec::new();
                                    for chunk in aux[8..].chunks_exact(4) {
                                        let mut bytes = [0u8; 4];
                                        bytes.copy_from_slice(chunk);
                                        res.push(if use_be { u32::from_be_bytes(bytes) } else { u32::from_ne_bytes(bytes) });
                                    }
                                    let mut out = vec![0u8; lz];
                                    let rl = res.len();
                                    if !(res.len() == 1 && res[0] == 0) || (aux.len() - 8) / 4 == lz {
                                        let mut bytes_out = Vec::new();
                                        for (idx, &val) in res.iter().enumerate().rev() {
                                            let bytes = val.to_be_bytes();
                                            if idx == rl - 1 {
                                                 let mut skip = 0;
                                                 while skip < 4 && bytes[skip] == 0 { skip += 1; }
                                                 bytes_out.extend_from_slice(&bytes[skip..]);
                                            } else { bytes_out.extend_from_slice(&bytes); }
                                        }
                                        out.extend(bytes_out);
                                    }
                                    b_data = out;
                                } else { b_data = Vec::new(); }
                                aux.clear();
                            },
                            Primitive::BigIntDecode { base, .. } => {
                                let mut res = vec![0u32; 0];
                                let mut lz = 0;
                                for &v in &b_data { if v == 0 { lz += 1; } else { break; } }
                                for &v in &b_data[lz..] {
                                    let mut carry = v as u64;
                                    for digit in res.iter_mut() {
                                        let prod = (*digit as u64) * (base as u64) + carry;
                                        *digit = prod as u32;
                                        carry = prod >> 32;
                                    }
                                    while carry > 0 { res.push(carry as u32); carry >>= 32; }
                                }
                                let mut out = vec![0u8; lz];
                                let rl = res.len();
                                if rl > 0 {
                                    for (idx, &val) in res.iter().enumerate().rev() {
                                        let bytes = val.to_be_bytes();
                                        if idx == rl - 1 {
                                             let mut skip = 0;
                                             while skip < 4 && bytes[skip] == 0 { skip += 1; }
                                             out.extend_from_slice(&bytes[skip..]);
                                        } else { out.extend_from_slice(&bytes); }
                                    }
                                }
                                b_data = out;
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