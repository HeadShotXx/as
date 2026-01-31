extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};

#[derive(Clone, Debug)]
enum MapVariant { Simple, Xor, Split, Shuffled }

#[derive(Clone, Debug)]
enum Primitive {
    Map { alphabet: Vec<u8>, variant: MapVariant },
    BitLoad,
    BitEmit { bits: u32, total_bits: u64 },
    BaseLoad,
    BaseEmit { base: u128, in_c: usize, out_c: usize, total_bytes: u64 },
    BigIntInit,
    BigIntPush { base: u128 },
    BigIntEmit { total_bytes: u64 },
    Noop { val: u32 },
    Sync,
    XorNoise { val: u8 },
}

struct Pipeline {
    encoder: Box<dyn Fn(&[u8]) -> (Vec<u8>, Vec<Primitive>)>,
}

fn encode_bits(data: &[u8], bits: u32, alphabet: &[u8]) -> (Vec<u8>, u64) {
    let mut out = Vec::new();
    let (mut acc, mut count) = (0u128, 0u32);
    for &b in data {
        acc = (acc << 8) | (b as u128);
        count += 8;
        while count >= bits {
            count -= bits;
            out.push(alphabet[((acc >> count) & ((1 << bits) - 1)) as usize]);
            acc &= (1 << count) - 1;
        }
    }
    if count > 0 { out.push(alphabet[((acc << (bits - count)) & ((1 << bits) - 1)) as usize]); }
    (out, data.len() as u64 * 8)
}

fn encode_bigint(data: &[u8], base: u128, alphabet: &[u8]) -> Vec<u8> {
    let mut lz = 0;
    for &b in data { if b == 0 { lz += 1; } else { break; } }
    let mut res = Vec::new();
    let mut bytes = data[lz..].to_vec();
    while !bytes.iter().all(|&b| b == 0) {
        let mut rem = 0u64;
        for b in bytes.iter_mut() {
            let val = *b as u64 + (rem * 256);
            *b = (val / base as u64) as u8;
            rem = val % base as u64;
        }
        res.push(alphabet[rem as usize]);
    }
    for _ in 0..lz { res.push(alphabet[0]); }
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
    let b64_alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec();
    let b32_alpha = b"abcdefghijklmnopqrstuvwxyz234567".to_vec();
    let b36_alpha = b"0123456789abcdefghijklmnopqrstuvwxyz".to_vec();
    let z85_alpha = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#".to_vec();

    let b32 = || {
        let alpha = b32_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bits) = encode_bits(data, 5, &alpha);
                (out, vec![
                    Primitive::Map { alphabet: alpha.clone(), variant: MapVariant::Simple },
                    Primitive::BitLoad,
                    Primitive::BitEmit { bits: 5, total_bits }
                ])
            }),
        }
    };
    let b36 = || {
        let alpha = b36_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let out = encode_bigint(data, 36, &alpha);
                (out, vec![
                    Primitive::Map { alphabet: alpha.clone(), variant: MapVariant::Simple },
                    Primitive::BigIntInit,
                    Primitive::BigIntPush { base: 36 },
                    Primitive::BigIntEmit { total_bytes: data.len() as u64 }
                ])
            }),
        }
    };
    let b64 = || {
        let alpha = b64_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bits) = encode_bits(data, 6, &alpha);
                (out, vec![
                    Primitive::Map { alphabet: alpha.clone(), variant: MapVariant::Simple },
                    Primitive::BitLoad,
                    Primitive::BitEmit { bits: 6, total_bits }
                ])
            }),
        }
    };
    let z85 = || {
        let alpha = z85_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let (out, total_bytes) = encode_z85_custom(data, &alpha);
                (out, vec![
                    Primitive::Map { alphabet: alpha.clone(), variant: MapVariant::Simple },
                    Primitive::BaseLoad,
                    Primitive::BaseEmit { base: 85, in_c: 5, out_c: 4, total_bytes }
                ])
            }),
        }
    };
    let b91 = || {
        let mut b91_alpha = Vec::new();
        for i in 33..127u8 { if i != b'\"' && i != b'\'' && i != b'\\' { b91_alpha.push(i); } }
        let alpha = b91_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let out = encode_bigint(data, alpha.len() as u128, &alpha);
                (out, vec![
                    Primitive::Map { alphabet: alpha.clone(), variant: MapVariant::Simple },
                    Primitive::BigIntInit,
                    Primitive::BigIntPush { base: alpha.len() as u128 },
                    Primitive::BigIntEmit { total_bytes: data.len() as u64 }
                ])
            }),
        }
    };
    vec![b32(), b36(), b64(), z85(), b91()]
}

fn compute_entropy(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| {
        acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555
    })
}

fn generate_storage_setup(rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
        0 => quote! {
            #[derive(Clone)]
            struct Storage(Vec<u8>);
            impl Storage {
                fn new() -> Self { Self(Vec::new()) }
                fn with_capacity(c: usize) -> Self { Self(Vec::with_capacity(c)) }
                fn push(&mut self, b: u8) { self.0.push(b); }
                fn len(&self) -> usize { self.0.len() }
                fn is_empty(&self) -> bool { self.0.is_empty() }
                fn clear(&mut self) { self.0.clear(); }
                fn get(&self, i: usize) -> u8 { self.0[i] }
                fn set(&mut self, i: usize, v: u8) { self.0[i] = v; }
                fn iter(&self) -> impl Iterator<Item = u8> + '_ { self.0.iter().copied() }
                fn extend_from_slice(&mut self, s: &[u8]) { self.0.extend_from_slice(s); }
                fn from_vec(v: Vec<u8>) -> Self { Self(v) }
                fn to_vec(&self) -> Vec<u8> { self.0.clone() }
                fn compute_entropy(&self) -> u32 {
                    self.0.iter().fold(0u32, |acc, &b| {
                        acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555
                    })
                }
            }
        },
        _ => quote! {
            #[derive(Clone)]
            struct Storage { inner: Vec<u32>, len: usize }
            impl Storage {
                fn new() -> Self { Self { inner: Vec::new(), len: 0 } }
                fn with_capacity(c: usize) -> Self { Self { inner: Vec::with_capacity((c + 3) / 4), len: 0 } }
                fn push(&mut self, b: u8) {
                    let w_idx = self.len / 4; let b_idx = self.len % 4;
                    if b_idx == 0 { self.inner.push(0); }
                    self.inner[w_idx] |= (b as u32) << (b_idx * 8);
                    self.len += 1;
                }
                fn len(&self) -> usize { self.len }
                fn is_empty(&self) -> bool { self.len == 0 }
                fn clear(&mut self) { self.inner.clear(); self.len = 0; }
                fn get(&self, i: usize) -> u8 {
                    let word = self.inner[i / 4];
                    ((word >> ((i % 4) * 8)) & 0xff) as u8
                }
                fn set(&mut self, i: usize, v: u8) {
                    let w_idx = i / 4; let b_idx = i % 4;
                    let mut word = self.inner[w_idx];
                    word &= !(0xff << (b_idx * 8));
                    word |= (v as u32) << (b_idx * 8);
                    self.inner[w_idx] = word;
                }
                fn iter(&self) -> impl Iterator<Item = u8> + '_ { (0..self.len).map(move |i| self.get(i)) }
                fn extend_from_slice(&mut self, s: &[u8]) { for &b in s { self.push(b); } }
                fn from_vec(v: Vec<u8>) -> Self { let mut s = Self::with_capacity(v.len()); s.extend_from_slice(&v); s }
                fn to_vec(&self) -> Vec<u8> { self.iter().collect() }
                fn compute_entropy(&self) -> u32 {
                    (0..self.len).fold(0u32, |acc, i| {
                        let b = self.get(i);
                        acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555
                    })
                }
            }
        }
    }
}

fn generate_obfuscated_map(alphabet: &[u8], variant: &MapVariant, rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    match variant {
        MapVariant::Xor => {
            let key = rng.gen::<u8>();
            let enc: Vec<u8> = map.iter().map(|&b| if b == 255 { 255 } else { b ^ key }).collect();
            let enc_lit = Literal::byte_string(&enc);
            quote! {
                let mut out = Storage::with_capacity(data.len());
                let m = #enc_lit;
                for b in data.iter() {
                    let v = m[b as usize];
                    if v != 255 { out.push(v ^ #key); }
                }
                *data = out;
            }
        },
        MapVariant::Split => {
            let h1 = Literal::byte_string(&map[0..128]);
            let h2 = Literal::byte_string(&map[128..256]);
            quote! {
                let mut out = Storage::with_capacity(data.len());
                let (h1, h2) = (#h1, #h2);
                for b in data.iter() {
                    let v = if b < 128 { h1[b as usize] } else { h2[b as usize - 128] };
                    if v != 255 { out.push(v); }
                }
                *data = out;
            }
        },
        MapVariant::Shuffled => {
            let mut shuffled_alpha = alphabet.to_vec();
            let mut indices: Vec<usize> = (0..alphabet.len()).collect();
            for i in (1..indices.len()).rev() {
                let j = rng.gen_range(0..=i);
                indices.swap(i, j); shuffled_alpha.swap(i, j);
            }
            let mut rev_map = vec![255u8; 256];
            for (i, &idx) in indices.iter().enumerate() { rev_map[i] = idx as u8; }
            let alpha_lit = Literal::byte_string(&shuffled_alpha);
            let rev_lit = Literal::byte_string(&rev_map);
            quote! {
                let mut out = Storage::with_capacity(data.len());
                let (alpha, rev) = (#alpha_lit, #rev_lit);
                for b in data.iter() {
                    if let Some(pos) = alpha.iter().position(|&s| s == b) { out.push(rev[pos]); }
                }
                *data = out;
            }
        },
        _ => {
            let map_lit = Literal::byte_string(&map);
            quote! {
                let mut out = Storage::with_capacity(data.len());
                let m = #map_lit;
                for b in data.iter() {
                    let v = m[b as usize]; if v != 255 { out.push(v); }
                }
                *data = out;
            }
        }
    }
}

fn generate_bit_emit(bits: u32, total_bits: u64, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
        0 => quote! {
            let mut out = Storage::new();
            let (mut acc, mut count, mut bc) = (0u128, 0u32, 0u64);
            for v in aux.iter() {
                acc = (acc << #bits) | (v as u128);
                count += #bits;
                while count >= 8 {
                    count -= 8;
                    if bc < #total_bits { out.push((acc >> count) as u8); bc += 8; }
                    acc &= (1 << count) - 1;
                }
            }
            *data = out; aux.clear();
        },
        _ => quote! {
            let (mut acc, mut count, mut bc) = (0u128, 0u32, 0u64);
            let mut out_v = Vec::new();
            for v in aux.iter() {
                acc = (acc << #bits) | (v as u128);
                count += #bits;
                while count >= 8 {
                    count -= 8;
                    if bc < #total_bits { out_v.push((acc >> count) as u8); bc += 8; }
                    acc &= (1 << count) - 1;
                }
            }
            *data = Storage::from_vec(out_v); aux.clear();
        }
    }
}

fn generate_base_emit(base: u128, in_c: usize, out_c: usize, total_bytes: u64) -> TokenStream2 {
    quote! {
        let mut out = Storage::new();
        let mut len_v = 0u64;
        let av = aux.to_vec();
        for chunk in av.chunks(#in_c) {
            if chunk.len() < #in_c { continue; }
            let mut v = 0u128;
            for &c in chunk { v = v * #base + (c as u128); }
            for i in (0..#out_c).rev() {
                if len_v < #total_bytes { out.push(((v >> (i * 8)) & 0xff) as u8); len_v += 1; }
            }
        }
        *data = out; aux.clear();
    }
}

fn generate_bigint_push(base: u128) -> TokenStream2 {
    quote! {
        let dv = data.to_vec();
        let mut lz = 0;
        for &v in &dv { if v == 0 { lz += 1; } else { break; } }
        let av = aux.to_vec();
        let mut res = Vec::new();
        let skip = if av.len() >= 8 { 8 } else { 0 };
        for chunk in av[skip..].chunks_exact(4) {
            let mut b = [0u8; 4]; b.copy_from_slice(chunk);
            res.push(u32::from_ne_bytes(b));
        }
        for &v in &dv[lz..] {
            let mut carry = v as u64;
            for digit in res.iter_mut() {
                let prod = (*digit as u64) * (#base as u64) + carry;
                *digit = prod as u32; carry = prod >> 32;
            }
            while carry > 0 { res.push(carry as u32); carry >>= 32; }
        }
        aux.clear();
        aux.extend_from_slice(&(lz as u64).to_ne_bytes());
        for val in res { aux.extend_from_slice(&val.to_ne_bytes()); }
    }
}

fn generate_bigint_emit() -> TokenStream2 {
    quote! {
        if aux.len() >= 8 {
            let av = aux.to_vec();
            let mut lz_b = [0u8; 8]; lz_b.copy_from_slice(&av[0..8]);
            let lz = u64::from_ne_bytes(lz_b) as usize;
            let mut res = Vec::new();
            for chunk in av[8..].chunks_exact(4) {
                let mut b = [0u8; 4]; b.copy_from_slice(chunk);
                res.push(u32::from_ne_bytes(b));
            }
            let mut out = vec![0u8; lz];
            if !(res.len() == 1 && res[0] == 0) || (av.len() - 8) / 4 == lz {
                let mut bo = Vec::new();
                let rl = res.len();
                for (i, &v) in res.iter().enumerate().rev() {
                    let b = v.to_be_bytes();
                    if i == rl - 1 {
                        let mut s = 0; while s < 4 && b[s] == 0 { s += 1; }
                        bo.extend_from_slice(&b[s..]);
                    } else { bo.extend_from_slice(&b); }
                }
                out.extend(bo);
            }
            *data = Storage::from_vec(out);
        } else { *data = Storage::new(); }
        aux.clear();
    }
}

fn transform_pipeline(prims: Vec<Primitive>, rng: &mut impl Rng) -> Vec<Primitive> {
    let mut out = Vec::new();
    for p in prims {
        match p {
            Primitive::Map { alphabet, .. } => {
                let variant = match rng.gen_range(0..4) {
                    0 => MapVariant::Simple, 1 => MapVariant::Xor, 2 => MapVariant::Split, _ => MapVariant::Shuffled,
                };
                out.push(Primitive::Map { alphabet, variant });
            },
            _ => out.push(p),
        }
    }
    if rng.gen_bool(0.3) {
        let v = rng.gen::<u8>();
        out.push(Primitive::XorNoise { val: v });
        out.push(Primitive::XorNoise { val: v });
    }
    out
}

fn decode_bits_manual(data: &[u8], bits: u32, total_bits: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut count, mut bc) = (0u128, 0u32, 0u64);
    for &v in data {
        acc = (acc << bits) | (v as u128);
        count += bits;
        while count >= 8 {
            count -= 8;
            if bc < total_bits { out.push((acc >> count) as u8); bc += 8; }
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
        let mut v = 0u128;
        for &c in chunk { v = v * base + (c as u128); }
        for i in (0..out_c).rev() {
            if len_v < total_bytes { out.push(((v >> (i * 8)) & 0xff) as u8); len_v += 1; }
        }
    }
    out
}

fn decode_bigint_manual_from_aux(aux: &[u8]) -> Vec<u8> {
    if aux.len() < 8 { return Vec::new(); }
    let mut lz_b = [0u8; 8]; lz_b.copy_from_slice(&aux[0..8]);
    let lz = u64::from_ne_bytes(lz_b) as usize;
    let mut res = Vec::new();
    for chunk in aux[8..].chunks_exact(4) {
        let mut b = [0u8; 4]; b.copy_from_slice(chunk);
        res.push(u32::from_ne_bytes(b));
    }
    let mut out = vec![0u8; lz];
    if !(res.len() == 1 && res[0] == 0) || (aux.len() - 8) / 4 == lz {
        let mut bo = Vec::new();
        let rl = res.len();
        for (i, &v) in res.iter().enumerate().rev() {
            let b = v.to_be_bytes();
            if i == rl - 1 {
                let mut s = 0; while s < 4 && b[s] == 0 { s += 1; }
                bo.extend_from_slice(&b[s..]);
            } else { bo.extend_from_slice(&b); }
        }
        out.extend(bo);
    }
    out
}

fn simulate_primitive(p: &Primitive, b_data: &mut Vec<u8>, aux: &mut Vec<u8>) {
    match p {
        Primitive::Map { alphabet, .. } => {
            let mut map = [255u8; 256];
            for (j, &c) in alphabet.iter().enumerate() { map[c as usize] = j as u8; }
            let mut out = Vec::new();
            for &b in &*b_data { let v = map[b as usize]; if v != 255 { out.push(v); } }
            *b_data = out;
        },
        Primitive::BitLoad | Primitive::BaseLoad => { aux.extend_from_slice(&b_data); b_data.clear(); },
        Primitive::BitEmit { bits, total_bits } => { *b_data = decode_bits_manual(&aux, *bits, *total_bits); aux.clear(); },
        Primitive::BaseEmit { base, in_c, out_c, total_bytes } => { *b_data = decode_z85_manual(&aux, *base, *in_c, *out_c, *total_bytes); aux.clear(); },
        Primitive::BigIntInit => { aux.clear(); aux.extend_from_slice(&0u32.to_ne_bytes()); },
        Primitive::BigIntPush { base } => {
            let (mut res, mut lz) = (Vec::new(), 0);
            let skip = if aux.len() >= 8 { 8 } else { 0 };
            for chunk in aux[skip..].chunks_exact(4) {
                let mut b = [0u8; 4]; b.copy_from_slice(chunk);
                res.push(u32::from_ne_bytes(b));
            }
            for &v in &*b_data { if v == 0 { lz += 1; } else { break; } }
            for &v in &b_data[lz..] {
                let mut carry = v as u64;
                for digit in res.iter_mut() {
                    let prod = (*digit as u64) * (*base as u64) + carry;
                    *digit = prod as u32; carry = prod >> 32;
                }
                while carry > 0 { res.push(carry as u32); carry >>= 32; }
            }
            aux.clear(); aux.extend_from_slice(&(lz as u64).to_ne_bytes());
            for val in res { aux.extend_from_slice(&val.to_ne_bytes()); }
        },
        Primitive::BigIntEmit { .. } => { *b_data = decode_bigint_manual_from_aux(&aux); aux.clear(); },
        Primitive::XorNoise { val } => { for b in b_data.iter_mut() { *b ^= val; } },
        _ => {}
    }
}

fn apply_scramble_compile(data: &mut Vec<u8>, seed: u32) {
    let mut s = seed;
    for b in data.iter_mut() {
        s = s.wrapping_mul(1103515245).wrapping_add(12345);
        *b = b.wrapping_add((s & 0x3) as u8);
    }
}
fn apply_unscramble_compile(data: &mut Vec<u8>, seed: u32) {
    let mut s = seed;
    for b in data.iter_mut() {
        s = s.wrapping_mul(1103515245).wrapping_add(12345);
        *b = b.wrapping_sub((s & 0x3) as u8);
    }
}
fn apply_corr_compile(data: &mut Vec<u8>, seed: u32) {
    for (i, b) in data.iter_mut().enumerate() { *b = b.wrapping_add((i as u32 ^ seed) as u8); }
}
fn apply_uncorr_compile(data: &mut Vec<u8>, seed: u32) {
    for (i, b) in data.iter_mut().enumerate() { *b = b.wrapping_sub((i as u32 ^ seed) as u8); }
}
fn apply_lock_compile(data: &mut Vec<u8>, rs: u32, seed: u32) {
    let k = rs ^ seed ^ (rs >> 16);
    for b in data.iter_mut() { *b = b.wrapping_add((k & 0xff) as u8) ^ ((k >> 8) & 0xff) as u8; }
}
fn apply_unlock_compile(data: &mut Vec<u8>, rs: u32, seed: u32) {
    let k = rs ^ seed ^ (rs >> 16);
    for b in data.iter_mut() { *b = (*b ^ ((k >> 8) & 0xff) as u8).wrapping_sub((k & 0xff) as u8); }
}

fn generate_junk_logic(rng: &mut impl Rng, rs_var: Option<&Ident>, rs_compile: &mut u32) -> TokenStream2 {
    let mut code = Vec::new();
    if let Some(rsv) = rs_var {
        let val = rng.gen::<u32>(); *rs_compile ^= val;
        code.push(quote! { #rsv ^= #val; });
    }
    quote! { #(#code)* }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let os = lit_str.value();
    let mut rng = thread_rng();
    let pl = get_pipelines();
    let mut cd = os.clone().into_bytes();
    let mut layers_data = Vec::new();
    for _ in 0..3 {
        let (encoded, primitives) = (pl[rng.gen_range(0..pl.len())].encoder)(&cd);
        cd = encoded;
        let (s_sc, s_cr) = (rng.gen::<u32>(), rng.gen::<u32>());
        apply_scramble_compile(&mut cd, s_sc);
        apply_corr_compile(&mut cd, s_cr);
        layers_data.push((s_sc, s_cr, transform_pipeline(primitives, &mut rng)));
    }
    layers_data.reverse();
    let (lock_seed, salt, mult) = (rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>() | 1);
    let (mut vt_c, mut rids) = (Vec::new(), Vec::new());
    let mut cd_sim = cd.clone();
    let mut rs_sim = 0u32;
    apply_lock_compile(&mut cd_sim, 0, lock_seed); // eb = Initial Locked Encoded Data

    for (s_sc, s_cr, primitives) in layers_data {
        let id = rng.gen::<u32>();
        let rs_in_compile = rs_sim;
        let mut arm_code = Vec::new();
        arm_code.push(quote! {
            {
                let k = rs_in ^ #lock_seed ^ (rs_in >> 16);
                for i in 0..data.len() {
                    let b = data.get(i); data.set(i, (b ^ ((k >> 8) & 0xff) as u8).wrapping_sub((k & 0xff) as u8));
                }
            }
            for i in 0..data.len() { let b = data.get(i); data.set(i, b.wrapping_sub((i as u32 ^ #s_cr) as u8)); }
            {
                let mut s = #s_sc;
                for i in 0..data.len() {
                    s = s.wrapping_mul(1103515245).wrapping_add(12345);
                    let b = data.get(i); data.set(i, b.wrapping_sub((s & 0x3) as u8));
                }
            }
        });
        apply_unlock_compile(&mut cd_sim, rs_sim, lock_seed);
        apply_uncorr_compile(&mut cd_sim, s_cr);
        apply_unscramble_compile(&mut cd_sim, s_sc);
        let mut aux_sim = Vec::new();
        for p in &primitives {
            arm_code.push(match p {
                Primitive::Map { alphabet, variant } => generate_obfuscated_map(alphabet, variant, &mut rng),
                Primitive::BitLoad => quote! { aux.extend_from_slice(&data.to_vec()); data.clear(); },
                Primitive::BitEmit { bits, total_bits } => generate_bit_emit(*bits, *total_bits, &mut rng),
                Primitive::BaseLoad => quote! { aux.extend_from_slice(&data.to_vec()); data.clear(); },
                Primitive::BaseEmit { base, in_c, out_c, total_bytes } => generate_base_emit(*base, *in_c, *out_c, *total_bytes),
                Primitive::BigIntInit => quote! { aux.clear(); aux.extend_from_slice(&0u32.to_ne_bytes()); },
                Primitive::BigIntPush { base } => generate_bigint_push(*base),
                Primitive::BigIntEmit { .. } => generate_bigint_emit(),
                Primitive::Noop { val } => quote! { let _ = #val; },
                Primitive::Sync => quote! { { let _ = &data; } },
                Primitive::XorNoise { val } => quote! { for i in 0..data.len() { let b = data.get(i); data.set(i, b ^ #val); } },
            });
            simulate_primitive(p, &mut cd_sim, &mut aux_sim);
        }
        let rsv = Ident::new("rs", Span::call_site());
        rs_sim = rs_sim.wrapping_add(id).rotate_left(5);
        let junk = generate_junk_logic(&mut rng, Some(&rsv), &mut rs_sim);
        rs_sim ^= compute_entropy(&cd_sim);
        apply_lock_compile(&mut cd_sim, rs_sim, lock_seed);
        arm_code.push(quote! {
            rs = rs.wrapping_add(#id).rotate_left(5);
            #junk
            rs ^= data.compute_entropy();
            {
                let k = rs ^ #lock_seed ^ (rs >> 16);
                for i in 0..data.len() {
                    let b = data.get(i); data.set(i, b.wrapping_add((k & 0xff) as u8) ^ ((k >> 8) & 0xff) as u8);
                }
            }
        });
        let arm_key = (id ^ rs_in_compile).wrapping_mul(mult) ^ salt;
        vt_c.push(quote! { #arm_key => { let mut rs = rs_in; #(#arm_code)* rs } });
        rids.push(id);
    }
    // Wait, if cd_sim has locks, and I want eb to be cd locked with 0.
    let mut eb_locked = cd.clone();
    apply_lock_compile(&mut eb_locked, 0, lock_seed);

    let (s_n, m_n, i_v, a_v) = (Ident::new(&format!("O_{}", rng.gen::<u32>()), Span::call_site()), Ident::new(&format!("r_{}", rng.gen::<u32>()), Span::call_site()), Ident::new("ds", Span::call_site()), Ident::new("aux", Span::call_site()));
    let storage_setup = generate_storage_setup(&mut rng);
    let el = Literal::byte_string(&eb_locked);
    let expanded = quote! {{
        struct #s_n<'a> { d: &'a [u8] }
        impl<'a> #s_n<'a> {
            fn #m_n(&mut self) -> String {
                #storage_setup
                let mut #i_v = Storage::from_vec(self.d.to_vec());
                let mut #a_v = Storage::new();
                let mut rs = 0u32;
                for &id in &[#(#rids),*] {
                    let rs_in = rs;
                    let data = &mut #i_v; let aux = &mut #a_v;
                    rs = match (id ^ rs_in).wrapping_mul(#mult) ^ #salt {
                        #(#vt_c)*
                        _ => rs_in
                    };
                }
                let k = rs ^ #lock_seed ^ (rs >> 16);
                let mut o = Vec::new();
                for i in 0..#i_v.len() {
                    let b = #i_v.get(i);
                    o.push((b ^ ((k >> 8) & 0xff) as u8).wrapping_sub((k & 0xff) as u8));
                }
                o.iter().map(|&b| b as char).collect()
            }
        }
        let mut inst = #s_n { d: #el }; inst.#m_n()
    }};
    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_random_pipelines() {
        let mut rng = thread_rng();
        let originals = vec![b"Simple Calculator".to_vec(), vec![0, 1, 2, 3], b"A".to_vec(), b"".to_vec()];
        let pl = get_pipelines();
        for original in originals {
            for _ in 0..50 {
                let mut data = original.clone();
                let mut layer_prims = Vec::new();
                for _ in 0..3 {
                    let idx = rng.gen_range(0..pl.len());
                    let (encoded, primitives) = (pl[idx].encoder)(&data);
                    data = encoded;
                    layer_prims.push(transform_pipeline(primitives, &mut rng));
                }
                layer_prims.reverse();
                let (mut b_data, mut aux) = (data, Vec::new());
                for primitives in layer_prims { for p in primitives { simulate_primitive(&p, &mut b_data, &mut aux); } }
                assert_eq!(b_data, original);
            }
        }
    }
}
