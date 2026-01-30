extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};

#[derive(Clone, Debug)]
enum Primitive {
    Map(Vec<u8>),
    BitLoad { _bits: u32 },
    BitEmit { bits: u32, total_bits: u64 },
    BaseLoad { _base: u128, _in_c: usize },
    BaseEmit { base: u128, in_c: usize, out_c: usize, total_bytes: u64 },
    BigIntInit,
    BigIntPush { base: u128 },
    BigIntEmit { total_bytes: u64 },
    Noop { val: u32 },
    Sync,
    MappedBitLoad { table: Vec<u8> },
    MappedBaseLoad { table: Vec<u8> },
    BitLoadPart { start_pct: usize, end_pct: usize },
    // Reversible Noise Primitives
    XorNoise { val: u8 },
    AddNoise { val: u8 },
    SubNoise { val: u8 },
    RotNoise { val: u32 },
    // Topology Primitives
    Block(Vec<Primitive>),
    Lock { variant: u32, seed: u32 },
    Unlock { variant: u32, seed: u32 },
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
                let (out, total_bits) = encode_bits(data, 5, &alpha);
                (out, vec![
                    Primitive::Map(alpha.clone()),
                    Primitive::BitLoad { _bits: 5 },
                    Primitive::Noop { val: 0x32 },
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
                    Primitive::Map(alpha.clone()),
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
                    Primitive::Map(alpha.clone()),
                    Primitive::BitLoad { _bits: 6 },
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
                    Primitive::Map(alpha.clone()),
                    Primitive::BaseLoad { _base: 85, _in_c: 5 },
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
                let out = encode_bigint(data, 91, &alpha);
                (out, vec![
                    Primitive::Map(alpha.clone()),
                    Primitive::BigIntInit,
                    Primitive::BigIntPush { base: 91 },
                    Primitive::BigIntEmit { total_bytes: data.len() as u64 }
                ])
            }),
        }
    };

    vec![b32(), b36(), b64(), z85(), b91()]
}

// --- HELPERS ---

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

fn simulate_primitive(p: &Primitive, b_data: &mut Vec<u8>, aux: &mut Vec<u8>) {
    match p {
        Primitive::Map(alphabet) => {
            let mut map = [255u8; 256];
            for (j, &c) in alphabet.iter().enumerate() { map[c as usize] = j as u8; }
            let mut out = Vec::new();
            for &b in &*b_data { let v = map[b as usize]; if v != 255 { out.push(v); } }
            *b_data = out;
        },
        Primitive::BitLoad { .. } | Primitive::BaseLoad { .. } => {
            aux.extend_from_slice(&b_data);
            b_data.clear();
        },
        Primitive::MappedBitLoad { table } | Primitive::MappedBaseLoad { table } => {
            let mut map = [255u8; 256];
            for (j, &c) in table.iter().enumerate() { map[c as usize] = j as u8; }
            for &b in &*b_data {
                let v = map[b as usize];
                if v != 255 { aux.push(v); }
            }
            b_data.clear();
        },
        Primitive::BitEmit { bits, total_bits } => {
            *b_data = decode_bits_manual(&aux, *bits, *total_bits);
            aux.clear();
        },
        Primitive::BitLoadPart { start_pct, end_pct } => {
            let start = b_data.len() * start_pct / 100;
            let end = b_data.len() * end_pct / 100;
            aux.extend_from_slice(&b_data[start..end]);
            if *end_pct == 100 { b_data.clear(); }
        },
        Primitive::XorNoise { val } => {
            for b in b_data.iter_mut() { *b ^= val; }
        },
        Primitive::AddNoise { val } => {
            for b in b_data.iter_mut() { *b = b.wrapping_add(*val); }
        },
        Primitive::SubNoise { val } => {
            for b in b_data.iter_mut() { *b = b.wrapping_sub(*val); }
        },
        Primitive::RotNoise { val } => {
            for b in b_data.iter_mut() { *b = b.rotate_left(*val); }
        },
        Primitive::Block(inner) => {
            for ip in inner { simulate_primitive(ip, b_data, aux); }
        }
        Primitive::BaseEmit { base, in_c, out_c, total_bytes } => {
            *b_data = decode_z85_manual(&aux, *base, *in_c, *out_c, *total_bytes);
            aux.clear();
        },
        Primitive::BigIntInit => {
            aux.clear();
            aux.extend_from_slice(&0u32.to_ne_bytes());
        },
        Primitive::BigIntPush { base } => {
            let mut res = Vec::new();
            let mut lz = 0;
            if aux.len() >= 8 {
                for chunk in aux[8..].chunks_exact(4) {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(chunk);
                    res.push(u32::from_ne_bytes(bytes));
                }
            } else {
                for chunk in aux.chunks_exact(4) {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(chunk);
                    res.push(u32::from_ne_bytes(bytes));
                }
            }
            for &v in &*b_data { if v == 0 { lz += 1; } else { break; } }
            for &v in &b_data[lz..] {
                let mut carry = v as u64;
                for digit in res.iter_mut() {
                    let prod = (*digit as u64) * (*base as u64) + carry;
                    *digit = prod as u32;
                    carry = prod >> 32;
                }
                while carry > 0 { res.push(carry as u32); carry >>= 32; }
            }
            aux.clear();
            aux.extend_from_slice(&(lz as u64).to_ne_bytes());
            for val in res { aux.extend_from_slice(&val.to_ne_bytes()); }
        },
        Primitive::BigIntEmit { .. } => {
            *b_data = decode_bigint_manual_from_aux(&aux);
            aux.clear();
        },
        Primitive::Lock { .. } => {
        },
        Primitive::Unlock { .. } => {
        },
        _ => {}
    }
}

fn compute_entropy(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| {
        acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555
    })
}

// --- PIPELINE MANAGER ---

fn transform_pipeline(primitives: Vec<Primitive>, rng: &mut impl Rng) -> Vec<Primitive> {
    let mut current = primitives;

    // Pass 1: Commutative Reordering (Objective 4)
    let mut i = 0;
    while i + 1 < current.len() {
        let can_swap = match (&current[i], &current[i+1]) {
            (Primitive::Noop { .. }, Primitive::Noop { .. }) => true,
            (Primitive::Sync, Primitive::Noop { .. }) => true,
            (Primitive::Noop { .. }, Primitive::Sync) => true,
            _ => false,
        };
        if can_swap && rng.gen_bool(0.3) {
            current.swap(i, i+1);
            i += 1;
        }
        i += 1;
    }

    // Pass 2: Merging and Splitting
    let mut out = Vec::new();
    let mut i = 0;
    while i < current.len() {
        if i + 1 < current.len() {
            match (&current[i], &current[i+1]) {
                (Primitive::Map(table), Primitive::BitLoad { .. }) => {
                    if rng.gen_bool(0.5) {
                        out.push(Primitive::MappedBitLoad { table: table.clone() });
                        i += 2; continue;
                    }
                },
                (Primitive::Map(table), Primitive::BaseLoad { .. }) => {
                    if rng.gen_bool(0.5) {
                        out.push(Primitive::MappedBaseLoad { table: table.clone() });
                        i += 2; continue;
                    }
                },
                _ => {}
            }
        }
        match &current[i] {
            Primitive::BitLoad { .. } | Primitive::BaseLoad { .. } => {
                if rng.gen_bool(0.4) {
                    out.push(Primitive::BitLoadPart { start_pct: 0, end_pct: 50 });
                    out.push(Primitive::BitLoadPart { start_pct: 50, end_pct: 100 });
                    i += 1; continue;
                }
            },
            _ => {}
        }
        out.push(current[i].clone());
        i += 1;
    }

    // Pass 3: Topology
    if rng.gen_bool(0.3) && out.len() >= 3 {
        let split_at = rng.gen_range(1..out.len()-1);
        let (head, tail) = out.split_at(split_at);
        let mut new_out = head.to_vec();
        new_out.push(Primitive::Block(tail.to_vec()));
        out = new_out;
    }

    // Objective 5: Reversible Math Noise Layer (XOR chains)
    if rng.gen_bool(0.2) {
        let k1 = rng.gen::<u8>();
        let k2 = rng.gen::<u8>();
        let k3 = k1 ^ k2;
        let mut new_out = Vec::new();
        new_out.push(Primitive::XorNoise { val: k1 });
        new_out.push(Primitive::XorNoise { val: k2 });
        new_out.push(Primitive::XorNoise { val: k3 });
        new_out.extend(out);
        out = new_out;
    }

    // Objective 4: Atomic Noise Injection at layer boundaries
    if rng.gen_bool(0.2) {
        let val = rng.gen::<u8>();
        out.push(Primitive::XorNoise { val });
        out.push(Primitive::XorNoise { val });
    }
    if rng.gen_bool(0.1) {
        let val = rng.gen::<u8>();
        out.push(Primitive::AddNoise { val });
        out.push(Primitive::SubNoise { val });
    }
    if rng.gen_bool(0.1) {
        let val = rng.gen_range(1..8);
        out.push(Primitive::RotNoise { val });
        out.push(Primitive::RotNoise { val: 8 - val });
    }

    out
}

// --- STORAGE MANAGER ---

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
                fn chunks(&self, size: usize) -> Vec<Vec<u8>> {
                    self.0.chunks(size).map(|c| c.to_vec()).collect()
                }
                fn compute_entropy(&self) -> u32 {
                    self.0.iter().fold(0u32, |acc, &b| {
                        acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555
                    })
                }
            }
        },
        _ => quote! {
            #[derive(Clone)]
            struct Storage { inner: Vec<u32>, len: usize, }
            impl Storage {
                fn new() -> Self { Self { inner: Vec::new(), len: 0 } }
                fn with_capacity(c: usize) -> Self { Self { inner: Vec::with_capacity((c + 3) / 4), len: 0 } }
                fn push(&mut self, b: u8) {
                    let w_idx = self.len / 4;
                    let b_idx = self.len % 4;
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
                fn chunks(&self, size: usize) -> Vec<Vec<u8>> {
                    self.to_vec().chunks(size).map(|c| c.to_vec()).collect()
                }
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

// --- PRIMITIVES GENERATOR ---

fn generate_primitive_code(p: &Primitive, rng: &mut impl Rng) -> TokenStream2 {
    let rs = Ident::new("rs", Span::call_site());
    match p {
        Primitive::Map(table) => generate_obfuscated_map(table, rng),
        Primitive::BitLoad { _bits: _ } => generate_bit_load(rng),
        Primitive::BitEmit { bits, total_bits } => generate_bit_emit(*bits, *total_bits, rng),
        Primitive::BaseLoad { _base: _, _in_c: _ } => generate_base_load(rng),
        Primitive::BaseEmit { base, in_c, out_c, total_bytes } => generate_base_emit(*base, *in_c, *out_c, *total_bytes, rng),
        Primitive::BigIntInit => generate_bigint_init(rng),
        Primitive::BigIntPush { base } => generate_bigint_push(*base, rng),
        Primitive::BigIntEmit { total_bytes } => generate_bigint_emit(*total_bytes, rng),
        Primitive::Noop { val } => quote! { let _ = #val; },
        Primitive::Sync => quote! { { let _ = &data; } },
        Primitive::MappedBitLoad { table } => generate_mapped_bit_load(table, rng),
        Primitive::MappedBaseLoad { table } => generate_mapped_base_load(table, rng),
        Primitive::BitLoadPart { start_pct, end_pct } => generate_bit_load_part(*start_pct, *end_pct, rng),
        Primitive::XorNoise { val } => quote! {
            {
                let mut dv = data.to_vec();
                for b in dv.iter_mut() { *b ^= #val; }
                *data = Storage::from_vec(dv);
            }
        },
        Primitive::AddNoise { val } => quote! {
            {
                let mut dv = data.to_vec();
                for b in dv.iter_mut() { *b = b.wrapping_add(#val); }
                *data = Storage::from_vec(dv);
            }
        },
        Primitive::SubNoise { val } => quote! {
            {
                let mut dv = data.to_vec();
                for b in dv.iter_mut() { *b = b.wrapping_sub(#val); }
                *data = Storage::from_vec(dv);
            }
        },
        Primitive::RotNoise { val } => quote! {
            {
                let mut dv = data.to_vec();
                for b in dv.iter_mut() { *b = b.rotate_left(#val); }
                *data = Storage::from_vec(dv);
            }
        },
        Primitive::Block(inner) => {
            let mut code = Vec::new();
            for p in inner {
                code.push(generate_primitive_code(p, rng));
            }
            quote! { { #(#code)* } }
        },
        Primitive::Lock { variant, seed } => {
            let k = quote! { (#rs ^ #seed ^ (#rs >> 13) ^ (#rs >> 21)) };
            match variant % 2 {
                0 => quote! {
                    {
                        let mut dv = data.to_vec();
                        let key = #k;
                        for b in dv.iter_mut() {
                            *b = b.wrapping_add((key & 0xff) as u8) ^ ((key >> 8) & 0xff) as u8;
                            *b = b.rotate_left((key >> 16) as u32 % 8);
                        }
                        *data = Storage::from_vec(dv);
                        let e = data.compute_entropy();
                        let mut dv2 = data.to_vec();
                        for b in dv2.iter_mut() { *b ^= (e & 0xff) as u8; }
                        *data = Storage::from_vec(dv2);
                    }
                },
                _ => quote! {
                    {
                        let mut dv = data.to_vec();
                        let key = #k;
                        for b in dv.iter_mut() {
                            *b ^= ((key >> 16) & 0xff) as u8;
                            *b = b.wrapping_sub((key & 0xff) as u8).rotate_right((key >> 8) as u32 % 8);
                        }
                        *data = Storage::from_vec(dv);
                        let e = data.compute_entropy();
                        let mut dv2 = data.to_vec();
                        for b in dv2.iter_mut() { *b = b.wrapping_add(((e >> 8) & 0xff) as u8); }
                        *data = Storage::from_vec(dv2);
                    }
                }
            }
        },
        Primitive::Unlock { variant, seed } => {
            let rs_in = Ident::new("rs_in", Span::call_site());
            let k = quote! { (#rs_in ^ #seed ^ (#rs_in >> 13) ^ (#rs_in >> 21)) };
            match variant % 2 {
                0 => quote! {
                    {
                        let e = data.compute_entropy();
                        let mut dv = data.to_vec();
                        for b in dv.iter_mut() { *b ^= (e & 0xff) as u8; }
                        let key = #k;
                        for b in dv.iter_mut() {
                            *b = b.rotate_right((key >> 16) as u32 % 8);
                            *b = (*b ^ ((key >> 8) & 0xff) as u8).wrapping_sub((key & 0xff) as u8);
                        }
                        *data = Storage::from_vec(dv);
                    }
                },
                _ => quote! {
                    {
                        let e = data.compute_entropy();
                        let mut dv = data.to_vec();
                        for b in dv.iter_mut() { *b = b.wrapping_sub(((e >> 8) & 0xff) as u8); }
                        let key = #k;
                        for b in dv.iter_mut() {
                            *b = b.rotate_left((key >> 8) as u32 % 8).wrapping_add((key & 0xff) as u8);
                            *b ^= ((key >> 16) & 0xff) as u8;
                        }
                        *data = Storage::from_vec(dv);
                    }
                }
            }
        }
    }
}

fn generate_obfuscated_map(alphabet: &[u8], rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    match rng.gen_range(0..3) {
        0 => { // XOR encoded
            let key = rng.gen::<u8>();
            let encoded: Vec<u8> = map.iter().map(|&b| b ^ key).collect();
            let encoded_lit = Literal::byte_string(&encoded);
            quote! {
                let mut out = Storage::with_capacity(data.len());
                let enc = #encoded_lit;
                for b in data.iter() {
                    let v = enc[b as usize] ^ #key;
                    if v != 255 { out.push(v); }
                }
                *data = out;
            }
        },
        1 => { // Split halves
            let h1 = Literal::byte_string(&map[0..128]);
            let h2 = Literal::byte_string(&map[128..256]);
            quote! {
                let mut out = Storage::with_capacity(data.len());
                let h1 = #h1;
                let h2 = #h2;
                for b in data.iter() {
                    let idx = b as usize;
                    let v = if idx < 128 { h1[idx] } else { h2[idx - 128] };
                    if v != 255 { out.push(v); }
                }
                *data = out;
            }
        },
        2 => { // Reversible transform
            let mut a = (rng.gen::<u8>() | 1) as u8;
            let mut b_off = rng.gen::<u8>();
            // Ensure no valid val maps to 255 unless it was already 255
            while map.iter().any(|&v| v != 255 && v.wrapping_mul(a).wrapping_add(b_off) == 255) {
                a = (rng.gen::<u8>() | 1) as u8;
                b_off = rng.gen::<u8>();
            }

            let transformed: Vec<u8> = map.iter().map(|&val| {
                if val == 255 { 255 }
                else { val.wrapping_mul(a).wrapping_add(b_off) }
            }).collect();
            let transformed_lit = Literal::byte_string(&transformed);

            let mut a_inv = 0u8;
            for i in 0..256 {
                if (a as u32 * i as u32) as u8 == 1 {
                    a_inv = i as u8;
                    break;
                }
            }

            quote! {
                let mut out = Storage::with_capacity(data.len());
                let trans = #transformed_lit;
                for b in data.iter() {
                    let tv = trans[b as usize];
                    if tv != 255 {
                        let v = tv.wrapping_sub(#b_off).wrapping_mul(#a_inv);
                        out.push(v);
                    }
                }
                *data = out;
            }
        },
        _ => { // Bit planes reconstruction
            let mut planes = Vec::new();
            let mut indices = Vec::new();
            for p in 0..8 {
                let mut plane = vec![0u8; 32];
                for i in 0..256 {
                    if (map[i] >> p) & 1 == 1 {
                        plane[i / 8] |= 1 << (i % 8);
                    }
                }
                planes.push(Literal::byte_string(&plane));
                indices.push(Literal::u32_unsuffixed(p as u32));
            }
            quote! {
                let mut out = Storage::with_capacity(data.len());
                let mut map_rec = [0u8; 256];
                #(
                    {
                        let plane = #planes;
                        for i in 0..256 {
                            if (plane[i / 8] >> (i % 8)) & 1 == 1 {
                                map_rec[i] |= 1 << #indices;
                            }
                        }
                    }
                )*
                for b in data.iter() {
                    let v = map_rec[b as usize];
                    if v != 255 { out.push(v); }
                }
                *data = out;
            }
        }
    }
}

fn generate_bit_load(_rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.extend_from_slice(&data.to_vec());
        data.clear();
    }
}

fn generate_bit_load_part(start_pct: usize, end_pct: usize, _rng: &mut impl Rng) -> TokenStream2 {
    let is_final = end_pct == 100;
    let clear_data = if is_final { quote! { data.clear(); } } else { quote! {} };
    quote! {
        {
            let dv = data.to_vec();
            let start = dv.len() * #start_pct / 100;
            let end = dv.len() * #end_pct / 100;
            aux.extend_from_slice(&dv[start..end]);
            #clear_data
        }
    }
}

fn generate_mapped_bit_load(table: &[u8], rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in table.iter().enumerate() { map[c as usize] = i as u8; }
    let key = rng.gen::<u8>();
    let enc: Vec<u8> = map.iter().map(|&b| b ^ key).collect();
    let enc_lit = Literal::byte_string(&enc);
    quote! {
        let m = #enc_lit;
        for b in data.iter() {
            let v = m[b as usize] ^ #key;
            if v != 255 { aux.push(v); }
        }
        data.clear();
    }
}

fn generate_mapped_base_load(table: &[u8], _rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in table.iter().enumerate() { map[c as usize] = i as u8; }
    let h1 = Literal::byte_string(&map[0..128]);
    let h2 = Literal::byte_string(&map[128..256]);
    quote! {
        let h1 = #h1;
        let h2 = #h2;
        for b in data.iter() {
            let idx = b as usize;
            let v = if idx < 128 { h1[idx] } else { h2[idx - 128] };
            if v != 255 { aux.push(v); }
        }
        data.clear();
    }
}

fn generate_bit_emit(bits: u32, total_bits: u64, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..4) {
        0 => { // Procedural push
            quote! {
                let mut out = Storage::new();
                let mut acc = 0u128;
                let mut count = 0u32;
                let mut bc = 0u64;
                for v in aux.iter() {
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
                *data = out;
                aux.clear();
            }
        },
        1 => { // Branchless arithmetic version
            let mask = (1u128 << bits) - 1;
            quote! {
                let mut out = Storage::new();
                let mut acc = 0u128;
                let mut count = 0u32;
                let mut bc = 0u64;
                for v in aux.iter() {
                    acc = (acc << #bits) | ((v as u128) & #mask);
                    count += #bits;
                    // Branchless-ish loop unroll for small bit counts
                    for _ in 0..2 {
                        let can_emit = (count >= 8) as u32;
                        let should_emit = (bc < #total_bits) as u32;
                        if can_emit & should_emit != 0 {
                            count -= 8;
                            out.push((acc >> count) as u8);
                            bc += 8;
                            acc &= (1 << count) - 1;
                        }
                    }
                    while count >= 8 {
                        count -= 8;
                        if bc < #total_bits {
                            out.push((acc >> count) as u8);
                            bc += 8;
                        }
                        acc &= (1 << count) - 1;
                    }
                }
                *data = out;
                aux.clear();
            }
        },
        2 => { // Lookup-table based (optimized)
            quote! {
                let mut out = Storage::new();
                let mut acc = 0u128;
                let mut count = 0u32;
                let mut bc = 0u64;
                let lut: [u8; 256] = {
                    let mut l = [0u8; 256];
                    let mut i = 0;
                    while i < 256 { l[i] = i as u8; i += 1; }
                    l
                };
                for v in aux.iter() {
                    acc = (acc << #bits) | (v as u128);
                    count += #bits;
                    while count >= 8 {
                        count -= 8;
                        if bc < #total_bits {
                            let val = (acc >> count) as u8;
                            out.push(lut[val as usize]);
                            bc += 8;
                        }
                        acc &= (1 << count) - 1;
                    }
                }
                *data = out;
                aux.clear();
            }
        },
        _ => { // Functional pull
            quote! {
                let mut acc = 0u128;
                let mut count = 0u32;
                let mut bc = 0u64;
                let out_v: Vec<u8> = aux.iter().flat_map(|v| {
                    acc = (acc << #bits) | (v as u128);
                    count += #bits;
                    let mut res = Vec::new();
                    while count >= 8 {
                        count -= 8;
                        if bc < #total_bits {
                            res.push((acc >> count) as u8);
                            bc += 8;
                        }
                        acc &= (1 << count) - 1;
                    }
                    res
                }).collect();
                *data = Storage::from_vec(out_v);
                aux.clear();
            }
        }
    }
}

fn generate_base_load(_rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.extend_from_slice(&data.to_vec());
        data.clear();
    }
}

fn generate_base_emit(base: u128, in_c: usize, out_c: usize, total_bytes: u64, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..4) {
        0 => { // Chunk-based shift
            quote! {
                let mut out = Storage::new();
                let mut len_v = 0u64;
                let av = aux.to_vec();
                for chunk in av.chunks(#in_c) {
                    if chunk.len() < #in_c { continue; }
                    let mut v = 0u128;
                    for &c in chunk { v = v * #base + (c as u128); }
                    let mut bytes = [0u8; 16];
                    for i in 0..#out_c {
                        bytes[#out_c - 1 - i] = (v & 0xff) as u8;
                        v >>= 8;
                    }
                    for i in 0..#out_c {
                        if len_v < #total_bytes {
                            out.push(bytes[i]);
                            len_v += 1;
                        }
                    }
                }
                *data = out;
                aux.clear();
            }
        },
        1 => { // Reverse accumulation
            quote! {
                let mut out = Storage::new();
                let mut len_v = 0u64;
                let av = aux.to_vec();
                for chunk in av.chunks(#in_c) {
                    if chunk.len() < #in_c { continue; }
                    let mut v = 0u128;
                    for &c in chunk { v = v * #base + (c as u128); }
                    let mut chunk_rev = Vec::with_capacity(#out_c);
                    let mut temp = v;
                    for _ in 0..#out_c {
                        chunk_rev.push((temp & 0xff) as u8);
                        temp >>= 8;
                    }
                    for &b in chunk_rev.iter().rev() {
                        if len_v < #total_bytes {
                            out.push(b);
                            len_v += 1;
                        }
                    }
                }
                *data = out;
                aux.clear();
            }
        },
        2 => { // Division based
            quote! {
                let mut out = Storage::new();
                let mut len_v = 0u64;
                let av = aux.to_vec();
                for chunk in av.chunks(#in_c) {
                    if chunk.len() < #in_c { continue; }
                    let mut v = 0u128;
                    for &c in chunk { v = v * #base + (c as u128); }
                    let mut chunk_out = [0u8; 16];
                    let mut temp_v = v;
                    for i in 0..#out_c {
                        chunk_out[#out_c - 1 - i] = (temp_v % 256) as u8;
                        temp_v /= 256;
                    }
                    for i in 0..#out_c {
                        if len_v < #total_bytes {
                            out.push(chunk_out[i]);
                            len_v += 1;
                        }
                    }
                }
                *data = out;
                aux.clear();
            }
        },
        _ => { // Byte-at-a-time functional pull
             quote! {
                let av = aux.to_vec();
                let mut len_v = 0u64;
                let res: Vec<u8> = av.chunks(#in_c).flat_map(|chunk| {
                    if chunk.len() < #in_c { return Vec::new(); }
                    let mut v = 0u128;
                    for &c in chunk { v = v * #base + (c as u128); }
                    let mut out_chunk = Vec::new();
                    for i in (0..#out_c).rev() {
                        out_chunk.push(((v >> (i * 8)) & 0xff) as u8);
                    }
                    out_chunk
                }).filter(|_| {
                    let ok = len_v < #total_bytes;
                    if ok { len_v += 1; }
                    ok
                }).collect();
                *data = Storage::from_vec(res);
                aux.clear();
            }
        }
    }
}

fn generate_bigint_init(_rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.clear();
        aux.extend_from_slice(&0u32.to_ne_bytes());
    }
}

fn generate_bigint_push(base: u128, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
        0 => { // procedural
            quote! {
                let dv = data.to_vec();
                let mut leading_zeros = 0;
                for &v in &dv { if v == 0 { leading_zeros += 1; } else { break; } }
                let av = aux.to_vec();
                let mut res = Vec::new();
                let skip = if av.len() >= 8 { 8 } else { 0 };
                for chunk in av[skip..].chunks_exact(4) {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(chunk);
                    res.push(u32::from_ne_bytes(bytes));
                }

                for &v in &dv[leading_zeros..] {
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
                let lz = leading_zeros as u64;
                aux.extend_from_slice(&lz.to_ne_bytes());
                for val in res { aux.extend_from_slice(&val.to_ne_bytes()); }
            }
        },
        _ => { // Alternative loop style
            quote! {
                let dv = data.to_vec();
                let mut leading_zeros = 0;
                while leading_zeros < dv.len() && dv[leading_zeros] == 0 {
                    leading_zeros += 1;
                }
                let av = aux.to_vec();
                let skip = if av.len() >= 8 { 8 } else { 0 };
                let mut res: Vec<u32> = av[skip..].chunks_exact(4)
                    .map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();

                for i in leading_zeros..dv.len() {
                    let v = dv[i];
                    let mut carry = v as u64;
                    res.iter_mut().for_each(|digit| {
                        let prod = (*digit as u64) * (#base as u64) + carry;
                        *digit = prod as u32;
                        carry = prod >> 32;
                    });
                    while carry > 0 {
                        res.push(carry as u32);
                        carry >>= 32;
                    }
                }

                aux.clear();
                let lz = leading_zeros as u64;
                aux.extend_from_slice(&lz.to_ne_bytes());
                for val in res {
                    aux.extend_from_slice(&val.to_ne_bytes());
                }
            }
        }
    }
}

fn generate_bigint_emit(_total_bytes: u64, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
        0 => { // Procedural
            quote! {
                if aux.len() >= 8 {
                    let av = aux.to_vec();
                    let mut lz_bytes = [0u8; 8];
                    lz_bytes.copy_from_slice(&av[0..8]);
                    let lz = u64::from_ne_bytes(lz_bytes) as usize;

                    let mut res = Vec::new();
                    for chunk in av[8..].chunks_exact(4) {
                        let mut bytes = [0u8; 4];
                        bytes.copy_from_slice(chunk);
                        res.push(u32::from_ne_bytes(bytes));
                    }

                    let mut out = vec![0u8; lz];
                    if !(res.len() == 1 && res[0] == 0) || (av.len() - 8) / 4 == lz {
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
                        *data = Storage::from_vec(out);
                    } else {
                        *data = Storage::from_vec(out);
                    }
                } else {
                    *data = Storage::new();
                }
                aux.clear();
            }
        },
        _ => { // Using iterators
            quote! {
                if aux.len() >= 8 {
                    let av = aux.to_vec();
                    let lz = u64::from_ne_bytes(av[0..8].try_into().expect("Invalid BigInt metadata")) as usize;
                    let res: Vec<u32> = av[8..].chunks_exact(4)
                        .map(|c| u32::from_ne_bytes(c.try_into().expect("Invalid BigInt limb")))
                        .collect();

                    let mut out = vec![0u8; lz];
                    if !(res.len() == 1 && res[0] == 0) || (av.len() - 8) / 4 == lz {
                        let mut bytes_out = Vec::new();
                        let rl = res.len();
                        for (idx, val) in res.iter().enumerate().rev() {
                            let bytes = val.to_be_bytes();
                            if idx == rl - 1 {
                                let skip = bytes.iter().take_while(|&&b| b == 0).count();
                                bytes_out.extend_from_slice(&bytes[skip..]);
                            } else {
                                bytes_out.extend_from_slice(&bytes);
                            }
                        }
                         out.extend(bytes_out);
                        *data = Storage::from_vec(out);
                    } else {
                        *data = Storage::from_vec(out);
                    }
                } else {
                    *data = Storage::new();
                }
                aux.clear();
            }
        }
    }
}

// --- MACRO GENERATION HELPERS ---

// Enhanced junk logic that is semantically required
fn generate_junk_logic(rng: &mut impl Rng, _real_var: Option<&Ident>, rs_var: Option<&Ident>, rs_compile: &mut u32) -> TokenStream2 {
    let mut code = Vec::new();
    if let Some(rsv) = rs_var {
        for _ in 0..rng.gen_range(1..=2) {
             match rng.gen_range(0..3) {
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
                _ => {
                    let val = rng.gen::<u32>();
                    *rs_compile ^= val;
                    code.push(quote! { #rsv ^= #val; });
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

fn apply_lock_compile(data: &mut Vec<u8>, rs: u32, variant: u32, seed: u32) {
    let key = rs ^ seed ^ (rs >> 13) ^ (rs >> 21);
    match variant % 2 {
        0 => {
            for b in data.iter_mut() {
                *b = b.wrapping_add((key & 0xff) as u8) ^ ((key >> 8) & 0xff) as u8;
                *b = b.rotate_left((key >> 16) as u32 % 8);
            }
            let e = compute_entropy(data);
            for b in data.iter_mut() { *b ^= (e & 0xff) as u8; }
        },
        _ => {
            for b in data.iter_mut() {
                *b ^= ((key >> 16) & 0xff) as u8;
                *b = b.wrapping_sub((key & 0xff) as u8).rotate_right((key >> 8) as u32 % 8);
            }
            let e = compute_entropy(data);
            for b in data.iter_mut() { *b = b.wrapping_add(((e >> 8) & 0xff) as u8); }
        }
    }
}

fn apply_unlock_compile(data: &mut Vec<u8>, rs: u32, variant: u32, seed: u32) {
    let key = rs ^ seed ^ (rs >> 13) ^ (rs >> 21);
    match variant % 2 {
        0 => {
            let e = compute_entropy(data);
            for b in data.iter_mut() { *b ^= (e & 0xff) as u8; }
            for b in data.iter_mut() {
                *b = b.rotate_right((key >> 16) as u32 % 8);
                *b = (*b ^ ((key >> 8) & 0xff) as u8).wrapping_sub((key & 0xff) as u8);
            }
        },
        _ => {
            let e = compute_entropy(data);
            for b in data.iter_mut() { *b = b.wrapping_sub(((e >> 8) & 0xff) as u8); }
            for b in data.iter_mut() {
                *b = b.rotate_left((key >> 8) as u32 % 8).wrapping_add((key & 0xff) as u8);
                *b ^= ((key >> 16) & 0xff) as u8;
            }
        }
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
        for i in 0..data.len() {
            let idx_mask = ((i as u32).wrapping_add(#offset_var) & 0x7) as u8;
            let b = data.get(i);
            data.set(i, b.wrapping_sub(idx_mask ^ #mask));
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
            let mut out_sc = Storage::with_capacity(data.len());
            let mut scramble_idx = #scramble_seed;
            for b in data.iter() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (scramble_idx & 0x3) as u8;
                out_sc.push(b.wrapping_add(offset));
            }
            *data = out_sc;
        }
    };
    
    let unscramble = quote! {
        {
            let mut out_un = Storage::with_capacity(data.len());
            let mut scramble_idx = #scramble_seed;
            for b in data.iter() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (scramble_idx & 0x3) as u8;
                out_un.push(b.wrapping_sub(offset));
            }
            *data = out_un;
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
            let mut #output_var = Storage::with_capacity(#input_expr.len());
            for byte in #input_expr.iter() {
                let #b_n = byte;
                #output_var.push(#b_n ^ #k_n);
                #u_l
            }
            #junk
        },
        1 => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Storage::new();
            let mut i = 0;
            while i < #input_expr.len() {
                let #b_n = #input_expr.get(i);
                #output_var.push(#b_n ^ #k_n);
                #u_l
                i += 1;
            }
            #junk
        },
        _ => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Storage::from_vec(#input_expr.iter().map(|#br_n| {
                let #b_n = #br_n;
                let db_inner = #b_n ^ #k_n;
                #u_l
                db_inner
            }).collect());
            #junk
        },
    };
    
    quote! {
        #core
    }
}

fn generate_fragmented_string_recovery(bytes_var: &Ident, rs_var: &Ident, rng: &mut impl Rng, lock_variant: u32, lock_seed: u32) -> TokenStream2 {
    let s_n = Ident::new(&format!("S_{}", rng.gen::<u32>()), Span::call_site());
    let chunk_size = rng.gen_range(3usize..=10usize);

    let unlock_logic = match lock_variant % 2 {
        0 => quote! {
            let e = self.0.compute_entropy();
            let key = rs_val ^ #lock_seed ^ (rs_val >> 13) ^ (rs_val >> 21);
            let mut unlocked = Vec::new();
            for b in self.0.iter() {
                let mut val = b ^ (e & 0xff) as u8;
                val = val.rotate_right((key >> 16) as u32 % 8);
                val = (val ^ ((key >> 8) & 0xff) as u8).wrapping_sub((key & 0xff) as u8);
                unlocked.push(val);
            }
        },
        _ => quote! {
            let e = self.0.compute_entropy();
            let key = rs_val ^ #lock_seed ^ (rs_val >> 13) ^ (rs_val >> 21);
            let mut unlocked = Vec::new();
            for b in self.0.iter() {
                let mut val = b.wrapping_sub(((e >> 8) & 0xff) as u8);
                val = val.rotate_left((key >> 8) as u32 % 8).wrapping_add((key & 0xff) as u8);
                val ^= ((key >> 16) & 0xff) as u8;
                unlocked.push(val);
            }
        }
    };

    quote! {
        {
            struct #s_n(Storage, u32);
            impl ::std::fmt::Display for #s_n {
                fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    let rs_val = self.1;
                    let mut temp_rs = rs_val;
                    #unlock_logic
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
            #s_n(#bytes_var.clone(), #rs_var).to_string()
        }
    }
}

fn generate_polymorphic_decode_chain(
    transform_ids: &[u32],
    junk_tokens: &[TokenStream2],
    initial_input_var: &Ident,
    mult: u32,
    salt: u32,
    vt_c: &[TokenStream2],
    aux_var: &Ident,
    rng: &mut impl Rng,
    lock_variant: u32,
    lock_seed: u32,
) -> TokenStream2 {
    let rs_n = Ident::new("rs", Span::call_site());
    let dispatch_style = rng.gen_range(0..2);

    let dispatch = |id_expr: TokenStream2, data_var: &Ident, aux_var: &Ident, rs_var: &Ident| {
        match dispatch_style {
            0 => quote! { // Direct match
                #rs_var = {
                    let data = &mut #data_var;
                    let aux = &mut #aux_var;
                    let rs_in = #rs_var;
                    match (#id_expr).wrapping_mul(#mult) ^ #salt {
                        #(#vt_c)*
                        _ => rs_in
                    }
                };
            },
            _ => { // Split match
                quote! {
                    #rs_var = {
                        let data = &mut #data_var;
                        let aux = &mut #aux_var;
                        let rs_in = #rs_var;
                        let key = (#id_expr).wrapping_mul(#mult) ^ #salt;
                        let mut final_rs = rs_in;
                        if key % 2 == 0 {
                            final_rs = match key {
                                #(#vt_c)*
                                _ => rs_in
                            };
                        } else {
                            final_rs = match key {
                                #(#vt_c)*
                                _ => rs_in
                            };
                        }
                        final_rs
                    };
                }
            }
        }
    };
    
    match rng.gen_range(0..6usize) {
        0 => { // Direct execution (Objective 1)
            let mut calls = Vec::new();
            let cv = Ident::new("cv", Span::call_site());
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                calls.push(dispatch(quote! { #id ^ #rs_n }, &cv, aux_var, &rs_n));
                calls.push(quote! { #junk });
            }
            let fr = generate_fragmented_string_recovery(&cv, &rs_n, rng, lock_variant, lock_seed);
            quote! {
                let mut cv = #initial_input_var.clone();
                let mut #rs_n = 0u32;
                #(#calls)*
                #fr
            }
        },
        1 => { // State machine (Existing)
            let mut arms = Vec::new();
            let s_n = Ident::new("s", Span::call_site());
            let m_n = Ident::new("m", Span::call_site());
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                let d_call = dispatch(quote! { #id ^ #rs_n }, &m_n, aux_var, &rs_n);
                if i < transform_ids.len() - 1 {
                    arms.push(quote! { #i => { #d_call #s_n += 1; #junk } });
                } else {
                    let fr = generate_fragmented_string_recovery(&m_n, &rs_n, rng, lock_variant, lock_seed);
                    arms.push(quote! { #i => { #d_call break #fr; } });
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
        2 => { // Stack-based execution (Objective 1)
            let mut calls = Vec::new();
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                let d_call = dispatch(quote! { #id ^ #rs_n }, &Ident::new("top", Span::call_site()), aux_var, &rs_n);
                calls.push(quote! {
                    {
                        let mut top = stack.pop().unwrap_or_else(Storage::new);
                        #d_call
                        stack.push(top);
                    }
                    #junk
                });
            }
            let fr = generate_fragmented_string_recovery(&Ident::new("final_top", Span::call_site()), &rs_n, rng, lock_variant, lock_seed);
            quote! {
                let mut stack = vec![#initial_input_var.clone()];
                let mut #rs_n = 0u32;
                #(#calls)*
                let final_top = stack.pop().unwrap_or_else(Storage::new);
                #fr
            }
        },
        3 => { // Register-style execution (Objective 1)
            let mut calls = Vec::new();
            let mut current_reg = 0;
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                let next_reg = (current_reg + 1) % 4;
                let reg_in = Ident::new(&format!("r{}", current_reg), Span::call_site());
                let reg_out = Ident::new(&format!("r{}", next_reg), Span::call_site());
                let d_call = dispatch(quote! { #id ^ #rs_n }, &reg_out, aux_var, &rs_n);
                calls.push(quote! {
                    #reg_out = #reg_in.clone();
                    #reg_in.clear();
                    #d_call
                    #junk
                });
                current_reg = next_reg;
            }
            let final_reg_id = Ident::new(&format!("r{}", current_reg), Span::call_site());
            let fr = generate_fragmented_string_recovery(&final_reg_id, &rs_n, rng, lock_variant, lock_seed);
            quote! {
                let mut r0 = #initial_input_var.clone();
                let mut r1 = Storage::new();
                let mut r2 = Storage::new();
                let mut r3 = Storage::new();
                let mut #rs_n = 0u32;
                #(#calls)*
                let #final_reg_id = #final_reg_id;
                #fr
            }
        },
        4 => { // Dual-buffer alternate strategy (Objective 2)
            let b1 = Ident::new("b1", Span::call_site());
            let b2 = Ident::new("b2", Span::call_site());
            let mut calls = Vec::new();
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                let (src, dst) = if i % 2 == 0 { (&b1, &b2) } else { (&b2, &b1) };
                let d_call = dispatch(quote! { #id ^ #rs_n }, dst, src, &rs_n);
                calls.push(quote! {
                    #dst = #src.clone();
                    #src.clear();
                    #d_call
                    #junk
                });
            }
            let final_res = if transform_ids.len() % 2 == 0 { &b1 } else { &b2 };
            let fr = generate_fragmented_string_recovery(final_res, &rs_n, rng, lock_variant, lock_seed);
            quote! {
                let mut #b1 = #initial_input_var.clone();
                let mut #b2 = Storage::new();
                let mut #rs_n = 0u32;
                #(#calls)*
                #fr
            }
        },
        _ => { // Linear with Fake Paths (Objective 6)
            let mut st = Vec::new();
            let cv = Ident::new("cv", Span::call_site());
            let shadow_rs = Ident::new("shadow_rs", Span::call_site());
            st.push(quote! { let mut #cv = #initial_input_var.clone(); });
            st.push(quote! { let mut #rs_n = 0u32; });
            st.push(quote! { let mut #shadow_rs = 0u32; });
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                if rng.gen_bool(0.2) {
                    let fake_id = rng.gen::<u32>();
                    let dummy = Ident::new("dummy", Span::call_site());
                    let dummy_aux = Ident::new("dummy_aux", Span::call_site());
                    let d_call = dispatch(quote! { #fake_id ^ #shadow_rs }, &dummy, &dummy_aux, &shadow_rs);
                    st.push(quote! {
                        if #rs_n % 7 == 0 {
                            let mut #dummy = Storage::from_vec(vec![1, 2, 3]);
                            let mut #dummy_aux = Storage::new();
                            #d_call
                        }
                    });
                }
                st.push(dispatch(quote! { #id ^ #rs_n }, &cv, aux_var, &rs_n));
                st.push(quote! { #junk });
                if i == transform_ids.len() - 1 {
                    let fr = generate_fragmented_string_recovery(&cv, &rs_n, rng, lock_variant, lock_seed);
                    st.push(fr);
                }
            }
            quote! { { #(#st)* } }
        }
    }
}

// --- MACRO ---

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
        let primitives = transform_pipeline(primitives, &mut rng);
        layers_data.push((seed_sc, seed_corr, mask_corr, primitives));
    }
    layers_data.reverse();

    let xk = rng.gen::<u8>();
    let ev = rng.gen_range(0..3u32);
    let mut key = xk;
    
    let d_b_i = Ident::new("db", Span::call_site());
    let dl_c = generate_obfuscated_decrypt(quote! { rd }, &d_b_i, &Ident::new("rs_junk", Span::call_site()), &mut 0u32, &mut rng, ev);

    let lock_seed = rng.gen::<u32>();
    let lock_variant = rng.gen::<u32>();

    let mut vt_c = Vec::new();
    let mut rids = Vec::new();
    let mut dc_junks = Vec::new();
    let salt = rng.gen::<u32>();
    let mult = rng.gen::<u32>() | 1;
    let mut rs = 0u32;
    
    // We'll use a copy of cd to simulate the final data after all locks and transformations
    let mut cd_sim = cd.clone();

    for (seed_sc, seed_corr, mask_corr, primitives) in layers_data {
        let mut layer_code = quote! {};

        let (scramble, unscramble) = generate_index_scrambler(seed_sc, &mut rng);
        let (init_corr, apply_corr) = generate_state_corruption(seed_corr, mask_corr, &mut rng);
        
        let unlock_p = Primitive::Unlock { variant: lock_variant, seed: lock_seed };
        let unlock_code = generate_primitive_code(&unlock_p, &mut rng);
        apply_unlock_compile(&mut cd_sim, rs, lock_variant, lock_seed);
        apply_scramble_compile(&mut cd_sim, seed_sc);

        layer_code = quote! { 
            #layer_code 
            #unlock_code
            #scramble 
        };

        let mut aux_sim = Vec::new();
        for p in primitives {
            let step_code = generate_primitive_code(&p, &mut rng);
            layer_code = quote! { #layer_code #step_code };
            simulate_primitive(&p, &mut cd_sim, &mut aux_sim);
        }
        
        let offset_sim = seed_corr.wrapping_mul(0x9E3779B9);
        for (idx_sim, b_sim) in cd_sim.iter_mut().enumerate() {
            let idx_mask = ((idx_sim as u32).wrapping_add(offset_sim) & 0x7) as u8;
            *b_sim = b_sim.wrapping_sub(idx_mask ^ mask_corr);
        }
        apply_unscramble_compile(&mut cd_sim, seed_sc);

        let id_val = rng.gen::<u32>();
        let mut arm_rs = rs;
        let rs_salt = rng.gen::<u32>();
        arm_rs = arm_rs.wrapping_add(id_val).rotate_left(5) ^ rs_salt;

        let core_rs_update = quote! {
            rs = rs.wrapping_add(#id_val).rotate_left(5) ^ #rs_salt;
        };

        let arm_junk_compile_rs = &mut arm_rs;
        let arm_junk = generate_junk_logic(&mut rng, None, Some(&Ident::new("rs", Span::call_site())), arm_junk_compile_rs);

        let lock_p = Primitive::Lock { variant: lock_variant, seed: lock_seed };
        let lock_code = generate_primitive_code(&lock_p, &mut rng);
        apply_lock_compile(&mut cd_sim, arm_rs, lock_variant, lock_seed);

        layer_code = quote! {
            #layer_code
            #init_corr
            #apply_corr
            #unscramble
            #core_rs_update
            #arm_junk
            #lock_code
        };

        let arm_key = (id_val ^ rs).wrapping_mul(mult) ^ salt;
        
        vt_c.push(quote! {
            #arm_key => {
                let mut rs = rs_in;
                #layer_code
                rs
            }
        });
        
        // Decorative junk for the decode chain (doesn't modify rs)
        let mut dummy_rs = 0u32;
        let dc_junk = generate_junk_logic(&mut rng, None, None, &mut dummy_rs);
        dc_junks.push(dc_junk);

        rids.push(id_val);
        rs = arm_rs;
    }

    // Finally, encrypt the simulated data into eb
    apply_lock_compile(&mut cd_sim, 0, lock_variant, lock_seed); // Initial lock for runtime rd

    let mut eb = Vec::with_capacity(cd_sim.len());
    for &ob in &cd_sim {
        let eb_b = ob ^ key;
        eb.push(eb_b);
        match ev {
            0 => key = key.wrapping_add(eb_b),
            1 => key = key.wrapping_sub(eb_b),
            _ => key = key.rotate_left(3),
        };
    }

    let s_n = Ident::new(&format!("O_{}", rng.gen::<u32>()), Span::call_site());
    let m_n = Ident::new(&format!("r_{}", rng.gen::<u32>()), Span::call_site());
    let i_v = Ident::new("ds", Span::call_site());
    let a_v = Ident::new("aux", Span::call_site());
    
    let storage_setup = generate_storage_setup(&mut rng);
    let dc = generate_polymorphic_decode_chain(&rids, &dc_junks, &i_v, mult, salt, &vt_c, &a_v, &mut rng, lock_variant, lock_seed);
    
    let (df, di, rl) = match rng.gen_range(0..3) {
        0 => {
            let dl = Literal::byte_string(&eb);
            (quote! { d: &'a [u8], }, quote! { d: #dl, }, quote! { let mut rd = Storage::from_vec(self.d.to_vec()); })
        },
        1 => {
            let even: Vec<u8> = eb.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = eb.iter().skip(1).step_by(2).cloned().collect();
            let el = Literal::byte_string(&even);
            let ol = Literal::byte_string(&odd);
            (quote! { e: &'a [u8], o: &'a [u8], }, quote! { e: #el, o: #ol, },
             quote! {
                let mut rd = Storage::new();
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
            (quote! { j: &'a [u8], }, quote! { j: #dl, }, quote! { let mut rd = Storage::from_vec(self.j.iter().step_by(2).cloned().collect()); })
        }
    };
    
    let expanded = quote! {{
        struct #s_n<'a> { #df key: u8, }
        impl<'a> #s_n<'a> {
            fn #m_n(&mut self) -> String {
                #storage_setup
                let mut #a_v = Storage::new();
                let mut rs_junk = 0u32;
                #rl
                #dl_c
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
                    let transformed = transform_pipeline(primitives, &mut rng);
                    layer_prims.push(transformed);
                }
                layer_prims.reverse();
                let mut b_data = data;
                let mut aux = Vec::new();
                for primitives in layer_prims {
                    for p in primitives {
                        simulate_primitive(&p, &mut b_data, &mut aux);
                    }
                }
                assert_eq!(b_data, original);
            }
        }
    }
}
