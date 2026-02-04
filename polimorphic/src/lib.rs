extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng, SeedableRng};
use rand::rngs::StdRng;
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};

#[derive(Clone, Debug)]
enum Primitive {
    Map(Vec<u8>),
    BitLoad { bits: u32 },
    BitEmit { bits: u32, total_bits: u64 },
    BaseLoad { base: u128, in_c: usize },
    BaseEmit { base: u128, in_c: usize, out_c: usize, total_bytes: u64 },
    BigIntInit,
    BigIntPush { base: u128 },
    BigIntEmit { total_bytes: u64 },
    Noop { val: u32 },
    Sync,
    BitUnpack { bits: u32, total_bits: u64 },
    XorTransform { key: u8 },
    AddTransform { val: u8 },
    SubTransform { val: u8 },
    Reverse,
    BaseDirect { base: u128, in_c: usize, out_c: usize, total_bytes: u64 },
    BigIntDirect { base: u128, total_bytes: u64 },
    MapXor { key: u8 },
    MapAdd { val: u8 },
    MapSub { val: u8 },
    Interleave { step: usize },
    Deinterleave { step: usize },
    BitArithmetic { bits: u32, total_bits: u64 },
    RotateLeft { rot: u32 },
    RotateRight { rot: u32 },
    ArithmeticChain { ops: [u8; 4], kinds: u8 },
    SwapBuffers,
    Ghost { val: u8 },
    CustomTransform { op: u8, kind: u8 },
    MapCombined { table: Vec<u8>, post_op: u8, post_kind: u8 },
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
                let mut rng = thread_rng();
                let primitives = match rng.gen_range(0..3) {
                    0 => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitLoad { bits: 5 },
                        Primitive::Noop { val: 0x32 },
                        Primitive::BitEmit { bits: 5, total_bits }
                    ],
                    1 => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitUnpack { bits: 5, total_bits }
                    ],
                    _ => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitArithmetic { bits: 5, total_bits }
                    ],
                };
                (out, primitives)
            }),
        }
    };
    let b36 = || {
        let alpha = b36_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let out = encode_bigint(data, 36, &alpha);
                let mut rng = thread_rng();
                let primitives = if rng.gen_bool(0.5) {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntInit,
                        Primitive::BigIntPush { base: 36 },
                        Primitive::BigIntEmit { total_bytes: data.len() as u64 }
                    ]
                } else {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntDirect { base: 36, total_bytes: data.len() as u64 }
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
                let (out, total_bits) = encode_bits(data, 6, &alpha);
                let mut rng = thread_rng();
                let primitives = match rng.gen_range(0..3) {
                    0 => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitLoad { bits: 6 },
                        Primitive::BitEmit { bits: 6, total_bits }
                    ],
                    1 => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitUnpack { bits: 6, total_bits }
                    ],
                    _ => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BitArithmetic { bits: 6, total_bits }
                    ],
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
                let mut rng = thread_rng();
                let primitives = if rng.gen_bool(0.5) {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BaseLoad { base: 85, in_c: 5 },
                        Primitive::Sync,
                        Primitive::BaseEmit { base: 85, in_c: 5, out_c: 4, total_bytes }
                    ]
                } else {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BaseDirect { base: 85, in_c: 5, out_c: 4, total_bytes }
                    ]
                };
                (out, primitives)
            }),
        }
    };
    let b91 = || {
        let alpha = b91_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| {
                let out = encode_bigint(data, 91, &alpha);
                let mut rng = thread_rng();
                let primitives = if rng.gen_bool(0.5) {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntInit,
                        Primitive::BigIntPush { base: 91 },
                        Primitive::BigIntEmit { total_bytes: data.len() as u64 }
                    ]
                } else {
                    vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntDirect { base: 91, total_bytes: data.len() as u64 }
                    ]
                };
                (out, primitives)
            }),
        }
    };

    let arith_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let val = rng.gen::<u8>();
                let mode = rng.gen_bool(0.5); // true: Add, false: Sub
                let out: Vec<u8> = if mode {
                    data.iter().map(|&b| b.wrapping_add(val)).collect()
                } else {
                    data.iter().map(|&b| b.wrapping_sub(val)).collect()
                };
                let primitives = match (mode, rng.gen_range(0..3)) {
                    (true, 0) => vec![Primitive::SubTransform { val }],
                    (true, 1) => vec![Primitive::MapSub { val }],
                    (true, _) => {
                        let v1 = rng.gen::<u8>();
                        let v2 = val.wrapping_sub(v1);
                        let mut ops = [0u8; 4];
                        ops[0] = v1; ops[1] = v2;
                        vec![Primitive::ArithmeticChain { ops, kinds: 0x03 }] // sub v1, sub v2
                    },
                    (false, 0) => vec![Primitive::AddTransform { val }],
                    (false, 1) => vec![Primitive::MapAdd { val }],
                    (false, _) => {
                        let v1 = rng.gen::<u8>();
                        let v2 = val.wrapping_sub(v1);
                        let mut ops = [0u8; 4];
                        ops[0] = v1; ops[1] = v2;
                        vec![Primitive::ArithmeticChain { ops, kinds: 0x00 }] // add v1, add v2
                    },
                };
                (out, primitives)
            }),
        }
    };

    let perm_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let step = rng.gen_range(2..=5);
                // Interleave for encoding
                let mut out = Vec::with_capacity(data.len());
                if data.len() > 0 {
                    for i in 0..step {
                        let mut j = i;
                        while j < data.len() {
                            out.push(data[j]);
                            j += step;
                        }
                    }
                }
                let primitives = vec![Primitive::Deinterleave { step }];
                (out, primitives)
            }),
        }
    };

    let xor_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let key = rng.gen::<u8>();
                let out: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
                let primitives = match rng.gen_range(0..6) {
                    0 => vec![Primitive::XorTransform { key }],
                    1 => {
                        let k1 = rng.gen::<u8>();
                        let k2 = key ^ k1;
                        vec![Primitive::XorTransform { key: k1 }, Primitive::XorTransform { key: k2 }]
                    },
                    2 => vec![Primitive::Reverse, Primitive::XorTransform { key }, Primitive::Reverse],
                    3 => {
                        let v = rng.gen::<u8>();
                        vec![Primitive::AddTransform { val: v }, Primitive::SubTransform { val: v }, Primitive::XorTransform { key }]
                    },
                    _ => vec![Primitive::MapXor { key }]
                };
                (out, primitives)
            }),
        }
    };

    let split_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut out = Vec::with_capacity(data.len() * 2);
                for &b in data {
                    out.push(b >> 4);
                    out.push(b & 0x0F);
                }
                let mut rng = thread_rng();
                let primitives = if rng.gen_bool(0.5) {
                    vec![
                        Primitive::Sync,
                        Primitive::BitLoad { bits: 4 },
                        Primitive::BitEmit { bits: 4, total_bits: data.len() as u64 * 8 }
                    ]
                } else {
                    vec![Primitive::BitUnpack { bits: 4, total_bits: data.len() as u64 * 8 }]
                };
                (out, primitives)
            }),
        }
    };

    vec![b32(), b36(), b64(), z85(), b91(), arith_p(), perm_p(), xor_p(), split_p()]
}

// --- HELPERS ---

enum MapSemantic {
    None,
    Xor(u8),
    Add(u8),
    Sub(u8),
}

fn identify_map_semantic(table: &[u8]) -> MapSemantic {
    if table.len() != 256 { return MapSemantic::None; }

    let k = table[0] ^ 0;
    let mut is_xor = true;
    for i in 0..256 {
        if table[i] != (i as u8) ^ k { is_xor = false; break; }
    }
    if is_xor { return MapSemantic::Xor(k); }

    let v = table[0].wrapping_sub(0);
    let mut is_add = true;
    for i in 0..256 {
        if table[i] != (i as u8).wrapping_add(v) { is_add = false; break; }
    }
    if is_add { return MapSemantic::Add(v); }

    let s = (0u8).wrapping_sub(table[0]);
    let mut is_sub = true;
    for i in 0..256 {
        if table[i] != (i as u8).wrapping_sub(s) { is_sub = false; break; }
    }
    if is_sub { return MapSemantic::Sub(s); }

    MapSemantic::None
}

fn compute_entropy(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| {
        acc.wrapping_add(b as u32).rotate_left(b as u32 % 8 + 1) ^ 0x55555555
    })
}

// --- GENERATORS ---

fn generate_obfuscated_map(alphabet: &[u8], ctx_expr: TokenStream2, rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);
    if rng.gen_bool(0.5) {
        quote! {
            {
                let mut out = Vec::with_capacity(#ctx_expr.data.len());
                for &b in &#ctx_expr.data {
                    let v = (#map_lit)[b as usize];
                    if v != 255 { out.push(v); }
                }
                #ctx_expr.data = out;
            }
        }
    } else {
        quote! {
            #ctx_expr.data = #ctx_expr.data.iter().filter_map(|&b| {
                let v = (#map_lit)[b as usize];
                if v == 255 { None } else { Some(v) }
            }).collect();
        }
    }
}

fn generate_bit_load(ctx_expr: TokenStream2, _bits: u32, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        #ctx_expr.aux.extend_from_slice(&#ctx_expr.data);
        #ctx_expr.data.clear();
    }
}

fn generate_bit_emit(ctx_expr: TokenStream2, bits: u32, total_bits: u64, rng: &mut impl Rng) -> TokenStream2 {
    if rng.gen_bool(0.5) {
        quote! {
            {
                let mut out = Vec::new();
                let mut acc = 0u128;
                let mut count = 0u32;
                let mut bc = 0u64;
                for &v in #ctx_expr.aux.iter() {
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
                #ctx_expr.data = out;
                #ctx_expr.aux.clear();
            }
        }
    } else {
        let mask = rng.gen::<u64>();
        let masked_bits = total_bits ^ mask;
        quote! {
            {
                let mut out = Vec::new();
                let mut acc = 0u128;
                let mut count = 0u32;
                let mut bc = 0u64;
                let tb = #masked_bits ^ #mask;
                for &v in #ctx_expr.aux.iter() {
                    acc = (acc << #bits) | (v as u128);
                    count += #bits;
                    while count >= 8 {
                        count -= 8;
                        if bc < tb {
                            out.push((acc >> count) as u8);
                            bc += 8;
                        }
                        acc &= (1 << count) - 1;
                    }
                }
                #ctx_expr.data = out;
                #ctx_expr.aux.clear();
            }
        }
    }
}

fn generate_base_load(ctx_expr: TokenStream2, _base: u128, _in_c: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        #ctx_expr.aux.extend_from_slice(&#ctx_expr.data);
        #ctx_expr.data.clear();
    }
}

fn generate_base_emit(ctx_expr: TokenStream2, base: u128, in_c: usize, out_c: usize, total_bytes: u64, rng: &mut impl Rng) -> TokenStream2 {
    if rng.gen_bool(0.5) {
        quote! {
            {
                let mut out = Vec::new();
                let mut len_v = 0u64;
                for chunk in #ctx_expr.aux.chunks(#in_c) {
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
                #ctx_expr.data = out;
                #ctx_expr.aux.clear();
            }
        }
    } else {
        quote! {
            {
                let mut out = Vec::new();
                let mut len_v = 0u64;
                let mut chunks_iter = #ctx_expr.aux.chunks_exact(#in_c);
                while let Some(chunk) = chunks_iter.next() {
                    let mut v = 0u128;
                    for i in 0..#in_c { v = v * #base + (chunk[i] as u128); }
                    let mut i = #out_c;
                    while i > 0 {
                        i -= 1;
                        if len_v < #total_bytes {
                            out.push(((v >> (i * 8)) & 0xff) as u8);
                            len_v += 1;
                        }
                    }
                }
                #ctx_expr.data = out;
                #ctx_expr.aux.clear();
            }
        }
    }
}

fn generate_bigint_init(ctx_expr: TokenStream2, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        #ctx_expr.aux.clear();
        #ctx_expr.aux.extend_from_slice(&0u32.to_ne_bytes());
    }
}

fn generate_bigint_push(ctx_expr: TokenStream2, base: u128, rng: &mut impl Rng) -> TokenStream2 {
    if rng.gen_bool(0.5) {
        quote! {
            {
                let mut leading_zeros = 0;
                for &v in &#ctx_expr.data { if v == 0 { leading_zeros += 1; } else { break; } }
                let mut res = Vec::new();
                for chunk in #ctx_expr.aux.chunks_exact(4) {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(chunk);
                    res.push(u32::from_ne_bytes(bytes));
                }

                for &v in &#ctx_expr.data[leading_zeros..] {
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

                #ctx_expr.aux.clear();
                for val in res { #ctx_expr.aux.extend_from_slice(&val.to_ne_bytes()); }
                let lz = leading_zeros as u64;
                let mut next_aux = lz.to_ne_bytes().to_vec();
                next_aux.extend_from_slice(&#ctx_expr.aux);
                #ctx_expr.aux.clear();
                #ctx_expr.aux.extend(next_aux);
            }
        }
    } else {
        quote! {
            {
                let lz = #ctx_expr.data.iter().take_while(|&&x| x == 0).count();
                let mut res: Vec<u32> = #ctx_expr.aux.chunks_exact(4).map(|c| {
                    let mut b = [0u8; 4];
                    b.copy_from_slice(c);
                    u32::from_ne_bytes(b)
                }).collect();

                #ctx_expr.data.iter().skip(lz).for_each(|&v| {
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
                });

                #ctx_expr.aux.clear();
                res.iter().for_each(|val| #ctx_expr.aux.extend_from_slice(&val.to_ne_bytes()));
                let mut next_aux = (lz as u64).to_ne_bytes().to_vec();
                next_aux.extend_from_slice(&#ctx_expr.aux);
                #ctx_expr.aux.clear();
                #ctx_expr.aux.extend(next_aux);
            }
        }
    }
}

fn generate_bigint_emit(ctx_expr: TokenStream2, _total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        {
            if #ctx_expr.aux.len() >= 8 {
                let mut lz_bytes = [0u8; 8];
                lz_bytes.copy_from_slice(&#ctx_expr.aux[0..8]);
                let lz = u64::from_ne_bytes(lz_bytes) as usize;

                let mut res = Vec::new();
                for chunk in #ctx_expr.aux[8..].chunks_exact(4) {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(chunk);
                    res.push(u32::from_ne_bytes(bytes));
                }

                let mut out = vec![0u8; lz];
                if !(res.len() == 1 && res[0] == 0) || (#ctx_expr.aux.len() - 8) / 4 == lz {
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
                #ctx_expr.data = out;
            } else {
                #ctx_expr.data = Vec::new();
            }
            #ctx_expr.aux.clear();
        }
    }
}

fn generate_bit_unpack(ctx_expr: TokenStream2, bits: u32, total_bits: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        {
            let mut out = Vec::new();
            let mut acc = 0u128;
            let mut count = 0u32;
            let mut bc = 0u64;
            for &v in #ctx_expr.data.iter() {
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
            #ctx_expr.data = out;
        }
    }
}

fn generate_xor_transform(ctx_expr: TokenStream2, key: u8, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in #ctx_expr.data.iter_mut() {
            let n = (#ctx_expr.rs >> 8) as u8;
            *b = b.wrapping_add(n).wrapping_sub(n);
            *b ^= #key;
        }
    }
}

fn generate_add_transform(ctx_expr: TokenStream2, val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in #ctx_expr.data.iter_mut() {
            let n = (#ctx_expr.rs >> 16) as u8;
            *b ^= n ^ n;
            *b = b.wrapping_add(#val);
        }
    }
}

fn generate_sub_transform(ctx_expr: TokenStream2, val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in #ctx_expr.data.iter_mut() {
            let n = (#ctx_expr.rs & 0xFF) as u8;
            *b = b.rotate_left(1).rotate_right(1);
            *b = b.wrapping_sub(#val);
        }
    }
}

fn generate_reverse(ctx_expr: TokenStream2, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        #ctx_expr.data.reverse();
    }
}

fn generate_base_direct(ctx_expr: TokenStream2, base: u128, in_c: usize, out_c: usize, total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        {
            let mut out = Vec::new();
            let mut len_v = 0u64;
            for chunk in #ctx_expr.data.chunks(#in_c) {
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
            #ctx_expr.data = out;
        }
    }
}

fn generate_map_xor(ctx_expr: TokenStream2, key: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut table = [0u8; 256];
    for i in 0..256 { table[i] = (i as u8) ^ key; }
    let table_lit = Literal::byte_string(&table);
    quote! {
        for b in #ctx_expr.data.iter_mut() { *b = (#table_lit)[*b as usize]; }
    }
}

fn generate_map_add(ctx_expr: TokenStream2, val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut table = [0u8; 256];
    for i in 0..256 { table[i] = (i as u8).wrapping_add(val); }
    let table_lit = Literal::byte_string(&table);
    quote! {
        for b in #ctx_expr.data.iter_mut() { *b = (#table_lit)[*b as usize]; }
    }
}

fn generate_map_sub(ctx_expr: TokenStream2, val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut table = [0u8; 256];
    for i in 0..256 { table[i] = (i as u8).wrapping_sub(val); }
    let table_lit = Literal::byte_string(&table);
    quote! {
        for b in #ctx_expr.data.iter_mut() { *b = (#table_lit)[*b as usize]; }
    }
}

fn generate_interleave(ctx_expr: TokenStream2, step: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        if #ctx_expr.data.len() > 0 {
            let mut out = Vec::with_capacity(#ctx_expr.data.len());
            for i in 0..#step {
                let mut j = i;
                while j < #ctx_expr.data.len() {
                    out.push(#ctx_expr.data[j]);
                    j += #step;
                }
            }
            #ctx_expr.data = out;
        }
    }
}

fn generate_rotate_left(ctx_expr: TokenStream2, rot: u32, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in #ctx_expr.data.iter_mut() { *b = b.rotate_left(#rot); }
    }
}

fn generate_rotate_right(ctx_expr: TokenStream2, rot: u32, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in #ctx_expr.data.iter_mut() { *b = b.rotate_right(#rot); }
    }
}

fn generate_arithmetic_chain(ctx_expr: TokenStream2, ops: [u8; 4], kinds: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut code = Vec::new();
    for i in 0..4 {
        let op = ops[i];
        if (kinds >> i) & 1 == 0 {
            code.push(quote! { *b = b.wrapping_add(#op); });
        } else {
            code.push(quote! { *b = b.wrapping_sub(#op); });
        }
    }
    quote! {
        for b in #ctx_expr.data.iter_mut() {
            #(#code)*
        }
    }
}

fn generate_swap_buffers(ctx_expr: TokenStream2, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        ::std::mem::swap(&mut #ctx_expr.data, &mut #ctx_expr.aux);
    }
}

fn generate_ghost_from_sim(val: u8, op: u32, ctx_expr: TokenStream2) -> TokenStream2 {
    quote! {
        {
            let mut ghost = Vec::new();
            ghost.push(#val);
            #ctx_expr.rs = #ctx_expr.rs.wrapping_add(#op).rotate_left(1u32);
            let _ = ghost;
        }
    }
}

fn generate_custom_transform(ctx_expr: TokenStream2, op: u8, kind: u8, _rng: &mut impl Rng) -> TokenStream2 {
    match kind {
        0 => quote! { for b in #ctx_expr.data.iter_mut() { *b = b.wrapping_add(#op); } },
        1 => quote! { for b in #ctx_expr.data.iter_mut() { *b = b.wrapping_sub(#op); } },
        2 => quote! { for b in #ctx_expr.data.iter_mut() { *b ^= #op; } },
        3 => {
            let rot = (op % 7 + 1) as u32;
            quote! { for b in #ctx_expr.data.iter_mut() { *b = b.rotate_left(#rot); } }
        },
        _ => {
            let rot = (op % 7 + 1) as u32;
            quote! { for b in #ctx_expr.data.iter_mut() { *b = b.rotate_right(#rot); } }
        },
    }
}

fn generate_map_combined(ctx_expr: TokenStream2, alphabet: &[u8], post_op: u8, post_kind: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);

    let op_code = match post_kind {
        0 => quote! { v = v.wrapping_add(#post_op).wrapping_sub(#post_op); },
        1 => quote! { v = v.wrapping_sub(#post_op).wrapping_add(#post_op); },
        _ => quote! { v = (v ^ #post_op) ^ #post_op; },
    };

    quote! {
        #ctx_expr.data = #ctx_expr.data.iter().filter_map(|&b| {
            let mut v = (#map_lit)[b as usize];
            if v == 255 { None } else {
                #op_code
                Some(v)
            }
        }).collect();
    }
}

fn generate_bit_arithmetic(ctx_expr: TokenStream2, bits: u32, total_bits: u64, _rng: &mut impl Rng) -> TokenStream2 {
    match bits {
        6 => quote! {
            {
                let mut out = Vec::new();
                let mut bc = 0u64;
                for chunk in #ctx_expr.data.chunks(4) {
                    let mut val = 0u64;
                    for (i, &idx) in chunk.iter().enumerate() {
                        val |= (idx as u64) << (18 - i * 6);
                    }
                    for i in (0..3).rev() {
                        if bc < #total_bits {
                            out.push(((val >> (i * 8)) & 0xff) as u8);
                            bc += 8;
                        }
                    }
                }
                #ctx_expr.data = out;
            }
        },
        5 => quote! {
            {
                let mut out = Vec::new();
                let mut bc = 0u64;
                for chunk in #ctx_expr.data.chunks(8) {
                    let mut val = 0u64;
                    for (i, &idx) in chunk.iter().enumerate() {
                        val |= (idx as u64) << (35 - i * 5);
                    }
                    for i in (0..5).rev() {
                        if bc < #total_bits {
                            out.push(((val >> (i * 8)) & 0xff) as u8);
                            bc += 8;
                        }
                    }
                }
                #ctx_expr.data = out;
            }
        },
        _ => quote! {
            {
                let mut out = Vec::new();
                let mut acc = 0u128;
                let mut count = 0u32;
                let mut bc = 0u64;
                for &v in #ctx_expr.data.iter() {
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
                #ctx_expr.data = out;
            }
        }
    }
}

fn generate_deinterleave(ctx_expr: TokenStream2, step: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        if #ctx_expr.data.len() > 0 {
            let mut out = vec![0u8; #ctx_expr.data.len()];
            let mut idx = 0;
            for i in 0..#step {
                let mut j = i;
                while j < #ctx_expr.data.len() {
                    out[j] = #ctx_expr.data[idx];
                    idx += 1;
                    j += #step;
                }
            }
            #ctx_expr.data = out;
        }
    }
}

fn generate_bigint_direct(ctx_expr: TokenStream2, base: u128, total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        {
            let mut leading_zeros = 0;
            for &v in &#ctx_expr.data { if v == 0 { leading_zeros += 1; } else { break; } }
            let mut res = vec![0u32; 1];

            for &v in &#ctx_expr.data[leading_zeros..] {
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

            let mut out = vec![0u8; leading_zeros];
            let rl = res.len();
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
            while out.len() > #total_bytes as usize { out.remove(0); }
            while out.len() < #total_bytes as usize { out.insert(0, 0); }
            #ctx_expr.data = out;
        }
    }
}

fn simulate_junk_logic(mut rs: u32, rng: &mut StdRng) -> (u32, Vec<u32>, Vec<u32>) {
    let num_ops = rng.gen_range(1..=3);
    let mut ops = Vec::new();
    let mut vals = Vec::new();
    for _ in 0..num_ops {
        let op = rng.gen_range(0..4);
        ops.push(op);
        let val = if op == 1 { rng.gen_range(1..31u32) } else { rng.gen::<u32>() };
        vals.push(val);
        match op {
            0 => rs = rs.wrapping_add(val),
            1 => rs = rs.rotate_left(val),
            2 => rs ^= val,
            _ => rs = rs.wrapping_sub(val).rotate_right(7u32),
        }
    }
    (rs, ops, vals)
}

fn generate_junk_logic_from_sim(ops: &[u32], vals: &[u32], ctx_expr: TokenStream2) -> TokenStream2 {
    let mut code = Vec::new();
    for (i, &op) in ops.iter().enumerate() {
        let val = vals[i];
        match op {
            0 => code.push(quote! { #ctx_expr.rs = #ctx_expr.rs.wrapping_add(#val); }),
            1 => code.push(quote! { #ctx_expr.rs = #ctx_expr.rs.rotate_left(#val); }),
            2 => code.push(quote! { #ctx_expr.rs ^= #val; }),
            _ => code.push(quote! { #ctx_expr.rs = #ctx_expr.rs.wrapping_sub(#val).rotate_right(7u32); }),
        }
    }
    if code.is_empty() { quote! {} } else { quote! { #(#code)* } }
}

fn apply_state_corruption_compile(data: &mut Vec<u8>, seed: u32, mask: u8) {
    let offset = seed.wrapping_mul(0x9E3779B9);
    for (i, b) in data.iter_mut().enumerate() {
        let idx_mask = ((i as u32).wrapping_add(offset) & 0x7) as u8;
        *b = b.wrapping_add(idx_mask ^ mask);
    }
}

// Generate semantically required state modifiers
fn generate_state_corruption(ctx_expr: TokenStream2, seed: u32, mask: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let offset_var = Ident::new(&format!("offset_{}", seed % 1000000), Span::call_site());
    quote! {
        {
            let #offset_var = #seed.wrapping_mul(0x9E3779B9);
            for (i, b) in #ctx_expr.data.iter_mut().enumerate() {
                let idx_mask = ((i as u32).wrapping_add(#offset_var) & 0x7) as u8;
                *b = b.wrapping_sub(idx_mask ^ #mask);
            }
        }
    }
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

fn generate_unscramble(ctx_expr: TokenStream2, seed: u32) -> TokenStream2 {
    quote! {
        {
            let mut scramble_idx = #seed;
            for b in #ctx_expr.data.iter_mut() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (scramble_idx & 0x3) as u8;
                *b = b.wrapping_sub(offset);
            }
        }
    }
}

fn generate_unscramble_reverse(ctx_expr: TokenStream2, seed: u32) -> TokenStream2 {
    quote! {
        {
            let mut scramble_idx = #seed;
            for b in #ctx_expr.data.iter_mut() {
                scramble_idx = scramble_idx.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (scramble_idx & 0x3) as u8;
                *b = b.wrapping_add(offset);
            }
        }
    }
}

fn generate_obfuscated_decrypt(input_expr: TokenStream2, ctx_expr: TokenStream2, rng: &mut StdRng, variant: u32, junk_ops: &[u32], junk_vals: &[u32]) -> TokenStream2 {
    let k_n = Ident::new(&format!("k_{}", rng.gen::<u32>()), Span::call_site());
    let b_n = Ident::new(&format!("b_{}", rng.gen::<u32>()), Span::call_site());
    let br_n = Ident::new(&format!("br_{}", rng.gen::<u32>()), Span::call_site());
    
    let u_l = match variant {
        0 => quote! { #k_n = #k_n.wrapping_add(#b_n); },
        1 => quote! { #k_n = #k_n.wrapping_sub(#b_n); },
        _ => quote! { #k_n = #k_n.rotate_left(3u32); },
    };
    
    let junk = generate_junk_logic_from_sim(junk_ops, junk_vals, ctx_expr.clone());
    
    match rng.gen_range(0..3) {
        0 => quote! {
            {
                let mut #k_n = self.key;
                let mut data = Vec::<u8>::with_capacity(#input_expr.len());
                for byte in #input_expr.iter() {
                    let #b_n = *byte;
                    data.push(#b_n ^ #k_n);
                    #u_l
                }
                #junk
                let lock_out_junk = (#ctx_expr.rs ^ (#ctx_expr.rs >> 13) ^ (#ctx_expr.rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock_out_junk; }
                data
            }
        },
        1 => quote! {
            {
                let mut #k_n = self.key;
                let mut data = Vec::<u8>::new();
                let mut i = 0;
                while i < #input_expr.len() {
                    let #b_n = #input_expr[i];
                    data.push(#b_n ^ #k_n);
                    #u_l
                    i += 1;
                }
                #junk
                let lock_out_junk = (#ctx_expr.rs ^ (#ctx_expr.rs >> 13) ^ (#ctx_expr.rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock_out_junk; }
                data
            }
        },
        _ => quote! {
            {
                let mut #k_n = self.key;
                let mut data: Vec<u8> = #input_expr.iter().map(|#br_n| {
                    let #b_n = *#br_n;
                    let db = #b_n ^ #k_n;
                    #u_l
                    db
                }).collect();
                #junk
                let lock_out_junk = (#ctx_expr.rs ^ (#ctx_expr.rs >> 13) ^ (#ctx_expr.rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock_out_junk; }
                data
            }
        },
    }
}

fn generate_fragmented_string_recovery(ctx_expr: TokenStream2, rng: &mut impl Rng) -> TokenStream2 {
    let s_n = Ident::new(&format!("S_{}", rng.gen::<u32>()), Span::call_site());
    let chunk_size = rng.gen_range(3usize..=10usize);

    quote! {
        {
            struct #s_n<'a>(&'a Vec<u8>, u32);
            impl<'a> ::std::fmt::Display for #s_n<'a> {
                fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    let mut temp_rs = self.1;
                    let lock = (temp_rs ^ (temp_rs >> 13) ^ (temp_rs >> 21)) as u8;
                    let unlocked: Vec<u8> = self.0.iter().map(|&b| b ^ lock).collect();
                    for chunk in unlocked.chunks(#chunk_size) {
                        let s: String = chunk.iter().map(|&b| {
                            temp_rs = temp_rs.wrapping_add(b as u32).rotate_left(3u32);
                            b as char
                        }).collect();
                        f.write_str(&s)?;
                    }
                    let _ = temp_rs;
                    Ok(())
                }
            }
            #s_n(&#ctx_expr.data, #ctx_expr.rs).to_string()
        }
    }
}

// --- CFG SYSTEM ---

#[derive(Clone, Debug)]
enum Edge { Direct(u32), Conditional(u32, u32) }
#[derive(Clone, Debug)]
struct GraphNode { id: u32, logic: TokenStream2, transition: Edge, is_exit: bool }
#[derive(Clone, Debug)]
struct Topology { nodes: Vec<GraphNode>, entry_id: u32 }

fn generate_topology(num_blocks: usize, rng: &mut StdRng) -> Topology {
    let ids: Vec<u32> = (0..num_blocks + 1).map(|_| rng.gen()).collect();
    let mut nodes = Vec::new();
    for i in 0..num_blocks {
        let trans = if rng.gen_bool(0.3) && i + 2 < ids.len() {
            Edge::Conditional(ids[i+1], ids[rng.gen_range(i+1..ids.len())])
        } else {
            Edge::Direct(ids[i+1])
        };
        nodes.push(GraphNode { id: ids[i], logic: quote!{}, transition: trans, is_exit: false });
    }
    nodes.push(GraphNode { id: ids[num_blocks], logic: quote!{}, transition: Edge::Direct(0), is_exit: true });
    Topology { nodes, entry_id: ids[0] }
}

fn generate_opaque_predicate(ctx_expr: TokenStream2, rng: &mut StdRng) -> TokenStream2 {
    match rng.gen_range(0..4) {
        0 => quote! { (#ctx_expr.rs.wrapping_mul(#ctx_expr.rs.wrapping_add(1)) % 2 == 0) },
        1 => quote! { ((#ctx_expr.rs.wrapping_add(1) ^ #ctx_expr.rs) != 0) },
        2 => quote! { ((#ctx_expr.rs.wrapping_mul(#ctx_expr.rs).wrapping_add(#ctx_expr.rs) % 2) == 0) },
        _ => quote! { (#ctx_expr.rs | 1 != 0) },
    }
}

fn render_as_state_machine(topology: Topology, ctx_expr: TokenStream2, rng: &mut StdRng) -> TokenStream2 {
    let mut arms = Vec::new();
    let s_n = Ident::new("node_id", Span::call_site());
    for node in &topology.nodes {
        let nid = node.id;
        let logic = &node.logic;
        let trans = if node.is_exit { quote!{ break; } } else {
            match &node.transition {
                Edge::Direct(next) => quote!{ #s_n = #next; },
                Edge::Conditional(t, f) => {
                    let op = generate_opaque_predicate(ctx_expr.clone(), rng);
                    quote!{ if #op { #s_n = #t; } else { #s_n = #f; } }
                }
            }
        };
        arms.push(quote!{ #nid => { #logic #trans } });
    }
    let entry = topology.entry_id;
    quote! {
        {
            let mut #s_n = #entry;
            loop { match #s_n { #(#arms)* _ => break } }
        }
    }
}

fn render_as_trampoline(topology: Topology, ctx_expr: TokenStream2, rng: &mut StdRng) -> TokenStream2 {
    let mut arms = Vec::new();
    let s_n = Ident::new("node_id", Span::call_site());
    for node in &topology.nodes {
        let nid = node.id;
        let logic = &node.logic;
        let trans = if node.is_exit { quote!{ 0 } } else {
            match &node.transition {
                Edge::Direct(next) => quote!{ #next },
                Edge::Conditional(t, f) => {
                    let op = generate_opaque_predicate(ctx_expr.clone(), rng);
                    quote!{ if #op { #t } else { #f } }
                }
            }
        };
        arms.push(quote!{ #nid => { #logic #trans } });
    }
    let entry = topology.entry_id;
    quote! {
        {
            let mut #s_n = #entry;
            while #s_n != 0 {
                #s_n = match #s_n { #(#arms)* _ => 0 };
            }
        }
    }
}

fn render_as_recursive(topology: Topology, ctx_struct_n: &Ident, rng: &mut StdRng) -> TokenStream2 {
    let mut fns = Vec::new();
    let ctx_type_n = format_ident!("Ctx_{}", rng.gen::<u32>());
    for node in &topology.nodes {
        let fn_name = format_ident!("node_{}", node.id);
        let logic = &node.logic;
        let trans = if node.is_exit { quote!{} } else {
            match &node.transition {
                Edge::Direct(next) => { let next_f = format_ident!("node_{}", next); quote!{ #next_f(ctx); } }
                Edge::Conditional(t, f) => {
                    let tf = format_ident!("node_{}", t);
                    let ff = format_ident!("node_{}", f);
                    let op = generate_opaque_predicate(quote!{ (*ctx) }, rng);
                    quote!{ if #op { #tf(ctx); } else { #ff(ctx); } }
                }
            }
        };
        fns.push(quote!{
            fn #fn_name(ctx: &mut #ctx_type_n) {
                { #logic }
                #trans
            }
        });
    }
    let entry_f = format_ident!("node_{}", topology.entry_id);
    quote! {
        {
            struct #ctx_type_n { data: Vec<u8>, aux: Vec<u8>, rs: u32 }
            #(#fns)*
            let mut ctx_val = #ctx_type_n {
                data: ::std::mem::take(&mut #ctx_struct_n.data),
                aux: ::std::mem::take(&mut #ctx_struct_n.aux),
                rs: #ctx_struct_n.rs
            };
            #entry_f(&mut ctx_val);
            #ctx_struct_n.data = ctx_val.data;
            #ctx_struct_n.aux = ctx_val.aux;
            #ctx_struct_n.rs = ctx_val.rs;
        }
    }
}

fn render_as_nested(topology: Topology, ctx_expr: TokenStream2, rng: &mut StdRng) -> TokenStream2 {
    fn render_node(nid: u32, topology: &Topology, ctx_expr: TokenStream2, rng: &mut StdRng, visited: &mut Vec<u32>) -> TokenStream2 {
        if visited.contains(&nid) { return quote!{}; }
        visited.push(nid);
        let node = topology.nodes.iter().find(|n| n.id == nid).expect("Node not found");
        let logic = &node.logic;
        let trans = if node.is_exit { quote!{} } else {
            match &node.transition {
                Edge::Direct(next) => render_node(*next, topology, ctx_expr, rng, visited),
                Edge::Conditional(t, f) => {
                    let op = generate_opaque_predicate(ctx_expr.clone(), rng);
                    let true_path = render_node(*t, topology, ctx_expr.clone(), rng, visited);
                    let false_path = render_node(*f, topology, ctx_expr.clone(), rng, visited);
                    quote!{ if #op { #true_path } else { #false_path } }
                }
            }
        };
        quote!{ { #logic #trans } }
    }
    let mut visited = Vec::new();
    render_node(topology.entry_id, &topology, ctx_expr, rng, &mut visited)
}

// --- POLYMORPHIC SYSTEM HELPERS ---

#[derive(Clone, Debug)]
enum TaskInternal {
    Scramble { seed: u32, lock_in: u32, lock_out: u32 },
    Unscramble { seed: u32, lock_in: u32, lock_out: u32 },
    Corruption { seed: u32, mask: u8, lock_in: u32, lock_out: u32 },
    Primitive { p: Primitive, lock_in: u32, lock_out: u32 },
    Ghost { val: u8, op: u32, lock_in: u32, lock_out: u32 },
}

fn get_primitive_rs_delta(p: &Primitive) -> u32 {
    match p {
        Primitive::Map(v) => v.len() as u32,
        Primitive::BitLoad { bits } => *bits,
        Primitive::BitEmit { bits, .. } => *bits,
        Primitive::BaseLoad { base, .. } => *base as u32,
        Primitive::BaseEmit { base, .. } => *base as u32,
        Primitive::BigIntInit => 0xBB,
        Primitive::BigIntPush { base } => *base as u32,
        Primitive::BigIntEmit { .. } => 0xEE,
        Primitive::Noop { val } => *val,
        Primitive::Sync => 0x55,
        Primitive::BitUnpack { bits, .. } => *bits,
        Primitive::XorTransform { key } => *key as u32,
        Primitive::AddTransform { val } => *val as u32,
        Primitive::SubTransform { val } => *val as u32,
        Primitive::Reverse => 0x11,
        Primitive::BaseDirect { base, .. } => *base as u32,
        Primitive::BigIntDirect { base, .. } => *base as u32,
        Primitive::MapXor { key } => *key as u32,
        Primitive::MapAdd { val } => *val as u32,
        Primitive::MapSub { val } => *val as u32,
        Primitive::Interleave { step } => *step as u32,
        Primitive::Deinterleave { step } => *step as u32,
        Primitive::BitArithmetic { bits, .. } => *bits,
        Primitive::RotateLeft { rot } => *rot,
        Primitive::RotateRight { rot } => *rot,
        Primitive::ArithmeticChain { kinds, .. } => *kinds as u32,
        Primitive::SwapBuffers => 0x99,
        Primitive::Ghost { val } => *val as u32,
        Primitive::CustomTransform { op, .. } => *op as u32,
        Primitive::MapCombined { post_op, .. } => *post_op as u32,
    }
}

fn simulate_rs(tasks: &[TaskInternal], initial_rs: u32) -> u32 {
    let mut rs = initial_rs;
    for task in tasks {
        match task {
            TaskInternal::Primitive { p, lock_in, lock_out } => {
                rs ^= *lock_in;
                rs = rs.wrapping_add(get_primitive_rs_delta(p));
                rs = rs.wrapping_add(*lock_out);
            }
            TaskInternal::Ghost { op, lock_in, lock_out, .. } => {
                rs ^= *lock_in;
                rs = rs.wrapping_add(*op).rotate_left(1u32);
                rs = rs.wrapping_add(*lock_out);
            }
            TaskInternal::Scramble { lock_in, lock_out, .. } |
            TaskInternal::Unscramble { lock_in, lock_out, .. } |
            TaskInternal::Corruption { lock_in, lock_out, .. } => {
                rs ^= *lock_in;
                rs = rs.wrapping_add(*lock_out);
            }
        }
    }
    rs
}

fn render_tasks_to_logic(tasks: Vec<TaskInternal>, ctx_expr: TokenStream2, rng: &mut StdRng) -> TokenStream2 {
    let mut logic = Vec::new();
    for task in tasks {
        let (task_code, rs_up_tokens, lock_in, lock_out) = match task {
            TaskInternal::Primitive { p, lock_in, lock_out } => {
                let rs_up = get_primitive_rs_delta(&p);
                let code = match p {
                    Primitive::Map(ref table) => generate_obfuscated_map(table, ctx_expr.clone(), rng),
                    Primitive::BitLoad { bits } => generate_bit_load(ctx_expr.clone(), bits, rng),
                    Primitive::BitEmit { bits, total_bits } => generate_bit_emit(ctx_expr.clone(), bits, total_bits, rng),
                    Primitive::BaseLoad { base, in_c } => generate_base_load(ctx_expr.clone(), base, in_c, rng),
                    Primitive::BaseEmit { base, in_c, out_c, total_bytes } => generate_base_emit(ctx_expr.clone(), base, in_c, out_c, total_bytes, rng),
                    Primitive::BigIntInit => generate_bigint_init(ctx_expr.clone(), rng),
                    Primitive::BigIntPush { base } => generate_bigint_push(ctx_expr.clone(), base, rng),
                    Primitive::BigIntEmit { total_bytes } => generate_bigint_emit(ctx_expr.clone(), total_bytes, rng),
                    Primitive::Noop { val } => quote! { let _ = #val; },
                    Primitive::Sync => quote! { let mut data = #ctx_expr.data.clone(); },
                    Primitive::BitUnpack { bits, total_bits } => generate_bit_unpack(ctx_expr.clone(), bits, total_bits, rng),
                    Primitive::XorTransform { key } => generate_xor_transform(ctx_expr.clone(), key, rng),
                    Primitive::AddTransform { val } => generate_add_transform(ctx_expr.clone(), val, rng),
                    Primitive::SubTransform { val } => generate_sub_transform(ctx_expr.clone(), val, rng),
                    Primitive::Reverse => generate_reverse(ctx_expr.clone(), rng),
                    Primitive::BaseDirect { base, in_c, out_c, total_bytes } => generate_base_direct(ctx_expr.clone(), base, in_c, out_c, total_bytes, rng),
                    Primitive::BigIntDirect { base, total_bytes } => generate_bigint_direct(ctx_expr.clone(), base, total_bytes, rng),
                    Primitive::MapXor { key } => generate_map_xor(ctx_expr.clone(), key, rng),
                    Primitive::MapAdd { val } => generate_map_add(ctx_expr.clone(), val, rng),
                    Primitive::MapSub { val } => generate_map_sub(ctx_expr.clone(), val, rng),
                    Primitive::Interleave { step } => generate_interleave(ctx_expr.clone(), step, rng),
                    Primitive::Deinterleave { step } => generate_deinterleave(ctx_expr.clone(), step, rng),
                    Primitive::BitArithmetic { bits, total_bits } => generate_bit_arithmetic(ctx_expr.clone(), bits, total_bits, rng),
                    Primitive::RotateLeft { rot } => generate_rotate_left(ctx_expr.clone(), rot, rng),
                    Primitive::RotateRight { rot } => generate_rotate_right(ctx_expr.clone(), rot, rng),
                    Primitive::ArithmeticChain { ops, kinds } => generate_arithmetic_chain(ctx_expr.clone(), ops, kinds, rng),
                    Primitive::SwapBuffers => generate_swap_buffers(ctx_expr.clone(), rng),
                    Primitive::Ghost { val } => generate_ghost_from_sim(val, 0, ctx_expr.clone()),
                    Primitive::CustomTransform { op, kind } => generate_custom_transform(ctx_expr.clone(), op, kind, rng),
                    Primitive::MapCombined { ref table, post_op, post_kind } => generate_map_combined(ctx_expr.clone(), table, post_op, post_kind, rng),
                };
                (code, quote! { #ctx_expr.rs = #ctx_expr.rs.wrapping_add(#rs_up); }, lock_in, lock_out)
            }
            TaskInternal::Ghost { val, op, lock_in, lock_out } => {
                let code = generate_ghost_from_sim(val, op, ctx_expr.clone());
                (code, quote!{}, lock_in, lock_out)
            }
            TaskInternal::Scramble { seed, lock_in, lock_out } => {
                let code = generate_unscramble_reverse(ctx_expr.clone(), seed);
                (code, quote!{}, lock_in, lock_out)
            }
            TaskInternal::Unscramble { seed, lock_in, lock_out } => {
                let code = generate_unscramble(ctx_expr.clone(), seed);
                (code, quote!{}, lock_in, lock_out)
            }
            TaskInternal::Corruption { seed, mask, lock_in, lock_out } => {
                let code = generate_state_corruption(ctx_expr.clone(), seed, mask, rng);
                (code, quote!{}, lock_in, lock_out)
            }
        };
        logic.push(quote! {
            {
                let lock_v = (#ctx_expr.rs ^ (#ctx_expr.rs >> 13) ^ (#ctx_expr.rs >> 21)) as u8;
                for b in #ctx_expr.data.iter_mut() { *b ^= lock_v; }
                #ctx_expr.rs ^= #lock_in;
                #task_code
                #rs_up_tokens
                #ctx_expr.rs = #ctx_expr.rs.wrapping_add(#lock_out);
                let lock_v = (#ctx_expr.rs ^ (#ctx_expr.rs >> 13) ^ (#ctx_expr.rs >> 21)) as u8;
                for b in #ctx_expr.data.iter_mut() { *b ^= lock_v; }
            }
        });
    }
    quote! { #(#logic)* }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let os = lit_str.value();
    let entropy = compute_entropy(os.as_bytes());
    let mut real_rng = thread_rng();
    let mut trng = StdRng::from_seed(real_rng.gen());
    let pl = get_pipelines();

    let mut num_layers = ((entropy % 3) + 8) as usize; // 8 to 10 layers
    if os.len() < 10 { num_layers = num_layers.max(10); }
    
    let mut cd = os.clone().into_bytes();
    let mut layers_data = Vec::new();
    
    for _ in 0..num_layers {
        let seed_sc = trng.gen::<u32>();
        let seed_corr = trng.gen::<u32>();
        let mask_corr = trng.gen::<u8>();

        apply_scramble_compile(&mut cd, seed_sc);
        apply_state_corruption_compile(&mut cd, seed_corr, mask_corr);

        let idx = trng.gen_range(0..pl.len());
        let (encoded, primitives) = (pl[idx].encoder)(&cd);
        cd = encoded;

        apply_unscramble_compile(&mut cd, seed_sc);
        layers_data.push((seed_sc, seed_corr, mask_corr, primitives));
    }
    layers_data.reverse();

    let xk = trng.gen::<u8>();
    let ev = trng.gen_range(0..3u32);
    let (rs_after_junk, junk_ops, junk_vals) = simulate_junk_logic(0, &mut trng);
    
    let mut tasks = Vec::new();
    for (seed_sc, seed_corr, mask_corr, primitives) in layers_data {
        fn is_pos_indep(p: &Primitive) -> bool {
            match p {
                Primitive::Map(_) | Primitive::XorTransform { .. } | Primitive::AddTransform { .. } |
                Primitive::SubTransform { .. } | Primitive::MapXor { .. } | Primitive::MapAdd { .. } |
                Primitive::MapSub { .. } | Primitive::Noop { .. } | Primitive::Sync => true,
                _ => false,
            }
        }

        let mut final_primitives = Vec::new();
        for p in primitives {
            let mut p = p;
            if trng.gen_bool(0.3) {
                p = match p {
                    Primitive::XorTransform { key } => Primitive::CustomTransform { op: key, kind: 2 },
                    Primitive::AddTransform { val } => Primitive::CustomTransform { op: val, kind: 0 },
                    Primitive::SubTransform { val } => Primitive::CustomTransform { op: val, kind: 1 },
                    Primitive::RotateLeft { rot } => {
                        let mut table = [0u8; 256];
                        for i in 0..256 { table[i] = (i as u8).rotate_left(rot); }
                        Primitive::Map(table.to_vec())
                    },
                    Primitive::Map(table) => {
                        let post_op = trng.gen::<u8>();
                        let post_kind = trng.gen_range(0..3);
                        Primitive::MapCombined { table: table.clone(), post_op, post_kind }
                    },
                    _ => p,
                };
            }
            if trng.gen_bool(0.2) {
                match p {
                    Primitive::XorTransform { key } => {
                        let k1 = trng.gen::<u8>();
                        let k2 = key ^ k1;
                        final_primitives.push(Primitive::XorTransform { key: k1 });
                        final_primitives.push(Primitive::XorTransform { key: k2 });
                    },
                    Primitive::AddTransform { val } => {
                        let v1 = trng.gen::<u8>();
                        let v2 = val.wrapping_sub(v1);
                        final_primitives.push(Primitive::AddTransform { val: v1 });
                        final_primitives.push(Primitive::AddTransform { val: v2 });
                    },
                    Primitive::Noop { val } => {
                        final_primitives.push(Primitive::Noop { val });
                        final_primitives.push(Primitive::Sync);
                    },
                    _ => final_primitives.push(p),
                }
            } else {
                match &p {
                    Primitive::Map(ref table) => {
                        match identify_map_semantic(table) {
                            MapSemantic::Xor(k) => final_primitives.push(Primitive::MapXor { key: k }),
                            MapSemantic::Add(v) => final_primitives.push(Primitive::MapAdd { val: v }),
                            MapSemantic::Sub(s) => final_primitives.push(Primitive::MapSub { val: s }),
                            _ => final_primitives.push(p),
                        }
                    },
                    _ => final_primitives.push(p),
                }
            }
        }

        let all_pos_indep = final_primitives.iter().all(is_pos_indep);
        if all_pos_indep && trng.gen_bool(0.3) {
            match trng.gen_range(0..2) {
                0 => {
                    final_primitives.insert(0, Primitive::Reverse);
                    final_primitives.push(Primitive::Reverse);
                },
                _ => {
                    let step = trng.gen_range(2..=5);
                    final_primitives.insert(0, Primitive::Interleave { step });
                    final_primitives.push(Primitive::Deinterleave { step });
                }
            }
        }

        tasks.push(TaskInternal::Scramble { seed: seed_sc, lock_in: trng.gen(), lock_out: trng.gen() });
        for p in final_primitives {
            tasks.push(TaskInternal::Primitive { p, lock_in: trng.gen(), lock_out: trng.gen() });
            if trng.gen_bool(0.1) { tasks.push(TaskInternal::Ghost { val: trng.gen(), op: trng.gen(), lock_in: trng.gen(), lock_out: trng.gen() }); }
        }
        tasks.push(TaskInternal::Corruption { seed: seed_corr, mask: mask_corr, lock_in: trng.gen(), lock_out: trng.gen() });
        tasks.push(TaskInternal::Unscramble { seed: seed_sc, lock_in: trng.gen(), lock_out: trng.gen() });
    }

    for _ in 0..5 {
        let pos = trng.gen_range(0..=tasks.len());
        tasks.insert(pos, TaskInternal::Ghost { val: trng.gen(), op: trng.gen(), lock_in: trng.gen(), lock_out: trng.gen() });
    }

    let _rs_f = simulate_rs(&tasks, rs_after_junk);

    let mut eb = Vec::with_capacity(cd.len());
    let mut key = xk;
    for &ob in &cd {
        let eb_b = ob ^ key;
        eb.push(eb_b);
        match ev {
            0 => key = key.wrapping_add(eb_b),
            1 => key = key.wrapping_sub(eb_b),
            _ => key = key.rotate_left(3),
        };
    }
    let eb_lit = Literal::byte_string(&eb);

    let ctx_n = format_ident!("ctx");
    
    let mut top = generate_topology(tasks.len()/2 + 1, &mut trng);
    let mut t_iter = tasks.into_iter();
    let path: Vec<u32> = top.nodes.iter().map(|n| n.id).collect();
    for &nid in &path {
        if let Some(node) = top.nodes.iter_mut().find(|n| n.id == nid) {
            let mut nt = Vec::new();
            for _ in 0..2 { if let Some(t) = t_iter.next() { nt.push(t); } }
            node.logic = render_tasks_to_logic(nt, quote!{ #ctx_n }, &mut trng);
        }
    }

    let dc = match trng.gen_range(0..4) {
        0 => render_as_state_machine(top, quote!{ #ctx_n }, &mut trng),
        1 => render_as_trampoline(top, quote!{ #ctx_n }, &mut trng),
        2 => render_as_recursive(top, &ctx_n, &mut trng),
        _ => render_as_nested(top, quote!{ #ctx_n }, &mut trng),
    };

    let recovery = generate_fragmented_string_recovery(quote!{ #ctx_n }, &mut trng);
    let decrypt_call = generate_obfuscated_decrypt(quote! { rd }, quote!{ #ctx_n }, &mut trng, ev, &junk_ops, &junk_vals);
    
    let s_n = Ident::new(&format!("O_{}", trng.gen::<u32>()), Span::call_site());
    let m_n_method = Ident::new(&format!("m_{}", trng.gen::<u32>()), Span::call_site());

    TokenStream::from(quote! { {
        struct #s_n { key: u8 }
        impl #s_n {
            fn #m_n_method(&self) -> String {
                struct Context { data: Vec<u8>, aux: Vec<u8>, rs: u32 }
                let mut rd = #eb_lit.to_vec();
                let mut #ctx_n = Context {
                    data: Vec::new(),
                    aux: Vec::new(),
                    rs: 0
                };
                #ctx_n.data = { #decrypt_call };
                #dc
                #recovery
            }
        }
        #s_n { key: #xk }.#m_n_method()
    } })
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

    #[test]
    fn test_cross_family_equivalence() {
        let original = b"Polymorphic Test".to_vec();
        let b64_alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec();

        // Encode using bit-based
        let (encoded, total_bits) = encode_bits(&original, 6, &b64_alpha);

        // Decoder A: BitUnpack
        let mut map = [255u8; 256];
        for (i, &c) in b64_alpha.iter().enumerate() { map[c as usize] = i as u8; }
        let mut indices = Vec::new();
        for &b in &encoded { indices.push(map[b as usize]); }

        let decoded_a = decode_bits_manual(&indices, 6, total_bits);
        assert_eq!(decoded_a, original);
    }
}
