extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng, seq::SliceRandom};
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
    MbaTransform { op: u8, kind: u8 },
    BitPermute { permutation: [u8; 8] },
    Rotate { rot: u8 },
    BitFsm { key: u8 },
    BigIntPoly { base: u128, total_bytes: u64 },
    MapConv { k0: u8 },
    IdentityBranch { path_a: Vec<Primitive>, path_b: Vec<Primitive> },
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
                let primitives = match rng.gen_range(0..2) {
                    0 => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntDirect { base: 36, total_bytes: data.len() as u64 }
                    ],
                    _ => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::Reverse,
                        Primitive::Reverse,
                        Primitive::BigIntDirect { base: 36, total_bytes: data.len() as u64 }
                    ],
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
                let primitives = match rng.gen_range(0..2) {
                    0 => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BaseDirect { base: 85, in_c: 5, out_c: 4, total_bytes }
                    ],
                    _ => {
                        let val = rng.gen::<u8>();
                        vec![
                            Primitive::Map(alpha.clone()),
                            Primitive::XorTransform { key: val },
                            Primitive::XorTransform { key: val },
                            Primitive::BaseDirect { base: 85, in_c: 5, out_c: 4, total_bytes }
                        ]
                    }
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
                let primitives = match rng.gen_range(0..2) {
                    0 => vec![
                        Primitive::Map(alpha.clone()),
                        Primitive::BigIntDirect { base: 91, total_bytes: data.len() as u64 }
                    ],
                    _ => {
                        let r = rng.gen_range(1..7);
                        vec![
                            Primitive::Map(alpha.clone()),
                            Primitive::RotateLeft { rot: r },
                            Primitive::RotateRight { rot: r },
                            Primitive::BigIntDirect { base: 91, total_bytes: data.len() as u64 }
                        ]
                    }
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

    let bit_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let mut p = [0,1,2,3,4,5,6,7];
                p.shuffle(&mut rng);
                let out: Vec<u8> = data.iter().map(|&b| {
                    let mut res = 0u8;
                    for (i, &src) in p.iter().enumerate() {
                        if (b & (1 << i)) != 0 { res |= 1 << src; }
                    }
                    res
                }).collect();
                (out, vec![Primitive::BitPermute { permutation: p }])
            }),
        }
    };

    let rot_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let rot = rng.gen_range(1..7) as u8;
                let out: Vec<u8> = data.iter().map(|&b| b.rotate_right(rot as u32)).collect();
                (out, vec![Primitive::Rotate { rot }])
            }),
        }
    };

    let extra_adv_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                match rng.gen_range(0..3) {
                    0 => {
                        let key = rng.gen::<u8>();
                        let k_low = key & 0x0F;
                        let k_high = key >> 4;
                        let out = data.iter().map(|&b| {
                            let x = b;
                            let high = (x >> 4) & 0xF;
                            let low = x & 0xF;
                            let h_e = high ^ (low ^ k_low);
                            let l_e = low ^ (h_e ^ k_high);
                            (h_e << 4) | (l_e & 0xF)
                        }).collect();
                        (out, vec![Primitive::BitFsm { key }])
                    },
                    1 => {
                        let k0 = rng.gen::<u8>();
                        let mut out = Vec::with_capacity(data.len());
                        let mut last = 0u8;
                        for &b in data {
                            let enc = b ^ k0 ^ last;
                            out.push(enc);
                            last = b;
                        }
                        (out, vec![Primitive::MapConv { k0 }])
                    },
                    _ => {
                        let key = rng.gen::<u8>();
                        let out = data.iter().map(|&b| b ^ key).collect();
                        (out, vec![Primitive::XorTransform { key }])
                    }
                }
            }),
        }
    };

    let adv_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let alpha = "0123456789abcdefghijklmnopqrstuvwxyz".as_bytes().to_vec();
                let out = encode_bigint(data, 36, &alpha);
                let k0 = rng.gen::<u8>();
                let primitives = match rng.gen_range(0..2) {
                    0 => vec![
                        Primitive::Map(alpha),
                        Primitive::BigIntPoly { base: 36, total_bytes: data.len() as u64 },
                        Primitive::MapConv { k0 }
                    ],
                    _ => vec![
                        Primitive::Map(alpha),
                        Primitive::MapConv { k0 },
                        Primitive::BigIntPoly { base: 36, total_bytes: data.len() as u64 }
                    ]
                };
                (out, primitives)
            }),
        }
    };

    let identity_p = || {
        Pipeline {
            encoder: Box::new(move |data| {
                let mut rng = thread_rng();
                let p1 = vec![Primitive::XorTransform { key: rng.gen() }];
                let p2 = vec![Primitive::AddTransform { val: rng.gen() }];
                (data.to_vec(), vec![Primitive::IdentityBranch { path_a: p1, path_b: p2 }])
            }),
        }
    };

    vec![b32(), b36(), b64(), z85(), b91(), arith_p(), perm_p(), xor_p(), split_p(), bit_p(), rot_p(), adv_p(), extra_adv_p(), identity_p()]
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

fn generate_obfuscated_map(alphabet: &[u8], rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);
    if rng.gen_bool(0.5) {
        quote! {
            let mut out = Vec::with_capacity(data.len());
            for &b in &data {
                let v = (#map_lit)[b as usize];
                if v != 255 { out.push(v); }
            }
            data = out;
        }
    } else {
        quote! {
            data = data.iter().filter_map(|&b| {
                let v = (#map_lit)[b as usize];
                if v == 255 { None } else { Some(v) }
            }).collect::<Vec<u8>>();
        }
    }
}

fn generate_primitive_dispatch_logic(p: &Primitive, rng: &mut impl Rng, arm_rs: &mut u32) -> TokenStream2 {
    match p {
        Primitive::Map(table) => generate_obfuscated_map(&table, rng),
        Primitive::BitLoad { bits } => generate_bit_load(*bits, rng),
        Primitive::BitEmit { bits, total_bits } => generate_bit_emit(*bits, *total_bits, rng),
        Primitive::BaseLoad { base, in_c } => generate_base_load(*base, *in_c, rng),
        Primitive::BaseEmit { base, in_c, out_c, total_bytes } => generate_base_emit(*base, *in_c, *out_c, *total_bytes, rng),
        Primitive::BigIntInit => generate_bigint_init(rng),
        Primitive::BigIntPush { base } => generate_bigint_push(*base, rng),
        Primitive::BigIntEmit { total_bytes } => generate_bigint_emit(*total_bytes, rng),
        Primitive::Noop { val } => quote! { let _ = #val; },
        Primitive::Sync => quote! { let _ = &data; },
        Primitive::BitUnpack { bits, total_bits } => generate_bit_unpack(*bits, *total_bits, rng),
        Primitive::XorTransform { key } => generate_xor_transform(*key, rng),
        Primitive::AddTransform { val } => generate_add_transform(*val, rng),
        Primitive::SubTransform { val } => generate_sub_transform(*val, rng),
        Primitive::Reverse => generate_reverse(rng),
        Primitive::BaseDirect { base, in_c, out_c, total_bytes } => generate_base_direct(*base, *in_c, *out_c, *total_bytes, rng),
        Primitive::BigIntDirect { base, total_bytes } => generate_bigint_direct(*base, *total_bytes, rng),
        Primitive::MapXor { key } => generate_map_xor(*key, rng),
        Primitive::MapAdd { val } => generate_map_add(*val, rng),
        Primitive::MapSub { val } => generate_map_sub(*val, rng),
        Primitive::Interleave { step } => generate_interleave(*step, rng),
        Primitive::Deinterleave { step } => generate_deinterleave(*step, rng),
        Primitive::BitArithmetic { bits, total_bits } => generate_bit_arithmetic(*bits, *total_bits, rng),
        Primitive::RotateLeft { rot } => generate_rotate_left(*rot, rng),
        Primitive::RotateRight { rot } => generate_rotate_right(*rot, rng),
        Primitive::ArithmeticChain { ops, kinds } => generate_arithmetic_chain(*ops, *kinds, rng),
        Primitive::SwapBuffers => generate_swap_buffers(rng),
        Primitive::Ghost { val } => generate_ghost(*val, rng, Some(&Ident::new("rs", Span::call_site())), arm_rs),
        Primitive::CustomTransform { op, kind } => generate_custom_transform(*op, *kind, rng),
        Primitive::MapCombined { table, post_op, post_kind } => generate_map_combined(table, *post_op, *post_kind, rng),
        Primitive::MbaTransform { op, kind } => generate_mba_transform(*op, *kind, rng),
        Primitive::BitPermute { permutation } => generate_bit_permute(*permutation, rng),
        Primitive::Rotate { rot } => generate_rotate(*rot, rng),
        Primitive::BitFsm { key } => generate_bit_fsm(*key, rng),
        Primitive::BigIntPoly { base, total_bytes } => generate_bigint_poly(*base, *total_bytes, rng),
        Primitive::MapConv { k0 } => generate_map_conv(*k0, rng),
        Primitive::IdentityBranch { path_a, path_b } => generate_identity_branch(path_a, path_b, rng, arm_rs),
    }
}

fn generate_identity_branch(path_a: &[Primitive], path_b: &[Primitive], rng: &mut impl Rng, arm_rs: &mut u32) -> TokenStream2 {
    let op = generate_opaque_predicate(&Ident::new("rs", Span::call_site()), rng);
    let initial_rs = *arm_rs;

    let mut code_a = Vec::new();
    let mut rs_a = initial_rs;
    for p in path_a {
        code_a.push(generate_primitive_dispatch_logic(p, rng, &mut rs_a));
    }

    let mut code_b = Vec::new();
    let mut rs_b = initial_rs;
    for p in path_b {
        code_b.push(generate_primitive_dispatch_logic(p, rng, &mut rs_b));
    }

    *arm_rs = rs_a;

    quote! {
        if #op {
            #(#code_a)*
        } else {
            #(#code_b)*
        }
    }
}

fn generate_bit_fsm(key: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let k_low = key & 0x0F;
    let k_high = key >> 4;
    quote! {
        for b in data.iter_mut() {
            let mut high = (*b >> 4) & 0x0F;
            let mut low = *b & 0x0F;
            low ^= high ^ #k_high;
            high ^= low ^ #k_low;
            *b = (high << 4) | low;
        }
    }
}

fn generate_bigint_poly(base: u128, total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        let mut lz = 0;
        for &v in &data { if v == 0 { lz += 1; } else { break; } }
        let mut res = vec![0u32; 1];

        for &v in &data[lz..] {
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

        let mut out = vec![0u8; lz];
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
        data = out;
    }
}

fn generate_map_conv(k0: u8, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        let mut last = 0u8;
        for b in data.iter_mut() {
            *b ^= #k0 ^ last;
            last = *b;
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
    if rng.gen_bool(0.5) {
        quote! {
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
        }
    } else {
        let mask = rng.gen::<u64>();
        let masked_bits = total_bits ^ mask;
        quote! {
            let mut out = Vec::new();
            let mut acc = 0u128;
            let mut count = 0u32;
            let mut bc = 0u64;
            let tb = #masked_bits ^ #mask;
            for &v in aux.iter() {
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
            data = out;
            aux.clear();
        }
    }
}

fn generate_base_load(_base: u128, _in_c: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.extend_from_slice(&data);
        data.clear();
    }
}

fn generate_base_emit(base: u128, in_c: usize, out_c: usize, total_bytes: u64, rng: &mut impl Rng) -> TokenStream2 {
    if rng.gen_bool(0.5) {
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
    } else {
        // Semi-unrolled variant
        quote! {
            let mut out = Vec::new();
            let mut len_v = 0u64;
            let mut chunks_iter = aux.chunks_exact(#in_c);
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
            data = out;
            aux.clear();
        }
    }
}

fn generate_bigint_init(_rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        aux.clear();
        let lz = 0u64;
        let zero = 0u32;
        aux.extend_from_slice(&lz.to_ne_bytes());
        aux.extend_from_slice(&zero.to_ne_bytes());
    }
}

fn generate_bigint_push(base: u128, rng: &mut impl Rng) -> TokenStream2 {
    let core = quote! {
        if aux.len() >= 8 {
            let mut lz_b = [0u8; 8];
            lz_b.copy_from_slice(&aux[0..8]);
            let mut lz = u64::from_ne_bytes(lz_b);

            let mut leading_zeros = 0;
            for &v in &data { if v == 0 { leading_zeros += 1; } else { break; } }
            lz += leading_zeros as u64;

            let mut res = Vec::new();
            for chunk in aux[8..].chunks_exact(4) {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(chunk);
                res.push(u32::from_ne_bytes(bytes));
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
            aux.extend_from_slice(&lz.to_ne_bytes());
            for val in res { aux.extend_from_slice(&val.to_ne_bytes()); }
        }
    };
    if rng.gen_bool(0.5) {
        core
    } else {
        quote! { { #core } }
    }
}

fn generate_bigint_emit(total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        if aux.len() >= 8 {
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
            while out.len() > #total_bytes as usize { out.remove(0); }
            while out.len() < #total_bytes as usize { out.insert(0, 0); }
            data = out;
        }
        aux.clear();
    }
}

fn generate_bit_unpack(bits: u32, total_bits: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
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
    }
}

fn generate_xor_transform(key: u8, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in data.iter_mut() {
            let n = (rs >> 8) as u8;
            *b = b.wrapping_add(n).wrapping_sub(n);
            *b ^= #key;
        }
    }
}

fn generate_add_transform(val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in data.iter_mut() {
            let n = (rs >> 16) as u8;
            *b ^= n ^ n;
            *b = b.wrapping_add(#val);
        }
    }
}

fn generate_sub_transform(val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in data.iter_mut() {
            let n = (rs & 0xFF) as u8;
            *b = b.rotate_left(1u32).rotate_right(1u32);
            *b = b.wrapping_sub(#val);
        }
    }
}

fn generate_reverse(_rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        data.reverse();
    }
}

fn generate_base_direct(base: u128, in_c: usize, out_c: usize, total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        let mut out = Vec::new();
        let mut len_v = 0u64;
        for chunk in data.chunks(#in_c) {
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
    }
}

fn generate_map_xor(key: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut table = [0u8; 256];
    for i in 0..256 { table[i] = (i as u8) ^ key; }
    let table_lit = Literal::byte_string(&table);
    quote! {
        for b in data.iter_mut() { *b = (#table_lit)[*b as usize]; }
    }
}

fn generate_map_add(val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut table = [0u8; 256];
    for i in 0..256 { table[i] = (i as u8).wrapping_add(val); }
    let table_lit = Literal::byte_string(&table);
    quote! {
        for b in data.iter_mut() { *b = (#table_lit)[*b as usize]; }
    }
}

fn generate_map_sub(val: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut table = [0u8; 256];
    for i in 0..256 { table[i] = (i as u8).wrapping_sub(val); }
    let table_lit = Literal::byte_string(&table);
    quote! {
        for b in data.iter_mut() { *b = (#table_lit)[*b as usize]; }
    }
}

fn generate_interleave(step: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        if data.len() > 0 {
            let mut out = Vec::with_capacity(data.len());
            for i in 0..#step {
                let mut j = i;
                while j < data.len() {
                    out.push(data[j]);
                    j += #step;
                }
            }
            data = out;
        }
    }
}

fn generate_rotate_left(rot: u32, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in data.iter_mut() { *b = b.rotate_left(#rot as u32); }
    }
}

fn generate_rotate_right(rot: u32, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        for b in data.iter_mut() { *b = b.rotate_right(#rot as u32); }
    }
}

fn generate_arithmetic_chain(ops: [u8; 4], kinds: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut code = Vec::new();
    for i in 0..4usize {
        let op = ops[i];
        if (kinds >> i) & 1 == 0 {
            code.push(quote! { *b = b.wrapping_add(#op); });
        } else {
            code.push(quote! { *b = b.wrapping_sub(#op); });
        }
    }
    quote! {
        for b in data.iter_mut() {
            #(#code)*
        }
    }
}

fn generate_swap_buffers(_rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        ::std::mem::swap(&mut data, aux);
    }
}

fn generate_ghost(val: u8, rng: &mut impl Rng, rs_var: Option<&Ident>, rs_compile: &mut u32) -> TokenStream2 {
    let mut code = Vec::new();
    if let Some(rsv) = rs_var {
        let op = rng.gen::<u32>();
        *rs_compile = rs_compile.wrapping_add(op).rotate_left(1u32);
        code.push(quote! { #rsv = #rsv.wrapping_add(#op).rotate_left(1u32); });
    }
    quote! {
        {
            let mut ghost = Vec::new();
            ghost.push(#val);
            #(#code)*
            let _ = ghost;
        }
    }
}

fn generate_custom_transform(op: u8, kind: u8, _rng: &mut impl Rng) -> TokenStream2 {
    match kind {
        0 => quote! { for b in data.iter_mut() { *b = b.wrapping_add(#op); } },
        1 => quote! { for b in data.iter_mut() { *b = b.wrapping_sub(#op); } },
        2 => quote! { for b in data.iter_mut() { *b ^= #op; } },
        3 => {
            let rot = (op % 7 + 1) as u32;
            quote! { for b in data.iter_mut() { *b = b.rotate_left(#rot as u32); } }
        },
        _ => {
            let rot = (op % 7 + 1) as u32;
            quote! { for b in data.iter_mut() { *b = b.rotate_right(#rot as u32); } }
        },
    }
}

fn generate_map_combined(alphabet: &[u8], post_op: u8, post_kind: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);

    let op_code = match post_kind {
        0 => quote! { v = v.wrapping_add(#post_op).wrapping_sub(#post_op); },
        1 => quote! { v = v.wrapping_sub(#post_op).wrapping_add(#post_op); },
        _ => quote! { v = (v ^ #post_op) ^ #post_op; },
    };

    quote! {
        data = data.iter().filter_map(|&b| {
            let mut v = (#map_lit)[b as usize];
            if v == 255 { None } else {
                #op_code
                Some(v)
            }
        }).collect::<Vec<u8>>();
    }
}

fn generate_mba_transform(op: u8, kind: u8, _rng: &mut impl Rng) -> TokenStream2 {
    match kind {
        0 => { // XOR via (x | y) - (x & y)
            quote! { for b in data.iter_mut() { *b = (*b | #op).wrapping_sub(*b & #op); } }
        },
        1 => { // ADD via (x ^ y) + 2*(x & y)
            quote! { for b in data.iter_mut() { *b = ((*b ^ #op).wrapping_add((*b & #op).wrapping_shl(1))); } }
        },
        _ => { // SUB via (x ^ y) - 2 * (!x & y)
            quote! { for b in data.iter_mut() { *b = (*b ^ #op).wrapping_sub(((!*b) & #op).wrapping_shl(1)); } }
        }
    }
}

fn generate_bit_permute(permutation: [u8; 8], _rng: &mut impl Rng) -> TokenStream2 {
    let mut bit_logic = Vec::new();
    for (i, &p) in permutation.iter().enumerate() {
        let src_bit = p;
        let dst_bit = i as u8;
        bit_logic.push(quote! { if (v & (1 << #src_bit)) != 0 { res |= (1 << #dst_bit); } });
    }
    quote! {
        for b in data.iter_mut() {
            let v = *b;
            let mut res = 0u8;
            #(#bit_logic)*
            *b = res;
        }
    }
}

fn generate_rotate(rot: u8, _rng: &mut impl Rng) -> TokenStream2 {
    let r = (rot % 8) as u32;
    quote! { for b in data.iter_mut() { *b = b.rotate_left(#r as u32); } }
}

fn generate_bit_arithmetic(bits: u32, total_bits: u64, _rng: &mut impl Rng) -> TokenStream2 {
    match bits {
        6 => quote! {
            let mut out = Vec::new();
            let mut bc = 0u64;
            for chunk in data.chunks(4) {
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
            data = out;
        },
        5 => quote! {
            let mut out = Vec::new();
            let mut bc = 0u64;
            for chunk in data.chunks(8) {
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
            data = out;
        },
        _ => quote! {
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
        }
    }
}

fn generate_deinterleave(step: usize, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        if data.len() > 0 {
            let mut out = vec![0u8; data.len()];
            let mut idx = 0;
            for i in 0..#step {
                let mut j = i;
                while j < data.len() {
                    out[j] = data[idx];
                    idx += 1;
                    j += #step;
                }
            }
            data = out;
        }
    }
}

fn generate_bigint_direct(base: u128, total_bytes: u64, _rng: &mut impl Rng) -> TokenStream2 {
    quote! {
        let mut leading_zeros = 0;
        for &v in &data { if v == 0 { leading_zeros += 1; } else { break; } }
        let mut res = vec![0u32; 1];

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
        data = out;
    }
}

// Enhanced junk logic that is semantically required
fn generate_mba_constant(val: u32, rng: &mut impl Rng, depth: usize) -> TokenStream2 {
    if depth == 0 {
        return quote! { #val };
    }
    match rng.gen_range(0..4) {
        0 => { // (x + y) = (x | y) + (x & y)
             let v1 = rng.gen::<u32>();
             let v2 = val.wrapping_sub(v1);
             let e1 = generate_mba_constant(v1, rng, depth - 1);
             let e2 = generate_mba_constant(v2, rng, depth - 1);
             quote! { (#e1 | #e2).wrapping_add(#e1 & #e2) }
        },
        1 => { // (x ^ y) = (x | y) - (x & y)
             let v1 = rng.gen::<u32>();
             let v2 = val ^ v1;
             let e1 = generate_mba_constant(v1, rng, depth - 1);
             let e2 = generate_mba_constant(v2, rng, depth - 1);
             quote! { (#e1 | #e2).wrapping_sub(#e1 & #e2) }
        },
        2 => { // x = (x & y) + (x & !y)
             let y = rng.gen::<u32>();
             let e_x = generate_mba_constant(val, rng, depth - 1);
             let e_y = generate_mba_constant(y, rng, depth - 1);
             quote! { (#e_x & #e_y).wrapping_add(#e_x & !#e_y) }
        },
        _ => { // x = (x | y) - (!x & y)
             let y = rng.gen::<u32>();
             let e_x = generate_mba_constant(val, rng, depth - 1);
             let e_y = generate_mba_constant(y, rng, depth - 1);
             quote! { (#e_x | #e_y).wrapping_sub(!#e_x & #e_y) }
        }
    }
}

fn generate_junk_logic(rng: &mut impl Rng, real_var: Option<&Ident>, rs_var: Option<&Ident>, rs_compile: &mut u32) -> TokenStream2 {
    let mut code = Vec::new();
    if let Some(rv) = real_var {
        if rng.gen_bool(0.3) {
            let val = rng.gen::<u8>();
            let vmba = generate_mba_constant(val as u32, rng, 1);
            code.push(quote! {
                for b in #rv.iter_mut() { *b = b.wrapping_add(#vmba as u8); }
                for b in #rv.iter_mut() { *b = b.wrapping_sub(#vmba as u8); }
            });
        }
        if rng.gen_bool(0.3) {
            let key = rng.gen::<u8>();
            let kmba = generate_mba_constant(key as u32, rng, 1);
            code.push(quote! {
                for b in #rv.iter_mut() { *b ^= #kmba as u8; }
                for b in #rv.iter_mut() { *b ^= #kmba as u8; }
            });
        }
    }
    if let Some(rsv) = rs_var {
        let num_ops = rng.gen_range(1..=3);
        for _ in 0..num_ops {
             match rng.gen_range(0..6) {
                0 => {
                    let val = rng.gen::<u32>();
                    *rs_compile = rs_compile.wrapping_add(val);
                    let vmba = generate_mba_constant(val, rng, 2);
                    code.push(quote! { #rsv = #rsv.wrapping_add(#vmba); });
                },
                1 => {
                    let val = rng.gen_range(1..31);
                    *rs_compile = rs_compile.rotate_left(val);
                    code.push(quote! { #rsv = #rsv.rotate_left(#val as u32); });
                },
                2 => {
                    let val = rng.gen::<u32>();
                    *rs_compile ^= val;
                    let vmba = generate_mba_constant(val, rng, 2);
                    code.push(quote! { #rsv ^= #vmba; });
                },
                3 => {
                    let val = rng.gen::<u32>();
                    *rs_compile = rs_compile.wrapping_sub(val).rotate_right(7u32);
                    let vmba = generate_mba_constant(val, rng, 2);
                    code.push(quote! { #rsv = #rsv.wrapping_sub(#vmba).rotate_right(7u32); });
                },
                4 => {
                    let val = rng.gen::<u32>();
                    *rs_compile ^= val;
                    let vmba = generate_mba_constant(val, rng, 2);
                    code.push(quote! { #rsv = (#rsv | #vmba).wrapping_sub(#rsv & #vmba); });
                },
                _ => {
                    let val = rng.gen::<u32>();
                    *rs_compile = rs_compile.wrapping_add(val);
                    let vmba = generate_mba_constant(val, rng, 2);
                    code.push(quote! { #rsv = (#rsv | #vmba).wrapping_add(#rsv & #vmba); });
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
        _ => quote! { #k_n = #k_n.rotate_left(3u32); },
    };
    
    let junk = generate_junk_logic(rng, Some(output_var), Some(rs_var), rs_compile);
    
    let core = match rng.gen_range(0..3) {
        0 => quote! {
            let mut #k_n = self.key;
            let mut #output_var: Vec<u8> = Vec::with_capacity(#input_expr.len());
            for byte in #input_expr.iter() {
                let #b_n = *byte;
                #output_var.push(#b_n ^ #k_n);
                #u_l
            }
            #junk
        },
        1 => quote! {
            let mut #k_n = self.key;
            let mut #output_var: Vec<u8> = Vec::new();
            let mut i = 0usize;
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
    let lock_logic = quote! { (#rs_var ^ (#rs_var >> 13) ^ (#rs_var >> 21)) as u8 };

    match rng.gen_range(0..5) {
        0 => {
            let s_n = Ident::new(&format!("s_{}", rng.gen::<u32>()), Span::call_site());
            quote! {
                {
                    struct #s_n(Vec<u8>, u32);
                    impl ::std::fmt::Display for #s_n {
                        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                            let l = (self.1 ^ (self.1 >> 13) ^ (self.1 >> 21)) as u8;
                            let s: String = self.0.iter().map(|&b| (b ^ l) as char).collect();
                            f.write_str(&s)
                        }
                    }
                    #s_n(#bytes_var.to_vec(), #rs_var).to_string()
                }
            }
        },
        1 => {
            quote! {
                {
                    let l = #lock_logic;
                    #bytes_var.iter().map(|&b| (b ^ l) as char).collect::<String>()
                }
            }
        },
        2 => {
            quote! {
                {
                    let l = #lock_logic;
                    let mut s = String::with_capacity(#bytes_var.len());
                    for &b in #bytes_var.iter() {
                        s.push((b ^ l) as char);
                    }
                    s
                }
            }
        },
        3 => {
            quote! {
                {
                    let l = #lock_logic;
                    let mut s = String::new();
                    #bytes_var.iter().for_each(|&b| s.push((b ^ l) as char));
                    s
                }
            }
        },
        _ => {
            quote! {
                {
                    let l = #lock_logic;
                    let mut b = #bytes_var.to_vec();
                    for x in b.iter_mut() { *x ^= l; }
                    String::from_utf8(b).expect("Polymorphic recovery failure")
                }
            }
        }
    }
}

fn generate_opaque_predicate(rs_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let rs = rs_var;
    match rng.gen_range(0..4) {
        0 => quote! { (#rs.wrapping_mul(#rs.wrapping_add(1)) % 2 == 0) },
        1 => quote! { ((#rs.wrapping_add(1) ^ #rs) != 0) },
        2 => quote! { (#rs.wrapping_sub(#rs.wrapping_add(1)) != 0) },
        _ => {
            let c = rng.gen::<u32>() | 1;
            quote! { (#rs.wrapping_mul(#c).wrapping_add(1) != #rs.wrapping_mul(#c)) }
        }
    }
}

struct GraphNode {
    id: u32,
    tasks: Vec<(u32, TokenStream2)>,
    next_states: Vec<u32>, // Multiple possible next states for branching
    is_exit: bool,
}

struct Topology {
    nodes: Vec<GraphNode>,
    entry_id: u32,
}

fn build_topology_recursive(
    tasks: &[(u32, TokenStream2)],
    exit_id: u32,
    nodes: &mut Vec<GraphNode>,
    rng: &mut impl Rng,
    depth: usize,
) -> u32 {
    let entry_id = rng.gen::<u32>();

    if depth > 7 || tasks.len() <= 1 {
        nodes.push(GraphNode {
            id: entry_id,
            tasks: tasks.to_vec(),
            next_states: vec![exit_id],
            is_exit: false,
        });
        return entry_id;
    }

    let split = rng.gen_range(0..=tasks.len());
    let (left, right) = tasks.split_at(split);

    match rng.gen_range(0..4) {
        0 => { // Simple Sequence: [Left] -> [Right] -> exit_id
            let r_entry = build_topology_recursive(right, exit_id, nodes, rng, depth + 1);
            build_topology_recursive(left, r_entry, nodes, rng, depth + 1)
        },
        1 => { // Branching Junk: [Left] -> (Main: [Right] -> exit_id | Junk: [Junk] -> exit_id)
            let r_entry = build_topology_recursive(right, exit_id, nodes, rng, depth + 1);
            let junk_id = rng.gen::<u32>();
            let mut rs_c = 0u32;
            nodes.push(GraphNode {
                id: junk_id,
                tasks: vec![(0, generate_ghost(rng.gen(), rng, None, &mut rs_c))],
                next_states: vec![exit_id],
                is_exit: false,
            });

            let branch_id = rng.gen::<u32>();
            nodes.push(GraphNode {
                id: branch_id,
                tasks: Vec::new(),
                next_states: vec![r_entry, junk_id],
                is_exit: false,
            });

            build_topology_recursive(left, branch_id, nodes, rng, depth + 1)
        },
        2 => { // Fake Parallelism (Opaque Branch): Branch -> ([Left] -> [Right] -> exit_id | Decoy -> Trap)
            let r_entry = build_topology_recursive(right, exit_id, nodes, rng, depth + 1);
            let l_entry = build_topology_recursive(left, r_entry, nodes, rng, depth + 1);

            let decoy_id = rng.gen::<u32>();
            nodes.push(GraphNode {
                id: decoy_id,
                tasks: vec![(0, quote! { final_res = Some(String::new()); })],
                next_states: Vec::new(),
                is_exit: true,
            });

            let branch_id = rng.gen::<u32>();
            nodes.push(GraphNode {
                id: branch_id,
                tasks: Vec::new(),
                next_states: vec![l_entry, decoy_id],
                is_exit: false,
            });
            branch_id
        },
        _ => { // Diamond Merge: [Left] -> Branch -> (Mid1 | Mid2) -> Merge -> [Right] -> exit_id
            let r_entry = build_topology_recursive(right, exit_id, nodes, rng, depth + 1);

            let merge_id = rng.gen::<u32>();
            nodes.push(GraphNode {
                id: merge_id,
                tasks: Vec::new(),
                next_states: vec![r_entry],
                is_exit: false,
            });

            let m1_id = rng.gen::<u32>();
            let mut rs_c1 = 0u32;
            nodes.push(GraphNode {
                id: m1_id,
                tasks: vec![(0, generate_ghost(rng.gen(), rng, None, &mut rs_c1))],
                next_states: vec![merge_id],
                is_exit: false,
            });

            let m2_id = rng.gen::<u32>();
            let mut rs_c2 = 0u32;
            nodes.push(GraphNode {
                id: m2_id,
                tasks: vec![(0, generate_ghost(rng.gen(), rng, None, &mut rs_c2))],
                next_states: vec![merge_id],
                is_exit: false,
            });

            let branch_id = rng.gen::<u32>();
            nodes.push(GraphNode {
                id: branch_id,
                tasks: Vec::new(),
                next_states: vec![m1_id, m2_id],
                is_exit: false,
            });

            build_topology_recursive(left, branch_id, nodes, rng, depth + 1)
        }
    }
}

fn generate_fractal_topology(tasks: &[(u32, TokenStream2)], rng: &mut impl Rng) -> Topology {
    let mut nodes = Vec::new();
    let exit_id = rng.gen::<u32>();

    nodes.push(GraphNode {
        id: exit_id,
        tasks: Vec::new(),
        next_states: Vec::new(),
        is_exit: true,
    });

    let entry_id = build_topology_recursive(tasks, exit_id, &mut nodes, rng, 0);

    Topology { nodes, entry_id }
}

fn generate_advanced_topology(num_blocks: usize, rng: &mut impl Rng) -> Topology {
    let mut nodes = Vec::new();
    let mut ids: Vec<u32> = (0..num_blocks as u32 + 2).map(|_| rng.gen::<u32>()).collect();
    ids.sort();
    ids.dedup();
    while ids.len() < num_blocks + 2 {
        ids.push(rng.gen());
        ids.sort();
        ids.dedup();
    }
    ids.shuffle(rng);

    let entry_id = ids[0];
    let exit_id = ids[num_blocks + 1];

    for i in 0..num_blocks + 1 {
        let current_id = ids[i];
        let next_id = if i + 1 < num_blocks + 1 { ids[i + 1] } else { exit_id };

        let mut next_states = vec![next_id];
        // Add some random edges to other nodes (junk paths)
        if rng.gen_bool(0.3) && num_blocks > 1 {
            let junk_target = ids[rng.gen_range(0..num_blocks + 1)];
            if junk_target != current_id && junk_target != next_id {
                next_states.push(junk_target);
            }
        }

        nodes.push(GraphNode {
            id: current_id,
            tasks: Vec::new(),
            next_states,
            is_exit: false,
        });
    }

    nodes.push(GraphNode {
        id: exit_id,
        tasks: Vec::new(),
        next_states: Vec::new(),
        is_exit: true,
    });

    Topology { nodes, entry_id }
}

fn fill_topology_with_tasks(
    mut topology: Topology,
    tasks: &[(u32, TokenStream2)],
    rng: &mut impl Rng,
) -> Topology {
    let num_real_nodes = topology.nodes.len() - 1;
    let mut task_idx = 0;

    for i in 0..num_real_nodes {
        let remaining_tasks = tasks.len() - task_idx;
        let remaining_nodes = num_real_nodes - i;

        let take = if remaining_nodes == 1 {
            remaining_tasks
        } else {
            rng.gen_range(1..=(remaining_tasks - (remaining_nodes - 1)).max(1))
        };

        for _ in 0..take {
            if task_idx < tasks.len() {
                topology.nodes[i].tasks.push(tasks[task_idx].clone());
                task_idx += 1;
            }
        }

        // Inject some ghost tasks into every node
        for _ in 0..rng.gen_range(0..3) {
            let mut rs_c = 0u32;
            let g = generate_ghost(rng.gen(), rng, None, &mut rs_c);
            topology.nodes[i].tasks.push((0, g));
        }
    }

    // Exit node can also have some ghost tasks
    for _ in 0..rng.gen_range(1..3) {
        let mut rs_c = 0u32;
        let g = generate_ghost(rng.gen(), rng, None, &mut rs_c);
        topology.nodes.last_mut().unwrap().tasks.push((0, g));
    }

    topology
}

fn generate_interpreter_cfg(
    topology: Topology,
    initial_input_var: &Ident,
    m_var: &Ident,
    rs_var: &Ident,
    aux_var: &Ident,
    dispatch_name: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let mut arms = Vec::new();
    let s_n = Ident::new("node_id", Span::call_site());
    let final_res = Ident::new("final_res", Span::call_site());

    for node in &topology.nodes {
        let node_id = node.id;
        let mut node_logic = Vec::new();
        for (id, junk) in &node.tasks {
            if *id == 0 {
                node_logic.push(quote! { #junk });
            } else {
                node_logic.push(quote! {
                    let (res, next_rs) = #dispatch_name(#id ^ #rs_var, &#m_var, #rs_var, &mut #aux_var);
                    #m_var = res; #rs_var = next_rs; #junk
                });
            }
        }

        let next_node_update = if node.is_exit {
            quote! { break; }
        } else if node.next_states.len() == 1 {
            let next_id = node.next_states[0];
            quote! { #s_n = #next_id; }
        } else {
            // Branching logic
            let op = generate_opaque_predicate(rs_var, rng);
            let true_id = node.next_states[0];
            let false_id = node.next_states[1];
            quote! {
                if #op {
                    #s_n = #true_id;
                } else {
                    #s_n = #false_id;
                }
            }
        };

        arms.push(quote! {
            #node_id => {
                #(#node_logic)*
                #next_node_update
            }
        });
    }

    let fr = generate_fragmented_string_recovery(m_var, rs_var, rng);
    let entry_id = topology.entry_id;

    quote! {
        {
            let mut #s_n = #entry_id;
            let mut #m_var: Vec<u8> = #initial_input_var.clone();
            let mut #rs_var = 0u32;
            let mut #final_res: Option<String> = None;
            loop {
                match #s_n {
                    #(#arms)*
                    _ => break,
                }
            }
            #final_res.unwrap_or_else(|| #fr)
        }
    }
}

fn generate_cfg_node(
    tasks: &[(u32, TokenStream2)],
    m_var: &Ident,
    rs_var: &Ident,
    aux_var: &Ident,
    dispatch_name: &Ident,
    rng: &mut impl Rng,
    depth: usize,
    cc_var: Option<&Ident>,
) -> TokenStream2 {
    if tasks.is_empty() { return quote! {}; }

    let cc_inc = if let Some(cc) = cc_var { quote! { #cc += 1; } } else { quote! {} };

    if tasks.len() == 1 || depth >= 4 {
        let mut st = Vec::new();
        for (id, junk) in tasks {
            st.push(quote! {
                let (res, next_rs) = #dispatch_name(#id ^ #rs_var, &#m_var, #rs_var, &mut #aux_var);
                #m_var = res;
                #rs_var = next_rs;
                #cc_inc
                #junk
            });
        }
        return quote! { #(#st)* };
    }

    let split_idx = rng.gen_range(1..tasks.len());
    let (left, right) = tasks.split_at(split_idx);

    match rng.gen_range(0..5) {
        0 => { // Sequence
            let l = generate_cfg_node(left, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            let r = generate_cfg_node(right, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            quote! { #l #r }
        },
        1 => { // Scrambled FSM Node (Order Preserving)
            let mut arms = Vec::new();
            let s_n = Ident::new(&format!("s_{}_{}", depth, rng.gen::<u32>()), Span::call_site());
            let mut states: Vec<usize> = (0..left.len()).collect();
            states.shuffle(rng);
            let exit_s = left.len() + 7;

            for i in 0..left.len() {
                let (id, junk) = &left[i];
                let current_s = states[i];
                let next_s = if i + 1 < left.len() { states[i + 1] } else { exit_s };
                arms.push(quote! {
                    #current_s => {
                        let (res, next_rs) = #dispatch_name(#id ^ #rs_var, &#m_var, #rs_var, &mut #aux_var);
                        #m_var = res;
                        #rs_var = next_rs;
                        #s_n = #next_s;
                        #cc_inc
                        #junk
                    }
                });
            }
            let start_s = states[0];
            let l_node = quote! {
                let mut #s_n = #start_s;
                while #s_n != #exit_s {
                    match #s_n {
                        #(#arms)*
                        _ => break,
                    }
                }
            };
            let r_node = generate_cfg_node(right, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            quote! { #l_node #r_node }
        },
        2 => { // Opaque Predicate Wrapper
            let op = generate_opaque_predicate(rs_var, rng);
            let l = generate_cfg_node(left, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            let r = generate_cfg_node(right, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            quote! {
                if #op { #l } else { #l }
                #r
            }
        },
        3 => { // Double-Buffered Node
            let m2 = Ident::new(&format!("m2_{}_{}", depth, rng.gen::<u32>()), Span::call_site());
            let l = generate_cfg_node(left, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            let r = generate_cfg_node(right, &m2, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            quote! {
                #l
                let mut #m2: Vec<u8> = #m_var.clone();
                #r
                #m_var = #m2;
            }
        },
        _ => { // Loop-Jump
            let l = generate_cfg_node(left, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            let r = generate_cfg_node(right, m_var, rs_var, aux_var, dispatch_name, rng, depth + 1, cc_var);
            let loop_label = syn::Lifetime::new(&format!("'L_{}_{}", depth, rng.gen::<u32>()), Span::call_site());
            quote! {
                #loop_label: loop {
                    #l
                    break #loop_label;
                }
                #r
            }
        }
    }
}

fn generate_trampoline_cfg(
    tasks: &[(u32, TokenStream2)],
    initial_input_var: &Ident,
    dispatch_name: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let mut blocks = Vec::new();
    let mut current_idx = 0;
    while current_idx < tasks.len() {
        let size = rng.gen_range(1..=3).min(tasks.len() - current_idx);
        blocks.push(&tasks[current_idx..current_idx + size]);
        current_idx += size;
    }

    let mut arms = Vec::new();
    let ctx_n = Ident::new("ctx", Span::call_site());
    let m_n = Ident::new("m", Span::call_site());
    let rs_n = Ident::new("rs", Span::call_site());
    let aux_n = Ident::new("aux", Span::call_site());

    for (i, block) in blocks.iter().enumerate() {
        let mut block_logic = Vec::new();
        for (id, junk) in *block {
            block_logic.push(quote! {
                let (res, next_rs) = #dispatch_name(#id ^ #ctx_n.#rs_n, &#ctx_n.#m_n, #ctx_n.#rs_n, &mut #ctx_n.#aux_n);
                #ctx_n.#m_n = res; #ctx_n.#rs_n = next_rs; #junk
            });
        }

        let next_step = if i + 1 < blocks.len() {
            let next_idx = i + 1;
            quote! { Some(#next_idx) }
        } else {
            quote! { None }
        };

        arms.push(quote! {
            #i => {
                #(#block_logic)*
                #next_step
            }
        });
    }

    let fr = generate_fragmented_string_recovery(&Ident::new("m", Span::call_site()), &Ident::new("rs", Span::call_site()), rng);

    quote! {
        {
            struct Ctx { m: Vec<u8>, rs: u32, aux: Vec<u8> }
            let mut #ctx_n = Ctx { m: #initial_input_var.clone(), rs: 0, aux: Vec::new() };
            let mut next_idx = Some(0usize);
            while let Some(idx) = next_idx {
                next_idx = match idx {
                    #(#arms)*
                    _ => None,
                };
            }
            let m = #ctx_n.m;
            let rs = #ctx_n.rs;
            #fr
        }
    }
}

fn generate_unbounded_cfg_graph(
    tasks: &[(u32, TokenStream2)],
    initial_input_var: &Ident,
    m_var: &Ident,
    rs_var: &Ident,
    aux_var: &Ident,
    dispatch_name: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let mut blocks = Vec::new();
    let mut current_idx = 0;
    while current_idx < tasks.len() {
        let size = rng.gen_range(1..=3).min(tasks.len() - current_idx);
        blocks.push(&tasks[current_idx..current_idx + size]);
        current_idx += size;
    }

    let state_ids: Vec<u32> = (0..blocks.len()).map(|_| rng.gen::<u32>()).collect();
    let exit_state = rng.gen::<u32>();

    let mut path_hash = 0u32;
    let mut arms = Vec::new();
    let s_n = Ident::new("s", Span::call_site());
    let ph_n = Ident::new("ph", Span::call_site());
    let loop_label = syn::Lifetime::new(&format!("'L_{}", rng.gen::<u32>()), Span::call_site());

    for (i, block) in blocks.iter().enumerate() {
        let curr_s = state_ids[i];
        let next_s = if i + 1 < blocks.len() { state_ids[i + 1] } else { exit_state };

        path_hash = path_hash.wrapping_add(curr_s).rotate_left(1u32);

        let mut block_logic = Vec::new();
        for (id, junk) in *block {
            block_logic.push(quote! {
                let (res, next_rs) = #dispatch_name(#id ^ #rs_var, &#m_var, #rs_var, &mut #aux_var);
                #m_var = res; #rs_var = next_rs; #junk
            });
        }

        arms.push(quote! {
            #curr_s => {
                #(#block_logic)*
                #ph_n = #ph_n.wrapping_add(#s_n).rotate_left(1u32);
                #s_n = #next_s;
            }
        });
    }

    let fr = generate_fragmented_string_recovery(m_var, rs_var, rng);
    arms.push(quote! {
        #exit_state => {
            if #ph_n == #path_hash {
                break #loop_label #fr;
            } else {
                break #loop_label String::new();
            }
        }
    });

    let start_s = state_ids[0];
    quote! {
        {
            let mut #s_n = #start_s;
            let mut #ph_n = 0u32;
            let mut #m_var: Vec<u8> = #initial_input_var.clone();
            let mut #rs_var = 0u32;
            #loop_label: loop {
                match #s_n {
                    #(#arms)*
                    _ => break #loop_label String::new(),
                }
            }
        }
    }
}

fn generate_super_vm(
    tasks: &[(u32, TokenStream2)],
    initial_input_var: &Ident,
    dispatch_name: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let mut bytecode = Vec::new();
    let mut arms = Vec::new();

    let op_exec = rng.gen_range(1..64u8);
    let op_mov  = rng.gen_range(65..128u8);
    let op_swap = rng.gen_range(129..192u8);
    let op_junk = rng.gen_range(193..254u8);

    for (id, junk) in tasks {

        let task_op = rng.gen::<u8>();
        let reg_idx = 0u8;

        bytecode.push(op_exec);
        bytecode.push(task_op);
        bytecode.push(reg_idx);
        bytecode.push(rng.gen());

        arms.push(quote! {
            (#op_exec, #task_op) => {
                let r_idx = bc[pc + 2] as usize;
                let (res, next_rs) = #dispatch_name(#id ^ rs, &regs[r_idx], rs, &mut aux_buf);
                regs[r_idx] = res;
                rs = next_rs;
                {
                    let db = &mut regs[r_idx];
                    let mut rs_junk = rs;
                    #junk
                    rs = rs_junk;
                }
            }
        });
    }

    let bc_lit = Literal::byte_string(&bytecode);
    let fr = generate_fragmented_string_recovery(&Ident::new("final_m", Span::call_site()), &Ident::new("rs", Span::call_site()), rng);

    quote! {
        {
            let bc = #bc_lit;
            let mut pc = 0usize;
            let mut regs: [Vec<u8>; 4] = [
                #initial_input_var.clone(),
                #initial_input_var.clone(),
                #initial_input_var.clone(),
                #initial_input_var.clone(),
            ];
            let mut aux_buf: Vec<u8> = Vec::new();
            let mut rs = 0u32;
            let mut v_noise = 0u32;

            while pc < bc.len() {
                let inst = bc[pc];
                let sub  = bc[pc + 1];
                match (inst, sub) {
                    #(#arms)*
                    (#op_mov, _) => {
                        let src = bc[pc + 1] as usize;
                        let dst = bc[pc + 2] as usize;
                        if src < 4 && dst < 4 { regs[dst] = regs[src].clone(); }
                    }
                    (#op_swap, _) => {
                        let r1 = bc[pc + 1] as usize;
                        let r2 = bc[pc + 2] as usize;
                        if r1 < 4 && r2 < 4 { regs.swap(r1, r2); }
                    }
                    (#op_junk, _) => {
                        v_noise = v_noise.wrapping_add(bc[pc + 2] as u32).rotate_right(3u32);
                    }
                    _ => {
                        v_noise = v_noise.wrapping_sub(pc as u32 ^ sub as u32);
                    }
                }
                pc += 4;
            }
            let _ = v_noise;
            let final_m = regs[0].clone();
            #fr
        }
    }
}

fn generate_professional_vm(
    tasks: &[(u32, TokenStream2)],
    initial_input_var: &Ident,
    dispatch_name: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let mut bytecode = Vec::new();
    let mut arms = Vec::new();

    let salt = rng.gen::<u8>();
    let encode = |op: u8| -> u8 { op.wrapping_add(salt).rotate_right(3u32) };

    let mut get_aliases = |count: usize| -> Vec<u8> {
        (0..count).map(|_| rng.gen::<u8>()).collect()
    };

    let op_exec_aliases = get_aliases(3);
    let op_push_aliases = get_aliases(2);
    let op_pop_aliases  = get_aliases(2);
    let op_add_aliases  = get_aliases(2);
    let op_xor_aliases  = get_aliases(2);
    let op_mov_aliases  = get_aliases(2);
    let op_jmp_aliases  = get_aliases(2);
    let op_junk_aliases = get_aliases(3);

    let mut current_reg = 0u8;

    for (id, junk) in tasks {

        // Register hopping
        let next_reg = rng.gen_range(0..8u8);
        if next_reg != current_reg {
            let mov_op = *op_mov_aliases.choose(rng).unwrap();
            bytecode.push(encode(mov_op));
            bytecode.push(current_reg);
            bytecode.push(next_reg);
            bytecode.push(rng.gen());
            current_reg = next_reg;
        }

        let exec_op = *op_exec_aliases.choose(rng).unwrap();
        let task_op = rng.gen::<u8>();
        bytecode.push(encode(exec_op));
        bytecode.push(task_op);
        bytecode.push(current_reg);
        bytecode.push(rng.gen());

        arms.push(quote! {
            (#exec_op, #task_op) => {
                let r_idx = bc[pc + 2] as usize;
                let (res, next_rs) = #dispatch_name(#id ^ rs, &regs[r_idx], rs, &mut aux_buf);
                regs[r_idx] = res;
                rs = next_rs;
                {
                    let db = &mut regs[r_idx];
                    let mut rs_junk = rs;
                    #junk
                    rs = rs_junk;
                }
            }
        });
    }

    let bc_lit = Literal::byte_string(&bytecode);
    let fr = generate_fragmented_string_recovery(&Ident::new("final_m", Span::call_site()), &Ident::new("rs", Span::call_site()), rng);

    quote! {
        {
            let bc = #bc_lit;
            let mut pc = 0usize;
            let mut regs: [Vec<u8>; 8] = [
                #initial_input_var.clone(), #initial_input_var.clone(),
                #initial_input_var.clone(), #initial_input_var.clone(),
                #initial_input_var.clone(), #initial_input_var.clone(),
                #initial_input_var.clone(), #initial_input_var.clone(),
            ];
            let mut stk: Vec<Vec<u8>> = Vec::new();
            let mut aux_buf: Vec<u8> = Vec::new();
            let mut rs = 0u32;
            let mut v_noise = 0u32;

            while pc < bc.len() {
                let inst = (bc[pc].rotate_left(3u32)).wrapping_sub(#salt);
                let sub  = bc[pc + 1];
                match (inst, sub) {
                    #(#arms)*
                    (inst, _) if [#(#op_push_aliases),*].contains(&inst) => {
                        let r_idx = bc[pc + 1] as usize;
                        if r_idx < 8 { stk.push(regs[r_idx].clone()); }
                    }
                    (inst, _) if [#(#op_pop_aliases),*].contains(&inst) => {
                        let r_idx = bc[pc + 1] as usize;
                        if r_idx < 8 { if let Some(v) = stk.pop() { regs[r_idx] = v; } }
                    }
                    (inst, _) if [#(#op_add_aliases),*].contains(&inst) => {
                        let r_s = bc[pc + 1] as usize;
                        let r_d = bc[pc + 2] as usize;
                        if r_s < 8 && r_d < 8 {
                             let src = regs[r_s].clone();
                             for (i, b) in regs[r_d].iter_mut().enumerate() {
                                 if !src.is_empty() {
                                     *b = b.wrapping_add(src[i % src.len()]);
                                 }
                             }
                        }
                    }
                    (inst, _) if [#(#op_xor_aliases),*].contains(&inst) => {
                        let r_s = bc[pc + 1] as usize;
                        let r_d = bc[pc + 2] as usize;
                        if r_s < 8 && r_d < 8 {
                             let src = regs[r_s].clone();
                             for (i, b) in regs[r_d].iter_mut().enumerate() {
                                 if !src.is_empty() {
                                     *b ^= src[i % src.len()];
                                 }
                             }
                        }
                    }
                    (inst, _) if [#(#op_mov_aliases),*].contains(&inst) => {
                        let r_s = bc[pc + 1] as usize;
                        let r_d = bc[pc + 2] as usize;
                        if r_s < 8 && r_d < 8 { regs[r_d] = regs[r_s].clone(); }
                    }
                    (inst, _) if [#(#op_jmp_aliases),*].contains(&inst) => {
                        pc = (pc as isize + bc[pc + 2] as isize) as usize;
                        continue;
                    }
                    (inst, _) if [#(#op_junk_aliases),*].contains(&inst) => {
                         v_noise = v_noise.wrapping_add(sub as u32).rotate_left(3u32);
                    }
                    _ => {
                        v_noise = v_noise.wrapping_sub(pc as u32 ^ sub as u32);
                    }
                }
                pc += 4;
            }
            let final_m = regs[#current_reg as usize].clone();
            #fr
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
    let m_n = Ident::new("m", Span::call_site());
    let tasks: Vec<(u32, TokenStream2)> = transform_ids.iter().cloned().zip(junk_tokens.iter().cloned()).collect();

    match rng.gen_range(0..15) {
        0 => { // State machine (Scrambled)
            let mut arms = Vec::new();
            let s_n = Ident::new("s", Span::call_site());
            let m_n = Ident::new("m", Span::call_site());
            
            let mut shuffled: Vec<usize> = (0..transform_ids.len()).collect();
            shuffled.shuffle(rng);

            let mut next_state = vec![0usize; transform_ids.len()];
            for i in 0..transform_ids.len() - 1 {
                next_state[i] = shuffled[i+1];
            }

            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                let current_s = shuffled[i];
                let op = generate_opaque_predicate(&rs_n, rng);
                
                if i < transform_ids.len() - 1 {
                    let ns = next_state[i];
                    arms.push(quote! {
                        #current_s => {
                            if #op {
                                let (res_data, next_rs) = #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var);
                                #m_n = res_data;
                                #rs_n = next_rs;
                                #s_n = #ns;
                            } else {
                                #s_n = 0xDEAD;
                            }
                            #junk
                        }
                    });
                } else {
                    let fb_n = Ident::new("fb", Span::call_site());
                    let nr_n = Ident::new("nr", Span::call_site());
                    let fr = generate_fragmented_string_recovery(&fb_n, &nr_n, rng);
                    arms.push(quote! {
                        #current_s => {
                            let (res_data, next_rs) = #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var);
                            let #fb_n = res_data;
                            let #nr_n = next_rs;
                            break #fr;
                        }
                    });
                }
            }
            arms.push(quote! { _ => break String::new(), });
            
            let initial_s = shuffled[0];
            quote! {
                let mut #s_n = #initial_s;
                let mut #m_n: Vec<u8> = #initial_input_var.clone();
                let mut #rs_n = 0u32;
                loop { match #s_n { #(#arms)* } }
            }
        },
        1 => { // Nested blocks (Enhanced)
            if transform_ids.is_empty() { return quote! { String::new() }; }
            
            let last_idx = transform_ids.len() - 1;
            let last_id = transform_ids[last_idx];
            let last_input = Ident::new(&format!("nd_{}", last_idx), Span::call_site());
            let last_bytes = Ident::new("lb", Span::call_site());
            let nr_n = Ident::new("nr_last", Span::call_site());
            let fr = generate_fragmented_string_recovery(&last_bytes, &nr_n, rng);
            
            let op_final = generate_opaque_predicate(&rs_n, rng);

            let mut nl = quote! { 
                { 
                    let (res_data, next_rs) = #dispatch_name(#last_id ^ #rs_n, &#last_input, #rs_n, &mut #aux_var);
                    let #last_bytes = if #op_final { res_data } else { Vec::new() };
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
                let op = generate_opaque_predicate(&rs_n, rng);
                
                nl = quote! { 
                    { 
                        let (res_data, next_rs_val) = #dispatch_name(#id ^ #rs_n, &#ci, #rs_n, &mut #aux_var);
                        let mut #rs_n = next_rs_val; 
                        let #ob = if #op { res_data } else { #ci.clone() };
                        #junk 
                        let mut #ni = #ob; 
                        #nl 
                    } 
                };
            }
            
            let fv = Ident::new("nd_0", Span::call_site());
            quote! { { let mut #fv: Vec<u8> = #initial_input_var.clone(); let mut #rs_n = 0u32; #nl } }
        },
        2 => { // Linear with Divergent Paths
            let mut st = Vec::new();
            let cv = Ident::new("cv", Span::call_site());
            st.push(quote! { let mut #cv: Vec<u8> = #initial_input_var.clone(); });
            st.push(quote! { let mut #rs_n = 0u32; });
            
            for (i, &id) in transform_ids.iter().enumerate() {
                let nb = Ident::new(&format!("b_{}", i), Span::call_site());
                let junk = &junk_tokens[i];
                let op = generate_opaque_predicate(&rs_n, rng);
                
                st.push(quote! { 
                    let (#nb, nr_next) = if #op {
                        #dispatch_name(#id ^ #rs_n, &#cv, #rs_n, &mut #aux_var)
                    } else {
                        (#cv.clone(), #rs_n)
                    };
                    #rs_n = nr_next;
                    #junk
                });
                
                if i < transform_ids.len() - 1 {
                    st.push(quote! { #cv = #nb; });
                } else {
                    let fr = generate_fragmented_string_recovery(&nb, &rs_n, rng);
                    st.push(quote! { let frs = #fr; });
                }
            }
            quote! { { #(#st)* frs } }
        },
        3 => { // Bytecode VM
            let ops_n = Ident::new(&format!("ops_{}", rng.gen::<u32>()), Span::call_site());
            let pc_n = Ident::new("pc", Span::call_site());
            let m_n = Ident::new("m", Span::call_site());

            let mut arms = Vec::new();
            for (i, &id) in transform_ids.iter().enumerate() {
                let junk = &junk_tokens[i];
                arms.push(quote! {
                    #i => {
                        let (res_data, next_rs) = #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var);
                        #m_n = res_data;
                        #rs_n = next_rs;
                        #junk
                    }
                });
            }

            let fb_n = Ident::new("fb", Span::call_site());
            let nr_n = Ident::new("nr", Span::call_site());
            let fr = generate_fragmented_string_recovery(&fb_n, &nr_n, rng);

            quote! {
                let mut #m_n: Vec<u8> = #initial_input_var.clone();
                let mut #rs_n = 0u32;
                let mut #pc_n = 0usize;
                let #ops_n = [#( #transform_ids ),*];
                while #pc_n < #ops_n.len() {
                    match #pc_n {
                        #(#arms)*
                        _ => {}
                    }
                    #pc_n += 1;
                }
                let #fb_n = #m_n;
                let #nr_n = #rs_n;
                #fr
            }
        },
        4 => { // Divergent/Convergent Paths
            let mut st = Vec::new();
            st.push(quote! { let mut #m_n: Vec<u8> = #initial_input_var.clone(); });
            st.push(quote! { let mut #rs_n = 0u32; });
            for (_i, (id, junk)) in tasks.iter().enumerate() {
                let op = generate_opaque_predicate(&rs_n, rng);
                st.push(quote! {
                    let (d, r) = if #op {
                        #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var)
                    } else {
                        #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var)
                    };
                    #m_n = d; #rs_n = r; #junk
                });
            }
            let fr = generate_fragmented_string_recovery(&m_n, &rs_n, rng);
            quote! { { #(#st)* #fr } }
        },
        5 => { // Recursive Continuation
            let unfold_n = Ident::new("unfold", Span::call_site());
            let mut cases = Vec::new();
            for (i, (id, junk)) in tasks.iter().enumerate() {
                cases.push(quote! {
                    #i => {
                        let (res_data, next_rs) = #dispatch_name(#id ^ rs_val, &m_val, rs_val, aux_val);
                        #junk
                        #unfold_n(#i + 1, res_data, next_rs, aux_val)
                    }
                });
            }
            let fb_n = Ident::new("fb", Span::call_site());
            let nr_n = Ident::new("nr", Span::call_site());
            let fr = generate_fragmented_string_recovery(&fb_n, &nr_n, rng);
            quote! {
                {
                    fn #unfold_n(idx: usize, m_val: Vec<u8>, rs_val: u32, aux_val: &mut Vec<u8>) -> String {
                        match idx {
                            #(#cases)*
                            _ => {
                                let #fb_n = m_val;
                                let #nr_n = rs_val;
                                #fr
                            }
                        }
                    }
                    #unfold_n(0, #initial_input_var.clone(), 0u32, &mut #aux_var)
                }
            }
        },
        6 => { // Truly Dynamic Recursive (Fragment Composition) with Stealth Completion
            let cc_n = Ident::new("cc", Span::call_site());
            let total = tasks.len();
            let cfg = generate_cfg_node(&tasks, &m_n, &rs_n, aux_var, dispatch_name, rng, 0, Some(&cc_n));
            let fr = generate_fragmented_string_recovery(&m_n, &rs_n, rng);
            quote! {
                let mut #m_n: Vec<u8> = #initial_input_var.clone();
                let mut #rs_n = 0u32;
                let mut #cc_n = 0usize;
                #cfg
                if #cc_n == #total {
                    #fr
                } else {
                    String::new()
                }
            }
        },
        7 => { // Dynamic FSM with Stealth Completion
            let s_n = Ident::new("s", Span::call_site());
            let mut arms = Vec::new();
            let mut shuffled: Vec<usize> = (0..tasks.len()).collect();
            shuffled.shuffle(rng);
            let mut next_states = vec![0usize; tasks.len()];
            for i in 0..tasks.len()-1 { next_states[i] = shuffled[i+1]; }
            let recovery_state = tasks.len() + 100 + rng.gen_range(0..100);
            next_states[tasks.len()-1] = recovery_state;
            for (i, (id, junk)) in tasks.iter().enumerate() {
                let curr_s = shuffled[i];
                let ns = next_states[i];
                arms.push(quote! {
                    #curr_s => {
                        let (res, next_rs) = #dispatch_name(#id ^ #rs_n, &#m_n, #rs_n, &mut #aux_var);
                        #m_n = res; #rs_n = next_rs; #s_n = #ns; #junk
                    }
                });
            }
            let fr = generate_fragmented_string_recovery(&m_n, &rs_n, rng);
            arms.push(quote! { #recovery_state => break #fr, });
            let start_s = shuffled[0];
            quote! {
                let mut #m_n: Vec<u8> = #initial_input_var.clone();
                let mut #rs_n = 0u32;
                let mut #s_n = #start_s;
                loop { match #s_n { #(#arms)* _ => break String::new(), } }
            }
        },
        8 => { // Register-style (Grounded)
            let r0 = Ident::new("r0", Span::call_site());
            let r1 = Ident::new("r1", Span::call_site());
            let r2 = Ident::new("r2", Span::call_site());
            let mut st = Vec::new();
            st.push(quote! { let mut #r0: Vec<u8> = #initial_input_var.clone(); let mut #r1: Vec<u8> = Vec::new(); let mut #r2: Vec<u8> = Vec::new(); });
            for (i, (id, junk)) in tasks.iter().enumerate() {
                let src = match i % 3 { 0 => &r0, 1 => &r1, _ => &r2 };
                let dst = match (i + 1) % 3 { 0 => &r0, 1 => &r1, _ => &r2 };
                st.push(quote! {
                    let (res, next_rs) = #dispatch_name(#id ^ #rs_n, &#src, #rs_n, &mut #aux_var);
                    #rs_n = next_rs; #dst = res; #junk
                });
            }
            let lr = match tasks.len() % 3 { 0 => &r0, 1 => &r1, _ => &r2 };
            let fr = generate_fragmented_string_recovery(lr, &rs_n, rng);
            quote! { { let mut #rs_n = 0u32; #(#st)* #fr } }
        },
        9 => { // Stack-based (Grounded)
             let stack_n = Ident::new("stk", Span::call_site());
             let mut st = Vec::new();
             st.push(quote! { let mut #stack_n: Vec<Vec<u8>> = vec![#initial_input_var.clone()]; });
             for (id, junk) in tasks {
                 st.push(quote! {
                     let cur = #stack_n.pop().unwrap_or_default();
                     let (res, next_rs) = #dispatch_name(#id ^ #rs_n, &cur, #rs_n, &mut #aux_var);
                     #rs_n = next_rs; #stack_n.push(res); #junk
                 });
             }
             let fr = generate_fragmented_string_recovery(&Ident::new("final_data", Span::call_site()), &rs_n, rng);
             quote! {
                 {
                     let mut #rs_n = 0u32;
                     #(#st)*
                     let final_data = #stack_n.pop().unwrap_or_default();
                     #fr
                 }
             }
        },
        10 => { // Unbounded Graph-Based CFG
            generate_unbounded_cfg_graph(&tasks, initial_input_var, &m_n, &rs_n, aux_var, dispatch_name, rng)
        },
        11 => { // First-Class Interpreter CFG
            let topo = generate_advanced_topology(tasks.len() / 2 + 1, rng);
            let filled = fill_topology_with_tasks(topo, &tasks, rng);
            generate_interpreter_cfg(filled, initial_input_var, &m_n, &rs_n, aux_var, dispatch_name, rng)
        },
        12 => { // Fractal Graph-Based CFG
            let topo = generate_fractal_topology(&tasks, rng);
            generate_interpreter_cfg(topo, initial_input_var, &m_n, &rs_n, aux_var, dispatch_name, rng)
        },
        13 => { // SuperVM Virtual Machine Renderer
            generate_super_vm(&tasks, initial_input_var, dispatch_name, rng)
        },
        14 => { // ProfessionalVM level renderer
            generate_professional_vm(&tasks, initial_input_var, dispatch_name, rng)
        },
        _ => { // Trampoline Dispatcher
            generate_trampoline_cfg(&tasks, initial_input_var, dispatch_name, rng)
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
    let mut num_layers = ((entropy % 3) + 4) as usize; // 4 to 6 layers
    if os.len() < 10 { num_layers = num_layers.max(6); }
    
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
    let rs_initial = 0u32;
    let lock_in_0 = (rs_initial ^ (rs_initial >> 13) ^ (rs_initial >> 21)) as u8;
    let lock_junk = (rs_junk_compile ^ (rs_junk_compile >> 13) ^ (rs_junk_compile >> 21)) as u8 ^ lock_in_0;

    let mut eb = Vec::with_capacity(cd.len());
    for &ob in &cd {
        let eb_b = (ob ^ lock_junk) ^ key;
        eb.push(eb_b);
        match ev {
            0 => key = key.wrapping_add(eb_b),
            1 => key = key.wrapping_sub(eb_b),
            _ => key = key.rotate_left(3u32),
        };
    }

    enum TaskInternal {
        Scramble(u32),
        Unscramble(u32),
        Corruption(u32, u8),
        Primitive(Primitive),
        Ghost(u8),
    }

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
        for mut p in primitives {
            // Phase 1: Semantic Role Shifting (Overlap)
            if rng.gen_bool(0.4) {
                p = match p {
                    Primitive::XorTransform { key } => if rng.gen_bool(0.5) { Primitive::CustomTransform { op: key, kind: 2 } } else { Primitive::MbaTransform { op: key, kind: 0 } },
                    Primitive::AddTransform { val } => if rng.gen_bool(0.5) { Primitive::CustomTransform { op: val, kind: 0 } } else { Primitive::MbaTransform { op: val, kind: 1 } },
                    Primitive::SubTransform { val } => if rng.gen_bool(0.5) { Primitive::CustomTransform { op: val, kind: 1 } } else { Primitive::MbaTransform { op: val, kind: 2 } },
                    Primitive::RotateLeft { rot } => {
                        if rng.gen_bool(0.5) {
                            let mut table = [0u8; 256];
                            for i in 0..256 { table[i] = (i as u8).rotate_left(rot as u32); }
                            Primitive::Map(table.to_vec())
                        } else {
                            Primitive::Rotate { rot: rot as u8 }
                        }
                    },
                    Primitive::RotateRight { rot } => {
                        Primitive::Rotate { rot: (8u32.wrapping_sub(rot % 8) % 8) as u8 }
                    },
                    _ => p,
                };
            }

            {
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
        if all_pos_indep && rng.gen_bool(0.3) {
            match rng.gen_range(0..2) {
                0 => {
                    final_primitives.insert(0, Primitive::Reverse);
                    final_primitives.push(Primitive::Reverse);
                },
                _ => {
                    let step = rng.gen_range(2..=5);
                    final_primitives.insert(0, Primitive::Interleave { step });
                    final_primitives.push(Primitive::Deinterleave { step });
                }
            }
        }

        tasks.push(TaskInternal::Scramble(seed_sc));
        if rng.gen_bool(0.2) {
            match rng.gen_range(0..2) {
                0 => {
                    let r = rng.gen_range(1..7);
                    tasks.push(TaskInternal::Primitive(Primitive::XorTransform { key: r }));
                    tasks.push(TaskInternal::Primitive(Primitive::Ghost { val: rng.gen() }));
                    tasks.push(TaskInternal::Primitive(Primitive::XorTransform { key: r }));
                },
                _ => {
                    let r = rng.gen_range(1..7);
                    tasks.push(TaskInternal::Primitive(Primitive::RotateLeft { rot: r }));
                    tasks.push(TaskInternal::Primitive(Primitive::Ghost { val: rng.gen() }));
                    tasks.push(TaskInternal::Primitive(Primitive::RotateRight { rot: r }));
                }
            }
        }
        for p in final_primitives {
            tasks.push(TaskInternal::Primitive(p));
            if rng.gen_bool(0.1) { tasks.push(TaskInternal::Ghost(rng.gen())); }
        }
        tasks.push(TaskInternal::Corruption(seed_corr, mask_corr));
        tasks.push(TaskInternal::Unscramble(seed_sc));
    }

    for _ in 0..5 {
        let pos = rng.gen_range(0..=tasks.len());
        tasks.insert(pos, TaskInternal::Ghost(rng.gen()));
    }

    let mut vt_c = Vec::new();
    let mut all_rids = Vec::new();
    let mut dc_junks = Vec::new();
    let salt = rng.gen::<u32>();
    let mult = rng.gen::<u32>() | 1;
    let mut rs = 0u32;

    let mut tasks_iter = tasks.into_iter().peekable();
    while tasks_iter.peek().is_some() {
        let group_size = rng.gen_range(1..=3);
        let mut task_codes = Vec::new();

        let mut arm_rs = rs;
        for _ in 0..group_size {
            if let Some(task) = tasks_iter.next() {
                let task_code = match task {
                    TaskInternal::Scramble(seed) => {
                        let (sc, _) = generate_index_scrambler(seed, &mut rng);
                        sc
                    },
                    TaskInternal::Unscramble(seed) => {
                        let (_, un) = generate_index_scrambler(seed, &mut rng);
                        un
                    },
                    TaskInternal::Corruption(seed, mask) => {
                        let (init, apply) = generate_state_corruption(seed, mask, &mut rng);
                        quote! { #init #apply }
                    },
                    TaskInternal::Primitive(p) => generate_primitive_dispatch_logic(&p, &mut rng, &mut arm_rs),
            TaskInternal::Ghost(val) => generate_ghost(val, &mut rng, Some(&Ident::new("rs", Span::call_site())), &mut arm_rs),
                };
                task_codes.push(task_code);
            }
        }

        let num_aliases = rng.gen_range(1..=3);
        let mut id_vals = Vec::new();
        for _ in 0..num_aliases {
            id_vals.push(rng.gen::<u32>());
        }
        let id_val = id_vals[0]; // Use the first one for the "real" identity in simulation

        let rs_salt = rng.gen::<u32>();
        let rs_variant = rng.gen_range(0..6);
        match rs_variant {
            0 => arm_rs = arm_rs.wrapping_add(id_val).rotate_left(5u32) ^ rs_salt,
            1 => arm_rs = (arm_rs ^ id_val).wrapping_sub(rs_salt).rotate_right(3u32),
            2 => arm_rs = arm_rs.wrapping_mul(id_val | 1).wrapping_add(rs_salt),
            3 => arm_rs = (arm_rs | id_val).wrapping_sub(arm_rs & id_val) ^ rs_salt,
            4 => arm_rs = (arm_rs & id_val).wrapping_add(arm_rs | id_val).wrapping_add(rs_salt),
            _ => arm_rs = arm_rs.wrapping_sub((!arm_rs) & id_val).wrapping_sub(rs_salt),
        }

        let id_mba = generate_mba_constant(id_val, &mut rng, 1);
        let rs_salt_mba = generate_mba_constant(rs_salt, &mut rng, 1);

        let core_rs_update = match rs_variant {
            0 => quote! { rs = rs.wrapping_add(#id_mba).rotate_left(5u32) ^ #rs_salt_mba; },
            1 => quote! { rs = (rs ^ #id_mba).wrapping_sub(#rs_salt_mba).rotate_right(3u32); },
            2 => quote! { rs = rs.wrapping_mul(#id_mba | 1).wrapping_add(#rs_salt_mba); },
            3 => quote! { rs = (rs | #id_mba).wrapping_sub(rs & #id_mba) ^ #rs_salt_mba; },
            4 => quote! { rs = (rs & #id_mba).wrapping_add(rs | #id_mba).wrapping_add(#rs_salt_mba); },
            _ => quote! { rs = rs.wrapping_sub((!rs) & #id_mba).wrapping_sub(#rs_salt_mba); },
        };
        
        // Mandatory junk INSIDE the v-table arm
        let arm_junk = generate_junk_logic(&mut rng, Some(&Ident::new("data", Span::call_site())), Some(&Ident::new("rs", Span::call_site())), &mut arm_rs);

        let mut arm_keys = Vec::new();
        for &id in &id_vals {
             let k = ((id.wrapping_mul(mult) ^ salt).rotate_left((rs & 0x7) as u32 + 1) ^ rs).wrapping_add(0x1337);
             arm_keys.push(k);
        }
        
        vt_c.push(quote! {
            #(#arm_keys)|* => {
                let mut data = data.to_vec();
                let mut rs = rs_in;
                let lock_in = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock_in; }
                #(#task_codes)*
                #core_rs_update
                #arm_junk
                let lock_out = (rs ^ (rs >> 13) ^ (rs >> 21)) as u8;
                for b in data.iter_mut() { *b ^= lock_out; }
                (data, rs)
            }
        });
        
        // Decorative junk for the decode chain (doesn't modify rs)
        let mut dummy_rs = 0u32;
        let dc_junk = generate_junk_logic(&mut rng, None, None, &mut dummy_rs);
        dc_junks.push(dc_junk);

        all_rids.push(id_vals);
        rs = arm_rs;
    }

    let mut selected_rids = Vec::new();
    for aliases in &all_rids {
        selected_rids.push(*aliases.choose(&mut rng).unwrap());
    }

    let s_n = Ident::new(&format!("o_{}", rng.gen::<u32>()), Span::call_site());
    let m_n = Ident::new(&format!("m_{}", rng.gen::<u32>()), Span::call_site());
    let d_n = Ident::new(&format!("d_{}", rng.gen::<u32>()), Span::call_site());
    let i_v = Ident::new("ds", Span::call_site());
    let a_v = Ident::new("aux", Span::call_site());
    
    let gate_n = Ident::new(&format!("g_{}", rng.gen::<u32>()), Span::call_site());
    let gate_junk = if rng.gen_bool(0.5) {
        let dead = rng.gen::<u32>();
        quote! { if id == #dead { return (data.to_vec(), rs); } }
    } else {
        quote! {}
    };
    let dc = generate_polymorphic_decode_chain(&selected_rids, &dc_junks, &i_v, &gate_n, &a_v, &mut rng);
    
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
                fn #d_n(id: u32, data: &[u8], rs_in: u32, aux: &mut Vec<u8>) -> (Vec<u8>, u32) {
                    let sel = (((id ^ rs_in).wrapping_mul(#mult) ^ #salt).rotate_left(((rs_in & 0x7) as u32 + 1) as u32) ^ rs_in).wrapping_add(0x1337);
                    match sel {
                        #(#vt_c)*
                        _ => (data.to_vec(), rs_in)
                    }
                }
                let mut #a_v: Vec<u8> = Vec::new();
                let mut rs_junk = 0u32;
                let mut #d_b_i = { #rl #dl_c db };
                let mut #i_v = #d_b_i;
                fn #gate_n(id: u32, data: &[u8], rs: u32, aux: &mut Vec<u8>) -> (Vec<u8>, u32) {
                    #gate_junk
                    #d_n(id, data, rs, aux)
                }
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

    fn decode_bigint_direct_manual(data: &[u8], base: u128, total_bytes: u64) -> Vec<u8> {
        let mut leading_zeros = 0;
        for &v in data { if v == 0 { leading_zeros += 1; } else { break; } }
        let mut res = vec![0u32; 1];
        for &v in &data[leading_zeros..] {
            let mut carry = v as u64;
            for digit in res.iter_mut() {
                let prod = (*digit as u64) * (base as u64) + carry;
                *digit = prod as u32;
                carry = prod >> 32;
            }
            while carry > 0 { res.push(carry as u32); carry >>= 32; }
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
        while out.len() > total_bytes as usize { out.remove(0); }
        while out.len() < total_bytes as usize { out.insert(0, 0); }
        out
    }

    fn process_primitive_manual(p: &Primitive, b_data: &mut Vec<u8>, aux: &mut Vec<u8>) {
        match p {
            Primitive::Map(alphabet) => {
                let mut map = [255u8; 256];
                for (j, &c) in alphabet.iter().enumerate() { map[c as usize] = j as u8; }
                let mut out = Vec::new();
                for &b in b_data.iter() { let v = map[b as usize]; if v != 255 { out.push(v); } }
                *b_data = out;
            },
            Primitive::BitLoad { .. } | Primitive::BaseLoad { .. } => {
                aux.extend_from_slice(&b_data);
                b_data.clear();
            },
            Primitive::BitEmit { bits, total_bits } => {
                *b_data = decode_bits_manual(&aux, *bits, *total_bits);
                aux.clear();
            },
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
                for &v in b_data.iter() { if v == 0 { lz += 1; } else { break; } }
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
            Primitive::BitUnpack { bits, total_bits } => {
                *b_data = decode_bits_manual(&b_data, *bits, *total_bits);
            },
            Primitive::BitArithmetic { bits, total_bits } => {
                let mut out = Vec::new();
                let mut bc = 0u64;
                if *bits == 6 {
                    for chunk in b_data.chunks(4) {
                        let mut val = 0u64;
                        for (i, &idx) in chunk.iter().enumerate() { val |= (idx as u64) << (18 - i * 6); }
                        for i in (0..3).rev() { if bc < *total_bits { out.push(((val >> (i * 8)) & 0xff) as u8); bc += 8; } }
                    }
                } else if *bits == 5 {
                    for chunk in b_data.chunks(8) {
                        let mut val = 0u64;
                        for (i, &idx) in chunk.iter().enumerate() { val |= (idx as u64) << (35 - i * 5); }
                        for i in (0..5).rev() { if bc < *total_bits { out.push(((val >> (i * 8)) & 0xff) as u8); bc += 8; } }
                    }
                } else {
                    out = decode_bits_manual(&b_data, *bits, *total_bits);
                }
                *b_data = out;
            },
            Primitive::XorTransform { key } => {
                for b in b_data.iter_mut() { *b ^= key; }
            },
            Primitive::AddTransform { val } => {
                for b in b_data.iter_mut() { *b = b.wrapping_add(*val); }
            },
            Primitive::SubTransform { val } => {
                for b in b_data.iter_mut() { *b = b.wrapping_sub(*val); }
            },
            Primitive::Reverse => {
                b_data.reverse();
            },
            Primitive::BaseDirect { base, in_c, out_c, total_bytes } => {
                *b_data = decode_z85_manual(&b_data, *base, *in_c, *out_c, *total_bytes);
            },
            Primitive::BigIntDirect { base, total_bytes } => {
                *b_data = decode_bigint_direct_manual(&b_data, *base, *total_bytes);
            },
            Primitive::RotateLeft { rot } => {
                for b in b_data.iter_mut() { *b = b.rotate_left(*rot as u32); }
            },
            Primitive::RotateRight { rot } => {
                for b in b_data.iter_mut() { *b = b.rotate_right(*rot as u32); }
            },
            Primitive::ArithmeticChain { ops, kinds } => {
                for b in b_data.iter_mut() {
                    for i in 0..4usize {
                        let op = ops[i];
                        if (kinds >> i) & 1 == 0 { *b = b.wrapping_add(op); }
                        else { *b = b.wrapping_sub(op); }
                    }
                }
            },
            Primitive::SwapBuffers => {
                ::std::mem::swap(b_data, aux);
            },
            Primitive::Ghost { .. } => {},
            Primitive::MapXor { key } => {
                for b in b_data.iter_mut() { *b ^= key; }
            },
            Primitive::MapAdd { val } => {
                for b in b_data.iter_mut() { *b = b.wrapping_add(*val); }
            },
            Primitive::MapSub { val } => {
                for b in b_data.iter_mut() { *b = b.wrapping_sub(*val); }
            },
            Primitive::Interleave { step } => {
                let mut out = Vec::with_capacity(b_data.len());
                if b_data.len() > 0 {
                    for i in 0..*step {
                        let mut j = i;
                        while j < b_data.len() {
                            out.push(b_data[j]);
                            j += *step;
                        }
                    }
                }
                *b_data = out;
            },
            Primitive::Deinterleave { step } => {
                if b_data.len() > 0 {
                    let mut out = vec![0u8; b_data.len()];
                    let mut idx = 0;
                    for i in 0..*step {
                        let mut j = i;
                        while j < b_data.len() {
                            out[j] = b_data[idx];
                            idx += 1;
                            j += *step;
                        }
                    }
                    *b_data = out;
                }
            },
            Primitive::CustomTransform { op, kind } => {
                for b in b_data.iter_mut() {
                    match kind {
                        0 => *b = b.wrapping_add(*op),
                        1 => *b = b.wrapping_sub(*op),
                        2 => *b ^= op,
                        3 => *b = b.rotate_left((*op % 7 + 1) as u32),
                        _ => *b = b.rotate_right((*op % 7 + 1) as u32),
                    }
                }
            },
            Primitive::MapCombined { table, post_op, post_kind } => {
                for b in b_data.iter_mut() {
                    *b = table[*b as usize];
                    match post_kind {
                        0 => *b = b.wrapping_add(*post_op),
                        1 => *b = b.wrapping_sub(*post_op),
                        _ => *b ^= post_op,
                    }
                }
            },
            Primitive::MbaTransform { op, kind } => {
                match kind {
                    0 => for b in b_data.iter_mut() { *b ^= op; },
                    1 => for b in b_data.iter_mut() { *b = b.wrapping_add(*op); },
                    _ => for b in b_data.iter_mut() { *b = b.wrapping_sub(*op); },
                }
            },
            Primitive::BitPermute { permutation } => {
                for b in b_data.iter_mut() {
                    let v = *b;
                    let mut res = 0u8;
                    for (i, &src) in permutation.iter().enumerate() {
                        if (v & (1 << src)) != 0 { res |= 1 << i; }
                    }
                    *b = res;
                }
            },
            Primitive::Rotate { rot } => {
                let r = (*rot % 8) as u32;
                for b in b_data.iter_mut() { *b = b.rotate_left(r as u32); }
            },
            Primitive::BitFsm { key } => {
                let k_low = key & 0x0F;
                let k_high = key >> 4;
                for b in b_data.iter_mut() {
                    let mut high = (*b >> 4) & 0x0F;
                    let mut low = *b & 0x0F;
                    low ^= high ^ k_high;
                    high ^= low ^ k_low;
                    *b = (high << 4) | low;
                }
            },
            Primitive::BigIntPoly { base, total_bytes } => {
                *b_data = decode_bigint_direct_manual(&b_data, *base, *total_bytes);
            },
            Primitive::MapConv { k0 } => {
                let mut last = 0u8;
                for b in b_data.iter_mut() {
                    *b ^= k0 ^ last;
                    last = *b;
                }
            },
            Primitive::IdentityBranch { path_a, .. } => {
                for sp in path_a {
                    process_primitive_manual(sp, b_data, aux);
                }
            },
            Primitive::Noop { .. } | Primitive::Sync => {},
        }
    }

    #[test]
    fn test_hybrid_primitives() {
        let original = b"Hybrid Test".to_vec();

        // CustomTransform (Xor)
        let mut b_data = original.clone();
        for b in b_data.iter_mut() {
            let op = 0x55;
            let kind = 2; // XOR
            match kind {
                0 => *b = b.wrapping_add(op),
                1 => *b = b.wrapping_sub(op),
                2 => *b ^= op,
                _ => {},
            }
        }
        for b in b_data.iter_mut() { *b ^= 0x55; }
        assert_eq!(b_data, original);

        // MapCombined Equivalence
        let alphabet = b"ABC".to_vec();
        let data_orig = b"ABC".to_vec();
        // Manual Map simulation
        let mut map = [255u8; 256];
        for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
        let mut data_map = Vec::new();
        for &b in &data_orig {
            let v = map[b as usize];
            if v != 255 { data_map.push(v); }
        }

        let post_op = 10;
        let mut data_comb = Vec::new();
        for &b in &data_orig {
            let mut v = map[b as usize];
            if v != 255 {
                v = v.wrapping_add(post_op).wrapping_sub(post_op);
                data_comb.push(v);
            }
        }

        assert_eq!(data_comb, data_map);
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

        // Decoder B: BitArithmetic
        let mut decoded_b = Vec::new();
        let mut bc = 0u64;
        for chunk in indices.chunks(4) {
            let mut val = 0u64;
            for (i, &idx) in chunk.iter().enumerate() { val |= (idx as u64) << (18 - i * 6); }
            for i in (0..3).rev() { if bc < total_bits { decoded_b.push(((val >> (i * 8)) & 0xff) as u8); bc += 8; } }
        }
        assert_eq!(decoded_b, original);
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
            vec![1],
            vec![255],
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
                        process_primitive_manual(&p, &mut b_data, &mut aux);
                    }
                }
                assert_eq!(b_data, original);
            }
        }
    }
}