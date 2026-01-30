use quote::quote;
use proc_macro2::{TokenStream as TokenStream2, Literal};
use rand::Rng;

#[derive(Clone, Debug)]
pub enum Primitive {
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
}

pub fn generate_primitive_code(p: &Primitive, rng: &mut impl Rng) -> TokenStream2 {
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
        Primitive::Sync => quote! { let mut data = data; },
        Primitive::MappedBitLoad { table } => generate_mapped_bit_load(table, rng),
        Primitive::MappedBaseLoad { table } => generate_mapped_base_load(table, rng),
        Primitive::BitLoadPart { start_pct, end_pct } => generate_bit_load_part(*start_pct, *end_pct, rng),
    }
}

fn generate_obfuscated_map(alphabet: &[u8], rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);

    match rng.gen_range(0..2) {
        0 => { // Procedural
            quote! {
                let mut out = Storage::with_capacity(data.len());
                for b in data.iter() {
                    let v = (#map_lit)[b as usize];
                    if v != 255 { out.push(v); }
                }
                *data = out;
            }
        },
        _ => { // Functional
            quote! {
                let out = Storage::from_vec(data.iter()
                    .map(|b| (#map_lit)[b as usize])
                    .filter(|&v| v != 255)
                    .collect());
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

fn generate_mapped_bit_load(table: &[u8], _rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in table.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);
    quote! {
        for b in data.iter() {
            let v = (#map_lit)[b as usize];
            if v != 255 { aux.push(v); }
        }
        data.clear();
    }
}

fn generate_mapped_base_load(table: &[u8], _rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in table.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);
    quote! {
        for b in data.iter() {
            let v = (#map_lit)[b as usize];
            if v != 255 { aux.push(v); }
        }
        data.clear();
    }
}

fn generate_bit_emit(bits: u32, total_bits: u64, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
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
    match rng.gen_range(0..2) {
        0 => { // Shift based
            quote! {
                let mut out = Storage::new();
                let mut len_v = 0u64;
                let av = aux.to_vec();
                for chunk in av.chunks(#in_c) {
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
                *data = out;
                aux.clear();
            }
        },
        _ => { // Division based
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
                let mut res = Vec::new();
                let av = aux.to_vec();
                for chunk in av.chunks_exact(4) {
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
                for val in res { aux.extend_from_slice(&val.to_ne_bytes()); }
                let lz = leading_zeros as u64;
                let mut next_aux = lz.to_ne_bytes().to_vec();
                next_aux.extend_from_slice(&aux.to_vec());
                aux.clear();
                aux.extend_from_slice(&next_aux);
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
                let mut res: Vec<u32> = av.chunks_exact(4)
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
                    }
                    *data = Storage::from_vec(out);
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
                    let lz = u64::from_ne_bytes(av[0..8].try_into().unwrap()) as usize;
                    let res: Vec<u32> = av[8..].chunks_exact(4)
                        .map(|c| u32::from_ne_bytes(c.try_into().unwrap()))
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
                    }
                    *data = Storage::from_vec(out);
                } else {
                    *data = Storage::new();
                }
                aux.clear();
            }
        }
    }
}
