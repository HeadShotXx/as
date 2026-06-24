extern crate proc_macro;

use proc_macro::{Delimiter, TokenStream, TokenTree};
use quote::quote;
use syn::{parse_macro_input, Expr, ExprLit, ItemFn, Lit, LitStr, Meta};
use syn::visit_mut::{self, VisitMut};
use syn::punctuated::Punctuated;
use syn::parse::Parser;
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use rand::distributions::Alphanumeric;
use crc32fast::Hasher;

// COCEC.RS
#[derive(Debug, Clone, Copy)]
enum Codec {
    Base36,
    Base45,
    Base58,
    Base85,
    Base91,
    Base122,
}

impl Codec {
    fn all() -> Vec<Self> {
        vec![
            Codec::Base36,
            Codec::Base45,
            Codec::Base58,
            Codec::Base85,
            Codec::Base91,
            Codec::Base122,
        ]
    }

    fn encode(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Codec::Base36 => base36::encode(data).as_bytes().to_vec(),
            Codec::Base45 => base45::encode(data).as_bytes().to_vec(),
            Codec::Base58 => bs58::encode(data).into_string().into_bytes(),
            Codec::Base85 => base85::encode(data).as_bytes().to_vec(),
            Codec::Base91 => base91::slice_encode(data),
            Codec::Base122 => base122_rs::encode(data).as_bytes().to_vec(),
        }
    }

    fn get_decode_logic(&self, data_var: &syn::Ident) -> proc_macro2::TokenStream {
        match self {
            Codec::Base36 => quote! { #data_var = base36::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
            Codec::Base45 => quote! { #data_var = base45::decode(String::from_utf8_lossy(&#data_var).as_ref()).unwrap(); },
            Codec::Base58 => quote! { #data_var = bs58::decode(String::from_utf8_lossy(&#data_var).as_ref()).into_vec().unwrap(); },
            Codec::Base85 => quote! { #data_var = base85::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
            Codec::Base91 => quote! { #data_var = base91::slice_decode(&#data_var); },
            Codec::Base122 => quote! { #data_var = base122_rs::decode(&String::from_utf8_lossy(&#data_var)).unwrap(); },
        }
    }

    fn decode(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Codec::Base36 => base36::decode(&String::from_utf8_lossy(data)).unwrap(),
            Codec::Base45 => base45::decode(String::from_utf8_lossy(data).as_ref()).unwrap(),
            Codec::Base58 => bs58::decode(String::from_utf8_lossy(data).as_ref()).into_vec().unwrap(),
            Codec::Base85 => base85::decode(&String::from_utf8_lossy(data)).unwrap(),
            Codec::Base91 => base91::slice_decode(data),
            Codec::Base122 => base122_rs::decode(&String::from_utf8_lossy(data)).unwrap(),
        }
    }
}

// KEY_MANAGEMENT.RS
fn generate_key_fragments(key_size: usize) -> (Vec<u8>, proc_macro2::TokenStream, Vec<syn::Ident>, Vec<syn::Ident>) {
    let mut rng = thread_rng();
    let key: Vec<u8> = (0..key_size).map(|_| rng.gen()).collect();

    let num_fragments = rng.gen_range(2..=8);
    let fragment_size = (key_size + num_fragments - 1) / num_fragments;

    let mut fragments: Vec<Vec<u8>> = Vec::new();
    let mut checksums: Vec<u32> = Vec::new();
    let mut fragment_vars = Vec::new();
    let mut checksum_vars = Vec::new();

    let mut static_defs = Vec::new();

    for i in 0..num_fragments {
        let start = i * fragment_size;
        let end = ((i + 1) * fragment_size).min(key_size);
        if start >= end {
            continue;
        }

        let fragment = &key[start..end];
        let encoded_fragment: Vec<u8> = fragment.iter().map(|b| b.wrapping_add(i as u8)).collect();

        let mut hasher = Hasher::new();
        hasher.update(&encoded_fragment);
        let checksum = hasher.finalize();

        fragments.push(encoded_fragment.clone());
        checksums.push(checksum);

        let var_name_base: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let fragment_var_name = syn::Ident::new(&format!("FRAG_{}", var_name_base), proc_macro2::Span::call_site());
        let checksum_var_name = syn::Ident::new(&format!("CS_{}", var_name_base), proc_macro2::Span::call_site());

        let encoded_fragment_literal = proc_macro2::Literal::byte_string(&encoded_fragment);

        static_defs.push(quote! {
            static #fragment_var_name: &'static [u8] = #encoded_fragment_literal;
            static #checksum_var_name: u32 = #checksum;
        });

        fragment_vars.push(fragment_var_name);
        checksum_vars.push(checksum_var_name);
    }

    let gen = quote! {
        #(#static_defs)*
    };

    (key, gen, fragment_vars, checksum_vars)
}

fn generate_key_reconstruction_logic(
    key_name: &str,
    key_size: usize,
    fragment_vars: &[syn::Ident],
    checksum_vars: &[syn::Ident],
) -> (syn::Ident, proc_macro2::TokenStream) {
    let key_var = syn::Ident::new(key_name, proc_macro2::Span::call_site());
    let mut reconstruction_steps = Vec::new();

    for (i, (fragment_var, checksum_var)) in fragment_vars.iter().zip(checksum_vars.iter()).enumerate() {
        let step = quote! {
            {
                let fragment_data = #fragment_var;
                let expected_checksum = #checksum_var;

                let mut hasher = crc32fast::Hasher::new();
                hasher.update(fragment_data);
                let actual_checksum = hasher.finalize();

                if actual_checksum != expected_checksum {
                    panic!("Checksum mismatch detected! Possible tampering.");
                }

                let decoded_fragment: Vec<u8> = fragment_data.iter().map(|b| b.wrapping_sub(#i as u8)).collect();
                #key_var.extend_from_slice(&decoded_fragment);
            }
        };
        reconstruction_steps.push(step);
    }

    let logic = quote! {
        let mut #key_var = Vec::with_capacity(#key_size);
        #(#reconstruction_steps)*
    };

    (key_var, logic)
}

fn generate_data_fragments(data: &[u8], prefix: &str) -> (proc_macro2::TokenStream, proc_macro2::TokenStream, syn::Ident) {
    let mut rng = thread_rng();
    let num_frags = rng.gen_range(3..=6);
    let frag_size = (data.len() + num_frags - 1) / num_frags;
    let salt_offset = rng.gen::<u8>();

    let mut static_defs = Vec::new();
    let mut recon_steps = Vec::new();
    let data_ident = syn::Ident::new(&format!("data_{}", prefix), proc_macro2::Span::call_site());

    for i in 0..num_frags {
        let start = i * frag_size;
        let end = ((i + 1) * frag_size).min(data.len());
        if start >= end { continue; }

        let fragment = &data[start..end];
        let salt = salt_offset.wrapping_add(i as u8);
        let encoded: Vec<u8> = fragment.iter().map(|b| b.wrapping_add(salt)).collect();

        let mut hasher = Hasher::new();
        hasher.update(&encoded);
        let checksum = hasher.finalize();

        let var_base: String = thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
        let f_ident = syn::Ident::new(&format!("D_{}_{}", prefix, var_base), proc_macro2::Span::call_site());
        let c_ident = syn::Ident::new(&format!("C_{}_{}", prefix, var_base), proc_macro2::Span::call_site());

        let f_lit = proc_macro2::Literal::byte_string(&encoded);

        static_defs.push(quote! {
            static #f_ident: &'static [u8] = #f_lit;
            static #c_ident: u32 = #checksum;
        });

        recon_steps.push(quote! {
            {
                let frag = #f_ident;
                let mut h = Hasher::new();
                h.update(frag);
                if h.finalize() != #c_ident { panic!("Integrity check failed"); }
                let s = #salt_offset.wrapping_add(#i as u8);
                #data_ident.extend(frag.iter().map(|b| b.wrapping_sub(s)));
            }
        });
    }

    let data_len = data.len();
    let recon_logic = quote! {
        let mut #data_ident = Vec::with_capacity(#data_len);
        #(#recon_steps)*
    };

    (quote! { #(#static_defs)* }, recon_logic, data_ident)
}

fn expr_to_bytes(expr: &Expr) -> Option<Vec<u8>> {
    match expr {
        Expr::Reference(r) => expr_to_bytes(&r.expr),
        Expr::Array(a) => {
            let mut bytes = Vec::with_capacity(a.elems.len());
            for elem in &a.elems {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Int(li), ..
                }) = elem
                {
                    bytes.push(li.base10_parse::<u8>().ok()?);
                } else {
                    return None;
                }
            }
            Some(bytes)
        }
        Expr::Lit(ExprLit {
            lit: Lit::ByteStr(lbs),
            ..
        }) => Some(lbs.value()),
        Expr::Lit(ExprLit {
            lit: Lit::Str(ls), ..
        }) => Some(ls.value().into_bytes()),
        _ => None,
    }
}

fn fast_parse_bytes(input: TokenStream) -> Option<Vec<u8>> {
    let mut iter = input.into_iter();
    let first = iter.next()?;

    match first {
        TokenTree::Punct(ref p) if p.as_char() == '&' => {
            if let Some(TokenTree::Group(g)) = iter.next() {
                if g.delimiter() == Delimiter::Bracket {
                    return tokens_to_bytes(g.stream());
                }
            }
        }
        TokenTree::Group(ref g) if g.delimiter() == Delimiter::Bracket => {
            return tokens_to_bytes(g.stream());
        }
        TokenTree::Literal(ref l) => {
            let s = l.to_string();
            if s.starts_with('b') && s.starts_with("b\"") {
                if let Ok(ls) = syn::parse_str::<syn::LitByteStr>(&s) {
                    return Some(ls.value());
                }
            } else if s.starts_with('"') {
                if let Ok(ls) = syn::parse_str::<syn::LitStr>(&s) {
                    return Some(ls.value().into_bytes());
                }
            }
            if let Ok(expr) = syn::parse_str::<Expr>(&s) {
                return expr_to_bytes(&expr);
            }
        }
        _ => {}
    }

    // Fallback to syn for anything else
    let ts: TokenStream = first.into();
    if let Ok(expr) = syn::parse2::<Expr>(ts.into()) {
        return expr_to_bytes(&expr);
    }

    None
}

fn tokens_to_bytes(tokens: TokenStream) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    let mut tokens_it = tokens.into_iter().peekable();

    while let Some(tt) = tokens_it.next() {
        if let TokenTree::Literal(l) = tt {
            let s = l.to_string();
            // Fast skip for strings/byte strings which shouldn't be in a u8 array
            if s.starts_with('b') || s.starts_with('"') || s.starts_with('\'') {
                continue;
            }

            let mut s_ref = s.as_str();
            let mut is_hex = false;
            if s_ref.starts_with("0x") || s_ref.starts_with("0X") {
                s_ref = &s_ref[2..];
                is_hex = true;
            }

            // Handle suffixes like 1u8
            if let Some(pos) = s_ref.find(|c: char| !c.is_ascii_hexdigit()) {
                if !is_hex {
                    // Re-check for non-hex digits if not 0x
                    if let Some(pos_dec) = s_ref.find(|c: char| !c.is_ascii_digit()) {
                        s_ref = &s_ref[..pos_dec];
                    }
                } else {
                    s_ref = &s_ref[..pos];
                }
            }

            if is_hex {
                if let Ok(v) = u8::from_str_radix(s_ref, 16) {
                    bytes.push(v);
                }
            } else if let Ok(v) = s_ref.parse::<u8>() {
                bytes.push(v);
            }
        }
    }

    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

fn generate_vm_logic() -> proc_macro2::TokenStream {
    quote! {
        struct VM {
            regs: [u64; 4],
            outputs: Vec<u64>,
        }
        impl VM {
            fn new() -> Self {
                Self { regs: [0; 4], outputs: Vec::new() }
            }
            fn execute(&mut self, bytecode: &[u8]) {
                let mut pc = 0;
                while pc < bytecode.len() {
                    if pc >= bytecode.len() { break; }
                    let op = bytecode[pc];
                    pc += 1;
                    match op {
                        1 => { // MOV reg, val
                            if pc + 9 > bytecode.len() { break; }
                            let reg = bytecode[pc] as usize;
                            let mut val_bytes = [0u8; 8];
                            val_bytes.copy_from_slice(&bytecode[pc + 1..pc + 9]);
                            self.regs[reg] = u64::from_le_bytes(val_bytes);
                            pc += 9;
                        }
                        2 => { // ADD r1, r2
                            if pc + 2 > bytecode.len() { break; }
                            let r1 = bytecode[pc] as usize;
                            let r2 = bytecode[pc + 1] as usize;
                            self.regs[r1] = self.regs[r1].wrapping_add(self.regs[r2]);
                            pc += 2;
                        }
                        3 => { // SUB r1, r2
                            if pc + 2 > bytecode.len() { break; }
                            let r1 = bytecode[pc] as usize;
                            let r2 = bytecode[pc + 1] as usize;
                            self.regs[r1] = self.regs[r1].wrapping_sub(self.regs[r2]);
                            pc += 2;
                        }
                        4 => { // XOR r1, r2
                            if pc + 2 > bytecode.len() { break; }
                            let r1 = bytecode[pc] as usize;
                            let r2 = bytecode[pc + 1] as usize;
                            self.regs[r1] ^= self.regs[r2];
                            pc += 2;
                        }
                        5 => { // MUL r1, r2
                            if pc + 2 > bytecode.len() { break; }
                            let r1 = bytecode[pc] as usize;
                            let r2 = bytecode[pc + 1] as usize;
                            self.regs[r1] = self.regs[r1].wrapping_mul(self.regs[r2]);
                            pc += 2;
                        }
                        6 => { // AND r1, r2
                            if pc + 2 > bytecode.len() { break; }
                            let r1 = bytecode[pc] as usize;
                            let r2 = bytecode[pc + 1] as usize;
                            self.regs[r1] &= self.regs[r2];
                            pc += 2;
                        }
                        7 => { // OR r1, r2
                            if pc + 2 > bytecode.len() { break; }
                            let r1 = bytecode[pc] as usize;
                            let r2 = bytecode[pc + 1] as usize;
                            self.regs[r1] |= self.regs[r2];
                            pc += 2;
                        }
                        8 => { // NOT r1
                            if pc + 1 > bytecode.len() { break; }
                            let r1 = bytecode[pc] as usize;
                            self.regs[r1] = !self.regs[r1];
                            pc += 1;
                        }
                        9 => { // OUTPUT reg
                            if pc + 1 > bytecode.len() { break; }
                            let reg = bytecode[pc] as usize;
                            self.outputs.push(self.regs[reg]);
                            pc += 1;
                        }
                        _ => break,
                    }
                }
            }
        }
    }
}

fn generate_bytecode_for_ops(target_ops: &[u64]) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut bytecode = Vec::new();

    for &val in target_ops {
        // We want to reach 'val' in R0.
        let mut steps = Vec::new();
        let mut temp = val;
        for _ in 0..3 {
            let op = rng.gen_range(0..3);
            match op {
                0 => { // ADD
                    let r: u64 = rng.gen_range(1..1000);
                    steps.push((0, r));
                    temp = temp.wrapping_sub(r);
                }
                1 => { // SUB
                    let r: u64 = rng.gen_range(1..1000);
                    steps.push((1, r));
                    temp = temp.wrapping_add(r);
                }
                2 => { // XOR
                    let r: u64 = rng.gen_range(1..1000);
                    steps.push((2, r));
                    temp ^= r;
                }
                _ => unreachable!(),
            }
        }

        // Initialize R0 with temp
        bytecode.push(1); bytecode.push(0); bytecode.extend_from_slice(&temp.to_le_bytes());

        // Apply steps to reach val
        for (op, r) in steps.into_iter().rev() {
            bytecode.push(1); bytecode.push(1); bytecode.extend_from_slice(&r.to_le_bytes());
            match op {
                0 => { bytecode.push(2); bytecode.push(0); bytecode.push(1); } // ADD
                1 => { bytecode.push(3); bytecode.push(0); bytecode.push(1); } // SUB
                2 => { bytecode.push(4); bytecode.push(0); bytecode.push(1); } // XOR
                _ => unreachable!(),
            }
        }

        // Output R0
        bytecode.push(9); bytecode.push(0);

        // Add some junk
        if rng.gen_bool(0.3) {
            let r_junk: u64 = rng.gen();
            bytecode.push(1); bytecode.push(2); bytecode.extend_from_slice(&r_junk.to_le_bytes());
            bytecode.push(5); bytecode.push(2); bytecode.push(0);
        }
    }

    bytecode
}

fn generate_advanced_junk_internal(
    rs_var: &syn::Ident,
    data_var: &syn::Ident,
    aux_var: &syn::Ident,
    idx_var: &syn::Ident,
    last_rs_var: &syn::Ident,
    case: usize,
) -> proc_macro2::TokenStream {
    match case {
        0 => quote! {
            if #data_var.len() > 0 {
                let val = #data_var[#idx_var % #data_var.len()] as u32;
                #rs_var = #rs_var.wrapping_add(val).rotate_left(3);
            }
        },
        1 => quote! {
            if !#aux_var.is_empty() {
                let a_val = #aux_var[#rs_var as usize % #aux_var.len()] as u32;
                #rs_var ^= a_val.wrapping_mul(0xdeadbeef);
            }
        },
        2 => quote! {
            let m = (#idx_var as u32).wrapping_mul(#data_var.len() as u32);
            #rs_var = #rs_var.wrapping_sub(m ^ 0x1337);
        },
        3 => quote! {
            for j in 0..(#rs_var & 0x7) {
                #rs_var = #rs_var.wrapping_add(j).rotate_right(1);
                if j % 2 == 0 {
                    #aux_var.push((#rs_var & 0xFF) as u8);
                }
            }
        },
        4 => quote! {
            if (#rs_var.wrapping_mul(#rs_var.wrapping_add(1u32)) % 2u32 == 0u32) {
                #rs_var ^= 0x55555555;
            } else {
                #rs_var = #rs_var.wrapping_add(1u32);
            }
        },
        5 => quote! {
            if #idx_var < #data_var.len() {
                let b = #data_var[#idx_var] as u32;
                let bit = (b >> (#rs_var % 8)) & 1;
                #rs_var ^= bit.wrapping_mul(0xfaceb00c);
            }
        },
        6 => quote! {
            #aux_var.push((#rs_var & 0xFF) as u8);
            if #aux_var.len() > 8 {
                let old = #aux_var.remove(0) as u32;
                #rs_var = #rs_var.wrapping_add(old << 16);
            }
        },
        7 => quote! {
            #rs_var ^= #last_rs_var;
            #last_rs_var = #rs_var;
        },
        8 => quote! {
            #rs_var = (#rs_var ^ 0xAAAAAAAA).wrapping_mul(0x31415927) ^ (#rs_var >> 13);
        },
        9 => quote! {
            #rs_var = std::hint::black_box(#rs_var).wrapping_add(1);
        },
        10 => quote! {
            #rs_var = #rs_var.wrapping_add(#data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32 ^ #aux_var.len() as u32).rotate_left(5);
        },
        11 => quote! {
            if #last_rs_var % 2 == 0 { #rs_var = #rs_var.wrapping_sub(#idx_var as u32); } else { #rs_var ^= #data_var.len() as u32; }
            #last_rs_var = #rs_var;
        },
        12 => quote! {
            let val = #data_var.iter().fold(#rs_var, |acc, &b| acc.wrapping_add(b as u32));
            #rs_var = val ^ #aux_var.get(#idx_var % #aux_var.len().max(1)).cloned().unwrap_or(0) as u32;
        },
        13 => quote! {
            for _ in 0..(#data_var.len() & 0x3) {
                #rs_var = #rs_var.wrapping_mul(31).wrapping_add(#idx_var as u32);
                #aux_var.push((#rs_var & 0xFF) as u8);
            }
        },
        14 => quote! {
            if let Some(&b) = #data_var.get(#idx_var % #data_var.len().max(1)) {
                let shift = (b % 16) as u32;
                #rs_var = #rs_var.rotate_right(shift) ^ (#last_rs_var.wrapping_add(#idx_var as u32));
            }
        },
        15 => quote! {
            let mut m = #rs_var;
            if #aux_var.len() > 0 { m ^= #aux_var[0] as u32; }
            #rs_var = (m.wrapping_mul(0x85ebca6b) ^ #idx_var as u32).wrapping_add(#data_var.len() as u32);
        },
        16 => quote! {
            if !#aux_var.is_empty() {
                let mut x = #aux_var.pop().unwrap_or(0) as u32;
                x = x.rotate_left((#rs_var % 16) as u32);
                #rs_var ^= x.wrapping_mul(#idx_var as u32 | 1);
                #aux_var.insert(0, (x & 0xFF) as u8);
            }
        },
        17 => quote! {
            let v1 = (#rs_var as u64).wrapping_mul(#data_var.len() as u64);
            let v2 = (#idx_var as u64).wrapping_add(#last_rs_var as u64);
            #rs_var = ((v1 ^ v2) as u32).wrapping_add(0x61C88647);
        },
        18 => quote! {
            if #aux_var.len() >= 2 {
                let i1 = (#rs_var as usize) % #aux_var.len();
                let i2 = (#idx_var as usize) % #aux_var.len();
                #aux_var.swap(i1, i2);
                #rs_var = #rs_var.wrapping_add(#aux_var[i1] as u32);
            }
        },
        19 => quote! {
            if let Some(&b) = #data_var.get(#idx_var % #data_var.len().max(1)) {
                let inter = (#rs_var & 0xAAAA) | ((b as u32 & 0x55) << 8);
                #rs_var = #rs_var.wrapping_sub(inter).rotate_left(1);
            }
        },
        20 => quote! {
            for j in 0..(#data_var.len() & 0x3).max(1) {
                let b = #data_var.get((#idx_var + j) % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
                #rs_var = #rs_var.wrapping_add(b).rotate_right(j as u32 + 1);
                #aux_var.push((#rs_var & 0xFF) as u8);
            }
        },
        21 => quote! {
            let mut p = 0u32;
            for &b in #data_var.iter().take(8) { p ^= b as u32; }
            if p % 2 == 0 { #rs_var = #rs_var.wrapping_add(p); } else { #rs_var ^= p; }
            #rs_var = #rs_var.rotate_left(3);
        },
        22 => quote! {
            if !#aux_var.is_empty() {
                let rot = (#rs_var % 8) as u32;
                for x in #aux_var.iter_mut() { *x = x.rotate_left(rot); }
                #rs_var = #rs_var.wrapping_add(#aux_var[0] as u32);
            }
        },
        23 => quote! {
            match #idx_var % 4 {
                0 => #rs_var = #rs_var.wrapping_add(0x11111111),
                1 => #rs_var ^= 0x22222222,
                2 => #rs_var = #rs_var.rotate_right(5),
                _ => {
                    if let Some(&b) = #data_var.get(#idx_var % #data_var.len().max(1)) {
                        #rs_var = #rs_var.wrapping_sub(b as u32);
                    }
                }
            }
        },
        24 => quote! {
            let fb = #last_rs_var.wrapping_mul(#data_var.len() as u32);
            #rs_var = #rs_var.wrapping_add(fb ^ 0x9e3779b9);
            #last_rs_var = #rs_var;
        },
        25 => quote! {
            let s: u32 = #aux_var.iter().take(4).map(|&b| b as u32).sum();
            #rs_var ^= s.wrapping_mul(#idx_var as u32 | 1);
        },
        26 => quote! {
            if #data_var.len() >= 2 {
                let b1 = #data_var[#idx_var % #data_var.len()] as u32;
                let b2 = #data_var[(#idx_var + 1) % #data_var.len()] as u32;
                #rs_var = #rs_var.wrapping_add(b1 << 8 | b2);
            }
        },
        27 => quote! {
            let mut temp_rs = #rs_var;
            for _ in 0..3 {
                temp_rs = (temp_rs ^ (temp_rs >> 16)).wrapping_mul(0x85ebca6b);
                temp_rs = (temp_rs ^ (temp_rs >> 13)).wrapping_mul(0xc2b2ae35);
            }
            #rs_var = temp_rs ^ #idx_var as u32;
        },
        28 => quote! {
            if #aux_var.len() > 4 {
                let mut h = Hasher::new();
                h.update(&#aux_var);
                #rs_var ^= h.finalize();
            }
        },
        29 => quote! {
            if (#rs_var & 1) != 0 {
                #rs_var = #rs_var.wrapping_mul(3).wrapping_add(1);
            } else {
                #rs_var /= 2;
            }
            #rs_var ^= #data_var.len() as u32;
        },
        30 => quote! {
            let ent = #data_var.iter().fold(0u32, |acc, &b| acc ^ (b as u32).rotate_left(acc % 8));
            #rs_var = #rs_var.wrapping_add(ent);
        },
        31 => quote! {
            let diff = #rs_var.wrapping_sub(#last_rs_var);
            #rs_var = #rs_var.wrapping_add(diff.rotate_right(4));
            #last_rs_var = #rs_var;
        },
        32 => quote! {
            #aux_var.push((#idx_var & 0xFF) as u8);
            if #aux_var.len() > 16 {
                let popped = #aux_var.pop().unwrap_or(0) as u32;
                #rs_var ^= popped.wrapping_mul(0x12345678);
            }
        },
        33 => quote! {
            let x = #rs_var;
            let y = #idx_var as u32;
            let mba = (x | y).wrapping_sub(x & y); // XOR
            #rs_var = mba.wrapping_add(#data_var.len() as u32);
        },
        34 => quote! {
            if let Some(&b) = #data_var.get(#idx_var % #data_var.len().max(1)) {
                let s = (b % 32) as u32;
                #rs_var = #rs_var.rotate_left(s) ^ #rs_var.rotate_right(32 - s);
            }
        },
        35 => quote! {
            if #aux_var.len() >= 4 {
                let pivot = (#idx_var % #aux_var.len()) as usize;
                let val = #aux_var[pivot] as u32;
                #rs_var = #rs_var.wrapping_add(val << (#idx_var % 24));
            }
        },
        36 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let m1 = 0x55555555;
            let m2 = 0xAAAAAAAA;
            #rs_var = ((#rs_var & m1) << 1) | ((#rs_var & m2) >> 1);
            #rs_var ^= b;
        },
        37 => quote! {
            let mut acc = 0u32;
            for &x in #aux_var.iter().rev().take(5) { acc = acc.wrapping_add(x as u32); }
            #rs_var ^= acc;
        },
        38 => quote! {
            let coupling = (#last_rs_var ^ (#data_var.len() as u32)).wrapping_mul(0x21212121);
            #rs_var = #rs_var.wrapping_add(coupling);
        },
        39 => quote! {
            let mut final_m = #rs_var ^ #last_rs_var ^ #idx_var as u32 ^ #data_var.len() as u32;
            if let Some(&b) = #aux_var.last() { final_m ^= b as u32; }
            #rs_var = final_m.rotate_left(7);
        },
        40 => quote! {
            #aux_var.push((#rs_var & 0xFF) as u8);
            if #aux_var.len() > 4 {
                let delayed = #aux_var.remove(0) as u32;
                #rs_var = #rs_var.wrapping_add(delayed ^ #idx_var as u32);
            }
        },
        41 => quote! {
            let feedback = #last_rs_var.wrapping_add(#data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32);
            #rs_var ^= feedback.rotate_right(3);
            #last_rs_var = #rs_var;
        },
        42 => quote! {
            let mut h = Hasher::new();
            h.update(&#aux_var);
            let check = h.finalize();
            if check % 2 == 0 {
                #rs_var = #rs_var.wrapping_add(check).rotate_left(5);
            } else {
                #rs_var ^= check.wrapping_mul(0x33445566);
            }
        },
        43 => quote! {
            let last_aux = #aux_var.last().cloned().unwrap_or(0) as u32;
            #rs_var = #rs_var.wrapping_add(last_aux ^ #idx_var as u32 ^ #data_var.len() as u32).rotate_right(2);
        },
        44 => quote! {
            if let Some(&b) = #data_var.get(#idx_var % #data_var.len().max(1)) {
                let x = #rs_var;
                let y = b as u32;
                let mba = (x & y).wrapping_add(x | y);
                #rs_var = mba.wrapping_sub(0x55AA55AA);
            }
        },
        45 => quote! {
            if #rs_var % 2 == 0 {
                let rot = (#data_var.len() % 8) as u32;
                for x in #aux_var.iter_mut() { *x = x.rotate_left(rot); }
            } else {
                #rs_var = #rs_var.wrapping_add(1);
            }
        },
        46 => quote! {
            while #aux_var.len() > 8 {
                let v = #aux_var.pop().unwrap_or(0) as u32;
                #rs_var = #rs_var.wrapping_sub(v).rotate_left(1);
            }
        },
        47 => quote! {
            let mask = #last_rs_var as usize;
            if let Some(&b) = #data_var.get(mask % #data_var.len().max(1)) {
                #rs_var ^= (b as u32).wrapping_mul(0x12345678);
            }
        },
        48 => quote! {
            #aux_var.push((#rs_var & 0xFF) as u8);
            let sum: u32 = #aux_var.iter().rev().take(3).map(|&b| b as u32).sum();
            #rs_var = #rs_var.wrapping_add(sum ^ #last_rs_var);
        },
        49 => quote! {
            let mut h = Hasher::new();
            h.update(&#data_var[..#idx_var % #data_var.len().max(1)]);
            let d_hash = h.finalize();
            if (#rs_var ^ d_hash) % 2 == 0 {
                #rs_var = #rs_var.wrapping_mul(3).wrapping_add(d_hash);
            }
        },
        50 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let al = #aux_var.len() as u32;
            #rs_var = #rs_var.rotate_left(b % 7).wrapping_add(al);
        },
        51 => quote! {
            for (i, &a) in #aux_var.iter().enumerate().take(4) {
                #rs_var = #rs_var.wrapping_add((a as u32).wrapping_mul((i as u32).wrapping_add(1)));
            }
        },
        52 => quote! {
            let sum = #data_var.iter().take(16).fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
            #rs_var ^= sum.wrapping_mul(#idx_var as u32 ^ #last_rs_var);
        },
        53 => quote! {
            if let Some(&b) = #data_var.get(#idx_var % #data_var.len().max(1)) {
                if b > 0x7F {
                    #rs_var = #rs_var.wrapping_add(0xDEADC0DE).rotate_right(13);
                } else {
                    #rs_var = #rs_var.wrapping_sub(0x13371337);
                }
            }
        },
        54 => quote! {
            let state_idx = (#rs_var as usize ^ #aux_var.len()) % 256;
            #rs_var = #rs_var.wrapping_add(state_idx as u32 ^ #data_var.len() as u32);
        },
        55 => quote! {
            let temp = #rs_var;
            #rs_var = #last_rs_var.wrapping_add(#data_var.len() as u32);
            #last_rs_var = temp ^ #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
        },
        56 => quote! {
            if #aux_var.len() >= 4 {
                let x = (#rs_var % 2) as usize;
                let y = (#idx_var % 2) as usize;
                let val = #aux_var[(x * 2 + y) % #aux_var.len()] as u32;
                #rs_var ^= val.wrapping_mul(#data_var.len() as u32);
            }
        },
        57 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let l = #rs_var & 0xFFFF;
            let r = #rs_var >> 16;
            let next_r = l ^ (r.wrapping_add(b).rotate_left(5));
            #rs_var = (r << 16) | next_r;
        },
        58 => quote! {
            let bc_data = #data_var.iter().take(8).map(|&b| b.count_ones()).sum::<u32>();
            let bc_aux = #aux_var.iter().take(8).map(|&b| b.count_ones()).sum::<u32>();
            #rs_var = #rs_var.wrapping_add(bc_data ^ bc_aux);
        },
        59 => quote! {
            #rs_var = (#rs_var ^ #last_rs_var).wrapping_add(#data_var.len() as u32).rotate_left(#aux_var.len() as u32 % 32) ^ #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
        },
        60 => quote! {
            let entropy = #data_var.iter().cycle().skip(#idx_var % #data_var.len().max(1)).take(4).fold(0u32, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u32));
            #rs_var = #rs_var.wrapping_add(entropy ^ #last_rs_var);
        },
        61 => quote! {
            if #aux_var.len() >= 8 {
                let mid = #aux_var.len() / 2;
                let v = #aux_var[mid] as u32;
                #rs_var = #rs_var.rotate_right(v % 32).wrapping_sub(#idx_var as u32);
            } else {
                #aux_var.push((#rs_var & 0xFF) as u8);
            }
        },
        62 => quote! {
            let mut h = Hasher::new();
            h.update(&[((#rs_var >> 24) & 0xFF) as u8, ((#rs_var >> 16) & 0xFF) as u8, (#idx_var & 0xFF) as u8]);
            let res = h.finalize();
            #rs_var ^= res.wrapping_mul(#data_var.len() as u32 | 1);
        },
        63 => quote! {
            let mask = (#rs_var ^ #idx_var as u32).wrapping_mul(0xdeadbeef);
            for i in 0..(#data_var.len() % 4).max(1) {
                #rs_var = #rs_var.wrapping_add(mask.rotate_left(i as u32));
            }
        },
        64 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let combined = b.wrapping_add(#aux_var.len() as u32).wrapping_mul(#last_rs_var | 1);
            #rs_var ^= combined;
        },
        65 => quote! {
            let mut x = #rs_var;
            x ^= x >> 16;
            x = x.wrapping_mul(0x85ebca6b);
            x ^= x >> 13;
            x = x.wrapping_mul(0xc2b2ae35);
            x ^= x >> 16;
            #rs_var = x.wrapping_add(#idx_var as u32);
        },
        66 => quote! {
            if #idx_var % 2 == 0 {
                #aux_var.push((#rs_var & 0xFF) as u8);
            } else if !#aux_var.is_empty() {
                let v = #aux_var.remove(0) as u32;
                #rs_var = #rs_var.wrapping_sub(v).rotate_left(5);
            }
        },
        67 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            #rs_var = #rs_var.wrapping_add(#last_rs_var).wrapping_xor(b.wrapping_mul(0x13371337));
        },
        68 => quote! {
            let mut sum = 0u32;
            for &val in #aux_var.iter().take(10) { sum = sum.wrapping_add(val as u32); }
            #rs_var = #rs_var.wrapping_add(sum ^ (#data_var.len() as u32));
        },
        69 => quote! {
            let s = (#rs_var % 16) as u32;
            #rs_var = #rs_var.rotate_left(s) ^ (#idx_var as u32).wrapping_mul(0x11223344);
        },
        70 => quote! {
            if let Some(&b) = #data_var.get((#idx_var ^ #rs_var as usize) % #data_var.len().max(1)) {
                #rs_var ^= (b as u32).wrapping_mul(0xCAFEBABE);
            }
        },
        71 => quote! {
            #aux_var.push(((#rs_var ^ #last_rs_var) & 0xFF) as u8);
            if #aux_var.len() > 32 { #aux_var.truncate(16); }
        },
        72 => quote! {
            let v = (#data_var.len() as u32).wrapping_add(#idx_var as u32).wrapping_mul(0x31415927);
            #rs_var = #rs_var.wrapping_add(v).rotate_right(11);
        },
        73 => quote! {
            let lrs = #last_rs_var;
            let mut h = Hasher::new();
            h.update(&lrs.to_le_bytes());
            #rs_var ^= h.finalize();
        },
        74 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let s = (b.count_ones() % 32) as u32;
            #rs_var = #rs_var.rotate_left(s).wrapping_add(#aux_var.len() as u32);
        },
        75 => quote! {
            let mut m = #rs_var;
            for _ in 0..2 {
                m = m.wrapping_mul(1664525).wrapping_add(1013904223);
            }
            #rs_var = m ^ #last_rs_var;
        },
        76 => quote! {
            if !#aux_var.is_empty() {
                let idx = (#rs_var as usize) % #aux_var.len();
                #rs_var ^= (#aux_var[idx] as u32).wrapping_mul(#idx_var as u32);
            }
        },
        77 => quote! {
            let d_len = #data_var.len() as u32;
            let a_len = #aux_var.len() as u32;
            #rs_var = #rs_var.wrapping_add(d_len ^ a_len ^ 0xAAAAAAAA).rotate_left(4);
        },
        78 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let mut x = #rs_var ^ b;
            x = x.wrapping_add(x << 10);
            x ^= x >> 6;
            #rs_var = x;
        },
        79 => quote! {
            #aux_var.push((#idx_var & 0xFF) as u8);
            let mut sum = 0u32;
            for &a in #aux_var.iter().rev().take(4) { sum ^= a as u32; }
            #rs_var = #rs_var.wrapping_sub(sum).rotate_right(3);
        },
        80 => quote! {
            let v = #last_rs_var.wrapping_add(#idx_var as u32).wrapping_xor(#data_var.len() as u32);
            #rs_var = #rs_var.wrapping_mul(3).wrapping_add(v);
        },
        81 => quote! {
            if let Some(&b) = #data_var.get(#idx_var % #data_var.len().max(1)) {
                let mask = (b as u32).wrapping_mul(0x55555555);
                #rs_var ^= mask;
            }
        },
        82 => quote! {
            let mut h = Hasher::new();
            h.update(&#data_var[..#idx_var % #data_var.len().max(1)]);
            h.update(&#aux_var);
            #rs_var = #rs_var.wrapping_add(h.finalize());
        },
        83 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let rot = (b % 32) as u32;
            #rs_var = #rs_var.rotate_left(rot).wrapping_xor(0x33333333);
        },
        84 => quote! {
            let mut acc = #rs_var;
            for i in 0..4 {
                acc = acc.wrapping_add(#aux_var.get(i).cloned().unwrap_or(0) as u32);
            }
            #rs_var = acc ^ #last_rs_var;
        },
        85 => quote! {
            let mut v = #rs_var;
            v = (v ^ (v >> 16)).wrapping_mul(0x45d9f3b);
            v = (v ^ (v >> 16)).wrapping_mul(0x45d9f3b);
            v = v ^ (v >> 16);
            #rs_var = v.wrapping_add(#idx_var as u32);
        },
        86 => quote! {
            if #data_var.len() > 10 {
                let val = #data_var[10 % #data_var.len()] as u32;
                #rs_var = #rs_var.wrapping_sub(val).rotate_right(7);
            }
        },
        87 => quote! {
            #aux_var.push((#rs_var & 0xFF) as u8);
            let mut h = Hasher::new();
            h.update(&#aux_var);
            #rs_var ^= h.finalize() ^ (#data_var.len() as u32);
        },
        88 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            let m = (b as u32).wrapping_mul(#idx_var as u32);
            #rs_var = #rs_var.wrapping_add(m).rotate_left(2);
        },
        89 => quote! {
            let mut x = #rs_var;
            x = (x.wrapping_add(0x7ed55d16)).wrapping_add(x << 12);
            x = (x ^ 0xc761c23c) ^ (x >> 19);
            #rs_var = x ^ #last_rs_var;
        },
        90 => quote! {
            if #aux_var.len() > 2 {
                let a = #aux_var[0] as u32;
                let b = #aux_var[1] as u32;
                #rs_var ^= (a << 8) | b;
            }
        },
        91 => quote! {
            let mut sum = 0u32;
            for &b in #data_var.iter().take(5) { sum = sum.wrapping_add(b as u32); }
            #rs_var = #rs_var.wrapping_sub(sum ^ #idx_var as u32);
        },
        92 => quote! {
            let rot = (#idx_var % 32) as u32;
            #rs_var = #rs_var.rotate_right(rot).wrapping_xor(#data_var.len() as u32);
        },
        93 => quote! {
            let val = #last_rs_var.wrapping_mul(31).wrapping_add(#rs_var);
            #rs_var = val ^ 0x12345678;
            #last_rs_var = #rs_var;
        },
        94 => quote! {
            if !#aux_var.is_empty() {
                let last = #aux_var.pop().unwrap() as u32;
                #rs_var = #rs_var.wrapping_add(last).rotate_left(1);
                #aux_var.insert(0, (last & 0xFF) as u8);
            }
        },
        95 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            #rs_var ^= b.wrapping_mul(0x21212121) ^ #aux_var.len() as u32;
        },
        96 => quote! {
            let mut m = #rs_var;
            m = (m ^ (m >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64 as u32);
            m = (m ^ (m >> 27)).wrapping_mul(0x94d049bb133111ebu64 as u32);
            #rs_var = m ^ (m >> 31);
        },
        97 => quote! {
            let d_len = #data_var.len() as u32;
            #rs_var = #rs_var.wrapping_add(d_len).rotate_right(d_len % 32);
        },
        98 => quote! {
            #aux_var.push((#idx_var & 0xFF) as u8);
            let check = #aux_var.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
            #rs_var ^= check;
        },
        99 => quote! {
            let b = #data_var.get(#idx_var % #data_var.len().max(1)).cloned().unwrap_or(0) as u32;
            #rs_var = (#rs_var ^ b).wrapping_add(#last_rs_var).rotate_left(3);
        },
        _ => unreachable!(),
    }
}

fn simulate_advanced_junk(
    case: usize,
    rs: &mut u32,
    data: &[u8],
    aux: &mut Vec<u8>,
    idx: usize,
    last_rs: &mut u32,
) {
    match case {
        0 => {
            if !data.is_empty() {
                let val = data[idx % data.len()] as u32;
                *rs = rs.wrapping_add(val).rotate_left(3);
            }
        },
        1 => {
            if !aux.is_empty() {
                let a_val = aux[*rs as usize % aux.len()] as u32;
                *rs ^= a_val.wrapping_mul(0xdeadbeef);
            }
        },
        2 => {
            let m = (idx as u32).wrapping_mul(data.len() as u32);
            *rs = rs.wrapping_sub(m ^ 0x1337);
        },
        3 => {
            for j in 0..(*rs & 0x7) {
                *rs = rs.wrapping_add(j).rotate_right(1);
                if j % 2 == 0 {
                    aux.push((*rs & 0xFF) as u8);
                }
            }
        },
        4 => {
            if rs.wrapping_mul(rs.wrapping_add(1)) % 2 == 0 {
                *rs ^= 0x55555555;
            } else {
                *rs = rs.wrapping_add(1);
            }
        },
        5 => {
            if idx < data.len() {
                let b = data[idx] as u32;
                let bit = (b >> (*rs % 8)) & 1;
                *rs ^= bit.wrapping_mul(0xfaceb00c);
            }
        },
        6 => {
            aux.push((*rs & 0xFF) as u8);
            if aux.len() > 8 {
                let old = aux.remove(0) as u32;
                *rs = rs.wrapping_add(old << 16);
            }
        },
        7 => {
            *rs ^= *last_rs;
            *last_rs = *rs;
        },
        8 => {
            *rs = (*rs ^ 0xAAAAAAAA).wrapping_mul(0x31415927) ^ (*rs >> 13);
        },
        9 => {
            *rs = rs.wrapping_add(1);
        },
        10 => {
            *rs = rs.wrapping_add(data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32 ^ aux.len() as u32).rotate_left(5);
        },
        11 => {
            if *last_rs % 2 == 0 { *rs = rs.wrapping_sub(idx as u32); } else { *rs ^= data.len() as u32; }
            *last_rs = *rs;
        },
        12 => {
            let val = data.iter().fold(*rs, |acc, &b| acc.wrapping_add(b as u32));
            *rs = val ^ aux.get(idx % aux.len().max(1)).cloned().unwrap_or(0) as u32;
        },
        13 => {
            for _ in 0..(data.len() & 0x3) {
                *rs = rs.wrapping_mul(31).wrapping_add(idx as u32);
                aux.push((*rs & 0xFF) as u8);
            }
        },
        14 => {
            if let Some(&b) = data.get(idx % data.len().max(1)) {
                let shift = (b % 16) as u32;
                *rs = rs.rotate_right(shift) ^ last_rs.wrapping_add(idx as u32);
            }
        },
        15 => {
            let mut m = *rs;
            if !aux.is_empty() { m ^= aux[0] as u32; }
            *rs = (m.wrapping_mul(0x85ebca6b) ^ idx as u32).wrapping_add(data.len() as u32);
        },
        16 => {
            if !aux.is_empty() {
                let mut x = aux.pop().unwrap_or(0) as u32;
                x = x.rotate_left((*rs % 16) as u32);
                *rs ^= x.wrapping_mul(idx as u32 | 1);
                aux.insert(0, (x & 0xFF) as u8);
            }
        },
        17 => {
            let v1 = (*rs as u64).wrapping_mul(data.len() as u64);
            let v2 = (idx as u64).wrapping_add(*last_rs as u64);
            *rs = ((v1 ^ v2) as u32).wrapping_add(0x61C88647);
        },
        18 => {
            if aux.len() >= 2 {
                let i1 = (*rs as usize) % aux.len();
                let i2 = (idx as usize) % aux.len();
                aux.swap(i1, i2);
                *rs = rs.wrapping_add(aux[i1] as u32);
            }
        },
        19 => {
            if let Some(&b) = data.get(idx % data.len().max(1)) {
                let inter = (*rs & 0xAAAA) | ((b as u32 & 0x55) << 8);
                *rs = rs.wrapping_sub(inter).rotate_left(1);
            }
        },
        20 => {
            for j in 0..(data.len() & 0x3).max(1) {
                let b = data.get((idx + j) % data.len().max(1)).cloned().unwrap_or(0) as u32;
                *rs = rs.wrapping_add(b).rotate_right(j as u32 + 1);
                aux.push((*rs & 0xFF) as u8);
            }
        },
        21 => {
            let mut p = 0u32;
            for &b in data.iter().take(8) { p ^= b as u32; }
            if p % 2 == 0 { *rs = rs.wrapping_add(p); } else { *rs ^= p; }
            *rs = rs.rotate_left(3);
        },
        22 => {
            if !aux.is_empty() {
                let rot = (*rs % 8) as u32;
                for x in aux.iter_mut() { *x = x.rotate_left(rot); }
                *rs = rs.wrapping_add(aux[0] as u32);
            }
        },
        23 => {
            match idx % 4 {
                0 => *rs = rs.wrapping_add(0x11111111),
                1 => *rs ^= 0x22222222,
                2 => *rs = rs.rotate_right(5),
                _ => {
                    if let Some(&b) = data.get(idx % data.len().max(1)) {
                        *rs = rs.wrapping_sub(b as u32);
                    }
                }
            }
        },
        24 => {
            let fb = last_rs.wrapping_mul(data.len() as u32);
            *rs = rs.wrapping_add(fb ^ 0x9e3779b9);
            *last_rs = *rs;
        },
        25 => {
            let s: u32 = aux.iter().take(4).map(|&b| b as u32).sum();
            *rs ^= s.wrapping_mul(idx as u32 | 1);
        },
        26 => {
            if data.len() >= 2 {
                let b1 = data[idx % data.len()] as u32;
                let b2 = data[(idx + 1) % data.len()] as u32;
                *rs = rs.wrapping_add(b1 << 8 | b2);
            }
        },
        27 => {
            let mut temp_rs = *rs;
            for _ in 0..3 {
                temp_rs = (temp_rs ^ (temp_rs >> 16)).wrapping_mul(0x85ebca6b);
                temp_rs = (temp_rs ^ (temp_rs >> 13)).wrapping_mul(0xc2b2ae35);
            }
            *rs = temp_rs ^ idx as u32;
        },
        28 => {
            if aux.len() > 4 {
                let mut h = Hasher::new();
                h.update(&aux);
                *rs ^= h.finalize();
            }
        },
        29 => {
            if (*rs & 1) != 0 {
                *rs = rs.wrapping_mul(3).wrapping_add(1);
            } else {
                *rs /= 2;
            }
            *rs ^= data.len() as u32;
        },
        30 => {
            let ent = data.iter().fold(0u32, |acc, &b| acc ^ (b as u32).rotate_left(acc % 8));
            *rs = rs.wrapping_add(ent);
        },
        31 => {
            let diff = rs.wrapping_sub(*last_rs);
            *rs = rs.wrapping_add(diff.rotate_right(4));
            *last_rs = *rs;
        },
        32 => {
            aux.push((idx & 0xFF) as u8);
            if aux.len() > 16 {
                let popped = aux.pop().unwrap_or(0) as u32;
                *rs ^= popped.wrapping_mul(0x12345678);
            }
        },
        33 => {
            let x = *rs;
            let y = idx as u32;
            let mba = (x | y).wrapping_sub(x & y); // XOR
            *rs = mba.wrapping_add(data.len() as u32);
        },
        34 => {
            if let Some(&b) = data.get(idx % data.len().max(1)) {
                let s = (b % 32) as u32;
                *rs = rs.rotate_left(s) ^ rs.rotate_right(32 - s);
            }
        },
        35 => {
            if aux.len() >= 4 {
                let pivot = (idx % aux.len()) as usize;
                let val = aux[pivot] as u32;
                *rs = rs.wrapping_add(val << (idx % 24));
            }
        },
        36 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let m1 = 0x55555555;
            let m2 = 0xAAAAAAAA;
            *rs = ((*rs & m1) << 1) | ((*rs & m2) >> 1);
            *rs ^= b;
        },
        37 => {
            let mut acc = 0u32;
            for &x in aux.iter().rev().take(5) { acc = acc.wrapping_add(x as u32); }
            *rs ^= acc;
        },
        38 => {
            let coupling = (*last_rs ^ (data.len() as u32)).wrapping_mul(0x21212121);
            *rs = rs.wrapping_add(coupling);
        },
        39 => {
            let mut final_m = *rs ^ *last_rs ^ idx as u32 ^ data.len() as u32;
            if let Some(&b) = aux.last() { final_m ^= b as u32; }
            *rs = final_m.rotate_left(7);
        },
        40 => {
            aux.push((*rs & 0xFF) as u8);
            if aux.len() > 4 {
                let delayed = aux.remove(0) as u32;
                *rs = rs.wrapping_add(delayed ^ idx as u32);
            }
        },
        41 => {
            let feedback = last_rs.wrapping_add(data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32);
            *rs ^= feedback.rotate_right(3);
            *last_rs = *rs;
        },
        42 => {
            let mut h = Hasher::new();
            h.update(&aux);
            let check = h.finalize();
            if check % 2 == 0 {
                *rs = rs.wrapping_add(check).rotate_left(5);
            } else {
                *rs ^= check.wrapping_mul(0x33445566);
            }
        },
        43 => {
            let last_aux = aux.last().cloned().unwrap_or(0) as u32;
            *rs = rs.wrapping_add(last_aux ^ idx as u32 ^ data.len() as u32).rotate_right(2);
        },
        44 => {
            if let Some(&b) = data.get(idx % data.len().max(1)) {
                let x = *rs;
                let y = b as u32;
                let mba = (x & y).wrapping_add(x | y);
                *rs = mba.wrapping_sub(0x55AA55AA);
            }
        },
        45 => {
            if *rs % 2 == 0 {
                let rot = (data.len() % 8) as u32;
                for x in aux.iter_mut() { *x = x.rotate_left(rot); }
            } else {
                *rs = rs.wrapping_add(1);
            }
        },
        46 => {
            while aux.len() > 8 {
                let v = aux.pop().unwrap_or(0) as u32;
                *rs = rs.wrapping_sub(v).rotate_left(1);
            }
        },
        47 => {
            let mask = *last_rs as usize;
            if let Some(&b) = data.get(mask % data.len().max(1)) {
                *rs ^= (b as u32).wrapping_mul(0x12345678);
            }
        },
        48 => {
            aux.push((*rs & 0xFF) as u8);
            let sum: u32 = aux.iter().rev().take(3).map(|&b| b as u32).sum();
            *rs = rs.wrapping_add(sum ^ *last_rs);
        },
        49 => {
            let mut h = Hasher::new();
            h.update(&data[..idx % data.len().max(1)]);
            let d_hash = h.finalize();
            if (*rs ^ d_hash) % 2 == 0 {
                *rs = rs.wrapping_mul(3).wrapping_add(d_hash);
            }
        },
        50 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let al = aux.len() as u32;
            *rs = rs.rotate_left(b % 7).wrapping_add(al);
        },
        51 => {
            for (i, &a) in aux.iter().enumerate().take(4) {
                *rs = rs.wrapping_add((a as u32).wrapping_mul((i as u32).wrapping_add(1)));
            }
        },
        52 => {
            let sum = data.iter().take(16).fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
            *rs ^= sum.wrapping_mul(idx as u32 ^ *last_rs);
        },
        53 => {
            if let Some(&b) = data.get(idx % data.len().max(1)) {
                if b > 0x7F {
                    *rs = rs.wrapping_add(0xDEADC0DE).rotate_right(13);
                } else {
                    *rs = rs.wrapping_sub(0x13371337);
                }
            }
        },
        54 => {
            let state_idx = (*rs as usize ^ aux.len()) % 256;
            *rs = rs.wrapping_add(state_idx as u32 ^ data.len() as u32);
        },
        55 => {
            let temp = *rs;
            *rs = last_rs.wrapping_add(data.len() as u32);
            *last_rs = temp ^ data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
        },
        56 => {
            if aux.len() >= 4 {
                let x = (*rs % 2) as usize;
                let y = (idx % 2) as usize;
                let val = aux[(x * 2 + y) % aux.len()] as u32;
                *rs ^= val.wrapping_mul(data.len() as u32);
            }
        },
        57 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let l = *rs & 0xFFFF;
            let r = *rs >> 16;
            let next_r = l ^ (r.wrapping_add(b).rotate_left(5));
            *rs = (r << 16) | next_r;
        },
        58 => {
            let bc_data = data.iter().take(8).map(|&b| b.count_ones()).sum::<u32>();
            let bc_aux = aux.iter().take(8).map(|&b| b.count_ones()).sum::<u32>();
            *rs = rs.wrapping_add(bc_data ^ bc_aux);
        },
        59 => {
            *rs = (*rs ^ *last_rs).wrapping_add(data.len() as u32).rotate_left(aux.len() as u32 % 32) ^ data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
        },
        60 => {
            let entropy = data.iter().cycle().skip(idx % data.len().max(1)).take(4).fold(0u32, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u32));
            *rs = rs.wrapping_add(entropy ^ *last_rs);
        },
        61 => {
            if aux.len() >= 8 {
                let mid = aux.len() / 2;
                let v = aux[mid] as u32;
                *rs = rs.rotate_right(v % 32).wrapping_sub(idx as u32);
            } else {
                aux.push((*rs & 0xFF) as u8);
            }
        },
        62 => {
            let mut h = Hasher::new();
            h.update(&[((*rs >> 24) & 0xFF) as u8, ((*rs >> 16) & 0xFF) as u8, (idx & 0xFF) as u8]);
            let res = h.finalize();
            *rs ^= res.wrapping_mul(data.len() as u32 | 1);
        },
        63 => {
            let mask = (*rs ^ idx as u32).wrapping_mul(0xdeadbeef);
            for i in 0..(data.len() % 4).max(1) {
                *rs = rs.wrapping_add(mask.rotate_left(i as u32));
            }
        },
        64 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let combined = b.wrapping_add(aux.len() as u32).wrapping_mul(*last_rs | 1);
            *rs ^= combined;
        },
        65 => {
            let mut x = *rs;
            x ^= x >> 16;
            x = x.wrapping_mul(0x85ebca6b);
            x ^= x >> 13;
            x = x.wrapping_mul(0xc2b2ae35);
            x ^= x >> 16;
            *rs = x.wrapping_add(idx as u32);
        },
        66 => {
            if idx % 2 == 0 {
                aux.push((*rs & 0xFF) as u8);
            } else if !aux.is_empty() {
                let v = aux.remove(0) as u32;
                *rs = rs.wrapping_sub(v).rotate_left(5);
            }
        },
        67 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            *rs = rs.wrapping_add(*last_rs).wrapping_xor(b.wrapping_mul(0x13371337));
        },
        68 => {
            let mut sum = 0u32;
            for &val in aux.iter().take(10) { sum = sum.wrapping_add(val as u32); }
            *rs = rs.wrapping_add(sum ^ (data.len() as u32));
        },
        69 => {
            let s = (*rs % 16) as u32;
            *rs = rs.rotate_left(s) ^ (idx as u32).wrapping_mul(0x11223344);
        },
        70 => {
            if let Some(&b) = data.get((idx ^ *rs as usize) % data.len().max(1)) {
                *rs ^= (b as u32).wrapping_mul(0xCAFEBABE);
            }
        },
        71 => {
            aux.push(((*rs ^ *last_rs) & 0xFF) as u8);
            if aux.len() > 32 { aux.truncate(16); }
        },
        72 => {
            let v = (data.len() as u32).wrapping_add(idx as u32).wrapping_mul(0x31415927);
            *rs = rs.wrapping_add(v).rotate_right(11);
        },
        73 => {
            let lrs = *last_rs;
            let mut h = Hasher::new();
            h.update(&lrs.to_le_bytes());
            *rs ^= h.finalize();
        },
        74 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let s = (b.count_ones() % 32) as u32;
            *rs = rs.rotate_left(s).wrapping_add(aux.len() as u32);
        },
        75 => {
            let mut m = *rs;
            for _ in 0..2 {
                m = m.wrapping_mul(1664525).wrapping_add(1013904223);
            }
            *rs = m ^ *last_rs;
        },
        76 => {
            if !aux.is_empty() {
                let idx_s = (*rs as usize) % aux.len();
                *rs ^= (aux[idx_s] as u32).wrapping_mul(idx as u32);
            }
        },
        77 => {
            let d_len = data.len() as u32;
            let a_len = aux.len() as u32;
            *rs = rs.wrapping_add(d_len ^ a_len ^ 0xAAAAAAAA).rotate_left(4);
        },
        78 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let mut x = *rs ^ b;
            x = x.wrapping_add(x << 10);
            x ^= x >> 6;
            *rs = x;
        },
        79 => {
            aux.push((idx & 0xFF) as u8);
            let mut sum = 0u32;
            for &a in aux.iter().rev().take(4) { sum ^= a as u32; }
            *rs = rs.wrapping_sub(sum).rotate_right(3);
        },
        80 => {
            let v = last_rs.wrapping_add(idx as u32).wrapping_xor(data.len() as u32);
            *rs = rs.wrapping_mul(3).wrapping_add(v);
        },
        81 => {
            if let Some(&b) = data.get(idx % data.len().max(1)) {
                let mask = (b as u32).wrapping_mul(0x55555555);
                *rs ^= mask;
            }
        },
        82 => {
            let mut h = Hasher::new();
            h.update(&data[..idx % data.len().max(1)]);
            h.update(&aux);
            *rs = rs.wrapping_add(h.finalize());
        },
        83 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let rot = (b % 32) as u32;
            *rs = rs.rotate_left(rot).wrapping_xor(0x33333333);
        },
        84 => {
            let mut acc = *rs;
            for i in 0..4 {
                acc = acc.wrapping_add(aux.get(i).cloned().unwrap_or(0) as u32);
            }
            *rs = acc ^ *last_rs;
        },
        85 => {
            let mut v = *rs;
            v = (v ^ (v >> 16)).wrapping_mul(0x45d9f3b);
            v = (v ^ (v >> 16)).wrapping_mul(0x45d9f3b);
            v = v ^ (v >> 16);
            *rs = v.wrapping_add(idx as u32);
        },
        86 => {
            if data.len() > 10 {
                let val = data[10 % data.len()] as u32;
                *rs = rs.wrapping_sub(val).rotate_right(7);
            }
        },
        87 => {
            aux.push((*rs & 0xFF) as u8);
            let mut h = Hasher::new();
            h.update(&aux);
            *rs ^= h.finalize() ^ (data.len() as u32);
        },
        88 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            let m = (b as u32).wrapping_mul(idx as u32);
            *rs = rs.wrapping_add(m).rotate_left(2);
        },
        89 => {
            let mut x = *rs;
            x = (x.wrapping_add(0x7ed55d16)).wrapping_add(x << 12);
            x = (x ^ 0xc761c23c) ^ (x >> 19);
            *rs = x ^ *last_rs;
        },
        90 => {
            if aux.len() > 2 {
                let a = aux[0] as u32;
                let b = aux[1] as u32;
                *rs ^= (a << 8) | b;
            }
        },
        91 => {
            let mut sum = 0u32;
            for &b in data.iter().take(5) { sum = sum.wrapping_add(b as u32); }
            *rs = rs.wrapping_sub(sum ^ idx as u32);
        },
        92 => {
            let rot = (idx % 32) as u32;
            *rs = rs.rotate_right(rot).wrapping_xor(data.len() as u32);
        },
        93 => {
            let val = last_rs.wrapping_mul(31).wrapping_add(*rs);
            *rs = val ^ 0x12345678;
            *last_rs = *rs;
        },
        94 => {
            if !aux.is_empty() {
                let last = aux.pop().unwrap() as u32;
                *rs = rs.wrapping_add(last).rotate_left(1);
                aux.insert(0, (last & 0xFF) as u8);
            }
        },
        95 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            *rs ^= b.wrapping_mul(0x21212121) ^ aux.len() as u32;
        },
        96 => {
            let mut m = *rs;
            m = (m ^ (m >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64 as u32);
            m = (m ^ (m >> 27)).wrapping_mul(0x94d049bb133111ebu64 as u32);
            *rs = m ^ (m >> 31);
        },
        97 => {
            let d_len = data.len() as u32;
            *rs = rs.wrapping_add(d_len).rotate_right(d_len % 32);
        },
        98 => {
            aux.push((idx & 0xFF) as u8);
            let check = aux.iter().fold(0u32, |acc, &x| acc.wrapping_add(x as u32));
            *rs ^= check;
        },
        99 => {
            let b = data.get(idx % data.len().max(1)).cloned().unwrap_or(0) as u32;
            *rs = (*rs ^ b).wrapping_add(*last_rs).rotate_left(3);
        },
        _ => unreachable!(),
    }
}

fn generate_junk_logic(
    rs_var: &syn::Ident,
    data_var: &syn::Ident,
    aux_var: &syn::Ident,
    idx_var: &syn::Ident,
    last_rs_var: &syn::Ident,
    cases: &[usize],
) -> proc_macro2::TokenStream {
    let mut junk = Vec::new();
    for &case in cases {
        junk.push(generate_advanced_junk_internal(rs_var, data_var, aux_var, idx_var, last_rs_var, case));
    }
    quote! {
        #(#junk)*
    }
}


fn obfuscate_data_internal(data_bytes: Vec<u8>, is_string: bool) -> proc_macro2::TokenStream {
    let mut rng = thread_rng();
    let call_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let mut codecs = Codec::all();
    codecs.shuffle(&mut rng);

    let (first_codecs, rest) = codecs.split_at(rng.gen_range(1..=3));
    let (second_codecs, third_codecs) = rest.split_at(rng.gen_range(1..=2));

    let (key1, key1_defs, key1_frag_vars, key1_checksum_vars) = generate_key_fragments(16);
    let (key2, key2_defs, key2_frag_vars, key2_checksum_vars) = generate_key_fragments(16);

    let mut data = data_bytes;

    for codec in first_codecs {
        data = codec.encode(&data);
    }
    data = data
        .iter()
        .zip(key1.iter().cycle())
        .map(|(&b, &k)| b ^ k)
        .collect();
    for codec in second_codecs {
        data = codec.encode(&data);
    }
    data = data
        .iter()
        .zip(key2.iter().cycle())
        .map(|(&b, &k)| b ^ k)
        .collect();
    for codec in third_codecs {
        data = codec.encode(&data);
    }

    let data_var = syn::Ident::new("data", proc_macro2::Span::call_site());

    let (key1_var, key1_recon_logic) = generate_key_reconstruction_logic(
        "reconstructed_key_1",
        16,
        &key1_frag_vars,
        &key1_checksum_vars,
    );
    let (key2_var, key2_recon_logic) = generate_key_reconstruction_logic(
        "reconstructed_key_2",
        16,
        &key2_frag_vars,
        &key2_checksum_vars,
    );

    let mut decoding_ops = Vec::new();
    for codec in third_codecs.iter().rev() {
        decoding_ops.push(codec.get_decode_logic(&data_var));
    }
    decoding_ops.push(quote! {
        #data_var = #data_var.iter().zip(#key2_var.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
        #key2_var.zeroize();
    });
    for codec in second_codecs.iter().rev() {
        decoding_ops.push(codec.get_decode_logic(&data_var));
    }
    decoding_ops.push(quote! {
        #data_var = #data_var.iter().zip(#key1_var.iter().cycle()).map(|(&b, &k)| b ^ k).collect();
        #key1_var.zeroize();
    });
    for codec in first_codecs.iter().rev() {
        decoding_ops.push(codec.get_decode_logic(&data_var));
    }

    // Generate Opcodes for decoding
    // 0: Base36, 1: Base45, 2: Base58, 3: Base85, 4: Base91, 5: Base122, 10: XOR Key1, 11: XOR Key2
    let mut real_opcodes = Vec::new();
    for codec in third_codecs.iter().rev() {
        real_opcodes.push(*codec as u64);
    }
    real_opcodes.push(11);
    for codec in second_codecs.iter().rev() {
        real_opcodes.push(*codec as u64);
    }
    real_opcodes.push(10);
    for codec in first_codecs.iter().rev() {
        real_opcodes.push(*codec as u64);
    }

    // Generate 11 paths (1 real, 10 fake)
    let mut all_static_defs = Vec::new();
    all_static_defs.push(key1_defs);
    all_static_defs.push(key2_defs);

    // Real Data fragments
    let (real_defs, real_recon, real_data_ident) = generate_data_fragments(&data, &format!("R{}", call_id));
    all_static_defs.push(real_defs);

    // Shared Fake Path Data
    let fake_len = if data.len() > 1024 { 256 } else { data.len() };
    let fake_data_bytes: Vec<u8> = (0..fake_len).map(|_| rng.gen()).collect();
    let (fake_defs, fake_recon, fake_data_ident) = generate_data_fragments(&fake_data_bytes, &format!("F{}", call_id));
    all_static_defs.push(fake_defs);

    let mut path_configs = Vec::new();
    // Real path config
    path_configs.push((true, real_opcodes.clone()));
    // Fake path configs
    for _ in 0..10 {
        let mut fake_ops = Vec::new();
        for _ in 0..rng.gen_range(3..7) {
            fake_ops.push(rng.gen_range(0..6));
        }
        path_configs.push((false, fake_ops));
    }
    path_configs.shuffle(&mut rng);

    let real_path_idx = path_configs.iter().position(|p| p.0).unwrap() as u64;

    let initial_rs: u32 = rng.gen();
    let mut current_rs = initial_rs;
    let mut current_aux = Vec::new();
    let mut last_rs = 0u32;
    let mut current_sim_data = data.clone();

    let rs_ident = syn::Ident::new("rs", proc_macro2::Span::call_site());
    let aux_ident = syn::Ident::new("aux", proc_macro2::Span::call_site());
    let d_ident = syn::Ident::new("d", proc_macro2::Span::call_site());
    let idx_ident = syn::Ident::new("idx", proc_macro2::Span::call_site());
    let last_rs_ident = syn::Ident::new("last_rs", proc_macro2::Span::call_site());

    let mut runner_arms = Vec::new();
    let mut real_opcodes_masked = Vec::new();

    for (op_idx, &op) in real_opcodes.iter().enumerate() {
        // Simulation: Op-masked match arm selection depends on RS from PREVIOUS step (or initial)
        let masked_op = op ^ (current_rs as u64);
        real_opcodes_masked.push(masked_op);

        // Junk happens AFTER matching but before decoding
        let mut junk_cases = Vec::new();
        for _ in 0..rng.gen_range(8..=16) {
            let case = rng.gen_range(0..100);
            junk_cases.push(case);
            simulate_advanced_junk(case, &mut current_rs, &current_sim_data, &mut current_aux, op_idx, &mut last_rs);
        }

        let junk_logic = generate_junk_logic(&rs_ident, &d_ident, &aux_ident, &idx_ident, &last_rs_ident, &junk_cases);

        let decode_step = match op {
            0 => quote! { #d_ident = base36::decode(&String::from_utf8_lossy(&#d_ident)).unwrap(); },
            1 => quote! { #d_ident = base45::decode(String::from_utf8_lossy(&#d_ident).as_ref()).unwrap(); },
            2 => quote! { #d_ident = bs58::decode(String::from_utf8_lossy(&#d_ident).as_ref()).into_vec().unwrap(); },
            3 => quote! { #d_ident = base85::decode(&String::from_utf8_lossy(&#d_ident)).unwrap(); },
            4 => quote! { #d_ident = base91::slice_decode(&#d_ident); },
            5 => quote! { #d_ident = base122_rs::decode(&String::from_utf8_lossy(&#d_ident)).unwrap(); },
            10 => quote! { #d_ident = #d_ident.iter().zip(k1.iter().cycle()).map(|(&b, &k)| b ^ k).collect(); k1.zeroize(); },
            11 => quote! { #d_ident = #d_ident.iter().zip(k2.iter().cycle()).map(|(&b, &k)| b ^ k).collect(); k2.zeroize(); },
            _ => unreachable!(),
        };

        // Update sim data for next steps
        match op {
            0..=5 => {
                let codec = match op {
                    0 => Codec::Base36, 1 => Codec::Base45, 2 => Codec::Base58, 3 => Codec::Base85, 4 => Codec::Base91, 5 => Codec::Base122,
                    _ => unreachable!(),
                };
                current_sim_data = codec.decode(&current_sim_data);
            }
            10 => { current_sim_data = current_sim_data.iter().zip(key1.iter().cycle()).map(|(&b, &k)| b ^ k).collect(); }
            11 => { current_sim_data = current_sim_data.iter().zip(key2.iter().cycle()).map(|(&b, &k)| b ^ k).collect(); }
            _ => unreachable!(),
        }

        runner_arms.push(quote! {
            #op => {
                #junk_logic
                #decode_step
            }
        });
    }

    let mut path_arms = Vec::new();
    for (i, (is_real, opcodes)) in path_configs.iter().enumerate() {
        let idx = i as u64;
        let bytecode = if *is_real {
            generate_bytecode_for_ops(&real_opcodes_masked)
        } else {
            generate_bytecode_for_ops(opcodes)
        };
        let bytecode_lit = proc_macro2::Literal::byte_string(&bytecode);

        let data_init = if *is_real {
            quote! {
                #real_recon
                (#real_data_ident, #bytecode_lit as &[u8])
            }
        } else {
            quote! {
                #fake_recon
                (#fake_data_ident, #bytecode_lit as &[u8])
            }
        };

        path_arms.push(quote! {
            #idx => { #data_init }
        });
    }

    let vm_def = generate_vm_logic();
    let real_idx_bytecode = generate_bytecode_for_ops(&[real_path_idx]);
    let real_idx_bytecode_lit = proc_macro2::Literal::byte_string(&real_idx_bytecode);

    let result_expr = if is_string {
        quote! { String::from_utf8_lossy(&final_data).to_string() }
    } else {
        quote! { final_data.to_vec() }
    };

    let logic_block = quote! {
        {
            #key1_recon_logic
            #key2_recon_logic
            #vm_def

            // ORIGINAL RUNNER (Preserved for additive rule)
            let mut runner_legacy = |mut d: Vec<u8>, bc: &[u8], k1: &mut Vec<u8>, k2: &mut Vec<u8>| {
                let mut vm = VM::new();
                vm.execute(bc);
                for op in vm.outputs {
                    match op {
                        0 => { d = base36::decode(&String::from_utf8_lossy(&d)).unwrap(); }
                        1 => { d = base45::decode(String::from_utf8_lossy(&d).as_ref()).unwrap(); }
                        2 => { d = bs58::decode(String::from_utf8_lossy(&d).as_ref()).into_vec().unwrap(); }
                        3 => { d = base85::decode(&String::from_utf8_lossy(&d)).unwrap(); }
                        4 => { d = base91::slice_decode(&d); }
                        5 => { d = base122_rs::decode(&String::from_utf8_lossy(&d)).unwrap(); }
                        10 => { d = d.iter().zip(k1.iter().cycle()).map(|(&b, &k)| b ^ k).collect(); k1.zeroize(); }
                        11 => { d = d.iter().zip(k2.iter().cycle()).map(|(&b, &k)| b ^ k).collect(); k2.zeroize(); }
                        _ => {}
                    }
                }
                d
            };

            // NEW 10/10 POLYMORPHIC RUNNER
            let mut runner = |mut #d_ident: Vec<u8>, bc: &[u8], k1: &mut Vec<u8>, k2: &mut Vec<u8>| {
                let mut #rs_ident: u32 = #initial_rs;
                let mut #aux_ident: Vec<u8> = Vec::new();
                let mut #last_rs_ident: u32 = 0;
                let mut vm = VM::new();
                vm.execute(bc);
                for (idx, op_masked) in vm.outputs.into_iter().enumerate() {
                    let #idx_ident = idx;
                    let real_op = (op_masked ^ (#rs_ident as u64)) as u64;
                    match real_op {
                        #(#runner_arms)*
                        _ => {
                            // Junk/Fake path
                            #rs_ident = #rs_ident.wrapping_add(real_op as u32).rotate_left(1);
                        }
                    }
                }

                // Additive rule: call legacy runner on dummy data to ensure it's not removed
                let _ = runner_legacy(vec![], &[], &mut vec![], &mut vec![]);

                #d_ident
            };

            let mut vm_idx = VM::new();
            vm_idx.execute(#real_idx_bytecode_lit);
            let target_idx = vm_idx.outputs[0];

            let (initial_data, bytecode) = match target_idx {
                #(#path_arms)*
                _ => panic!("Invalid path"),
            };

            let final_data = runner(initial_data, bytecode, &mut #key1_var, &mut #key2_var);
            #result_expr
        }
    };

    let obfuscated_logic = logic_block; // Skip arithmetic obfuscation for now to reduce bloat

    quote! {
        {
            use zeroize::Zeroize;
            use crc32fast::Hasher;
            #(#all_static_defs)*
            #obfuscated_logic
        }
    }
}

#[proc_macro]
pub fn obfuscate_string(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();
    obfuscate_data_internal(original_str.into_bytes(), true).into()
}

#[proc_macro]
pub fn obfuscate_bytes(input: TokenStream) -> TokenStream {
    if let Some(bytes) = fast_parse_bytes(input) {
        obfuscate_data_internal(bytes, false).into()
    } else {
        panic!("obfuscate_bytes! only supports byte string literals (b\"...\") or array literals (&[...]) of bytes.");
    }
}

fn apply_main_obfuscation(mut main_fn: ItemFn) -> (proc_macro2::TokenStream, ItemFn) {
    if main_fn.sig.ident != "main" {
        panic!("The main obfuscation can only be used on the main function");
    }

    let mut rng = thread_rng();
    let random_part: String = std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(20)
        .collect();
    let random_fn_name = format!("obf_{}", random_part);
    let random_fn_ident = syn::Ident::new(&random_fn_name, main_fn.sig.ident.span());

    let main_fn_body = main_fn.block;

    let new_fn = quote! {
        fn #random_fn_ident() {
            #main_fn_body
        }
    };

    let new_main_body = quote! {
        {
            #random_fn_ident();
        }
    };

    let new_main_body_tokens: TokenStream = new_main_body.into();
    main_fn.block = syn::parse(new_main_body_tokens).expect("Failed to parse new main body");

    (new_fn, main_fn)
}

#[derive(Default)]
struct ObfuscatorArgs {
    fonk_len: Option<u64>,
    garbage: bool,
    main: bool,
    inline: bool,
    control_f: bool,
    arithmetic: bool,
}

impl ObfuscatorArgs {
    fn from_attrs(attrs: &[Meta]) -> Self {
        let mut args = Self::default();
        for attr in attrs {
            if let Meta::NameValue(nv) = attr {
                if nv.path.is_ident("fonk_len") || nv.path.is_ident("len") {
                    if let Expr::Lit(ExprLit { lit: Lit::Int(lit_int), .. }) = &nv.value {
                        args.fonk_len = lit_int.base10_parse().ok();
                    }
                } else if nv.path.is_ident("garbage") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.garbage = lit_bool.value;
                    }
                } else if nv.path.is_ident("main") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.main = lit_bool.value;
                    }
                } else if nv.path.is_ident("inline") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.inline = lit_bool.value;
                    }
                } else if nv.path.is_ident("control_f") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.control_f = lit_bool.value;
                    }
                } else if nv.path.is_ident("arithmetic") {
                    if let Expr::Lit(ExprLit { lit: Lit::Bool(lit_bool), .. }) = &nv.value {
                        args.arithmetic = lit_bool.value;
                    }
                }
            }
        }
        args
    }
}

#[proc_macro_attribute]
pub fn obfuscate(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = Punctuated::<Meta, syn::Token![,]>::parse_terminated.parse(attr).unwrap();
    let args = ObfuscatorArgs::from_attrs(&attrs.into_iter().collect::<Vec<_>>());
    let mut subject_fn = parse_macro_input!(item as ItemFn);

    let mut output = quote! {};

    if args.main {
        let (new_fn, modified_main) = apply_main_obfuscation(subject_fn.clone());
        output.extend(new_fn);
        subject_fn = modified_main;
    }

    if args.garbage {
        let fonk_len = args.fonk_len.unwrap_or(3);
        subject_fn = apply_junk_obfuscation(subject_fn, fonk_len);
    }

    if args.inline {
        let inline_attr: syn::Attribute = syn::parse_quote! { #[inline] };
        subject_fn.attrs.push(inline_attr);
    }

    if args.control_f {
        let mut visitor = ControlFlowObfuscator;
        visitor.visit_item_fn_mut(&mut subject_fn);
    }

    if args.arithmetic {
        let mut visitor = ArithmeticObfuscator { enabled: true };
        visitor.visit_item_fn_mut(&mut subject_fn);
    }

    output.extend(quote! { #subject_fn });
    output.into()
}

struct ArithmeticObfuscator {
    enabled: bool,
}

impl VisitMut for ArithmeticObfuscator {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        if !self.enabled {
            return;
        }
        if let Expr::Lit(ExprLit {
            lit: Lit::Int(lit_int),
            ..
        }) = expr
        {
            let suffix = lit_int.suffix();
            if let Ok(val) = lit_int.base10_parse::<u64>() {
                let mut rng = thread_rng();
                // Only obfuscate 5% of literals to save compilation time
                if !rng.gen_bool(0.05) || val < 100 {
                    return;
                }

                let mut current_expr = if suffix.is_empty() {
                    quote! { #val }
                } else {
                    let s = syn::Ident::new(suffix, proc_macro2::Span::call_site());
                    quote! { (#val as #s) }
                };

                for _ in 0..1 {
                    let r: u64 = rng.gen_range(1..1000);
                    let op = rng.gen_range(0..2);
                    current_expr = if suffix.is_empty() {
                        match op {
                            0 => quote! { (#current_expr.wrapping_add(#r as _).wrapping_sub(#r as _)) },
                            1 => quote! { (#current_expr ^ (#r as _) ^ (#r as _)) },
                            _ => unreachable!(),
                        }
                    } else {
                        let s = syn::Ident::new(suffix, proc_macro2::Span::call_site());
                        match op {
                            0 => {
                                quote! { (#current_expr.wrapping_add(#r as #s).wrapping_sub(#r as #s)) }
                            }
                            1 => quote! { (#current_expr ^ (#r as #s) ^ (#r as #s)) },
                            _ => unreachable!(),
                        }
                    };
                }
                let new_expr = current_expr;
                if let Ok(e) = syn::parse2(new_expr) {
                    *expr = e;
                    return;
                }
            }
        }
        visit_mut::visit_expr_mut(self, expr);
    }
}

struct ControlFlowObfuscator;

impl VisitMut for ControlFlowObfuscator {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        if let Expr::If(if_expr) = expr {
            // Check if any condition uses `let` (if-let) which is not supported in match guards
            fn has_if_let(if_expr: &syn::ExprIf) -> bool {
                if let Expr::Let(_) = *if_expr.cond {
                    return true;
                }
                if let Some((_, ref next)) = if_expr.else_branch {
                    if let Expr::If(ref next_if) = **next {
                        return has_if_let(next_if);
                    }
                }
                false
            }
            if has_if_let(if_expr) {
                visit_mut::visit_expr_mut(self, expr);
                return;
            }

            let mut conditions_and_blocks = vec![];
            let mut final_else_block = None;
            let mut current_if = if_expr.clone();

            // 1. Deconstruct the entire if-else-if chain into a flat list.
            loop {
                let cond = *current_if.cond;
                let then_block = current_if.then_branch;
                conditions_and_blocks.push((cond, then_block));

                if let Some((_, else_branch)) = current_if.else_branch {
                    if let Expr::If(next_if) = *else_branch {
                        current_if = next_if;
                    } else {
                        if let Expr::Block(expr_block) = *else_branch {
                            final_else_block = Some(expr_block.block);
                        } else {
                            // Handle cases like `else { some_expression }`
                            let new_block = syn::parse_quote!({ #else_branch });
                            final_else_block = Some(new_block);
                        }
                        break;
                    }
                } else {
                    break;
                }
            }

            for (cond, block) in &mut conditions_and_blocks {
                self.visit_expr_mut(cond);
                self.visit_block_mut(block);
            }
            if let Some(else_block) = &mut final_else_block {
                self.visit_block_mut(else_block);
            }

            let mut rng = thread_rng();
            let mut arms = Vec::new();
            for (cond, block) in conditions_and_blocks {
                arms.push(quote! { _ if #cond => #block });
            }

            // Add junk arms that can never be reached.
            let num_junk_arms = rng.gen_range(2..=5);
            for _ in 0..num_junk_arms {
                let random_u32: u32 = rng.gen();
                arms.push(quote! { _ if false && #random_u32 == 0 => {} });
            }

            // Shuffle the arms to obscure the original order.
            arms.shuffle(&mut rng);

            let final_arm = if let Some(else_block) = final_else_block {
                quote! { #else_block }
            } else {
                quote! { {} }
            };

            let match_expr_tokens = quote! {
                match () {
                    #(#arms,)*
                    _ => #final_arm,
                }
            };

            if let Ok(new_match_expr) = syn::parse2(match_expr_tokens) {
                *expr = new_match_expr;
            }
            // If parsing fails, leave the original expression untouched.
            return;
        }

        // Default traversal for all other expression types.
        visit_mut::visit_expr_mut(self, expr);
    }
}


fn apply_junk_obfuscation(mut subject_fn: ItemFn, fonk_len: u64) -> ItemFn {
    let mut rng = thread_rng();

    // RESTORING ORIGINAL JUNK LOGIC AS PER ADDITIVE RULE
    let num_junk_statements = rng.gen_range(5..=15);
    let mut junk_statements = Vec::new();

    for _ in 0..num_junk_statements {
        let random_part: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(10)
            .collect();
        let var_name = format!("_{}", random_part);
        let var_ident = syn::Ident::new(&var_name, proc_macro2::Span::call_site());
        let random_val: u32 = rng.gen();

        let junk_statement = quote! {
            let #var_ident = #random_val;
        };
        junk_statements.push(junk_statement);
    }

    // Wrap junk code in a complex loop
    let loop_iterations = fonk_len;
    let loop_counter_name: String = format!(
        "i_{}",
        std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(8)
            .collect::<String>()
    );
    let loop_counter_ident = syn::Ident::new(&loop_counter_name, proc_macro2::Span::call_site());

    let original_junk_code_block = quote! {
        for #loop_counter_ident in 0..#loop_iterations {
            if #loop_counter_ident > #loop_iterations {
                #(#junk_statements)*
            }
        }
    };

    // ADDING NEW ADVANCED JUNK LOGIC
    let rs_ident = syn::Ident::new("rs", proc_macro2::Span::call_site());
    let aux_ident = syn::Ident::new("aux", proc_macro2::Span::call_site());
    let d_ident = syn::Ident::new("d", proc_macro2::Span::call_site());
    let idx_ident = syn::Ident::new("idx", proc_macro2::Span::call_site());
    let last_rs_ident = syn::Ident::new("last_rs", proc_macro2::Span::call_site());

    let mut junk_cases = Vec::new();
    let initial_rs: u32 = 0x1337BEEF;
    let mut sim_rs = initial_rs;
    let mut sim_aux = Vec::new();
    let sim_data = vec![1, 2, 3, 4, 5];
    let mut sim_last_rs = 0u32;

    for _ in 0..fonk_len.max(20) {
        let case = rng.gen_range(0..100);
        junk_cases.push(case);
        simulate_advanced_junk(case, &mut sim_rs, &sim_data, &mut sim_aux, 0, &mut sim_last_rs);
    }

    let junk_logic = generate_junk_logic(&rs_ident, &d_ident, &aux_ident, &idx_ident, &last_rs_ident, &junk_cases);

    let advanced_junk_code_block = quote! {
        let mut #rs_ident: u32 = #initial_rs;
        let mut #aux_ident: Vec<u8> = Vec::new();
        let mut #last_rs_ident: u32 = 0;
        let #d_ident: Vec<u8> = vec![1, 2, 3, 4, 5];
        let #idx_ident = 0usize;

        // Junk is always executed. To make it semantically null but structurally active,
        // we use its result to calculate a dummy value that is then 'checked' in a way
        // the compiler cannot optimize away.
        #junk_logic

        if std::hint::black_box(#rs_ident) != #sim_rs {
            // This path is never taken but the compiler must assume it could be,
            // because #rs_ident was mutated by complex, data-dependent junk logic.
            // Removal of junk code or its normalization will cause a mismatch.
            panic!("State drift detected! Junk code integrity failure.");
        }
    };

    let original_body = subject_fn.block;
    let new_body_block = syn::parse2(quote! {
        {
            use crc32fast::Hasher;
            #original_junk_code_block
            #advanced_junk_code_block
            #original_body
        }
    }).expect("Failed to parse new body");

    subject_fn.block = Box::new(new_body_block);

    subject_fn
}
