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
    path_configs.push((true, real_opcodes));
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

    let mut path_arms = Vec::new();
    for (i, (is_real, opcodes)) in path_configs.iter().enumerate() {
        let idx = i as u64;
        let bytecode = generate_bytecode_for_ops(opcodes);
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

            let mut runner = |mut d: Vec<u8>, bc: &[u8], k1: &mut Vec<u8>, k2: &mut Vec<u8>| {
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
                quote! { _ => #else_block }
            } else {
                quote! { _ => {} }
            };

            let match_expr_tokens = quote! {
                match () {
                    #(#arms,)*
                    #final_arm,
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

    let junk_code_block = quote! {
        for #loop_counter_ident in 0..#loop_iterations {
            if #loop_counter_ident > #loop_iterations {
                #(#junk_statements)*
            }
        }
    };

    let original_body = subject_fn.block;
    let new_body_block = syn::parse2(quote! {
        {
            #junk_code_block
            #original_body
        }
    }).expect("Failed to parse new body");

    subject_fn.block = Box::new(new_body_block);

    subject_fn
}
