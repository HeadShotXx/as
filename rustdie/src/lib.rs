// src/lib.rs
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Arm, Block, FnArg, Ident, ItemFn, Lit, LitByteStr, LitStr, MetaNameValue, Pat, Stmt, Token,
    parse_macro_input,
};
use rand::{Rng, seq::SliceRandom, rngs::OsRng};

// --- String/Byte Obfuscation ---

/// A randomly generated operation for polymorphic encryption/decryption.
enum ObfOp {
    Xor(u8),
    Add(u8),
    Sub(u8),
    Swap,
}

impl ObfOp {
    /// Generate a random operation.
    fn random(rng: &mut impl Rng) -> Self {
        let key = rng.gen::<u8>();
        match rng.gen_range(0..=3) {
            0 => ObfOp::Xor(key),
            1 => ObfOp::Add(key),
            2 => ObfOp::Sub(key),
            _ => ObfOp::Swap,
        }
    }

    /// Return the inverse operation.
    fn inverse(&self) -> Self {
        match *self {
            ObfOp::Xor(k) => ObfOp::Xor(k), // XOR is its own inverse
            ObfOp::Add(k) => ObfOp::Sub(k),
            ObfOp::Sub(k) => ObfOp::Add(k),
            ObfOp::Swap => ObfOp::Swap,   // SWAP is its own inverse
        }
    }

    /// Apply the operation to a byte (for compile-time encoding).
    fn apply(&self, val: u8) -> u8 {
        match *self {
            ObfOp::Xor(k) => val ^ k,
            ObfOp::Add(k) => val.wrapping_add(k),
            ObfOp::Sub(k) => val.wrapping_sub(k),
            ObfOp::Swap => (val << 4) | (val >> 4),
        }
    }
}

/// FNV-1a 64-bit deterministic hash (seed)
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Encodes bytes into a custom ASCII85-like format with length suffix.
fn ascii85_encode_bytes(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let mut chunk = [0u8; 4];
        let n = std::cmp::min(4, input.len() - i);
        chunk[..n].copy_from_slice(&input[i..i + n]);

        let value = u32::from_be_bytes(chunk);
        let mut chars = [0u8; 5];
        let mut v = value;
        for k in (0..5).rev() {
            chars[k] = (v % 85) as u8 + 33;
            v /= 85;
        }
        out.push_str(&String::from_utf8_lossy(&chars));
        i += 4;
    }
    format!("{}:{}", out, input.len())
}

/// Generate a random base key at compile time using build timestamp and process info
fn generate_build_key() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::process;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let pid = process::id() as u128;

    // Mix timestamp and PID to get pseudo-random byte
    let mix = timestamp.wrapping_mul(0x517cc1b727220a95) ^ pid.wrapping_mul(0x1234567890abcdef);
    ((mix ^ (mix >> 64)) & 0xFF) as u8
}

/// Core function to implement both `obf_str!` and `obf_bytes!`.
/// This function generates a fully polymorphic decoder for each call.
fn obf_impl(bytes: &[u8], span: proc_macro2::Span, is_str: bool) -> TokenStream {
    let mut rng = OsRng;
    let base_key = generate_build_key();
    let seed = fnv1a_64(bytes);

    // 1. Generate a random sequence of operations for the decoder
    let op_count = rng.gen_range(4..=8);
    let decode_ops: Vec<ObfOp> = (0..op_count).map(|_| ObfOp::random(&mut rng)).collect();
    let encode_ops: Vec<ObfOp> = decode_ops.iter().map(|op| op.inverse()).rev().collect();

    // 2. Encrypt the bytes using the inverse (encoding) operations
    let mut encrypted_bytes = bytes.to_vec();
    for (i, byte) in encrypted_bytes.iter_mut().enumerate() {
        let key_modifier = (seed >> ((i % 8) * 8)) as u8 ^ base_key ^ (i as u8);
        let mut current_val = *byte;
        for op in &encode_ops {
            // Modify the key for each operation to make it position-dependent
            let dynamic_key_op = match op {
                ObfOp::Xor(k) => ObfOp::Xor(k.wrapping_add(key_modifier)),
                ObfOp::Add(k) => ObfOp::Add(k.wrapping_add(key_modifier)),
                ObfOp::Sub(k) => ObfOp::Sub(k.wrapping_add(key_modifier)),
                ObfOp::Swap => ObfOp::Swap,
            };
            current_val = dynamic_key_op.apply(current_val);
        }
        *byte = current_val;
    }

    // 3. Generate the decoder function
    let decoder_name = Ident::new(&format!("__obf_decode_{}", rng.gen::<u64>()), span);
    let val_ident = Ident::new("val", span);
    let mut decoder_body = TokenStream2::new();
    for (_op_idx, op) in decode_ops.iter().enumerate() {
        let key_modifier = quote! { (seed >> ((i % 8) * 8)) as u8 ^ base_key ^ (i as u8) };
        let op_code = match op {
            ObfOp::Xor(k) => {
                let dynamic_key = quote!{ #k.wrapping_add(#key_modifier) };
                quote! { #val_ident ^= #dynamic_key; }
            },
            ObfOp::Add(k) => {
                let dynamic_key = quote!{ #k.wrapping_add(#key_modifier) };
                quote! { #val_ident = #val_ident.wrapping_add(#dynamic_key); }
            },
            ObfOp::Sub(k) => {
                let dynamic_key = quote!{ #k.wrapping_add(#key_modifier) };
                quote! { #val_ident = #val_ident.wrapping_sub(#dynamic_key); }
            },
            ObfOp::Swap => quote! { #val_ident = (#val_ident << 4) | (#val_ident >> 4); },
        };
        decoder_body.extend(op_code);
    }

    let decoder_fn = quote! {
        #[inline(always)]
        fn #decoder_name(bytes: &mut [u8], seed: u64, base_key: u8) {
            for (i, val_ref) in bytes.iter_mut().enumerate() {
                let mut #val_ident = *val_ref;
                #decoder_body
                *val_ref = #val_ident;
            }
        }
    };

    // 4. Encode the encrypted bytes using ASCII85
    let encoded_str = ascii85_encode_bytes(&encrypted_bytes);
    let lit_encoded = LitStr::new(&encoded_str, span);

    // 5. Choose the return type (`ObfString` or `ObfBytes`)
    let result_ty = if is_str {
        quote! { obf_helpers::ObfString }
    } else {
        quote! { obf_helpers::ObfBytes }
    };

    // 6. Final code expansion
    let expanded = quote! {
        {
            #decoder_fn

            let mut decoded_bytes = obf_helpers::ascii85_decode(#lit_encoded)
                .expect("internal error: invalid ascii85 chunk");

            #decoder_name(&mut decoded_bytes, #seed, #base_key);

            #result_ty::from_decrypted_bytes(decoded_bytes)
        }
    };

    TokenStream::from(expanded)
}

/// obf_str! procedural macro - now fully polymorphic
#[proc_macro]
pub fn obf_str(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    obf_impl(lit.value().as_bytes(), lit.span().into(), true)
}

/// obf_bytes! procedural macro - now fully polymorphic
#[proc_macro]
pub fn obf_bytes(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitByteStr);
    obf_impl(&lit.value(), lit.span().into(), false)
}

// --- Function Polymorphism ---

/// Parses `#[polymorph(...)]` arguments.
struct PolymorphArgs {
    fn_len: Option<usize>,
    garbage: bool,
    control_flow: bool,
}

impl Parse for PolymorphArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let items = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;
        let mut fn_len = None;
        let mut garbage = false;
        let mut control_flow = false;

        for m in items {
            if let Some(id) = m.path.get_ident() {
                match id.to_string().as_str() {
                    "fn_len" => {
                        if let syn::Expr::Lit(expr) = &m.value {
                            if let Lit::Int(li) = &expr.lit {
                                fn_len = Some(li.base10_parse()?);
                            }
                        }
                    }
                    "garbage" => {
                        if let syn::Expr::Lit(expr) = &m.value {
                            if let Lit::Bool(lb) = &expr.lit {
                                garbage = lb.value;
                            }
                        }
                    }
                    "control_flow" => {
                        if let syn::Expr::Lit(expr) = &m.value {
                            if let Lit::Bool(lb) = &expr.lit {
                                control_flow = lb.value;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(PolymorphArgs { fn_len, garbage, control_flow })
    }
}

/// Macro attribute that renames the function, injects junk (if requested),
/// and emits a wrapper under the original name.
#[proc_macro_attribute]
pub fn polymorph(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as PolymorphArgs);
    let input_fn = parse_macro_input!(item as ItemFn);

    if args.control_flow {
        // Defer to the new control flow obfuscation logic
        return control_flow_obfuscation(input_fn);
    }

    // Original garbage injection logic
    garbage_injection(input_fn, args)
}

/// The original garbage injection transformation.
fn garbage_injection(mut f: ItemFn, args: PolymorphArgs) -> TokenStream {
    let original_sig = f.sig.clone();
    let vis = f.vis.clone();
    let attrs = f.attrs.clone();
    let len = args.fn_len.unwrap_or(8);
    let mut rng_obj = OsRng;

    let new_name_str = random_ident_str(len, &mut rng_obj);
    let new_name = Ident::new(&new_name_str, f.sig.ident.span());
    f.sig.ident = new_name.clone();

    let mut stmts = Vec::new();
    if args.garbage {
        stmts.extend(generate_garbage_stmts(len, &mut rng_obj));
    }
    stmts.extend(f.block.stmts.clone());
    f.block.stmts = stmts;

    let original_arg_idents: Vec<Ident> = original_sig
        .inputs
        .iter()
        .filter_map(|arg| if let FnArg::Typed(pat_ty) = arg {
            if let Pat::Ident(pi) = &*pat_ty.pat { Some(pi.ident.clone()) } else { None }
        } else { None })
        .collect();

    let wrapper = quote! {
        #[allow(non_snake_case)]
        #(#attrs)*
        #vis #original_sig {
            #new_name( #( #original_arg_idents ),* )
        }
    };

    TokenStream::from(quote! {
        #f
        #wrapper
    })
}

/// New function for control-flow obfuscation.
fn control_flow_obfuscation(mut f: ItemFn) -> TokenStream {
    let mut rng = OsRng;

    // 1. Deconstruct the function into basic blocks.
    let mut blocks = vec![];
    let mut current_block = vec![];
    for stmt in f.block.stmts.iter() {
        current_block.push(stmt.clone());
        // Split after any expression statement, which includes control flow like `if` or `return`.
        if let Stmt::Expr(_, _) = stmt {
            blocks.push(Block {
                brace_token: f.block.brace_token,
                stmts: current_block.drain(..).collect(),
            });
        }
    }
    if !current_block.is_empty() {
        blocks.push(Block {
            brace_token: f.block.brace_token,
            stmts: current_block,
        });
    }

    let has_return = !matches!(f.sig.output, syn::ReturnType::Default);
    let mut block_map = std::collections::HashMap::new();
    let mut state_ids: Vec<usize> = (0..blocks.len()).collect();
    state_ids.shuffle(&mut rng);

    let mut arms = vec![];
    let mut _final_state_id = None;

    for (i, block) in blocks.into_iter().enumerate() {
        let state_id = state_ids[i];
        block_map.insert(i, state_id);

        let next_state_id = if i + 1 < state_ids.len() {
            state_ids[i + 1]
        } else {
            // This is the last block, so we'll break the loop.
            _final_state_id = Some(state_id);
            9999 // Sentinel for the last state
        };

        let mut block_stmts = block.stmts;
        if let Some(last_stmt) = block_stmts.last_mut() {
            if let Stmt::Expr(expr, semi) = last_stmt {
                // If it's a return-like expression (`return ...` or a final expression)
                if semi.is_none() && has_return {
                    let new_expr = quote! {
                        {
                            result.write(#expr);
                            state = #next_state_id;
                        }
                    };
                    *expr = syn::parse2(new_expr).unwrap();
                    *semi = Some(syn::token::Semi::default());
                } else {
                    // It's a regular statement, just append the state change.
                     let new_expr = quote! {
                        {
                            #expr;
                            state = #next_state_id;
                        }
                    };
                    *expr = syn::parse2(new_expr).unwrap();
                }
            } else {
                 block_stmts.push(syn::parse_quote! { state = #next_state_id; });
            }
        } else {
             block_stmts.push(syn::parse_quote! { state = #next_state_id; });
        }


        arms.push(quote! {
            #state_id => {
                #(#block_stmts)*
            }
        });
    }

    arms.shuffle(&mut rng);

    // Handle case where there are no blocks
    let initial_state = state_ids.get(0).cloned().unwrap_or(9999);
    let new_body = if has_return {
        quote! {
            let mut result = std::mem::MaybeUninit::uninit();
            let mut state = #initial_state;
            loop {
                match state {
                    #(#arms)*
                    _ => break,
                }
            }
            unsafe { result.assume_init() }
        }
    } else {
        quote! {
            let mut state = #initial_state;
            loop {
                match state {
                    #(#arms)*
                    _ => break,
                }
            }
        }
    };

    // Fix the panic by wrapping the body in braces
    let new_body_with_braces = quote! { { #new_body } };
    f.block = syn::parse2(new_body_with_braces).unwrap();
    f.into_token_stream().into()
}


/// Generates a series of junk statements.
fn generate_garbage_stmts(len: usize, rng: &mut impl Rng) -> Vec<Stmt> {
    let mut stmts = Vec::new();
    let r1: u32 = rng.gen();
    let r2: u32 = rng.gen();

    stmts.push(syn::parse_quote! {
        if (#r1.wrapping_mul(#r2) ^ #r1) % 2 == 1 { } else {}
    });

    let dname = Ident::new(&random_ident_str(len, rng), proc_macro2::Span::call_site());
    stmts.push(syn::parse_quote! {
        fn #dname(x: i32) -> i32 { x ^ (#r2 as i32) }
    });
    stmts.push(syn::parse_quote! {
        let _ = #dname(#r1 as i32);
    });

    let choice: usize = rng.gen_range(0..5);
    let arms: Vec<Arm> = (0..5).map(|i| {
        let lit = syn::LitInt::new(&format!("{}usize", i), proc_macro2::Span::call_site());
        syn::parse_quote! { #lit => { let _ = #lit; }, }
    }).collect();
    stmts.push(syn::parse_quote! {
        match #choice { #(#arms)* _ => {} }
    });

    for _ in 0..rng.gen_range(2..=4) {
        let v: u8 = rng.gen();
        stmts.push(syn::parse_quote! { let _junk = #v; });
    }
    stmts
}

/// Generates a random snake_case identifier string.
fn random_ident_str(len: usize, rng: &mut impl Rng) -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let words = rng.gen_range(1..=3);
    let mut remaining = len;
    let mut parts = Vec::with_capacity(words);

    for i in 0..words {
        let word_len = if i + 1 == words {
            remaining
        } else {
            let max_len = remaining - (words - i - 1);
            if max_len == 0 { 1 } else { rng.gen_range(1..=max_len) }
        };
        remaining -= word_len;

        let part: String = (0..word_len)
            .map(|_| {
                let idx = rng.gen_range(0..LETTERS.len());
                LETTERS[idx] as char
            })
            .collect();
        parts.push(part);
    }
    parts.join("_")
}