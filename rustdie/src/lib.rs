// build.rs - full, self-contained
// Whole-crate obfuscator: string pipeline (base45->base85->base58->base32->base64->xor->hex->pad->AES-192->AES-128->AES-256)
// Identifier renaming + use-statement dedupe + fallback parsing.
// Anti-patching: Original string literal checksum verification.

use std::fs;
use std::path::Path;
use std::time::SystemTime;
use std::collections::{HashMap, HashSet};

use walkdir::WalkDir;
use rand::{Rng, RngCore};
use rand::SeedableRng;
use rand::rngs::StdRng;

use quote::{quote, ToTokens};
use proc_macro2::TokenStream;
use syn::fold::{self, Fold};
use syn::{Item, Attribute, Visibility, Expr, Ident, Type, ItemFn, UseTree, ItemImpl, ItemStatic, Block};

// string pipeline crates (ensure these are in Cargo.toml)
use base45;
use base85;
use base32;
use base58::ToBase58;
use hex;

// AES and decoding helpers are imported where needed inside the submodule

// Use getrandom to seed StdRng in build script (avoid OsRng trait mismatch)
use getrandom;
use regex::Regex;

/// ------------------ Configuration -----------------
const RENAME_PUB: bool = true;
const SRC_DIR: &str = "src";
const OUT_FILE: &str = "src/obfuscated.rs";
const FORCE_REGEN: bool = true;
/// -------------------------------------------------------------------------

/// Calculates a checksum for a slice of bytes. Used to verify string integrity.
fn calculate_checksum(data: &[u8]) -> u64 {
    let mut a = 1u64;
    let mut b = 0u64;
    for &byte in data {
        a = (a.wrapping_add(byte as u64)) % 65521;
        b = (b.wrapping_add(a)) % 65521;
    }
    (b << 32) | a
}

/// Simple inclusive range helper using RngCore::next_u64.
fn rnd_range_inclusive(rng: &mut impl RngCore, low: usize, high_inclusive: usize) -> usize {
    if low >= high_inclusive {
        return low;
    }
    let range = (high_inclusive - low + 1) as u64;
    let v = rng.next_u64();
    (low as u64 + (v % range)) as usize
}

/// modern random-bytes helper (uses RngCore::next_u64 or fill_bytes from provided rng)
fn generate_random_bytes(rng: &mut impl RngCore, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    rng.fill_bytes(&mut buf);
    buf
}

fn random_ident(len: usize, rng: &mut impl RngCore) -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let words = rnd_range_inclusive(rng, 1, 3);
    let mut remaining = len;
    let mut parts = Vec::with_capacity(words);

    for i in 0..words {
        let word_len = if i + 1 == words {
            remaining
        } else {
            let max_possible = remaining - (words - i - 1);
            rnd_range_inclusive(rng, 1, max_possible)
        };
        remaining -= word_len;

        let mut part = String::with_capacity(word_len);
        for _ in 0..word_len {
            let idx = rnd_range_inclusive(rng, 0, LETTERS.len() - 1);
            part.push(LETTERS[idx] as char);
        }
        parts.push(part);
    }

    parts.join("_")
}

/// ---------------- String obfuscation module (with AES & base85/base58) ----------------
mod string_obfuscation {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    use aes::{Aes128, Aes192, Aes256};
    use base64::{engine::general_purpose, Engine as _};

    fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
        let mut padded = data.to_vec();
        let pad_len = block_size - (data.len() % block_size);
        padded.extend(vec![pad_len as u8; pad_len]);
        padded
    }

    fn generate_aes_key(rng: &mut impl RngCore, size: usize) -> Vec<u8> {
        generate_random_bytes(rng, size)
    }

    /// Encodes then encrypts the string; returns (encrypted_bytes, combined_key)
    pub fn encode_string(input: &str, rng: &mut impl RngCore) -> (Vec<u8>, Vec<u8>) {
        // 1) base45
        let base45_encoded = base45::encode(input.as_bytes());

        // 2) base85
        let base85_encoded = base85::encode(base45_encoded.as_bytes());

        // 3) base58 (from bytes -> string)
        let base58_encoded = base85_encoded.as_bytes().to_base58();

        // 4) base32 (RFC4648 padded)
        let base32_encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, base58_encoded.as_bytes());

        // 5) base64
        let base64_encoded = general_purpose::STANDARD.encode(base32_encoded.as_bytes());

        // 6) hex encode of base64 bytes
        let hex_encoded = hex::encode(base64_encoded.as_bytes());

        // XOR key (16 bytes)
        let xor_key = generate_aes_key(rng, 16);
        // XOR the hex-encoded ASCII bytes
        let mut xor_encoded: Vec<u8> = hex_encoded.as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ xor_key[i % xor_key.len()])
            .collect();

        // PKCS7 pad to 16-byte blocks before AES
        xor_encoded = pad_pkcs7(&xor_encoded, 16);

        // AES keys (192, 128, 256)
        let aes192_key = generate_aes_key(rng, 24);
        let aes128_key = generate_aes_key(rng, 16);
        let aes256_key = generate_aes_key(rng, 32);

        // AES-192 encrypt in-place (16-byte blocks)
        {
            let cipher192 = Aes192::new(GenericArray::from_slice(&aes192_key));
            for chunk in xor_encoded.chunks_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher192.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }

        // AES-128 encrypt
        {
            let cipher128 = Aes128::new(GenericArray::from_slice(&aes128_key));
            for chunk in xor_encoded.chunks_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher128.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }

        // AES-256 encrypt
        {
            let cipher256 = Aes256::new(GenericArray::from_slice(&aes256_key));
            for chunk in xor_encoded.chunks_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher256.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }

        // Combine keys: xor_key || aes192 || aes128 || aes256
        let mut combined_key = xor_key.clone();
        combined_key.extend(aes192_key);
        combined_key.extend(aes128_key);
        combined_key.extend(aes256_key);

        (xor_encoded, combined_key)
    }

    /// Returns a runtime expression string like `decode_fn(&[bytes...], &[key...], 12345u64)`
    pub fn generate_obfuscated_string(original: &str, rng: &mut impl RngCore, decoder_fn_name: &str, expected_checksum: u64) -> String {
        let (encrypted_data, key) = encode_string(original, rng);
        let encrypted_array = encrypted_data.iter().map(|b| format!("{}", b)).collect::<Vec<_>>().join(", ");
        let key_array = key.iter().map(|b| format!("{}", b)).collect::<Vec<_>>().join(", ");
        format!("{}(&[{}], &[{}], {}u64)", decoder_fn_name, encrypted_array, key_array, expected_checksum)
    }

    pub fn generate_decoder_function(decoder_fn_name: &str) -> String {
        let s = format!(
    r#"
#[inline(never)]
fn calculate_checksum_runtime(data: &[u8]) -> u64 {{
    let mut a = 1u64;
    let mut b = 0u64;
    for &byte in data {{
        a = (a.wrapping_add(byte as u64)) % 65521;
        b = (b.wrapping_add(a)) % 65521;
    }}
    (b << 32) | a
}}

fn {name}(encrypted: &[u8], key: &[u8], expected_sum: u64) -> &'static str {{
    let s: String = {{
        use aes::cipher::{{BlockDecrypt, KeyInit, generic_array::GenericArray}};
        use aes::{{Aes128, Aes192, Aes256}};
        use base58::FromBase58;
        use base64::{{engine::general_purpose, Engine as _}};

        if key.len() < 88 {{ return Box::leak(String::from_utf8_lossy(encrypted).to_string().into_boxed_str()); }}

        let xor_key = &key[0..16];
        let aes192_key = &key[16..40];
        let aes128_key = &key[40..56];
        let aes256_key = &key[56..88];

        let mut data = encrypted.to_vec();

        let cipher256 = Aes256::new(GenericArray::from_slice(aes256_key));
        for chunk in data.chunks_mut(16){{
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher256.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }}

        let cipher128 = Aes128::new(GenericArray::from_slice(aes128_key));
        for chunk in data.chunks_mut(16){{
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher128.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }}

        let cipher192 = Aes192::new(GenericArray::from_slice(aes192_key));
        for chunk in data.chunks_mut(16){{
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher192.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }}

        if !data.is_empty() {{
            let pad_len = data[data.len() - 1] as usize;
            if pad_len <= 16 && pad_len <= data.len() {{
                data.truncate(data.len() - pad_len);
            }}
        }}

        let xor_decoded: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ xor_key[i % xor_key.len()]).collect();
        let hex_str = match String::from_utf8(xor_decoded) {{ Ok(s) => s, Err(_) => return Box::leak("".into()) }};
        let base64_bytes = match hex::decode(&hex_str) {{ Ok(b) => b, Err(_) => return Box::leak(hex_str.into_boxed_str()) }};
        let base64_str = match String::from_utf8(base64_bytes) {{ Ok(s) => s, Err(_) => return Box::leak("".into()) }};
        let base32_bytes = match general_purpose::STANDARD.decode(&base64_str) {{ Ok(b) => b, Err(_) => return Box::leak(base64_str.into_boxed_str()) }};
        let base32_str = match String::from_utf8(base32_bytes) {{ Ok(s) => s, Err(_) => return Box::leak("".into()) }};
        let base58_bytes = match base32::decode(base32::Alphabet::Rfc4648 {{ padding: true }}, &base32_str) {{ Some(b) => b, None => return Box::leak(base32_str.into_boxed_str()) }};
        let base58_str = match String::from_utf8(base58_bytes) {{ Ok(s) => s, Err(_) => return Box::leak("".into()) }};
        let base85_bytes = match base58_str.from_base58() {{ Ok(b) => b, Err(_) => return Box::leak(base58_str.into_boxed_str()) }};
        let base85_str = match String::from_utf8(base85_bytes) {{ Ok(s) => s, Err(_) => return Box::leak("".into()) }};
        let base45_bytes = match base85::decode(&base85_str) {{ Ok(b) => b, Err(_) => return Box::leak(base85_str.into_boxed_str()) }};
        let base45_str = match String::from_utf8(base45_bytes) {{ Ok(s) => s, Err(_) => return Box::leak("".into()) }};

        match base45::decode(&base45_str) {{
            Ok(final_bytes) => {{
                let runtime_sum = calculate_checksum_runtime(&final_bytes);
                if runtime_sum != expected_sum {{
                    // Tampering detected! Simulated volatile write (to valid memory) then abort.
                    unsafe {{
                        let mut dummy: u8 = 0;
                        std::ptr::write_volatile(&mut dummy, 1);
                    }}
                    std::process::abort();
                }}
                String::from_utf8_lossy(&final_bytes).to_string()
            }},
            Err(_) => base45_str,
        }}
    }};
    Box::leak(s.into_boxed_str())
}}"#, name = decoder_fn_name);
        s
    }
}

/// Helper: detect presence of #[no_mangle] attribute
fn has_no_mangle(attrs: &Vec<Attribute>) -> bool {
    attrs.iter().any(|a| a.path().segments.iter().any(|s| s.ident == "no_mangle"))
}

/// Helper: detect proc-macro attributes
fn has_proc_macro_attr(attrs: &Vec<Attribute>) -> bool {
    attrs.iter().any(|a| {
        a.path().segments.iter().any(|s| {
            let id = s.ident.to_string();
            id == "proc_macro" || id == "proc_macro_attribute" || id == "proc_macro_derive"
        })
    })
}

/// detect extern "C" functions (best-effort)
fn is_extern_c_fn(item_fn: &ItemFn) -> bool {
    item_fn.sig.abi.is_some()
}

struct FullObfFold {
    ident_map: HashMap<String, String>,
    rng: StdRng,
    decoder_name: String,
    string_literals: HashMap<String, String>,
}

impl FullObfFold {
    pub fn new(map: HashMap<String, String>, rng: StdRng, decoder_name: String) -> Self {
        Self {
            ident_map: map,
            rng,
            decoder_name,
            string_literals: HashMap::new(),
        }
    }

    fn obf_name_for(&self, orig: &str) -> Option<Ident> {
        self.ident_map.get(orig).map(|s| Ident::new(s, proc_macro2::Span::call_site()))
    }

    fn obfuscate_string_literal(&mut self, literal: &str) -> String {
        if let Some(cached) = self.string_literals.get(literal) {
            return cached.clone();
        }
        if literal.len() <= 1 {
            let s = format!("\"{}\"", literal);
            self.string_literals.insert(literal.to_string(), s.clone());
            return s;
        }
        let expected_checksum = calculate_checksum(literal.as_bytes());
        let expr = string_obfuscation::generate_obfuscated_string(literal, &mut self.rng, &self.decoder_name, expected_checksum);
        self.string_literals.insert(literal.to_string(), expr.clone());
        expr
    }
}

impl Fold for FullObfFold {
    fn fold_item_fn(&mut self, i: ItemFn) -> ItemFn {
        let mut i = i;
        if !is_extern_c_fn(&i) && !has_no_mangle(&i.attrs) {
            if let Some(obf) = self.obf_name_for(&i.sig.ident.to_string()) {
                i.sig.ident = obf;
            }
        }
        fold::fold_item_fn(self, i)
    }

    fn fold_item_struct(&mut self, i: syn::ItemStruct) -> syn::ItemStruct {
        let mut i = i;
        if let Some(obf) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf;
        }
        fold::fold_item_struct(self, i)
    }

    fn fold_item_enum(&mut self, i: syn::ItemEnum) -> syn::ItemEnum {
        let mut i = i;
        if let Some(obf) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf;
        }
        fold::fold_item_enum(self, i)
    }

    fn fold_item_static(&mut self, i: ItemStatic) -> ItemStatic {
        let mut i = i;
        if let Some(obf_ident) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf_ident;
        }
        fold::fold_item_static(self, i)
    }
    
    fn fold_item_impl(&mut self, i: ItemImpl) -> ItemImpl {
        let mut i = i;
        if i.trait_.is_none() {
            i.self_ty = Box::new(self.fold_type(*i.self_ty));
        }
        fold::fold_item_impl(self, i)
    }

    fn fold_path(&mut self, path: syn::Path) -> syn::Path {
        let mut path = path;
        if path.leading_colon.is_none() {
            if let Some(first_seg) = path.segments.first_mut() {
                let ident_str = first_seg.ident.to_string();
                if self.ident_map.contains_key(&ident_str) {
                    if let Some(new_name) = self.ident_map.get(&ident_str) {
                         first_seg.ident = Ident::new(new_name, first_seg.ident.span());
                    }
                }
            }
        }
        fold::fold_path(self, path)
    }

    fn fold_expr_method_call(&mut self, call: syn::ExprMethodCall) -> syn::ExprMethodCall {
        let mut call = call;
        if let Some(new_name) = self.ident_map.get(&call.method.to_string()) {
            call.method = Ident::new(new_name, call.method.span());
        }
        fold::fold_expr_method_call(self, call)
    }

    fn fold_expr(&mut self, expr: Expr) -> Expr {
        if let Expr::Lit(lit_expr) = &expr {
            // Handle string literals
            if let syn::Lit::Str(str_lit) = &lit_expr.lit {
                let original = str_lit.value();
                if !original.is_empty() {
                    let obf_expr_str = self.obfuscate_string_literal(&original);
                    if let Ok(parsed_expr) = syn::parse_str::<Expr>(&obf_expr_str) {
                        return parsed_expr;
                    }
                }
            }

            // Handle integer literals to make patching harder
            if let syn::Lit::Int(int_lit) = &lit_expr.lit {
                if let Ok(val) = int_lit.base10_parse::<i128>() {
                    // Avoid changing small, common values that are often part of control flow or array indices
                    if val.abs() > 1 {
                        // Split the number into two random parts that sum to the original value
                        // Ensure the range for the random number is valid
                        let upper_bound = (val / 2).abs().max(2);
                        let part1 = self.rng.gen_range(1..upper_bound);
                        let part2 = val - part1;

                        // Generate the arithmetic expression as a string
                        let expr_str = format!("({} + {})", part1, part2);

                        // Re-apply the original type suffix if one existed (e.g., u32, i64)
                        let final_expr_str = if !int_lit.suffix().is_empty() {
                            format!("({} as {})", expr_str, int_lit.suffix())
                        } else {
                            expr_str
                        };
                        
                        // Parse the new expression string back into a syn::Expr
                        if let Ok(parsed_expr) = syn::parse_str::<Expr>(&final_expr_str) {
                            return parsed_expr;
                        }
                    }
                }
            }
        }
        // If it wasn't a literal we handled, continue the fold traversal
        fold::fold_expr(self, expr)
    }
}


/// Whether a visibility is public
fn is_visibility_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

/// Robust identifier collector using syn parsing.
fn collect_idents_from_sources(sources: &[std::path::PathBuf]) -> Vec<String> {
    let mut names = Vec::new();
    let re_fn_impl = Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();

    for path in sources {
        if let Ok(src) = std::fs::read_to_string(path) {
            if let Ok(file) = syn::parse_file(&src) {
                for item in file.items {
                    match item {
                        syn::Item::Fn(f) => { names.push(f.sig.ident.to_string()); }
                        syn::Item::Struct(s) => { names.push(s.ident.to_string()); }
                        syn::Item::Enum(e) => { names.push(e.ident.to_string()); }
                        syn::Item::Const(c) => { names.push(c.ident.to_string()); }
                        syn::Item::Static(st) => { names.push(st.ident.to_string()); }
                        syn::Item::Mod(m) => { names.push(m.ident.to_string()); }
                        syn::Item::Trait(t) => { names.push(t.ident.to_string()); }
                        syn::Item::Impl(imp) => {
                            if imp.trait_.is_none() {
                                for impl_item in imp.items {
                                    let tok = quote::ToTokens::to_token_stream(&impl_item).to_string();
                                    if let Some(cap) = re_fn_impl.captures(&tok) {
                                        if let Some(m) = cap.get(1) {
                                            names.push(m.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    names.sort();
    names.dedup();
    names
}

/// Recursively traverses a `UseTree` to collect fully-qualified import paths.
fn collect_paths_from_tree(tree: &UseTree, current_path: &mut Vec<String>, paths: &mut HashSet<String>) {
    match tree {
        UseTree::Path(p) => {
            current_path.push(p.ident.to_string());
            collect_paths_from_tree(&p.tree, current_path, paths);
            current_path.pop();
        }
        UseTree::Name(n) => {
            let mut path_parts = current_path.clone();
            path_parts.push(n.ident.to_string());
            paths.insert(path_parts.join("::"));
        }
        UseTree::Rename(r) => {
            let mut path_parts = current_path.clone();
            path_parts.push(r.ident.to_string());
            let full_path = format!("{} as {}", path_parts.join("::"), r.rename.to_string());
            paths.insert(full_path);
        }
        UseTree::Group(g) => {
            for item in &g.items {
                collect_paths_from_tree(item, current_path, paths);
            }
        }
        UseTree::Glob(_) => {
            let mut path_parts = current_path.clone();
            path_parts.push("*".to_string());
            paths.insert(path_parts.join("::"));
        }
    }
}

fn main() {
    let src_dir_env = SRC_DIR.to_string();
    let src_path = Path::new(&src_dir_env);
    let out_path = Path::new(OUT_FILE);

    if !src_path.exists() {
        panic!("source directory '{}' does not exist. Adjust SRC_DIR in build.rs.", src_dir_env);
    }

    let mut sources = Vec::new();
    for entry in WalkDir::new(src_path).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rs") {
            if p.file_name().and_then(|n| n.to_str()) == Some("obfuscated.rs") { continue; }
            sources.push(p.to_owned());
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }

    println!("cargo:warning=obfuscator: will write to {}", OUT_FILE);

    let mut need_gen = FORCE_REGEN;
    if !FORCE_REGEN {
        if let Ok(meta) = fs::metadata(out_path) {
            if let Ok(out_mtime) = meta.modified() {
                let mut newest_input = SystemTime::UNIX_EPOCH;
                let mut ok = true;
                for p in &sources {
                    match fs::metadata(p).and_then(|m| m.modified()) {
                        Ok(mtime) => { if mtime > newest_input { newest_input = mtime; } }
                        Err(_) => { ok = false; break; }
                    }
                }
                if ok && newest_input <= out_mtime { need_gen = false; }
            }
        }
    }

    if !need_gen {
        println!("cargo:warning=obfuscator: {} is up-to-date, skipping regeneration", out_path.display());
        return;
    }

    let mut declared = collect_idents_from_sources(&sources);

    if !declared.contains(&"main".to_string()) {
        declared.push("main".to_string());
    }

    if !RENAME_PUB {
        let mut preserve = HashSet::new();
        for path in &sources {
            if let Ok(src) = std::fs::read_to_string(path) {
                if let Ok(ast) = syn::parse_file(&src) {
                    for item in ast.items {
                        match item {
                            Item::Fn(f) => {
                                if is_visibility_public(&f.vis) || has_no_mangle(&f.attrs) || is_extern_c_fn(&f) || has_proc_macro_attr(&f.attrs) {
                                    preserve.insert(f.sig.ident.to_string());
                                }
                            }
                            Item::Struct(s) => if is_visibility_public(&s.vis) { preserve.insert(s.ident.to_string()); },
                            Item::Enum(e) => if is_visibility_public(&e.vis) { preserve.insert(e.ident.to_string()); },
                            Item::Const(c) => if is_visibility_public(&c.vis) { preserve.insert(c.ident.to_string()); },
                            Item::Static(st) => if is_visibility_public(&st.vis) { preserve.insert(st.ident.to_string()); },
                            Item::Mod(m) => if is_visibility_public(&m.vis) { preserve.insert(m.ident.to_string()); },
                            Item::Trait(t) => if is_visibility_public(&t.vis) { preserve.insert(t.ident.to_string()); },
                            _ => {}
                        }
                    }
                }
            }
        }
        declared.retain(|n| !preserve.contains(n));
    }

    declared.sort();
    declared.dedup();

    println!("cargo:warning=Collected identifiers (sample): {:?}", declared.iter().take(10).collect::<Vec<_>>());
    println!("cargo:warning=Contains main: {}", declared.contains(&"main".to_string()));

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom::fill failed to obtain OS randomness for seed");
    let mut global_rng: StdRng = StdRng::from_seed(seed);

    let main_obf_name = random_ident(8, &mut global_rng);

    let mut ident_map = HashMap::new();
    ident_map.insert("main".to_string(), main_obf_name.clone());
    for name in &declared {
        if name != "main" {
            let new_name = random_ident(8, &mut global_rng);
            ident_map.insert(name.clone(), new_name);
        }
    }

    let mut folder_seed = [0u8; 32];
    getrandom::fill(&mut folder_seed).expect("getrandom::fill failed to obtain folder seed");
    let folder_rng: StdRng = StdRng::from_seed(folder_seed);

    let mut decoder_name = format!("decode_{}", random_ident(12, &mut global_rng));
    while declared.contains(&decoder_name) {
        decoder_name = format!("decode_{}", random_ident(12, &mut global_rng));
    }

    let mut folder = FullObfFold::new(ident_map, folder_rng, decoder_name.clone());

    let mut combined_ts = quote! {};
    for path in &sources {
        let raw_src = fs::read_to_string(path).unwrap_or_default();
        println!("cargo:warning=Processing file: {:?} (full path: {}), size: {}",
            path.file_name(), path.display(), raw_src.len());

        match syn::parse_file(&raw_src) {
            Ok(ast) => {
                let folded = folder.fold_file(ast);
                combined_ts.extend(folded.into_token_stream());
            }
            Err(e) => {
                 println!("cargo:warning=Failed to parse file {:?}: {}. Skipping.", path, e);
            }
        }
    }

    let final_ast = match syn::parse2::<syn::File>(combined_ts) {
        Ok(ast) => ast,
        Err(e) => panic!("obfuscator: Failed to re-parse combined code into an AST: {}.", e),
    };

    let mut use_items = Vec::new();
    let mut other_items = Vec::new();
    for item in final_ast.items {
        if let Item::Use(use_item) = item {
            use_items.push(use_item);
        } else {
            other_items.push(item);
        }
    }

    let mut all_imported_paths = HashSet::<String>::new();
    for use_item in use_items {
        let mut current_parts = Vec::new();
        collect_paths_from_tree(&use_item.tree, &mut current_parts, &mut all_imported_paths);
    }
    
    let source_modules: HashSet<String> = sources.iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(String::from))
        .collect();

    let mut unique_use_items = Vec::<Item>::new();
    let mut sorted_paths: Vec<String> = all_imported_paths.into_iter().collect();
    sorted_paths.sort();

    for path_str in sorted_paths {
        let path_to_check = path_str.split(" as ").next().unwrap_or(&path_str);
        let path_parts: Vec<&str> = path_to_check.split("::").collect();

        let mut is_local_mod = false;
        if path_parts.get(0) == Some(&"crate") {
            if let Some(mod_name) = path_parts.get(1) {
                if source_modules.contains(*mod_name) {
                    is_local_mod = true;
                }
            }
        }

        if !is_local_mod {
            if let Ok(item) = syn::parse_str::<Item>(&format!("use {};", path_str)) {
                 unique_use_items.push(item);
            }
        }
    }

    let use_code = quote! { #(#unique_use_items)* }.to_string();
    let other_code = quote! { #(#other_items)* }.to_string();
    let decoder_fn = string_obfuscation::generate_decoder_function(&decoder_name);
    let main_wrapper = format!("fn main() {{ {}(); }}", main_obf_name);

    let mut final_code = format!(
        "{}\n\n{}\n\n{}\n\n{}",
        use_code,
        decoder_fn,
        other_code,
        main_wrapper
    );

    let re_mod_anywhere = Regex::new(r"\b(pub\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*;").unwrap();
    final_code = re_mod_anywhere.replace_all(&final_code, "").to_string();

    let re_multi_blank = Regex::new(r"\n{3,}").unwrap();
    final_code = re_multi_blank.replace_all(&final_code, "\n\n").to_string();

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create output directory");
    }

    fs::write(out_path, &final_code).expect("failed to write obfuscated file");

    println!("cargo:warning=obfuscator: wrote obfuscated code to {}", out_path.display());
}

