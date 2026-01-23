
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng, seq::SliceRandom};
use proc_macro2::{TokenStream as TokenStream2, Ident, Literal};
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Encoding {
    Base32,
    Base36,
    Base64,
    Base85,
    Base91,
}

const ALL_ENCODINGS: &[Encoding] = &[
    Encoding::Base32,
    Encoding::Base36,
    Encoding::Base64,
    Encoding::Base85,
    Encoding::Base91,
];

// --- Encoding/Decoding Helpers ---
fn encode_b32(data: &[u8]) -> String { ::base32::encode(::base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase() }
fn encode_b36(data: &[u8]) -> String { ::base36::encode(data) }
fn encode_b64(data: &[u8]) -> String { ::base64::engine::general_purpose::STANDARD.encode(data) }
fn encode_b85(data: &[u8]) -> String { ::z85::encode(data) }
fn encode_b91(data: &[u8]) -> String { String::from_utf8(::base91::slice_encode(data)).unwrap() }


// --- Polymorphic Algorithm Generators ---

fn generate_polymorphic_xor_decrypt_body(key: u8, rng: &mut impl Rng) -> TokenStream2 {
    let key_lit = Literal::u8_suffixed(key);
    match rng.gen_range(0..3) {
        0 => quote! { input.iter().map(|b| b ^ #key_lit).collect() },
        1 => quote! {{
            let mut result = Vec::with_capacity(input.len());
            for i in 0..input.len() { result.push(input[i] ^ #key_lit); }
            result
        }},
        _ => quote! {{
            let mut result = Vec::new();
            let mut i = 0;
            while i < input.len() { result.push(input[i] ^ #key_lit); i += 1; }
            result
        }},
    }
}

fn generate_polymorphic_decoder_body(encoding: Encoding) -> TokenStream2 {
    match encoding {
        Encoding::Base32 => quote! { ::base32::decode(::base32::Alphabet::RFC4648 { padding: false }, &String::from_utf8(input).unwrap()).unwrap() },
        Encoding::Base36 => quote! { ::base36::decode(&String::from_utf8(input).unwrap()).unwrap() },
        Encoding::Base64 => quote! { ::base64::engine::general_purpose::STANDARD.decode(&String::from_utf8(input).unwrap()).unwrap() },
        Encoding::Base85 => quote! { ::z85::decode(&String::from_utf8(input).unwrap()).unwrap() },
        Encoding::Base91 => quote! { ::base91::slice_decode(&input).unwrap() },
    }
}

fn generate_polymorphic_reassembly_body(layout_type: u32, rng: &mut impl Rng) -> TokenStream2 {
    match layout_type {
        0 => quote! { self.data.to_vec() }, // Simple case, no polymorphism needed
        1 => match rng.gen_range(0..2) {
            0 => quote! {{ // Iterator-based
                let mut reassembled = Vec::new();
                let mut even_iter = self.even_data.iter();
                let mut odd_iter = self.odd_data.iter();
                loop {
                    if let Some(e) = even_iter.next() { reassembled.push(*e); } else { break; }
                    if let Some(o) = odd_iter.next() { reassembled.push(*o); } else { break; }
                }
                reassembled
            }},
            _ => quote! {{ // Index-based
                let mut reassembled = Vec::with_capacity(self.even_data.len() + self.odd_data.len());
                let mut i = 0;
                loop {
                    if i < self.even_data.len() { reassembled.push(self.even_data[i]); } else { break; }
                    if i < self.odd_data.len() { reassembled.push(self.odd_data[i]); } else { break; }
                    i += 1;
                }
                reassembled
            }},
        },
        _ => match rng.gen_range(0..2) {
            0 => quote! { self.junk_data.iter().step_by(2).cloned().collect::<Vec<u8>>() },
            _ => quote! {{ // Manual loop
                let mut reassembled = Vec::new();
                let mut i = 0;
                while i < self.junk_data.len() {
                    reassembled.push(self.junk_data[i]);
                    i += 2;
                }
                reassembled
            }},
        },
    }
}

// --- Struct Generation Helper ---
fn generate_struct_logic(
    rng: &mut impl Rng,
    struct_fields: &TokenStream2,
    reassembly_method_body: &TokenStream2,
    xor_key: u8,
    encoding_layers: &[Encoding],
    is_decoy: bool,
) -> (TokenStream2, Ident) {
    let struct_name = format_ident!("ObfuscatedString_{}", rng.gen::<u32>());

    let mut methods = Vec::<TokenStream2>::new();
    let mut real_method_calls = Vec::<TokenStream2>::new();
    let mut decoy_method_calls = Vec::<TokenStream2>::new();

    // Reassembly
    methods.push(quote! { fn reassemble(&self) -> Vec<u8> { #reassembly_method_body } });
    real_method_calls.push(quote! { let mut current_data = self.reassemble(); });

    // XOR Decrypt
    let xor_decrypt_body = generate_polymorphic_xor_decrypt_body(xor_key, rng);
    methods.push(quote! { fn decrypt(&self, input: Vec<u8>) -> Vec<u8> { #xor_decrypt_body } });
    real_method_calls.push(quote! { current_data = self.decrypt(current_data); });

    // Decoding Layers
    for (i, encoding) in encoding_layers.iter().enumerate() {
        let method_name = format_ident!("decode_layer_{}", i as u32);
        let decoder_body = generate_polymorphic_decoder_body(*encoding);
        methods.push(quote! { fn #method_name(&self, input: Vec<u8>) -> Vec<u8> { #decoder_body } });
        real_method_calls.push(quote! { current_data = self.#method_name(current_data); });
    }

    // Enhanced Decoy methods
    let num_decoys = rng.gen_range(5..=10);
     for i in 0..num_decoys {
        let decoy_method = format_ident!("decoy_{}", i as u32);
        let rand_val1 = rng.gen::<u32>();
        let rand_val2 = rng.gen::<u32>() + 1; // Avoid division by zero
        methods.push(quote! { fn #decoy_method(&self) { let _ = #rand_val1 % #rand_val2; } });
        decoy_method_calls.push(quote! { self.#decoy_method(); });
    }

    let run_method_body = if is_decoy {
        quote! {
             // Intentionally broken logic for the dead path
             String::from("decoy")
        }
    } else {
        let mut all_calls = TokenStream2::new();
        let mut decoys = decoy_method_calls.clone();
        decoys.shuffle(rng);

        for (i, real_call) in real_method_calls.iter().enumerate() {
             // Add some decoys before the real call
            if i > 0 && rng.gen_bool(0.5) {
                if let Some(decoy) = decoys.pop() {
                    all_calls.extend(decoy);
                }
            }
            all_calls.extend(real_call.clone());
        }
        // Add any remaining decoys at the end
        for decoy in decoys {
            all_calls.extend(decoy);
        }

        quote! {
            #all_calls
            String::from_utf8(current_data).unwrap()
        }
    };

    let generated_code = quote! {
        pub struct #struct_name { #struct_fields }

        use ::base64::Engine;
        impl #struct_name {
            #(#methods)*

            pub fn run(&self) -> String {
                #run_method_body
            }
        }
    };
    (generated_code, struct_name)
}


#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let original_string = lit_str.value();
    let mut rng = thread_rng();

    // --- Encoding Layers (Shared) ---
    let num_layers = rng.gen_range(1..=4);
    let mut encoding_layers = Vec::new();
    let mut current_data = original_string.clone();
    for _ in 0..num_layers {
        let encoding = *ALL_ENCODINGS.choose(&mut rng).unwrap();
        encoding_layers.push(encoding);
        current_data = match encoding {
            Encoding::Base32 => encode_b32(current_data.as_bytes()),
            Encoding::Base36 => encode_b36(current_data.as_bytes()),
            Encoding::Base64 => encode_b64(current_data.as_bytes()),
            Encoding::Base85 => encode_b85(current_data.as_bytes()),
            Encoding::Base91 => encode_b91(current_data.as_bytes()),
        };
    }
    encoding_layers.reverse();

    // --- XOR Encryption (Shared) ---
    let xor_key = rng.gen::<u8>();
    let encrypted_bytes: Vec<u8> = current_data.bytes().map(|b| b ^ xor_key).collect();

    // --- Data Layout Generation (Shared) ---
    let layout_type = rng.gen_range(0..=2);
    let (struct_fields, struct_init) = match layout_type {
        0 => { // Simple byte array
            let data_lit = Literal::byte_string(&encrypted_bytes);
            ( quote!{ pub data: &'static [u8] }, quote!{ data: #data_lit } )
        },
        1 => { // Interleaved (even/odd)
            let even: Vec<u8> = encrypted_bytes.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = encrypted_bytes.iter().skip(1).step_by(2).cloned().collect();
            let even_lit = Literal::byte_string(&even);
            let odd_lit = Literal::byte_string(&odd);
            (
                quote!{ pub even_data: &'static [u8], pub odd_data: &'static [u8] },
                quote!{ even_data: #even_lit, odd_data: #odd_lit }
            )
        },
        _ => { // Interspersed with junk
            let junk_interspersed: Vec<u8> = encrypted_bytes.iter().flat_map(|&b| vec![b, rng.gen()]).collect();
            let data_lit = Literal::byte_string(&junk_interspersed);
            ( quote!{ pub junk_data: &'static [u8] }, quote!{ junk_data: #data_lit } )
        }
    };

    // --- Generate Two Valid Logics and One Decoy Logic ---
    let reassembly_body1 = generate_polymorphic_reassembly_body(layout_type, &mut rng);
    let (logic1, struct_name1) = generate_struct_logic(&mut rng, &struct_fields, &reassembly_body1, xor_key, &encoding_layers, false);

    let reassembly_body2 = generate_polymorphic_reassembly_body(layout_type, &mut rng);
    let (logic2, struct_name2) = generate_struct_logic(&mut rng, &struct_fields, &reassembly_body2, xor_key, &encoding_layers, false);

    let decoy_reassembly = generate_polymorphic_reassembly_body(layout_type, &mut rng);
    let (decoy_logic, decoy_struct_name) = generate_struct_logic(&mut rng, &struct_fields, &decoy_reassembly, xor_key, &encoding_layers, true);

    // --- Final Macro Expansion ---
    let expanded = quote! {{
        use std::time::{SystemTime, UNIX_EPOCH};

        mod obfuscated_path_a {
            use super::*;
            #logic1
        }
        mod obfuscated_path_b {
            use super::*;
            #logic2
        }
        mod obfuscated_path_decoy {
            use super::*;
            #decoy_logic
        }

        let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let nanos = duration.as_nanos();

        if nanos % 2 == 0 {
            let instance = obfuscated_path_a::#struct_name1 { #struct_init };
            instance.run()
        } else {
            let instance = obfuscated_path_b::#struct_name2 { #struct_init };
            instance.run()
        }
    }};

    TokenStream::from(expanded)
}
