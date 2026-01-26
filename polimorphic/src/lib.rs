
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use base64::Engine;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Encoding {
    Base32,
    Base36,
    Base64,
    Z85,
    Base91,
}

const ALL_ENCODINGS: &[Encoding] = &[
    Encoding::Base32,
    Encoding::Base36,
    Encoding::Base64,
    Encoding::Z85,
    Encoding::Base91,
];

#[derive(Debug, Clone, Copy)]
enum KeyMutation {
    Add,
    Sub,
    Xor,
    RotateLeft,
    RotateRight,
}

const ALL_KEY_MUTATIONS: &[KeyMutation] = &[
    KeyMutation::Add,
    KeyMutation::Sub,
    KeyMutation::Xor,
    KeyMutation::RotateLeft,
    KeyMutation::RotateRight,
];

#[derive(Debug, Clone)]
enum Operation {
    Decrypt,
    Decode(Encoding),
    ToString,
}

#[derive(Debug, Clone, PartialEq)]
enum DataType {
    String,
    Bytes,
}

#[derive(Debug, Clone, PartialEq)]
struct DataState {
    value: Vec<u8>,
    dtype: DataType,
}

fn generate_pipeline(rng: &mut impl Rng) -> Vec<Operation> {
    let mut pipeline = Vec::new();
    let num_layers = rng.gen_range(3..=5);
    let mut current_type = DataType::Bytes;
    let mut last_op_was_decrypt = false;

    for _ in 0..num_layers {
        let mut possible_ops = Vec::new();

        if current_type == DataType::Bytes {
            possible_ops.push(Operation::Decrypt);
            // We can only convert to a string if the bytes are valid UTF-8.
            // This is not the case after a decryption operation.
            if !last_op_was_decrypt {
                possible_ops.push(Operation::ToString);
            }
        } else { // String
            // Data is a string, so it must be decoded to get bytes.
            let encoding = *ALL_ENCODINGS.choose(rng).unwrap();
            possible_ops.push(Operation::Decode(encoding));
        }

        let op = possible_ops.choose(rng).unwrap().clone();

        last_op_was_decrypt = matches!(op, Operation::Decrypt);

        match &op {
            Operation::Decrypt => current_type = DataType::Bytes,
            Operation::Decode(_) => current_type = DataType::Bytes,
            Operation::ToString => current_type = DataType::String,
        }
        pipeline.push(op);
    }

    // The final result must be bytes to be converted to the final string.
    if current_type == DataType::String {
        // If the last operation resulted in a string, we need to decode it to get bytes.
        let encoding = *ALL_ENCODINGS.choose(rng).unwrap();
        pipeline.push(Operation::Decode(encoding));
    }

    pipeline.reverse();
    pipeline
}

fn generate_decoder_vtables(rng: &mut impl Rng) -> (Ident, TokenStream2, HashMap<Encoding, usize>) {
    let mut shuffled_encodings = ALL_ENCODINGS.to_vec();
    shuffled_encodings.shuffle(rng);

    let mut decoder_map = HashMap::new();
    let mut fn_defs = Vec::new();
    let mut fn_names = Vec::new();

    let vtable_name = Ident::new(&format!("DECODER_VTABLE_{}", rng.gen::<u32>()), Span::call_site());

    for (i, &encoding) in shuffled_encodings.iter().enumerate() {
        decoder_map.insert(encoding, i);
        let fn_name = Ident::new(&format!("decode_fn_{}_{}", i, rng.gen::<u32>()), Span::call_site());

        let decoder_logic = match encoding {
            Encoding::Base32 => quote! { base32::decode(base32::Alphabet::RFC4648 { padding: false }, std::str::from_utf8(s).expect("VTable: Invalid UTF-8 for Base32")).expect("VTable: Base32 decoding failed") },
            Encoding::Base36 => quote! { base36::decode(std::str::from_utf8(s).expect("VTable: Invalid UTF-8 for Base36")).expect("VTable: Base36 decoding failed") },
            Encoding::Base64 => quote! { base64::engine::general_purpose::STANDARD.decode(s).expect("VTable: Base64 decoding failed") },
            Encoding::Z85 => quote! { z85::decode(s).expect("VTable: Z85 decoding failed") },
            Encoding::Base91 => quote! { base91::slice_decode(s) },
        };

        fn_defs.push(quote! {
            fn #fn_name(s: &[u8]) -> Vec<u8> {
                use base64::Engine;
                #decoder_logic
            }
        });
        fn_names.push(fn_name);
    }

    let vtable_len = fn_names.len();
    let vtable_code = quote! {
        #(#fn_defs)*
        static #vtable_name: [fn(&[u8]) -> Vec<u8>; #vtable_len] = [ #(#fn_names),* ];
    };

    (vtable_name, vtable_code, decoder_map)
}

fn apply_pipeline_transform(
    initial_string: &str,
    pipeline: &[Operation],
    decryption_key: u8,
    key_mutation: &KeyMutation,
    decoder_map: &HashMap<Encoding, usize>,
) -> (Vec<u8>, Vec<usize>) {
    let mut current_state = DataState {
        value: initial_string.as_bytes().to_vec(),
        dtype: DataType::Bytes,
    };
    let mut vtable_indices = Vec::new();

    for op in pipeline.iter().rev() {
        current_state = match op {
            Operation::Decrypt => {
                // Inverse is encryption. Takes raw bytes, produces raw bytes.
                let encrypted = encrypt_bytes(&current_state.value, decryption_key, key_mutation);
                DataState { value: encrypted, dtype: DataType::Bytes }
            }
            Operation::Decode(encoding) => {
                // Inverse is encoding. Takes raw bytes, produces a string.
                let encoded = encode_bytes(&current_state.value, *encoding);
                vtable_indices.push(decoder_map[encoding]);
                DataState { value: encoded.into_bytes(), dtype: DataType::String }
            }
            Operation::ToString => {
                // Inverse is to treat the current value (a string) as bytes.
                // This requires a UTF-8 conversion at compile time.
                let s = String::from_utf8(current_state.value.clone())
                    .expect("Compile-time UTF-8 conversion for ToString inverse failed");
                DataState { value: s.into_bytes(), dtype: DataType::Bytes }
            }
        };
    }
    vtable_indices.reverse();
    (current_state.value, vtable_indices)
}

fn encode_bytes(bytes: &[u8], encoding: Encoding) -> String {
    match encoding {
        Encoding::Base32 => base32::encode(base32::Alphabet::RFC4648 { padding: false }, bytes),
        Encoding::Base36 => base36::encode(bytes),
        Encoding::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
        Encoding::Z85 => z85::encode(bytes),
        Encoding::Base91 => String::from_utf8(base91::slice_encode(bytes)).expect("Compile-time Base91 encode failed"),
    }
}

fn generate_false_dependencies(data_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let decoy_var = Ident::new(&format!("decoy_state_{}", rng.gen::<u32>()), Span::call_site());
    let initial_val: u8 = rng.gen();

    let update_logic = match rng.gen_range(0..3) {
        0 => quote! { #decoy_var = #decoy_var.wrapping_add(byte.wrapping_mul(3)); },
        1 => quote! { #decoy_var ^= byte.rotate_left(3); },
        _ => quote! { if byte > 128 { #decoy_var = #decoy_var.saturating_sub(byte); } },
    };

    let final_check = match rng.gen_range(0..2) {
        0 => quote! { if #decoy_var > 100 { /* Do nothing significant */ } },
        _ => quote! { let _ = #decoy_var.count_ones(); },
    };

    quote! {
        let mut #decoy_var: u8 = #initial_val;
        for &byte in #data_var.iter() {
            #update_logic
        }
        #final_check
    }
}

fn generate_fragmented_assembly(bytes_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..3) {
        0 => { // Chunking
            quote! {
                {
                    let mut reassembled = Vec::new();
                    for chunk in #bytes_var.chunks(3) {
                        reassembled.extend_from_slice(chunk);
                    }
                    String::from_utf8(reassembled).expect("Fragmented assembly from UTF-8 failed")
                }
            }
        },
        1 => { // Character-by-character
            quote! {
                #bytes_var.iter().map(|&b| b as char).collect::<String>()
            }
        },
        _ => { // Direct conversion
            quote! {
                String::from_utf8(#bytes_var.to_vec()).expect("Direct assembly from UTF-8 failed")
            }
        }
    }
}

fn generate_linear_logic(
    pipeline: &[Operation],
    vtable_name: &Ident,
    vtable_indices: &[usize],
    decryption_key: u8,
    key_mutation: &KeyMutation,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let mut logic = Vec::new();
    let data_var = Ident::new("current_data", Span::call_site());
    let mut vtable_idx_counter = 0;

    logic.push(quote! {
        let mut #data_var = self.data.to_vec();
    });

    for (i, op) in pipeline.iter().enumerate() {
        // Add false dependency logic before every other operation
        if i % 2 == 0 {
            logic.push(generate_false_dependencies(&data_var, rng));
        }

        let op_code = match op {
            Operation::Decrypt => {
                let decrypt_fn_call = generate_decrypt_function_call(decryption_key, key_mutation);
                quote! {
                    #data_var = #decrypt_fn_call(&#data_var);
                }
            }
            Operation::Decode(_) => {
                let vtable_index = vtable_indices[vtable_idx_counter];
                vtable_idx_counter += 1;
                quote! {
                    #data_var = (#vtable_name[#vtable_index])(&#data_var);
                }
            }
            Operation::ToString => {
                 quote! {
                    // This is a type transition. At runtime, the bytes are interpreted as a string
                    // by the next operation (which will be a decoder), so no code is needed here.
                }
            }
        };
        logic.push(op_code);
    }

    let final_assembly = generate_fragmented_assembly(&data_var, rng);
    logic.push(final_assembly);

    quote! {
        #(#logic)*
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let input_str = input.value();

    let mut rng = rand::rngs::StdRng::from_entropy();
    let decryption_key: u8 = rng.gen();
    let key_mutation = *ALL_KEY_MUTATIONS.choose(&mut rng).unwrap();

    let pipeline = generate_pipeline(&mut rng);
    let (vtable_name, vtable_code, decoder_map) = generate_decoder_vtables(&mut rng);

    let (final_encoded_bytes, vtable_indices) = apply_pipeline_transform(
        &input_str,
        &pipeline,
        decryption_key,
        &key_mutation,
        &decoder_map,
    );

    let runtime_logic = generate_linear_logic(
        &pipeline,
        &vtable_name,
        &vtable_indices,
        decryption_key,
        &key_mutation,
        &mut rng,
    );

    let struct_name = Ident::new(&format!("ObfuscatedStringHolder_{}", rng.gen::<u32>()), Span::call_site());

    let output = quote! {
        {
            use base64::Engine as _; // Ensure engine is in scope for generated code if needed

            #vtable_code

            struct #struct_name {
                data: &'static [u8],
            }

            impl #struct_name {
                fn deobfuscate(&self) -> String {
                    let data_vec = self.data.to_vec();
                    #runtime_logic
                }
            }

            let instance = #struct_name {
                data: &[#(#final_encoded_bytes),*],
            };
            instance.deobfuscate()
        }
    };

    // For debugging:
    // eprintln!("Generated pipeline: {:?}", pipeline);
    // eprintln!("Generated code: {}", output.to_string());

    TokenStream::from(output)
}

fn encrypt_bytes(bytes: &[u8], key: u8, mutation: &KeyMutation) -> Vec<u8> {
    let mut new_key = key;
    bytes.iter().map(|&b| {
        let encrypted_byte = b ^ new_key;
        new_key = mutate_key(new_key, mutation);
        encrypted_byte
    }).collect()
}

fn mutate_key(key: u8, mutation: &KeyMutation) -> u8 {
    match mutation {
        KeyMutation::Add => key.wrapping_add(3),
        KeyMutation::Sub => key.wrapping_sub(5),
        KeyMutation::Xor => key ^ 0xAF,
        KeyMutation::RotateLeft => key.rotate_left(3),
        KeyMutation::RotateRight => key.rotate_right(5),
    }
}

fn generate_decrypt_function_call(key: u8, mutation: &KeyMutation) -> TokenStream2 {
    let key_mutation_logic = match mutation {
        KeyMutation::Add => quote! { current_key = current_key.wrapping_add(3); },
        KeyMutation::Sub => quote! { current_key = current_key.wrapping_sub(5); },
        KeyMutation::Xor => quote! { current_key ^= 0xAF; },
        KeyMutation::RotateLeft => quote! { current_key = current_key.rotate_left(3); },
        KeyMutation::RotateRight => quote! { current_key = current_key.rotate_right(5); },
    };

    quote! {
        |data: &[u8]| -> Vec<u8> {
            let mut current_key = #key;
            data.iter().map(|&b| {
                let decrypted_byte = b ^ current_key;
                #key_mutation_logic
                decrypted_byte
            }).collect()
        }
    }
}
