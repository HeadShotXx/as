
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use base64::Engine;


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
    Decode(usize), // Opaque index into the v-table
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

struct Decoder {
    encode: fn(&[u8]) -> String,
    decode: TokenStream2,
}

fn get_decoders() -> Vec<Decoder> {
    vec![
        Decoder {
            encode: |b| base32::encode(base32::Alphabet::RFC4648 { padding: false }, b),
            decode: quote! { base32::decode(base32::Alphabet::RFC4648 { padding: false }, std::str::from_utf8(s).expect("VTable: Invalid UTF-8 for Base32")).expect("VTable: Base32 decoding failed") },
        },
        Decoder {
            encode: |b| base36::encode(b),
            decode: quote! { base36::decode(std::str::from_utf8(s).expect("VTable: Invalid UTF-8 for Base36")).expect("VTable: Base36 decoding failed") },
        },
        Decoder {
            encode: |b| base64::engine::general_purpose::STANDARD.encode(b),
            decode: quote! { base64::engine::general_purpose::STANDARD.decode(s).expect("VTable: Base64 decoding failed") },
        },
        Decoder {
            encode: |b| z85::encode(b),
            decode: quote! { z85::decode(s).expect("VTable: Z85 decoding failed") },
        },
        Decoder {
            encode: |b| String::from_utf8(base91::slice_encode(b)).expect("Compile-time Base91 encode failed"),
            decode: quote! { base91::slice_decode(s) },
        },
    ]
}

fn generate_pipeline(rng: &mut impl Rng, num_decoders: usize) -> Vec<Operation> {
    let mut pipeline = Vec::new();
    let num_layers = rng.gen_range(3..=5);
    let mut current_type = DataType::Bytes;
    let mut last_op_was_decrypt = false;

    for _ in 0..num_layers {
        let mut possible_ops = Vec::new();

        if current_type == DataType::Bytes {
            possible_ops.push(Operation::Decrypt);
            if !last_op_was_decrypt {
                possible_ops.push(Operation::ToString);
            }
        } else { // String
            let decoder_index = rng.gen_range(0..num_decoders);
            possible_ops.push(Operation::Decode(decoder_index));
        }

        let op = possible_ops.choose(rng).unwrap().clone();

        last_op_was_decrypt = matches!(op, Operation::Decrypt);

        match &op {
            Operation::Decrypt | Operation::Decode(_) => current_type = DataType::Bytes,
            Operation::ToString => current_type = DataType::String,
        }
        pipeline.push(op);
    }

    if current_type == DataType::String {
        let decoder_index = rng.gen_range(0..num_decoders);
        pipeline.push(Operation::Decode(decoder_index));
    }

    pipeline.reverse();
    pipeline
}

fn generate_decoder_vtables(rng: &mut impl Rng, decoders: &mut [Decoder]) -> (Ident, TokenStream2, Vec<usize>) {
    decoders.shuffle(rng);
    let mut vtable_indices = (0..decoders.len()).collect::<Vec<_>>();
    vtable_indices.shuffle(rng);

    let mut fn_defs = Vec::new();
    let mut fn_names = Vec::new();

    let vtable_name = Ident::new(&format!("DECODER_VTABLE_{}", rng.gen::<u32>()), Span::call_site());

    for &i in &vtable_indices {
        let decoder = &decoders[i];
        let fn_name = Ident::new(&format!("decode_fn_{}_{}", i, rng.gen::<u32>()), Span::call_site());
        let decoder_logic = &decoder.decode;

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

    (vtable_name, vtable_code, vtable_indices)
}

fn apply_pipeline_transform(
    initial_string: &str,
    pipeline: &[Operation],
    decryption_key: u8,
    key_mutation: &KeyMutation,
    decoders: &[Decoder],
) -> Vec<u8> {
    let mut current_state = DataState {
        value: initial_string.as_bytes().to_vec(),
        dtype: DataType::Bytes,
    };

    for op in pipeline.iter().rev() {
        current_state = match op {
            Operation::Decrypt => {
                let encrypted = encrypt_bytes(&current_state.value, decryption_key, key_mutation);
                DataState { value: encrypted, dtype: DataType::Bytes }
            }
            Operation::Decode(decoder_index) => {
                let decoder = &decoders[*decoder_index];
                let encoded = (decoder.encode)(&current_state.value);
                DataState { value: encoded.into_bytes(), dtype: DataType::String }
            }
            Operation::ToString => {
                let s = String::from_utf8(current_state.value.clone())
                    .expect("Compile-time UTF-8 conversion for ToString inverse failed");
                DataState { value: s.into_bytes(), dtype: DataType::Bytes }
            }
        };
    }
    current_state.value
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
    let data_var = Ident::new("data", Span::call_site());
    let mut vtable_idx_counter = 0;

    for (i, op) in pipeline.iter().enumerate() {
        // Add false dependency logic before every other operation
        if i % 2 == 0 {
            logic.push(generate_false_dependencies(&data_var, rng));
        }

        let op_code = match op {
            Operation::Decrypt => {
                let decrypt_fn_call = generate_decrypt_function_call(decryption_key, key_mutation);
                quote! {
                    data = #decrypt_fn_call(&data);
                }
            }
            Operation::Decode(_) => {
                let vtable_index = vtable_indices[vtable_idx_counter];
                vtable_idx_counter += 1;
                quote! {
                    data = (#vtable_name[#vtable_index])(&data);
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

fn generate_nested_block_logic(
    pipeline: &[Operation],
    vtable_name: &Ident,
    vtable_indices: &[usize],
    decryption_key: u8,
    key_mutation: &KeyMutation,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let data_var = Ident::new("data", Span::call_site());
    let mut vtable_idx_counter = 0;

    // Start with the innermost expression
    let final_assembly = generate_fragmented_assembly(&data_var, rng);
    let mut nested_logic = quote! { #final_assembly };

    for op in pipeline.iter().rev() {
        let previous_data_var = data_var.clone();

        let false_dependency = generate_false_dependencies(&previous_data_var, rng);

        nested_logic = match op {
            Operation::Decrypt => {
                let decrypt_fn_call = generate_decrypt_function_call(decryption_key, key_mutation);
                quote! {
                    {
                        let #data_var = #decrypt_fn_call(&#previous_data_var);
                        #false_dependency
                        #nested_logic
                    }
                }
            }
            Operation::Decode(_) => {
                let vtable_index = vtable_indices[vtable_indices.len() - 1 - vtable_idx_counter];
                vtable_idx_counter += 1;
                quote! {
                    {
                        let #data_var = (#vtable_name[#vtable_index])(&#previous_data_var);
                        #false_dependency
                        #nested_logic
                    }
                }
            }
            Operation::ToString => {
                // Type transition, just pass the data through in the next block
                quote! {
                    {
                        let #data_var = #previous_data_var.to_vec();
                        #false_dependency
                        #nested_logic
                    }
                }
            }
        };
    }

    quote! {
        let #data_var = data;
        #nested_logic
    }
}

fn generate_state_machine_logic(
    pipeline: &[Operation],
    vtable_name: &Ident,
    vtable_indices: &[usize],
    decryption_key: u8,
    key_mutation: &KeyMutation,
    rng: &mut impl Rng,
) -> TokenStream2 {
    let state_var = Ident::new("state", Span::call_site());
    let data_var = Ident::new("data", Span::call_site());
    let mut arms = Vec::new();
    let mut vtable_idx_counter = 0;

    for (i, op) in pipeline.iter().enumerate() {
        let current_state_num = i;
        let next_state_num = i + 1;

        let false_dependency = if i % 2 != 0 {
            generate_false_dependencies(&data_var, rng)
        } else {
            quote! {}
        };

        let op_logic = match op {
            Operation::Decrypt => {
                let decrypt_fn_call = generate_decrypt_function_call(decryption_key, key_mutation);
                quote! { data = #decrypt_fn_call(&data); }
            }
            Operation::Decode(_) => {
                let vtable_index = vtable_indices[vtable_idx_counter];
                vtable_idx_counter += 1;
                quote! { data = (#vtable_name[#vtable_index])(&data); }
            }
            Operation::ToString => quote! { /* Type transition, no-op */ },
        };

        arms.push(quote! {
            #current_state_num => {
                #false_dependency
                #op_logic
                #state_var = #next_state_num;
            }
        });
    }

    // Final state
    let final_state_num = pipeline.len();
    let final_assembly = generate_fragmented_assembly(&Ident::new("data", Span::call_site()), rng);
    arms.push(quote! {
        #final_state_num => {
            break #final_assembly;
        }
    });

    // Default arm
    arms.push(quote!{ _ => { break String::new(); } });

    quote! {
        let mut #state_var = 0;
        loop {
            match #state_var {
                #(#arms)*
            }
        }
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let input_str = input.value();

    let mut rng = rand::rngs::StdRng::from_entropy();

    let (final_encoded_bytes, runtime_logic, vtable_code) = if rng.gen_bool(0.5) {
        // Table-driven semantic family
        let (key, fragments) = apply_table_driven_transform(&input_str, &mut rng);
        let logic = generate_table_driven_logic(&fragments, &mut rng);
        (key, logic, quote! {})
    } else {
        // Pipeline-based semantic family
        let decryption_key: u8 = rng.gen();
        let key_mutation = *ALL_KEY_MUTATIONS.choose(&mut rng).unwrap();
        let mut decoders = get_decoders();
        let pipeline = generate_pipeline(&mut rng, decoders.len());
        let (vtable_name, vtable, vtable_indices) = generate_decoder_vtables(&mut rng, &mut decoders);

        let bytes = apply_pipeline_transform(
            &input_str,
            &pipeline,
            decryption_key,
            &key_mutation,
            &decoders,
        );

        let logic = match rng.gen_range(0..3) {
            0 => generate_linear_logic(&pipeline, &vtable_name, &vtable_indices, decryption_key, &key_mutation, &mut rng),
            1 => generate_nested_block_logic(&pipeline, &vtable_name, &vtable_indices, decryption_key, &key_mutation, &mut rng),
            _ => generate_state_machine_logic(&pipeline, &vtable_name, &vtable_indices, decryption_key, &key_mutation, &mut rng),
        };
        (bytes, logic, vtable)
    };

    let struct_name = Ident::new(&format!("ObfuscatedStringHolder_{}", rng.gen::<u32>()), Span::call_site());

    let output = quote! {
        {
            use base64::Engine as _;

            #vtable_code

            struct #struct_name {
                key: &'static [u8],
            }

            impl #struct_name {
                fn deobfuscate(&self) -> String {
                    let key = self.key.to_vec();
                    let mut data = self.key.to_vec(); // For pipeline compatibility
                    #runtime_logic
                }
            }

            let instance = #struct_name {
                key: &[#(#final_encoded_bytes),*],
            };
            instance.deobfuscate()
        }
    };

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

fn apply_table_driven_transform(
    initial_string: &str,
    rng: &mut impl Rng,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut fragments = Vec::new();
    let mut key = Vec::new();
    let string_bytes = initial_string.as_bytes().to_vec();

    let fragment_size = rng.gen_range(2..5);
    for (i, chunk) in string_bytes.chunks(fragment_size).enumerate() {
        fragments.push(chunk.to_vec());
        key.push(i as u8);
    }

    key.shuffle(rng);
    (key, fragments)
}

fn generate_table_driven_logic(
    fragments: &[Vec<u8>],
    rng: &mut impl Rng,
) -> TokenStream2 {
    let table_var = Ident::new(&format!("LOOKUP_TABLE_{}", rng.gen::<u32>()), Span::call_site());
    let key_var = Ident::new("key", Span::call_site());
    let result_var = Ident::new("result", Span::call_site());

    let num_fragments = fragments.len();
    let fragment_lits = fragments.iter().map(|f| quote!(&[#(#f),*]));

    quote! {
        {
            static #table_var: [&[u8]; #num_fragments] = [#(#fragment_lits),*];
            let mut #result_var = Vec::new();
            for &index in #key_var.iter() {
                #result_var.extend_from_slice(#table_var[index as usize]);
            }
            String::from_utf8(#result_var).expect("Table-driven assembly failed")
        }
    }
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
