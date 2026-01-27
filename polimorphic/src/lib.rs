
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use base64::Engine;

trait Transformation {
    fn apply_inverse(&self, bytes: &[u8]) -> Vec<u8>;
    fn generate_runtime_code(&self) -> TokenStream2;
}

struct DecodeTransform {
    encode: fn(&[u8]) -> String,
    decode: TokenStream2,
}

impl Transformation for DecodeTransform {
    fn apply_inverse(&self, bytes: &[u8]) -> Vec<u8> {
        (self.encode)(bytes).into_bytes()
    }
    fn generate_runtime_code(&self) -> TokenStream2 {
        let decode_logic = &self.decode;

        quote! {
            |data: &[u8]| -> Vec<u8> {
                use base64::Engine;
                let s = std::str::from_utf8(data).expect("Decode UTF-8 conversion failed");
                #decode_logic
            }
        }
    }
}

struct DecryptTransform {
    key: u8,
    encrypt_fn: fn(&[u8], u8) -> Vec<u8>,
    decrypt_fn_gen: fn(u8) -> TokenStream2,
}

impl Transformation for DecryptTransform {
    fn apply_inverse(&self, bytes: &[u8]) -> Vec<u8> {
        (self.encrypt_fn)(bytes, self.key)
    }
    fn generate_runtime_code(&self) -> TokenStream2 {
        (self.decrypt_fn_gen)(self.key)
    }
}

fn get_base_transforms(rng: &mut impl Rng) -> Vec<Box<dyn Transformation>> {
    let mut transforms: Vec<Box<dyn Transformation>> = Vec::new();

    // Add decoders
    transforms.push(Box::new(DecodeTransform {
        encode: |b| base32::encode(base32::Alphabet::RFC4648 { padding: false }, b),
        decode: quote! { base32::decode(base32::Alphabet::RFC4648 { padding: false }, s).expect("VTable: Base32 decoding failed") },
    }));
    transforms.push(Box::new(DecodeTransform {
        encode: |b| base36::encode(b),
        decode: quote! { base36::decode(s).expect("VTable: Base36 decoding failed") },
    }));
    transforms.push(Box::new(DecodeTransform {
        encode: |b| base64::engine::general_purpose::STANDARD.encode(b),
        decode: quote! { base64::engine::general_purpose::STANDARD.decode(s).expect("VTable: Base64 decoding failed") },
    }));
    transforms.push(Box::new(DecodeTransform {
        encode: |b| base_x::encode("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", b),
        decode: quote! { base_x::decode("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", s).expect("VTable: Base62 decoding failed") },
    }));
    transforms.push(Box::new(DecodeTransform {
        encode: |b| String::from_utf8(base91::slice_encode(b)).expect("Compile-time Base91 encode failed"),
        decode: quote! { base91::slice_decode(s.as_bytes()) },
    }));

    // Add decrypters
    let mutations: Vec<(fn(&[u8], u8) -> Vec<u8>, fn(u8) -> TokenStream2)> = vec![
        (encrypt_add, decrypt_add_gen),
        (encrypt_sub, decrypt_sub_gen),
        (encrypt_xor, decrypt_xor_gen),
        (encrypt_rot_left, decrypt_rot_left_gen),
        (encrypt_rot_right, decrypt_rot_right_gen),
    ];

    for (enc, dec_gen) in mutations {
        transforms.push(Box::new(DecryptTransform {
            key: rng.gen(),
            encrypt_fn: enc,
            decrypt_fn_gen: dec_gen,
        }));
    }

    transforms
}

fn generate_unified_vtable(
    transforms: &[Box<dyn Transformation>],
    rng: &mut impl Rng,
) -> (Ident, TokenStream2, Vec<usize>) {
    let mut vtable_indices: Vec<usize> = (0..transforms.len()).collect();
    vtable_indices.shuffle(rng);

    let mut fn_defs = Vec::new();
    let mut fn_names = Vec::new();

    let vtable_name = Ident::new(&format!("UNIFIED_VTABLE_{}", rng.gen::<u32>()), Span::call_site());

    // Generate in the final runtime order, not the shuffled order
    for i in 0..transforms.len() {
        let transform = &transforms[i];
        let fn_name = Ident::new(&format!("transform_fn_{}_{}", i, rng.gen::<u32>()), Span::call_site());
        let transform_logic = transform.generate_runtime_code();

        fn_defs.push(quote! {
            fn #fn_name(data: &[u8]) -> Vec<u8> {
                (#transform_logic)(data)
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

fn generate_unified_linear_logic(
    vtable_name: &Ident,
    runtime_indices: &[usize],
    rng: &mut impl Rng,
) -> TokenStream2 {
    let mut logic = Vec::new();
    let data_var = Ident::new("data", Span::call_site());

    for (i, &vtable_index) in runtime_indices.iter().enumerate() {
        if i % 2 == 0 {
            logic.push(generate_false_dependencies(&data_var, rng));
        }

        logic.push(quote! {
            data = (#vtable_name[#vtable_index])(&data);
        });
    }

    let final_assembly = generate_fragmented_assembly(&data_var, rng);
    logic.push(final_assembly);

    quote! {
        #(#logic)*
    }
}

fn generate_unified_nested_logic(
    vtable_name: &Ident,
    runtime_indices: &[usize],
    rng: &mut impl Rng,
) -> TokenStream2 {
    let data_var = Ident::new("data", Span::call_site());

    let final_assembly = generate_fragmented_assembly(&data_var, rng);
    let mut nested_logic = quote! { #final_assembly };

    for &vtable_index in runtime_indices.iter().rev() {
        let previous_data_var = data_var.clone();

        let false_dependency = generate_false_dependencies(&previous_data_var, rng);

        nested_logic = quote! {
            {
                let #data_var = (#vtable_name[#vtable_index])(&#previous_data_var);
                #false_dependency
                #nested_logic
            }
        };
    }

    quote! {
        let #data_var = data;
        #nested_logic
    }
}

fn generate_unified_state_machine_logic(
    vtable_name: &Ident,
    runtime_indices: &[usize],
    rng: &mut impl Rng,
) -> TokenStream2 {
    let state_var = Ident::new("state", Span::call_site());
    let data_var = Ident::new("data", Span::call_site());
    let mut arms = Vec::new();

    for (i, &vtable_index) in runtime_indices.iter().enumerate() {
        let current_state_num = i;
        let next_state_num = i + 1;

        let false_dependency = if i % 2 != 0 {
            generate_false_dependencies(&data_var, rng)
        } else {
            quote! {}
        };

        arms.push(quote! {
            #current_state_num => {
                #false_dependency
                data = (#vtable_name[#vtable_index])(&data);
                #state_var = #next_state_num;
            }
        });
    }

    let final_state_num = runtime_indices.len();
    let final_assembly = generate_fragmented_assembly(&Ident::new("data", Span::call_site()), rng);
    arms.push(quote! {
        #final_state_num => {
            break #final_assembly;
        }
    });
    arms.push(quote!{ _ => { break String::new(); } });

    quote! {
        let mut #state_var = 0;
        let mut data = data;
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
    let initial_string = input.value();

    let mut rng = rand::rngs::StdRng::from_entropy();

    // 1. Get all available transformations
    let mut available_transforms = get_base_transforms(&mut rng);
    available_transforms.shuffle(&mut rng);

    // 2. Select a random number of transformations to apply
    let num_transforms_to_apply = rng.gen_range(3..=available_transforms.len());
    let selected_transforms: Vec<_> = available_transforms.into_iter().take(num_transforms_to_apply).collect();

    // 3. Apply transformations at compile-time to get the final encoded bytes
    let mut current_bytes = initial_string.as_bytes().to_vec();
    for transform in selected_transforms.iter().rev() {
        current_bytes = transform.apply_inverse(&current_bytes);
    }
    let final_encoded_bytes = current_bytes;

    // 4. Generate the runtime logic (v-table and execution logic)
    let (vtable_name, vtable_code, runtime_indices) = generate_unified_vtable(&selected_transforms, &mut rng);

    let runtime_logic = match rng.gen_range(0..3) {
        0 => generate_unified_linear_logic(&vtable_name, &runtime_indices, &mut rng),
        1 => generate_unified_nested_logic(&vtable_name, &runtime_indices, &mut rng),
        _ => generate_unified_state_machine_logic(&vtable_name, &runtime_indices, &mut rng),
    };

    let struct_name = Ident::new(&format!("ObfuscatedStringHolder_{}", rng.gen::<u32>()), Span::call_site());

    let output = quote! {
        {
            #vtable_code

            struct #struct_name {
                data: &'static [u8],
            }

            impl #struct_name {
                fn deobfuscate(&self) -> String {
                    let mut data = self.data.to_vec();
                    #runtime_logic
                }
            }

            let instance = #struct_name {
                data: &[#(#final_encoded_bytes),*],
            };
            instance.deobfuscate()
        }
    };

    TokenStream::from(output)
}

fn encrypt_add(bytes: &[u8], key: u8) -> Vec<u8> {
    let mut current_key = key;
    bytes.iter().map(|&b| {
        let res = b ^ current_key;
        current_key = current_key.wrapping_add(3);
        res
    }).collect()
}

fn decrypt_add_gen(key: u8) -> TokenStream2 {
    quote! {
        |data: &[u8]| -> Vec<u8> {
            let mut current_key = #key;
            data.iter().map(|&b| {
                let res = b ^ current_key;
                current_key = current_key.wrapping_add(3);
                res
            }).collect()
        }
    }
}

fn encrypt_sub(bytes: &[u8], key: u8) -> Vec<u8> {
    let mut current_key = key;
    bytes.iter().map(|&b| {
        let res = b ^ current_key;
        current_key = current_key.wrapping_sub(5);
        res
    }).collect()
}

fn decrypt_sub_gen(key: u8) -> TokenStream2 {
    quote! {
        |data: &[u8]| -> Vec<u8> {
            let mut current_key = #key;
            data.iter().map(|&b| {
                let res = b ^ current_key;
                current_key = current_key.wrapping_sub(5);
                res
            }).collect()
        }
    }
}

fn encrypt_xor(bytes: &[u8], key: u8) -> Vec<u8> {
    let mut current_key = key;
    bytes.iter().map(|&b| {
        let res = b ^ current_key;
        current_key ^= 0xAF;
        res
    }).collect()
}

fn decrypt_xor_gen(key: u8) -> TokenStream2 {
    quote! {
        |data: &[u8]| -> Vec<u8> {
            let mut current_key = #key;
            data.iter().map(|&b| {
                let res = b ^ current_key;
                current_key ^= 0xAF;
                res
            }).collect()
        }
    }
}

fn encrypt_rot_left(bytes: &[u8], key: u8) -> Vec<u8> {
    let mut current_key = key;
    bytes.iter().map(|&b| {
        let res = b ^ current_key;
        current_key = current_key.rotate_left(3);
        res
    }).collect()
}

fn decrypt_rot_left_gen(key: u8) -> TokenStream2 {
    quote! {
        |data: &[u8]| -> Vec<u8> {
            let mut current_key = #key;
            data.iter().map(|&b| {
                let res = b ^ current_key;
                current_key = current_key.rotate_left(3);
                res
            }).collect()
        }
    }
}

fn encrypt_rot_right(bytes: &[u8], key: u8) -> Vec<u8> {
    let mut current_key = key;
    bytes.iter().map(|&b| {
        let res = b ^ current_key;
        current_key = current_key.rotate_right(5);
        res
    }).collect()
}

fn decrypt_rot_right_gen(key: u8) -> TokenStream2 {
    quote! {
        |data: &[u8]| -> Vec<u8> {
            let mut current_key = #key;
            data.iter().map(|&b| {
                let res = b ^ current_key;
                current_key = current_key.rotate_right(5);
                res
            }).collect()
        }
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
