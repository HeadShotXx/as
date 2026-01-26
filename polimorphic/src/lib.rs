
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng, seq::SliceRandom};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

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

fn encode_b32(data: &[u8]) -> String { base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase() }
fn encode_b36(data: &[u8]) -> String { base36::encode(data) }
fn encode_b64(data: &[u8]) -> String { BASE64_STANDARD.encode(data) }
fn encode_b85(data: &[u8]) -> String { z85::encode(data) }
fn encode_b91(data: &[u8]) -> String { base91::slice_encode(data).into_iter().map(|b| b as char).collect() }

fn generate_decoder(encoding: Encoding, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    let core_decode_logic = match encoding {
        Encoding::Base32 => quote! { base32::decode(base32::Alphabet::RFC4648 { padding: false }, &#input_var).expect("Base32 decoding failed") },
        Encoding::Base36 => quote! { base36::decode(&#input_var).expect("Base36 decoding failed") },
        Encoding::Base64 => quote! { BASE64_STANDARD.decode(&#input_var).expect("Base64 decoding failed") },
        Encoding::Base85 => quote! { z85::decode(&#input_var).expect("Base85 decoding failed") },
        Encoding::Base91 => quote! { base91::slice_decode(#input_var.as_bytes()) },
    };
    quote! { let #output_var = #core_decode_logic; }
}

fn generate_dead_decoder(encoding: Encoding, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    let decoder_logic = generate_decoder(encoding, input_var, output_var);
    quote! {
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("System time is before UNIX EPOCH").as_nanos() % 100 == 101 {
            let #input_var = "decoy";
            #decoder_logic
            let _ = #output_var.len();
        }
    }
}

fn generate_obfuscated_decrypt(input_expr: TokenStream2, output_var: &Ident, rng: &mut impl Rng, variant: u32) -> TokenStream2 {
    let key_ident = Ident::new(&format!("k_{}", rng.gen::<u32>()), Span::call_site());
    let temp_byte_ident = Ident::new(&format!("b_{}", rng.gen::<u32>()), Span::call_site());
    let temp_byte_ref_ident = Ident::new(&format!("br_{}", rng.gen::<u32>()), Span::call_site());

    let update_logic = match variant {
        0 => quote! { #key_ident = #key_ident.wrapping_add(#temp_byte_ident); },
        1 => quote! { #key_ident = #key_ident.wrapping_sub(#temp_byte_ident); },
        _ => quote! { #key_ident = #key_ident.rotate_left(3); },
    };

    match rng.gen_range(0..3) {
        0 => quote! {
            let mut #key_ident = self.key;
            let mut #output_var = Vec::with_capacity(#input_expr.len());
            for byte in #input_expr.iter() {
                let #temp_byte_ident = *byte;
                #output_var.push(#temp_byte_ident ^ #key_ident);
                #update_logic
            }
        },
        1 => quote! {
            let mut #key_ident = self.key;
            let mut #output_var = Vec::new();
            let mut i = 0;
            while i < #input_expr.len() {
                let #temp_byte_ident = #input_expr[i];
                #output_var.push(#temp_byte_ident ^ #key_ident);
                #update_logic
                i += 1;
            }
        },
        _ => quote! {
            let mut #key_ident = self.key;
            let #output_var: Vec<u8> = #input_expr.iter().map(|#temp_byte_ref_ident| {
                let #temp_byte_ident = *#temp_byte_ref_ident;
                let decrypted_byte = #temp_byte_ident ^ #key_ident;
                #update_logic
                decrypted_byte
            }).collect();
        },
    }
}

fn generate_final_assembly(bytes_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..3) {
        0 => quote! { String::from_utf8(#bytes_var.to_vec()).expect("Final assembly from UTF-8 failed") },
        1 => quote! {
            #bytes_var.iter().map(|b| *b as char).collect::<String>()
        },
        _ => quote! {
            {
                let mut s = String::new();
                for b in #bytes_var.iter() {
                    s.push(*b as char);
                }
                s
            }
        }
    }
}

fn generate_polymorphic_decode_chain(
    encoding_layers: &[Encoding],
    initial_input_var: &Ident,
    _final_output_var: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    match rng.gen_range(0..3) {
        0 => { // State machine
            let mut arms = Vec::new();
            let state_var = Ident::new("decode_state", Span::call_site());
            let machine_var = Ident::new("machine_data", Span::call_site());

            for (i, encoding) in encoding_layers.iter().enumerate() {
                let next_bytes = Ident::new(&format!("b_{}_{}", i, rng.gen::<u32>()), Span::call_site());
                let decoder_call = generate_decoder(*encoding, &machine_var, &next_bytes);

                if i < encoding_layers.len() - 1 {
                    arms.push(quote! {
                        #i => {
                            #decoder_call
                            let next_str = String::from_utf8(#next_bytes).expect("State machine UTF-8 conversion failed");
                            #machine_var = next_str;
                            #state_var += 1;
                        }
                    });
                } else {
                    let final_assembly = generate_final_assembly(&next_bytes, rng);
                    arms.push(quote! {
                        #i => {
                            #decoder_call
                            let final_val = #final_assembly;
                            break final_val;
                        }
                    });
                }
            }
            arms.push(quote! { _ => break String::new(), });

            quote! {
                let mut #state_var = 0;
                let mut #machine_var = #initial_input_var.clone();
                loop {
                    match #state_var {
                        #(#arms)*
                    }
                }
            }
        },
        1 => { // Nested blocks
            if encoding_layers.is_empty() {
                return quote! { String::new() };
            }

            // Start with the innermost expression: the final decoding and assembly.
            let last_layer_idx = encoding_layers.len() - 1;
            let last_layer_input = Ident::new(&format!("nested_data_{}", last_layer_idx), Span::call_site());
            let last_layer_output_bytes = Ident::new(&format!("nested_bytes_{}", last_layer_idx), Span::call_site());
            let last_decoder_call = generate_decoder(encoding_layers[last_layer_idx], &last_layer_input, &last_layer_output_bytes);
            let final_assembly = generate_final_assembly(&last_layer_output_bytes, rng);

            let mut nested_logic = quote! {
                #last_decoder_call
                #final_assembly
            };

            // Wrap the logic with the outer layers.
            for i in (0..last_layer_idx).rev() {
                let current_input = Ident::new(&format!("nested_data_{}", i), Span::call_site());
                let next_input = Ident::new(&format!("nested_data_{}", i + 1), Span::call_site());
                let output_bytes = Ident::new(&format!("nested_bytes_{}", i), Span::call_site());
                let decoder_call = generate_decoder(encoding_layers[i], &current_input, &output_bytes);

                nested_logic = quote! {
                    {
                        #decoder_call
                        let #next_input = String::from_utf8(#output_bytes).expect("Nested block UTF-8 conversion failed");
                        #nested_logic
                    }
                };
            }

            // Define the first input variable to kick off the chain.
            let first_data_var = Ident::new("nested_data_0", Span::call_site());
            quote! {
                let #first_data_var = #initial_input_var.clone();
                #nested_logic
            }
        },
        _ => { // Linear
            let mut statements = Vec::new();
            let mut current_var = initial_input_var.clone();

            for (i, encoding) in encoding_layers.iter().enumerate() {
                let next_bytes = Ident::new(&format!("b_{}_{}", i, rng.gen::<u32>()), Span::call_site());
                let decoder_call = generate_decoder(*encoding, &current_var, &next_bytes);
                statements.push(decoder_call);

                if i < encoding_layers.len() - 1 {
                    let next_str = Ident::new(&format!("s_{}_{}", i, rng.gen::<u32>()), Span::call_site());
                    statements.push(quote! { let #next_str = String::from_utf8(#next_bytes).expect("Linear chain UTF-8 conversion failed"); });
                    current_var = next_str;
                } else {
                     let final_assembly = generate_final_assembly(&next_bytes, rng);
                     statements.push(quote! { let final_val = #final_assembly; });
                }
            }

            quote! {
                #(#statements)*
                final_val
            }
        }
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let original_string = lit_str.value();
    let mut rng = thread_rng();

    // Encoding
    let num_layers = rng.gen_range(3..=7);
    let mut encoding_layers = Vec::new();
    let mut current_data = original_string.clone();
    for _ in 0..num_layers {
        let encoding = *ALL_ENCODINGS.choose(&mut rng).expect("Failed to choose an encoding");
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

    // Encryption
    let xor_key = rng.gen::<u8>();
    let encrypt_variant = rng.gen_range(0..3u32);
    let mut key = xor_key;
    let mut encrypted_bytes = Vec::with_capacity(current_data.len());
    for original_byte in current_data.bytes() {
        let encrypted_byte = original_byte ^ key;
        encrypted_bytes.push(encrypted_byte);
        match encrypt_variant {
            0 => key = key.wrapping_add(encrypted_byte),
            1 => key = key.wrapping_sub(encrypted_byte),
            _ => key = key.rotate_left(3),
        };
    }

    // Struct and Method Names
    let struct_name = Ident::new(&format!("ObfuscatedString_{}", rng.gen::<u32>()), Span::call_site());
    let method_name = Ident::new(&format!("reveal_{}", rng.gen::<u32>()), Span::call_site());

    // Decoding Logic Generation
    let initial_input_var = Ident::new("decrypted_str", Span::call_site());
    let final_output_var = Ident::new("final_result", Span::call_site());
    let decode_chain = generate_polymorphic_decode_chain(
        &encoding_layers,
        &initial_input_var,
        &final_output_var,
        &mut rng,
    );

    // Data Representation Polymorphism
    let (data_fields, data_initializers, reassembly_logic) = match rng.gen_range(0..3) {
        0 => {
            let data_lit = Literal::byte_string(&encrypted_bytes);
            (
                quote! { data: &'a [u8], },
                quote! { data: #data_lit, },
                quote! { let reassembled_data = self.data.to_vec(); }
            )
        },
        1 => {
            let even: Vec<u8> = encrypted_bytes.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = encrypted_bytes.iter().skip(1).step_by(2).cloned().collect();
            let even_lit = Literal::byte_string(&even);
            let odd_lit = Literal::byte_string(&odd);
            (
                quote! { even_data: &'a [u8], odd_data: &'a [u8], },
                quote! { even_data: #even_lit, odd_data: #odd_lit, },
                quote! {
                    let mut reassembled_data = Vec::new();
                    let mut even_iter = self.even_data.iter();
                    let mut odd_iter = self.odd_data.iter();
                    loop {
                        if let Some(e) = even_iter.next() { reassembled_data.push(*e); } else { break; }
                        if let Some(o) = odd_iter.next() { reassembled_data.push(*o); } else { break; }
                    }
                }
            )
        },
        _ => {
            let junk_interspersed: Vec<u8> = encrypted_bytes.iter().flat_map(|&b| vec![b, rng.gen()]).collect();
            let data_lit = Literal::byte_string(&junk_interspersed);
            (
                quote! { junk_data: &'a [u8], },
                quote! { junk_data: #data_lit, },
                quote! { let reassembled_data: Vec<u8> = self.junk_data.iter().step_by(2).cloned().collect(); }
            )
        }
    };

    // Decryption Logic
    let decryption_logic = generate_obfuscated_decrypt(
        quote! { reassembled_data },
        &Ident::new("decrypted_bytes", Span::call_site()),
        &mut rng,
        encrypt_variant,
    );

    // Decoy Logic
    let num_decoys = rng.gen_range(2..=5);
    let mut decoy_blocks = Vec::<TokenStream2>::new();
    for i in 0..num_decoys {
        let decoy_in = Ident::new(&format!("di_{}", i), Span::call_site());
        let decoy_out = Ident::new(&format!("do_{}", i), Span::call_site());
        decoy_blocks.push(generate_dead_decoder(*ALL_ENCODINGS.choose(&mut rng).expect("Failed to choose decoy encoding"), &decoy_in, &decoy_out));
    }

    // Final Expansion
    let real_logic_block = quote! {{
        #reassembly_logic
        #decryption_logic
        let #initial_input_var = String::from_utf8(decrypted_bytes).expect("Initial UTF-8 conversion after decryption failed");
        #decode_chain
    }};

    let result_var = Ident::new(&format!("final_res_{}", rng.gen::<u32>()), Span::call_site());
    let mut all_blocks = decoy_blocks;
    all_blocks.push(quote! { let #result_var = #real_logic_block; });
    all_blocks.shuffle(&mut rng);

    let expanded = quote! {{
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

        struct #struct_name<'a> {
            #data_fields
            key: u8,
        }

        impl<'a> #struct_name<'a> {
            fn #method_name(&self) -> String {
                #(#all_blocks)*
                #result_var
            }
        }

        let instance = #struct_name {
            #data_initializers
            key: #xor_key,
        };
        instance.#method_name()
    }};

    TokenStream::from(expanded)
}
