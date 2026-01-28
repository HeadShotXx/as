
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng, seq::SliceRandom};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};

struct Transformation {
    encoder: fn(&[u8]) -> String,
    decoder_gen: fn(&Ident, &Ident) -> TokenStream2,
}

fn get_transformations() -> Vec<Transformation> {
    vec![
        Transformation {
            encoder: |data| base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase(),
            decoder_gen: |input, output| quote! { let #output = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &#input).expect("E1"); },
        },
        Transformation {
            encoder: |data| base36::encode(data),
            decoder_gen: |input, output| quote! { let #output = base36::decode(&#input).expect("E2"); },
        },
        Transformation {
            encoder: |data| {
                use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
                BASE64_STANDARD.encode(data)
            },
            decoder_gen: |input, output| quote! {
                let #output = {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.decode(&#input).expect("E3")
                };
            },
        },
        Transformation {
            encoder: |data| z85::encode(data),
            decoder_gen: |input, output| quote! { let #output = z85::decode(&#input).expect("E4"); },
        },
        Transformation {
            encoder: |data| base91::slice_encode(data).into_iter().map(|b| b as char).collect(),
            decoder_gen: |input, output| quote! { let #output = base91::slice_decode(#input.as_bytes()); },
        },
    ]
}

fn generate_decoder(transformation: &Transformation, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    (transformation.decoder_gen)(input_var, output_var)
}

fn generate_dead_decoder(transformation: &Transformation, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    let decoder_logic = generate_decoder(transformation, input_var, output_var);
    quote! {
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("T").as_nanos() % 100 == 101 {
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
        0 => quote! { String::from_utf8(#bytes_var.to_vec()).expect("F") },
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
    transformations: &[&Transformation],
    initial_input_var: &Ident,
    _final_output_var: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    match rng.gen_range(0..3) {
        0 => { // State machine
            let mut arms = Vec::new();
            let state_var = Ident::new("decode_state", Span::call_site());
            let machine_var = Ident::new("machine_data", Span::call_site());

            for (i, transformation) in transformations.iter().enumerate() {
                let next_bytes = Ident::new(&format!("b_{}_{}", i, rng.gen::<u32>()), Span::call_site());
                let decoder_call = generate_decoder(transformation, &machine_var, &next_bytes);

                if i < transformations.len() - 1 {
                    arms.push(quote! {
                        #i => {
                            #decoder_call
                            let next_str = String::from_utf8(#next_bytes).expect("S");
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
            if transformations.is_empty() {
                return quote! { String::new() };
            }

            // Start with the innermost expression: the final decoding and assembly.
            let last_layer_idx = transformations.len() - 1;
            let last_layer_input = Ident::new(&format!("nested_data_{}", last_layer_idx), Span::call_site());
            let last_layer_output_bytes = Ident::new(&format!("nested_bytes_{}", last_layer_idx), Span::call_site());
            let last_decoder_call = generate_decoder(transformations[last_layer_idx], &last_layer_input, &last_layer_output_bytes);
            let final_assembly = generate_final_assembly(&last_layer_output_bytes, rng);

            let mut nested_logic = quote! {
                {
                    #last_decoder_call
                    #final_assembly
                }
            };

            // Wrap the logic with the outer layers.
            for i in (0..last_layer_idx).rev() {
                let current_input = Ident::new(&format!("nested_data_{}", i), Span::call_site());
                let next_input = Ident::new(&format!("nested_data_{}", i + 1), Span::call_site());
                let output_bytes = Ident::new(&format!("nested_bytes_{}", i), Span::call_site());
                let decoder_call = generate_decoder(transformations[i], &current_input, &output_bytes);

                nested_logic = quote! {
                    {
                        #decoder_call
                        let #next_input = String::from_utf8(#output_bytes).expect("S");
                        #nested_logic
                    }
                };
            }

            // Define the first input variable to kick off the chain.
            let first_data_var = Ident::new("nested_data_0", Span::call_site());
            quote! {
                {
                    let #first_data_var = #initial_input_var.clone();
                    #nested_logic
                }
            }
        },
        _ => { // Linear
            let mut statements = Vec::new();
            let mut current_var = initial_input_var.clone();

            for (i, transformation) in transformations.iter().enumerate() {
                let next_bytes = Ident::new(&format!("b_{}_{}", i, rng.gen::<u32>()), Span::call_site());
                let decoder_call = generate_decoder(transformation, &current_var, &next_bytes);
                statements.push(decoder_call);

                if i < transformations.len() - 1 {
                    let next_str = Ident::new(&format!("s_{}_{}", i, rng.gen::<u32>()), Span::call_site());
                    statements.push(quote! { let #next_str = String::from_utf8(#next_bytes).expect("S"); });
                    current_var = next_str;
                } else {
                     let final_assembly = generate_final_assembly(&next_bytes, rng);
                     statements.push(quote! { let final_val = #final_assembly; });
                }
            }

            quote! {
                {
                    #(#statements)*
                    final_val
                }
            }
        }
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let original_string = lit_str.value();
    let mut rng = thread_rng();
    let transformations = get_transformations();

    // Encoding
    let num_layers = rng.gen_range(3..=7);
    let mut selected_transformations = Vec::new();
    let mut current_data = original_string.clone();
    for _ in 0..num_layers {
        let idx = rng.gen_range(0..transformations.len());
        let transformation = &transformations[idx];
        selected_transformations.push(transformation);
        current_data = (transformation.encoder)(current_data.as_bytes());
    }
    selected_transformations.reverse();

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
        &selected_transformations,
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
        let trans_idx = rng.gen_range(0..transformations.len());
        decoy_blocks.push(generate_dead_decoder(&transformations[trans_idx], &decoy_in, &decoy_out));
    }

    // Final Expansion
    let real_logic_block = quote! {{
        #reassembly_logic
        #decryption_logic
        let #initial_input_var = String::from_utf8(decrypted_bytes).expect("I");
        #decode_chain
    }};

    let result_var = Ident::new(&format!("final_res_{}", rng.gen::<u32>()), Span::call_site());
    let mut all_blocks = decoy_blocks;
    all_blocks.push(quote! { let #result_var = #real_logic_block; });
    all_blocks.shuffle(&mut rng);

    let expanded = quote! {{
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
