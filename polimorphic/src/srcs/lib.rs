
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
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

// Corrected encoding functions
fn encode_b32(data: &[u8]) -> String { base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase() }
fn encode_b36(data: &[u8]) -> String { base36::encode(data) }
fn encode_b64(data: &[u8]) -> String { BASE64_STANDARD.encode(data) }
fn encode_b85(data: &[u8]) -> String { z85::encode(data) }
fn encode_b91(data: &[u8]) -> String { base91::encode(data).to_string() }

fn generate_decoder(encoding: Encoding, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    match encoding {
        Encoding::Base32 => quote! { let #output_var = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &#input_var).unwrap(); },
        Encoding::Base36 => quote! { let #output_var = base36::decode(&#input_var).unwrap(); },
        Encoding::Base64 => quote! { use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD}; let #output_var = BASE64_STANDARD.decode(&#input_var).unwrap(); },
        Encoding::Base85 => quote! { let #output_var = z85::decode(&#input_var).unwrap(); },
        Encoding::Base91 => quote! { let #output_var = base91::decode(&#input_var); },
    }
}

fn generate_dead_decoder(encoding: Encoding, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    let decoder_logic = generate_decoder(encoding, input_var, output_var);
    let random_bool = rand::random::<bool>();
    quote! {
        if #random_bool && 1 > 2 {
            let #input_var = "decoy";
            #decoder_logic
            println!("{}", #output_var.len());
        }
    }
}

fn generate_obfuscated_decrypt(key: u8, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    let mut rng = thread_rng();
    let key_ident = Ident::new(&format!("key_{}", rng.gen::<u32>()), Span::call_site());
    let len_ident = Ident::new(&format!("len_{}", rng.gen::<u32>()), Span::call_site());

    let loop_type = rng.gen_range(0..3);
    match loop_type {
        0 => quote! {
            let #key_ident = #key;
            let #len_ident = #input_var.len();
            let mut #output_var = Vec::with_capacity(#len_ident);
            for i in 0..#len_ident {
                #output_var.push(#input_var[i] ^ #key_ident);
            }
        },
        1 => quote! {
            let #key_ident = #key;
            let #len_ident = #input_var.len();
            let mut #output_var = Vec::with_capacity(#len_ident);
            let mut i = 0;
            while i < #len_ident {
                #output_var.push(#input_var[i] ^ #key_ident);
                i += 1;
            }
        },
        _ => quote! {
            let #key_ident = #key;
            let #output_var: Vec<u8> = #input_var.iter().map(|b| b ^ #key_ident).collect();
        },
    }
}


#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let original_string = lit_str.value();
    let mut rng = thread_rng();

    let num_layers = rng.gen_range(3..=7);
    let mut encoding_layers = Vec::new();
    let mut current_data = original_string.as_bytes().to_vec();

    for _ in 0..num_layers {
        let encoding = *ALL_ENCODINGS.choose(&mut rng).unwrap();
        encoding_layers.push(encoding);
        current_data = match encoding {
            Encoding::Base32 => encode_b32(&current_data).into_bytes(),
            Encoding::Base36 => encode_b36(&current_data).into_bytes(),
            Encoding::Base64 => encode_b64(&current_data).into_bytes(),
            Encoding::Base85 => encode_b85(&current_data).into_bytes(),
            Encoding::Base91 => encode_b91(&current_data).into_bytes(),
        };
    }
    encoding_layers.reverse();

    let xor_key = rng.gen::<u8>();
    let encrypted_bytes: Vec<u8> = current_data.iter().map(|&b| b ^ xor_key).collect();

    let data_layout_type = rng.gen_range(0..=2);
    let (data_definition, reassembly_logic) = match data_layout_type {
        0 => {
            let data_lit = Literal::byte_string(&encrypted_bytes);
            (quote! { let encrypted_data = #data_lit; }, quote! { let reassembled_data = encrypted_data.to_vec(); })
        },
        1 => {
            let even: Vec<u8> = encrypted_bytes.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = encrypted_bytes.iter().skip(1).step_by(2).cloned().collect();
            let even_lit = Literal::byte_string(&even);
            let odd_lit = Literal::byte_string(&odd);
            let total_len = encrypted_bytes.len();
            let reassembly = quote! {
                let mut reassembled_data = vec![0u8; #total_len];
                let (mut even_idx, mut odd_idx) = (0, 0);
                for i in 0..#total_len {
                    if i % 2 == 0 { reassembled_data[i] = even_data[even_idx]; even_idx += 1; }
                    else { reassembled_data[i] = odd_data[odd_idx]; odd_idx += 1; }
                }
            };
            (quote! { let even_data = #even_lit; let odd_data = #odd_lit; }, reassembly)
        },
        _ => {
            let junk_interspersed: Vec<u8> = encrypted_bytes.iter().flat_map(|&b| vec![b, rng.gen::<u8>()]).collect();
            let data_lit = Literal::byte_string(&junk_interspersed);
            (quote! { let junk_data = #data_lit; }, quote! { let reassembled_data: Vec<u8> = junk_data.iter().step_by(2).cloned().collect(); })
        }
    };

    let mut real_chain_statements = Vec::<TokenStream2>::new();
    let mut current_var = Ident::new("decrypted_bytes", Span::call_site());

    let decryption_logic = generate_obfuscated_decrypt(xor_key, &Ident::new("reassembled_data", Span::call_site()), &current_var);

    for (i, encoding) in encoding_layers.iter().enumerate() {
        let next_var = Ident::new(&format!("decoded_level_{}", i), Span::call_site());
        let current_input_is_string = i > 0 || matches!(encoding, Encoding::Base32 | Encoding::Base36 | Encoding::Base64 | Encoding::Base85);

        let pre_decode_conversion = if current_input_is_string {
             quote! { let #current_var = String::from_utf8(#current_var).unwrap(); }
        } else {
            quote! {}
        };

        real_chain_statements.push(pre_decode_conversion);
        let decoder_logic = generate_decoder(*encoding, &current_var, &next_var);
        real_chain_statements.push(decoder_logic);
        current_var = next_var;
    }
    let final_real_var = current_var;

    let num_decoys = rng.gen_range(2..=5);
    let mut all_logic_blocks = Vec::<TokenStream2>::new();

    for i in 0..num_decoys {
        let decoy_input_var = Ident::new(&format!("decoy_data_{}", i), Span::call_site());
        let decoy_output_var = Ident::new(&format!("decoy_result_{}", i), Span::call_site());
        let encoding = *ALL_ENCODINGS.choose(&mut rng).unwrap();
        let dead_code = generate_dead_decoder(encoding, &decoy_input_var, &decoy_output_var);
        all_logic_blocks.push(quote! {
            let #decoy_input_var = "some_random_decoy_string";
             #dead_code
        });
    }

    let final_len = original_string.as_bytes().len();
    let mut indices: Vec<usize> = (0..final_len).collect();
    indices.shuffle(&mut rng);

    let unshuffle_map: Vec<_> = (0..final_len).map(|i| indices.iter().position(|&p| p == i).unwrap()).collect();

    // NOTE: True polymorphic shuffling requires re-encoding the shuffled data.
    // This implementation unshuffles the *final* decoded result, which is less secure but simpler.
    let final_var_name = Ident::new(&format!("final_string_buffer_{}", rng.gen::<u32>()), Span::call_site());
    let final_assembly = quote! {
        let final_bytes = String::from_utf8(#final_real_var).unwrap();
        String::from(final_bytes)
    };

    let real_logic_block = quote! {
        #reassembly_logic
        #decryption_logic
        #(#real_chain_statements)*
        #final_assembly
    };

    all_logic_blocks.push(real_logic_block);
    all_logic_blocks.shuffle(&mut rng);

    let final_expr_var = Ident::new("final_expr_val", Span::call_site());

    let expanded = quote! {{
        #data_definition
        let #final_expr_var = { #(#all_logic_blocks)* };
        #final_expr_var
    }};

    TokenStream::from(expanded)
}
