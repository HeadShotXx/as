
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
}

const ALL_ENCODINGS: &[Encoding] = &[
    Encoding::Base32,
    Encoding::Base36,
    Encoding::Base64,
    Encoding::Base85,
];

fn encode_b32(data: &[u8]) -> String { base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase() }
fn encode_b36(data: &[u8]) -> String { base36::encode(data) }
fn encode_b64(data: &[u8]) -> String { BASE64_STANDARD.encode(data) }
fn encode_b85(data: &[u8]) -> String { z85::encode(data) }

fn generate_decoder(encoding: Encoding, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    let core_decode_logic = match encoding {
        Encoding::Base32 => quote! { base32::decode(base32::Alphabet::RFC4648 { padding: false }, &#input_var) },
        Encoding::Base36 => quote! { base36::decode(&#input_var) },
        Encoding::Base64 => quote! { BASE64_STANDARD.decode(&#input_var) },
        Encoding::Base85 => quote! { z85::decode(&#input_var) },
    };
    quote! { let #output_var = #core_decode_logic.unwrap(); }
}

fn generate_dead_decoder(encoding: Encoding, input_var: &Ident, output_var: &Ident) -> TokenStream2 {
    let decoder_logic = generate_decoder(encoding, input_var, output_var);
    quote! {
        if 1 > 2 {
            let #input_var = "decoy";
            #decoder_logic
            let _ = #output_var.len();
        }
    }
}

fn generate_obfuscated_decrypt(key: u8, input_var: &Ident, output_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let key_ident = Ident::new(&format!("k_{}", rng.gen::<u32>()), Span::call_site());
    let len_ident = Ident::new(&format!("l_{}", rng.gen::<u32>()), Span::call_site());

    match rng.gen_range(0..3) {
        0 => quote! {
            let #key_ident = #key;
            let #len_ident = #input_var.len();
            let mut #output_var = Vec::with_capacity(#len_ident);
            for i in 0..#len_ident { #output_var.push(#input_var[i] ^ #key_ident); }
        },
        1 => quote! {
            let #key_ident = #key;
            let #len_ident = #input_var.len();
            let mut #output_var = Vec::with_capacity(#len_ident);
            let mut i = 0;
            while i < #len_ident { #output_var.push(#input_var[i] ^ #key_ident); i += 1; }
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
    let mut current_data = original_string.clone();

    for _ in 0..num_layers {
        let encoding = *ALL_ENCODINGS.choose(&mut rng).unwrap();
        encoding_layers.push(encoding);
        current_data = match encoding {
            Encoding::Base32 => encode_b32(current_data.as_bytes()),
            Encoding::Base36 => encode_b36(current_data.as_bytes()),
            Encoding::Base64 => encode_b64(current_data.as_bytes()),
            Encoding::Base85 => encode_b85(current_data.as_bytes()),
        };
    }
    encoding_layers.reverse();

    let xor_key = rng.gen::<u8>();
    let encrypted_bytes: Vec<u8> = current_data.bytes().map(|b| b ^ xor_key).collect();

    let (data_definition, reassembly_logic) = match rng.gen_range(0..=2) {
        0 => {
            let data_lit = Literal::byte_string(&encrypted_bytes);
            (quote! { let encrypted_data = #data_lit; }, quote! { let reassembled_data = encrypted_data.to_vec(); })
        },
        1 => {
            let even: Vec<u8> = encrypted_bytes.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = encrypted_bytes.iter().skip(1).step_by(2).cloned().collect();
            let even_lit = Literal::byte_string(&even);
            let odd_lit = Literal::byte_string(&odd);
            (
                quote! { let even_data = #even_lit; let odd_data = #odd_lit; },
                quote! {
                    let mut reassembled_data = Vec::new();
                    let mut even_iter = even_data.iter();
                    let mut odd_iter = odd_data.iter();
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
            (quote! { let junk_data = #data_lit; }, quote! { let reassembled_data: Vec<u8> = junk_data.iter().step_by(2).cloned().collect(); })
        }
    };

    let mut real_chain_statements = Vec::<TokenStream2>::new();
    let mut current_var = Ident::new("s_0", Span::call_site());
    let decryption_logic = generate_obfuscated_decrypt(xor_key, &Ident::new("reassembled_data", Span::call_site()), &Ident::new("decrypted_bytes", Span::call_site()), &mut rng);

    real_chain_statements.push(quote! { let #current_var = String::from_utf8(decrypted_bytes).unwrap(); });

    for (i, encoding) in encoding_layers.iter().enumerate() {
        let next_bytes = Ident::new(&format!("b_{}", i + 1), Span::call_site());
        real_chain_statements.push(generate_decoder(*encoding, &current_var, &next_bytes));

        let next_str = Ident::new(&format!("s_{}", i + 1), Span::call_site());
        real_chain_statements.push(quote! { let #next_str = String::from_utf8(#next_bytes).unwrap(); });
        current_var = next_str;
    }

    let final_result_var = current_var;
    let real_logic_block = quote! {{
        #reassembly_logic
        #decryption_logic
        #(#real_chain_statements)*
        #final_result_var
    }};

    let num_decoys = rng.gen_range(2..=5);
    let mut decoy_blocks = Vec::<TokenStream2>::new();
    for i in 0..num_decoys {
        let decoy_in = Ident::new(&format!("di_{}", i), Span::call_site());
        let decoy_out = Ident::new(&format!("do_{}", i), Span::call_site());
        decoy_blocks.push(generate_dead_decoder(*ALL_ENCODINGS.choose(&mut rng).unwrap(), &decoy_in, &decoy_out));
    }

    let result_var = Ident::new("final_res", Span::call_site());
    let mut all_blocks = decoy_blocks;
    all_blocks.push(quote! { let #result_var = #real_logic_block; });
    all_blocks.shuffle(&mut rng);

    let expanded = quote! {{
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
        #data_definition
        #(#all_blocks)*
        #result_var
    }};

    TokenStream::from(expanded)
}
