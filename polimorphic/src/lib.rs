extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use proc_macro2::{TokenStream as TokenStream2, Ident, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Encoding {
    Base32,
    Base36,
    Base64,
    Base85,
    Base91,
}

fn encode(encoding: &Encoding, data: &[u8]) -> String {
    match encoding {
        Encoding::Base32 => base32::encode(base32::Alphabet::RFC4648 { padding: false }, data),
        Encoding::Base36 => base_x::encode("0123456789abcdefghijklmnopqrstuvwxyz", data),
        Encoding::Base64 => { use base64::Engine as _; base64::engine::general_purpose::STANDARD_NO_PAD.encode(data) },
        Encoding::Base85 => base85::encode(data),
        Encoding::Base91 => String::from_utf8(base91::slice_encode(data)).unwrap(),
    }
}

fn generate_dead_code(rng: &mut impl Rng) -> TokenStream2 {
    let dead_var1_start: u32 = rng.gen();
    let dead_var2_start: u32 = rng.gen();

    let mut dead_code_stmts = Vec::<TokenStream2>::new();
    for _ in 0..rng.gen_range(3..7) {
        let random_val: u32 = rng.gen();
        let random_shift: u32 = rng.gen_range(1..32);
        let choice = rng.gen_range(0..4);
        dead_code_stmts.push(match choice {
            0 => quote! { dead_var1 = dead_var1.wrapping_add(#random_val); },
            1 => quote! { dead_var2 = dead_var1.wrapping_mul(#random_val); },
            2 => quote! { dead_var1 = dead_var2.rotate_left(#random_shift); },
            _ => quote! { dead_var2 = dead_var1 ^ dead_var2; },
        });
    }

    quote! {
        let mut dead_var1: u32 = #dead_var1_start;
        let mut dead_var2: u32 = #dead_var2_start;
        #(#dead_code_stmts)*
    }
}

fn generate_obfuscated_decoder(encoding: &Encoding, input_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    let dead_code = generate_dead_code(rng);

    match encoding {
        Encoding::Base64 => {
            let original_table: [i8; 256] = [
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
                -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
            ];
            let mut key = [0i8; 256];
            rng.fill(&mut key);
            let obfuscated_table: Vec<i8> = original_table.iter().zip(key.iter()).map(|(v, k)| v ^ k).collect();
            quote! {{
                let input_bytes = String::from_utf8(#input_var).unwrap().into_bytes();
                const OBFUSCATED_TABLE: [i8; 256] = [#(#obfuscated_table),*];
                const TABLE_KEY: [i8; 256] = [#(#key),*];
                let mut table = [0i8; 256];
                for i in 0..256 { table[i] = OBFUSCATED_TABLE[i] ^ TABLE_KEY[i]; }
                #dead_code
                let mut result = Vec::new();
                let mut buffer = 0u32;
                let mut buffer_len = 0;
                for &byte in &input_bytes {
                    let value = table[byte as usize];
                    if value != -1 {
                        buffer = (buffer << 6) | (value as u32);
                        buffer_len += 6;
                        if buffer_len >= 8 { buffer_len -= 8; result.push((buffer >> buffer_len) as u8); }
                    }
                }
                result
            }}
        },
        Encoding::Base32 => {
            let original_table: [i8; 256] = [
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,-1,-1,-1,-1,-1,-1,-1,-1,
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
            ];
            let mut key = [0i8; 256];
            rng.fill(&mut key);
            let obfuscated_table: Vec<i8> = original_table.iter().zip(key.iter()).map(|(v, k)| v ^ k).collect();
            quote! {{
                let input_bytes = String::from_utf8(#input_var).unwrap().into_bytes();
                const OBFUSCATED_TABLE: [i8; 256] = [#(#obfuscated_table),*];
                const TABLE_KEY: [i8; 256] = [#(#key),*];
                let mut table = [0i8; 256];
                for i in 0..256 { table[i] = OBFUSCATED_TABLE[i] ^ TABLE_KEY[i]; }
                #dead_code
                let mut result = Vec::new();
                let mut buffer = 0u64;
                let mut buffer_len = 0;
                for &byte in &input_bytes {
                    let value = table[byte as usize];
                    if value != -1 {
                        buffer = (buffer << 5) | (value as u64);
                        buffer_len += 5;
                        if buffer_len >= 8 { buffer_len -= 8; result.push((buffer >> buffer_len) as u8); }
                    }
                }
                result
            }}
        },
        // For Base36, Base85, and Base91, we will use the standard libraries for decoding
        // as they don't rely on simple lookup tables and implementing them from scratch is complex.
        // We can still inject dead code for obfuscation.
        Encoding::Base36 => quote! {{
            #dead_code
            base_x::decode("0123456789abcdefghijklmnopqrstuvwxyz", &String::from_utf8(#input_var).unwrap()).unwrap()
        }},
        Encoding::Base85 => quote! {{
            #dead_code
            base85::decode(&String::from_utf8(#input_var).unwrap()).unwrap()
        }},
        Encoding::Base91 => quote! {{
            #dead_code
            base91::slice_decode(String::from_utf8(#input_var).unwrap().as_bytes())
        }},
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let original_string = lit_str.value();
    let mut rng = thread_rng();

    let mut encodings = [
        Encoding::Base32,
        Encoding::Base36,
        Encoding::Base64,
        Encoding::Base85,
        Encoding::Base91,
    ];
    encodings.shuffle(&mut rng);

    let mut encoded_string = original_string.as_bytes().to_vec();
    for encoding in &encodings {
        encoded_string = encode(encoding, &encoded_string).into_bytes();
    }

    let len = encoded_string.len();
    let key: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();
    let encrypted_bytes: Vec<u8> = encoded_string.iter().zip(key.iter()).map(|(&b, &k)| b ^ k).collect();

    let mut statements = Vec::<TokenStream2>::new();
    let mut current_var = Ident::new("decrypted_bytes", Span::call_site());

    for (i, encoding) in encodings.iter().rev().enumerate() {
        let next_var = Ident::new(&format!("decoded_bytes_{}", i), Span::call_site());
        let decoder_logic = generate_obfuscated_decoder(encoding, &current_var, &mut rng);
        statements.push(quote! { let #next_var = #decoder_logic; });
        current_var = next_var;
    }

    let expanded = quote! {
        {
            let encrypted: [u8; #len] = [#(#encrypted_bytes),*];
            let key: [u8; #len] = [#(#key),*];
            let mut decrypted_bytes = vec![0u8; #len];
            for i in 0..#len { decrypted_bytes[i] = encrypted[i] ^ key[i]; }

            #(#statements)*

            String::from_utf8(#current_var).unwrap()
        }
    };

    TokenStream::from(expanded)
}
