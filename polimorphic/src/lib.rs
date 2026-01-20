extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;

const BASE36_ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

#[derive(Debug, Clone, Copy)]
enum Encoding {
    Base32,
    Base36,
    Base64,
    Base85,
    Base91,
}

impl Encoding {
    fn encode(&self, data: &[u8]) -> String {
        match self {
            Encoding::Base32 => base32::encode(base32::Alphabet::RFC4648 { padding: true }, data),
            Encoding::Base36 => base_x::encode(BASE36_ALPHABET, data),
            Encoding::Base64 => { use base64::Engine as _; base64::engine::general_purpose::STANDARD.encode(data) },
            Encoding::Base85 => base85::encode(data),
            Encoding::Base91 => String::from_utf8(base91::slice_encode(data)).unwrap(),
        }
    }

    fn decoder_path(&self) -> proc_macro2::TokenStream {
        let alphabet = BASE36_ALPHABET;
        match self {
            Encoding::Base32 => quote! { |s: &str| ::base32::decode(::base32::Alphabet::RFC4648 { padding: true }, s).ok_or_else(|| "base32 decoding failed").unwrap() },
            Encoding::Base36 => quote! { |s: &str| ::base_x::decode(#alphabet, s).map_err(|e| e.to_string()).unwrap() },
            Encoding::Base64 => quote! { |s: &str| { use ::base64::Engine as _; ::base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| e.to_string()).unwrap() } },
            Encoding::Base85 => quote! { |s: &str| ::base85::decode(s).ok_or_else(|| "base85 decoding failed").unwrap() },
            Encoding::Base91 => quote! { |s: &str| ::base91::slice_decode(s.as_bytes()) },
        }
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

    let mut encoded_string = original_string;
    for encoding in &encodings {
        encoded_string = encoding.encode(encoded_string.as_bytes());
    }

    let encoded_bytes = encoded_string.as_bytes();
    let len = encoded_bytes.len();
    let key: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();

    let encrypted_bytes: Vec<u8> = encoded_bytes
        .iter()
        .zip(key.iter())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect();

    let decoders = encodings
        .iter()
        .rev()
        .map(|e| e.decoder_path());

    let mut statements = Vec::new();
    let mut current_var = quote! { decrypted_bytes };

    for (i, decoder) in decoders.enumerate() {
        let next_var = format!("decoded_bytes_{}", i);
        let next_var_ident = proc_macro2::Ident::new(&next_var, proc_macro2::Span::call_site());
        statements.push(quote! {
            let #next_var_ident = (#decoder)(&String::from_utf8(#current_var).unwrap());
        });
        current_var = quote! { #next_var_ident };
    }

    let expanded = quote! {
        {
            let encrypted: [u8; #len] = [#(#encrypted_bytes),*];
            let key: [u8; #len] = [#(#key),*];
            let mut decrypted_bytes = vec![0u8; #len];
            for i in 0..#len {
                decrypted_bytes[i] = encrypted[i] ^ key[i];
            }

            #(#statements)*

            String::from_utf8(#current_var).unwrap()
        }
    };

    TokenStream::from(expanded)
}
