extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use polimorphic_core::Encoding;

const BASE36_ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

fn encode(encoding: &Encoding, data: &[u8]) -> String {
    match encoding {
        Encoding::Base32 => base32::encode(base32::Alphabet::RFC4648 { padding: true }, data),
        Encoding::Base36 => base_x::encode(BASE36_ALPHABET, data),
        Encoding::Base64 => { use base64::Engine as _; base64::engine::general_purpose::STANDARD.encode(data) },
        Encoding::Base85 => base85::encode(data),
        Encoding::Base91 => String::from_utf8(base91::slice_encode(data)).unwrap(),
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
        encoded_string = encode(encoding, encoded_string.as_bytes());
    }

    let encoded_bytes = encoded_string.as_bytes();
    let len = encoded_bytes.len();
    let key: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();

    let encrypted_bytes: Vec<u8> = encoded_bytes
        .iter()
        .zip(key.iter())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect();

    let encoding_variants = encodings.iter().rev().map(|e| {
        match e {
            Encoding::Base32 => quote! { polimorphic_core::Encoding::Base32 },
            Encoding::Base36 => quote! { polimorphic_core::Encoding::Base36 },
            Encoding::Base64 => quote! { polimorphic_core::Encoding::Base64 },
            Encoding::Base85 => quote! { polimorphic_core::Encoding::Base85 },
            Encoding::Base91 => quote! { polimorphic_core::Encoding::Base91 },
        }
    });

    let expanded = quote! {
        polimorphic_core::decode_and_decrypt(&[#(#encrypted_bytes),*], &[#(#key),*], &[#(#encoding_variants),*]).unwrap()
    };

    TokenStream::from(expanded)
}
