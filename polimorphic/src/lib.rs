extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng};

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let original_string = lit_str.value();
    let original_bytes = original_string.as_bytes();
    let len = original_bytes.len();

    let mut rng = thread_rng();
    let key: Vec<u8> = (0..len).map(|_| rng.gen::<u8>()).collect();

    let encrypted_bytes: Vec<u8> = original_bytes
        .iter()
        .zip(key.iter())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect();

    let expanded = quote! {
        {
            let encrypted: [u8; #len] = [#(#encrypted_bytes),*];
            let key: [u8; #len] = [#(#key),*];
            let mut decrypted_bytes = [0u8; #len];
            for i in 0..#len {
                decrypted_bytes[i] = encrypted[i] ^ key[i];
            }
            String::from_utf8_lossy(&decrypted_bytes).to_string()
        }
    };

    TokenStream::from(expanded)
}
