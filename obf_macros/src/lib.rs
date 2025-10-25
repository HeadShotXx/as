extern crate proc_macro;
use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use syn::{parse_macro_input, LitStr};

#[proc_macro]
pub fn obf_str(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let original_str = input.value();
    let mut seed = [0u8; 32];
    for (i, byte) in original_str.as_bytes().iter().enumerate().take(32) {
        seed[i] = *byte;
    }
    let mut rng = StdRng::from_seed(seed);
    let key: u8 = rng.gen();

    let obfuscated_bytes: Vec<u8> = original_str.bytes().map(|b| b ^ key).collect();
    let bytes_literal = Literal::byte_string(&obfuscated_bytes);

    let expanded = quote! {
        {
            let mut s = String::with_capacity(#original_str.len());
            let key = #key;
            let obfuscated: &[u8] = #bytes_literal;
            for &b in obfuscated {
                s.push((b ^ key) as char);
            }
            s
        }
    };

    TokenStream::from(expanded)
}
