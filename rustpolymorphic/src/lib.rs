use proc_macro::Span;
use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Arm, FnArg, Ident, ItemFn, Lit, MetaNameValue, Pat, Token, parse_macro_input}; // <-- import Span here

use rand::{Rng, rng};

/// Parses `#[polymorph(fn_len = N, garbage = bool)]` arguments.
struct PolymorphArgs {
    fn_len: Option<usize>,
    garbage: bool,
}

impl Parse for PolymorphArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let items = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;
        let mut fn_len = None;
        let mut garbage = false;

        for m in items {
            if let Some(id) = m.path.get_ident() {
                match id.to_string().as_str() {
                    "fn_len" => {
                        if let syn::Expr::Lit(expr) = &m.value {
                            if let Lit::Int(li) = &expr.lit {
                                fn_len = Some(li.base10_parse()?);
                            }
                        }
                    }
                    "garbage" => {
                        if let syn::Expr::Lit(expr) = &m.value {
                            if let Lit::Bool(lb) = &expr.lit {
                                garbage = lb.value;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(PolymorphArgs { fn_len, garbage })
    }
}

/// Macro attribute that renames the function, injects junk (if requested),
/// and emits a wrapper under the original name.
#[proc_macro_attribute]
pub fn polymorph(attr: TokenStream, item: TokenStream) -> TokenStream {
    // 1) Parse the annotated function and signature
    let input_fn = parse_macro_input!(item as ItemFn);
    let original_sig = input_fn.sig.clone();
    let args = parse_macro_input!(attr as PolymorphArgs);

    let mut f = input_fn;
    let len = args.fn_len.unwrap_or(8);
    let do_garbage = args.garbage;

    // 2) Initialize RNG
    let mut rng_obj = rng();

    // 3) Generate a random new identifier of length `len`
    let new_name_str = random_ident(len, &mut rng_obj);
    let new_name = Ident::new(&new_name_str, f.sig.ident.span());
    f.sig.ident = new_name.clone();

    // 4) Build a vector of statements: (a) junk if requested, (b) original body
    let mut stmts = Vec::new();

    if do_garbage {
        // ─────── Injected junk ───────

        // a) Two random u32 values
        let r1: u32 = rng_obj.random::<u32>();
        let r2: u32 = rng_obj.random::<u32>();

        //  a.1) A meaningless if-statement
        stmts.push(syn::parse_quote! {
            if (#r1.wrapping_mul(#r2) ^ #r1) % 2 == 1 { } else {}
        });

        // b) A dummy helper function that xors its input with r2
        let dname = Ident::new(&random_ident(len, &mut rng_obj), f.sig.ident.span());
        stmts.push(syn::parse_quote! {
            fn #dname(x: i32) -> i32 { x ^ (#r2 as i32) }
        });
        stmts.push(syn::parse_quote! {
            let _ = #dname(#r1 as i32);
        });

        // c) A dummy `match` on a “random” choice in 0..5 (explicitly using usize literals)
        let choice_u32: u32 = rng_obj.random::<u32>();
        let choice: usize = (choice_u32 % 5) as usize;

        // Build arms with “0usize”, “1usize”, … “4usize”
        let mut arms: Vec<Arm> = Vec::new();
        for i in 0..5 {
            let lit = syn::LitInt::new(&format!("{}usize", i), Span::call_site().into());
            arms.push(syn::parse_quote! {
                #lit => { let _ = #lit; },
            });
        }
        stmts.push(syn::parse_quote! {
            match #choice { #(#arms)* _ => {} }
        });

        // d) A few random junk `let _junk = <u8>;` statements
        let junk_count_u32: u32 = rng_obj.random::<u32>();
        let junk_count: usize = ((junk_count_u32 % 3) as usize) + 2; // yields 2..4
        for _ in 0..junk_count {
            let v: u8 = rng_obj.random::<u8>();
            stmts.push(syn::parse_quote! {
                let _junk = #v;
            });
        }

        // ───────────────────────────────
    }

    // 5) Append the original function-body statements
    stmts.extend(f.block.stmts.clone());
    f.block.stmts = stmts;

    // 6) Extract argument identifiers so we can make a wrapper
    let original_arg_idents: Vec<Ident> = original_sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_ty) = arg {
                if let Pat::Ident(pi) = &*pat_ty.pat {
                    Some(pi.ident.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    // 7) Build a wrapper (same signature) that calls the obfuscated function
    let wrapper = quote! {
        #[allow(non_snake_case)]
        #original_sig {
            #new_name( #( #original_arg_idents ),* )
        }
    };

    // 8) Emit both: (a) the obfuscated function `#f` and (b) the wrapper
    TokenStream::from(quote! {
        #f
        #wrapper
    })
}

/// Generates a random snake_case identifier of exactly `len` characters total.
/// It picks between 1 and 3 “words,” each of random length, summing to `len`.
/// All random numbers come from `rng: &mut impl Rng` as `u32`, then reduced into `usize`.
fn random_ident(len: usize, rng: &mut impl Rng) -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

    // 1) Decide how many “words” (1..=3)
    let words_u32: u32 = rng.random::<u32>();
    let words = ((words_u32 % 3) + 1) as usize; // yields 1, 2, or 3

    let mut remaining = len;
    let mut parts = Vec::with_capacity(words);

    for i in 0..words {
        let word_len: usize;
        if i + 1 == words {
            // Last word takes all remaining characters
            word_len = remaining;
        } else {
            // Choose a length between 1..=(remaining - (words - i - 1))
            let max_possible = remaining - (words - i - 1);
            let random_u32: u32 = rng.random::<u32>();
            let chosen = (random_u32 % (max_possible as u32)) as usize;
            word_len = if chosen == 0 { 1 } else { chosen };
        }
        remaining -= word_len;

        // Build a random string of `word_len` letters:
        let mut part = String::with_capacity(word_len);
        for _ in 0..word_len {
            let idx_u32: u32 = rng.random::<u32>();
            let idx = (idx_u32 % (LETTERS.len() as u32)) as usize;
            part.push(LETTERS[idx] as char);
        }
        parts.push(part);
    }

    // Join with underscores, e.g. "abc_def_gh"
    parts.join("_")
}
