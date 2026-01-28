
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::{Rng, thread_rng, seq::SliceRandom};
use proc_macro2::{TokenStream as TokenStream2, Ident, Span, Literal};

#[derive(Clone, Debug)]
enum Primitive {
    Map(Vec<u8>),
    BitUnpack(u32),
    BaseUnpack { base: u128, in_c: usize, out_c: usize },
    BigInt(u128),
}

struct Pipeline {
    encoder: Box<dyn Fn(&[u8]) -> Vec<u8>>,
    steps: Vec<Primitive>,
}

// --- BITSTREAM HELPERS (Used by encoders at compile time) ---

fn encode_bits(data: &[u8], bits: u32, alphabet: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u128;
    let mut count = 0u32;
    for &b in data {
        acc = (acc << 8) | (b as u128);
        count += 8;
        while count >= bits {
            count -= bits;
            let idx = (acc >> count) & ((1 << bits) - 1);
            out.push(alphabet[idx as usize]);
            acc &= (1 << count) - 1;
        }
    }
    if count > 0 {
        let idx = (acc << (bits - count)) & ((1 << bits) - 1);
        out.push(alphabet[idx as usize]);
    }
    out
}

// --- BIGINT HELPERS (Used by encoders at compile time) ---

fn encode_bigint(data: &[u8], base: u128, alphabet: &[u8]) -> Vec<u8> {
    let mut leading_zeros = 0;
    for &b in data { if b == 0 { leading_zeros += 1; } else { break; } }
    let mut res = Vec::new();
    let mut bytes = data[leading_zeros..].to_vec();
    while !bytes.iter().all(|&b| b == 0) {
        let mut remainder = 0u64;
        for b in bytes.iter_mut() {
            let val = *b as u64 + (remainder * 256);
            *b = (val / base as u64) as u8;
            remainder = val % base as u64;
        }
        res.push(alphabet[remainder as usize]);
    }
    for _ in 0..leading_zeros {
        res.push(alphabet[0]);
    }
    res.reverse();
    res
}

// --- Z85 HELPERS (Used by encoders at compile time) ---

fn encode_z85_custom(data: &[u8], alphabet: &[u8]) -> Vec<u8> {
    let mut d = data.to_vec();
    let mut padding = 0;
    while d.len() % 4 != 0 {
        d.push(0);
        padding += 1;
    }
    let mut out = Vec::new();
    for chunk in d.chunks(4) {
        let mut val = 0u64;
        for &b in chunk { val = (val << 8) | b as u64; }
        let mut res = Vec::new();
        for _ in 0..5 {
            res.push(alphabet[(val % 85) as usize]);
            val /= 85;
        }
        res.reverse();
        out.extend(res);
    }
    out.push(alphabet[padding]);
    out
}

fn get_pipelines() -> Vec<Pipeline> {
    let b64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes().to_vec();
    let b32_alpha = "abcdefghijklmnopqrstuvwxyz234567".as_bytes().to_vec();
    let b36_alpha = "0123456789abcdefghijklmnopqrstuvwxyz".as_bytes().to_vec();
    let z85_alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#".as_bytes().to_vec();

    let mut b91_alpha = Vec::new();
    for i in 33..127u8 {
        if i == b'\"' || i == b'\'' || i == b'\\' { continue; }
        b91_alpha.push(i);
    }

    let b32 = || {
        let alpha = b32_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| encode_bits(data, 5, &alpha)),
            steps: vec![Primitive::Map(b32_alpha.clone()), Primitive::BitUnpack(5)],
        }
    };
    let b36 = || {
        let alpha = b36_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| encode_bigint(data, 36, &alpha)),
            steps: vec![Primitive::Map(b36_alpha.clone()), Primitive::BigInt(36)],
        }
    };
    let b64 = || {
        let alpha = b64_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| encode_bits(data, 6, &alpha)),
            steps: vec![Primitive::Map(b64_alpha.clone()), Primitive::BitUnpack(6)],
        }
    };
    let z85 = || {
        let alpha = z85_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| encode_z85_custom(data, &alpha)),
            steps: vec![Primitive::Map(z85_alpha.clone()), Primitive::BaseUnpack { base: 85, in_c: 5, out_c: 4 }],
        }
    };
    let b91 = || {
        let alpha = b91_alpha.clone();
        let alpha2 = b91_alpha.clone();
        Pipeline {
            encoder: Box::new(move |data| encode_bigint(data, 91, &alpha)),
            steps: vec![Primitive::Map(alpha2), Primitive::BigInt(91)],
        }
    };

    vec![b32(), b36(), b64(), z85(), b91()]
}

// --- GENERATORS ---

fn generate_obfuscated_map(alphabet: &[u8], rng: &mut impl Rng) -> TokenStream2 {
    let mut map = vec![255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { map[c as usize] = i as u8; }
    let map_lit = Literal::byte_string(&map);
    let t_n = Ident::new(&format!("t_{}", rng.gen::<u32>()), Span::call_site());
    quote! {
        {
            let #t_n: &[u8; 256] = #map_lit;
            let mut out = Vec::with_capacity(data.len());
            for &b in &data {
                let v = #t_n[b as usize];
                if v != 255 { out.push(v); }
            }
            out
        }
    }
}

fn generate_obfuscated_bit_unpack(bits: u32, rng: &mut impl Rng) -> TokenStream2 {
    let a_n = Ident::new(&format!("a_{}", rng.gen::<u32>()), Span::call_site());
    let c_n = Ident::new(&format!("c_{}", rng.gen::<u32>()), Span::call_site());
    quote! {
        {
            let mut out = Vec::new();
            let mut #a_n = 0u128;
            let mut #c_n = 0u32;
            for &v in &data {
                #a_n = (#a_n << #bits) | (v as u128);
                #c_n += #bits;
                while #c_n >= 8 {
                    #c_n -= 8;
                    out.push((#a_n >> #c_n) as u8);
                    #a_n &= (1 << #c_n) - 1;
                }
            }
            out
        }
    }
}

fn generate_obfuscated_base_unpack(base: u128, in_c: usize, out_c: usize, rng: &mut impl Rng) -> TokenStream2 {
    let v_n = Ident::new(&format!("v_{}", rng.gen::<u32>()), Span::call_site());
    quote! {
        {
            if data.is_empty() { Vec::new() }
            else {
                let padding = data[data.len() - 1] as usize;
                let main_data = &data[..data.len() - 1];
                let mut out = Vec::new();
                for chunk in main_data.chunks(#in_c) {
                    if chunk.len() < #in_c { continue; }
                    let mut #v_n = 0u128;
                    for &c in chunk {
                        #v_n = #v_n * #base + (c as u128);
                    }
                    for i in (0..#out_c).rev() {
                        out.push(((#v_n >> (i * 8)) & 0xff) as u8);
                    }
                }
                if out.len() >= padding {
                    out.truncate(out.len() - padding);
                }
                out
            }
        }
    }
}

fn generate_obfuscated_bigint_unpack(base: u128, rng: &mut impl Rng) -> TokenStream2 {
    let r_n = Ident::new(&format!("r_{}", rng.gen::<u32>()), Span::call_site());
    let c_n = Ident::new(&format!("c_{}", rng.gen::<u32>()), Span::call_site());
    let d_n = Ident::new(&format!("d_{}", rng.gen::<u32>()), Span::call_site());
    let l_n = Ident::new(&format!("l_{}", rng.gen::<u32>()), Span::call_site());
    quote! {
        {
            let mut #l_n = 0;
            for &v in &data { if v == 0 { #l_n += 1; } else { break; } }
            let mut #r_n = vec![0u32];
            for &v in &data[#l_n..] {
                let mut #c_n = v as u64;
                for #d_n in #r_n.iter_mut() {
                    let prod = (*#d_n as u64) * (#base as u64) + #c_n;
                    *#d_n = prod as u32;
                    #c_n = prod >> 32;
                }
                while #c_n > 0 {
                    #r_n.push(#c_n as u32);
                    #c_n >>= 32;
                }
            }
            let mut out = vec![0u8; #l_n];
            if !(#r_n.len() == 1 && #r_n[0] == 0) || data.len() == #l_n {
                let mut bytes_out = Vec::new();
                let rl = #r_n.len();
                for (idx, &val) in #r_n.iter().enumerate().rev() {
                    let bytes = val.to_be_bytes();
                    if idx == rl - 1 {
                         let mut skip = 0;
                         while skip < 4 && bytes[skip] == 0 { skip += 1; }
                         bytes_out.extend_from_slice(&bytes[skip..]);
                    } else { bytes_out.extend_from_slice(&bytes); }
                }
                if bytes_out.is_empty() && data.len() > #l_n { bytes_out.push(0); }
                out.extend(bytes_out);
            }
            out
        }
    }
}

fn generate_pipeline_code(pipeline: &Pipeline, rng: &mut impl Rng) -> TokenStream2 {
    let mut code = quote! { let mut data = data; };
    for step in &pipeline.steps {
        let step_code = match step {
            Primitive::Map(table) => generate_obfuscated_map(table, rng),
            Primitive::BitUnpack(bits) => generate_obfuscated_bit_unpack(*bits, rng),
            Primitive::BaseUnpack { base, in_c, out_c } => generate_obfuscated_base_unpack(*base, *in_c, *out_c, rng),
            Primitive::BigInt(base) => generate_obfuscated_bigint_unpack(*base, rng),
        };
        code = quote! { #code data = #step_code; };
    }
    quote! { { #code data } }
}

fn generate_junk_logic(rng: &mut impl Rng, real_var: Option<&Ident>) -> TokenStream2 {
    let j_v = Ident::new(&format!("j_{}", rng.gen::<u32>()), Span::call_site());
    let j_val = rng.gen::<u32>();
    let base_junk = match rng.gen_range(0..3) {
        0 => quote! { let mut #j_v = #j_val; if #j_v % 2 == 0 { #j_v += 1; } else { #j_v -= 1; } },
        1 => quote! { let mut #j_v = #j_val; for i in 0..3 { #j_v = #j_v.wrapping_add(i); } },
        _ => quote! { let #j_v = #j_val; let _ = #j_v ^ 0x55; },
    };
    if let Some(rv) = real_var {
        if rng.gen_bool(0.5) {
            let magic = rng.gen::<u32>();
            quote! {
                #base_junk
                if #j_v == #magic { #rv.push(0); }
            }
        } else {
            base_junk
        }
    } else {
        base_junk
    }
}

fn generate_obfuscated_decrypt(input_expr: TokenStream2, output_var: &Ident, rng: &mut impl Rng, variant: u32) -> TokenStream2 {
    let k_n = Ident::new(&format!("k_{}", rng.gen::<u32>()), Span::call_site());
    let b_n = Ident::new(&format!("b_{}", rng.gen::<u32>()), Span::call_site());
    let br_n = Ident::new(&format!("br_{}", rng.gen::<u32>()), Span::call_site());
    let u_l = match variant {
        0 => quote! { #k_n = #k_n.wrapping_add(#b_n); },
        1 => quote! { #k_n = #k_n.wrapping_sub(#b_n); },
        _ => quote! { #k_n = #k_n.rotate_left(3); },
    };
    let junk = generate_junk_logic(rng, Some(output_var));
    match rng.gen_range(0..3) {
        0 => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Vec::with_capacity(#input_expr.len());
            for byte in #input_expr.iter() {
                let #b_n = *byte;
                #output_var.push(#b_n ^ #k_n);
                #u_l
                #junk
            }
        },
        1 => quote! {
            let mut #k_n = self.key;
            let mut #output_var = Vec::new();
            let mut i = 0;
            while i < #input_expr.len() {
                let #b_n = #input_expr[i];
                #output_var.push(#b_n ^ #k_n);
                #u_l
                #junk
                i += 1;
            }
        },
        _ => quote! {
            let mut #k_n = self.key;
            let mut #output_var: Vec<u8> = #input_expr.iter().map(|#br_n| {
                let #b_n = *#br_n;
                let db = #b_n ^ #k_n;
                #u_l
                db
            }).collect();
            #junk
        },
    }
}

fn generate_final_assembly(bytes_var: &Ident, rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..3) {
        0 => quote! { String::from_utf8(#bytes_var.to_vec()).expect("F") },
        1 => quote! { #bytes_var.iter().map(|b| *b as char).collect::<String>() },
        _ => quote! { { let mut s = String::new(); for b in #bytes_var.iter() { s.push(*b as char); } s } }
    }
}

fn generate_polymorphic_decode_chain(
    transform_ids: &[u32],
    initial_input_var: &Ident,
    dispatch_name: &Ident,
    rng: &mut impl Rng,
) -> TokenStream2 {
    match rng.gen_range(0..3) {
        0 => { // State machine
            let mut arms = Vec::new();
            let s_n = Ident::new("s", Span::call_site());
            let m_n = Ident::new("m", Span::call_site());
            for (i, &id) in transform_ids.iter().enumerate() {
                let nb_n = Ident::new(&format!("b_{}", i), Span::call_site());
                let junk = generate_junk_logic(rng, Some(&m_n));
                if i < transform_ids.len() - 1 {
                    arms.push(quote! {
                        #i => {
                            let #nb_n = #dispatch_name(#id, &#m_n);
                            #m_n = #nb_n;
                            #s_n += 1;
                            #junk
                        }
                    });
                } else {
                    let fb_n = Ident::new("fb", Span::call_site());
                    let fa = generate_final_assembly(&fb_n, rng);
                    arms.push(quote! {
                        #i => {
                            let #fb_n = #dispatch_name(#id, &#m_n);
                            let fv = #fa;
                            break fv;
                        }
                    });
                }
            }
            arms.push(quote! { _ => break String::new(), });
            quote! {
                let mut #s_n = 0;
                let mut #m_n = #initial_input_var.clone();
                loop { match #s_n { #(#arms)* } }
            }
        },
        1 => { // Nested blocks
            if transform_ids.is_empty() { return quote! { String::new() }; }
            let last_idx = transform_ids.len() - 1;
            let last_id = transform_ids[last_idx];
            let last_input = Ident::new(&format!("nd_{}", last_idx), Span::call_site());
            let last_bytes = Ident::new("lb", Span::call_site());
            let fa = generate_final_assembly(&last_bytes, rng);
            let mut nl = quote! { { let #last_bytes = #dispatch_name(#last_id, &#last_input); #fa } };
            for i in (0..last_idx).rev() {
                let id = transform_ids[i];
                let ci = Ident::new(&format!("nd_{}", i), Span::call_site());
                let ni = Ident::new(&format!("nd_{}", i + 1), Span::call_site());
                let ob = Ident::new(&format!("nb_{}", i), Span::call_site());
                let junk = generate_junk_logic(rng, Some(&ci));
                nl = quote! { { let #ob = #dispatch_name(#id, &#ci); #junk let mut #ni = #ob; #nl } };
            }
            let fv = Ident::new("nd_0", Span::call_site());
            quote! { { let mut #fv = #initial_input_var.clone(); #nl } }
        },
        _ => { // Linear
            let mut st = Vec::new();
            let cv = Ident::new("cv", Span::call_site());
            st.push(quote! { let mut #cv = #initial_input_var.clone(); });
            for (i, &id) in transform_ids.iter().enumerate() {
                let nb = Ident::new(&format!("b_{}", i), Span::call_site());
                st.push(quote! { let #nb = #dispatch_name(#id, &#cv); });
                let junk = generate_junk_logic(rng, Some(&cv));
                st.push(quote! { #junk });
                if i < transform_ids.len() - 1 {
                    st.push(quote! { #cv = #nb; });
                } else {
                     let fvb = Ident::new("fv", Span::call_site());
                     st.push(quote! { let mut #fvb = #nb; });
                     let fa = generate_final_assembly(&fvb, rng);
                     st.push(quote! { let frs = #fa; });
                }
            }
            quote! { { #(#st)* frs } }
        }
    }
}

#[proc_macro]
pub fn str_obf(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as LitStr);
    let os = lit_str.value();
    let mut rng = thread_rng();
    let pl = get_pipelines();
    let num_layers = rng.gen_range(3..=7);
    let mut sel = Vec::new();
    let mut cd = os.clone().into_bytes();
    for _ in 0..num_layers {
        let idx = rng.gen_range(0..pl.len());
        sel.push(idx);
        cd = (pl[idx].encoder)(&cd);
    }
    sel.reverse();
    let xk = rng.gen::<u8>();
    let ev = rng.gen_range(0..3u32);
    let mut key = xk;
    let mut eb = Vec::with_capacity(cd.len());
    for &ob in &cd {
        let eb_b = ob ^ key;
        eb.push(eb_b);
        match ev {
            0 => key = key.wrapping_add(eb_b),
            1 => key = key.wrapping_sub(eb_b),
            _ => key = key.rotate_left(3),
        };
    }
    let mut vt_c = Vec::new();
    let mut rids = Vec::new();
    let salt = rng.gen::<u32>();
    let mult = rng.gen::<u32>() | 1;
    let ts = 32;
    let mut p2vt = vec![vec![]; pl.len()];
    for i in 0..ts {
        let p_idx = i % pl.len();
        p2vt[p_idx].push(i);
        vt_c.push(generate_pipeline_code(&pl[p_idx], &mut rng));
    }
    for &idx in &sel {
        let vi = *p2vt[idx].choose(&mut rng).expect("V");
        rids.push( (vi as u32).wrapping_mul(mult) ^ salt );
    }
    let t_ids: Vec<u32> = (0..ts).map(|i| (i as u32).wrapping_mul(mult) ^ salt).collect();
    let s_n = Ident::new(&format!("O_{}", rng.gen::<u32>()), Span::call_site());
    let m_n = Ident::new(&format!("r_{}", rng.gen::<u32>()), Span::call_site());
    let d_n = Ident::new(&format!("d_{}", rng.gen::<u32>()), Span::call_site());
    let i_v = Ident::new("ds", Span::call_site());
    let dc = generate_polymorphic_decode_chain(&rids, &i_v, &d_n, &mut rng);
    let (df, di, rl) = match rng.gen_range(0..3) {
        0 => {
            let dl = Literal::byte_string(&eb);
            (quote! { d: &'a [u8], }, quote! { d: #dl, }, quote! { let rd = self.d.to_vec(); })
        },
        1 => {
            let even: Vec<u8> = eb.iter().step_by(2).cloned().collect();
            let odd: Vec<u8> = eb.iter().skip(1).step_by(2).cloned().collect();
            let el = Literal::byte_string(&even);
            let ol = Literal::byte_string(&odd);
            (quote! { e: &'a [u8], o: &'a [u8], }, quote! { e: #el, o: #ol, },
             quote! {
                let mut rd = Vec::new();
                let mut ei = self.e.iter();
                let mut oi = self.o.iter();
                loop {
                    match (ei.next(), oi.next()) {
                        (Some(ev), Some(ov)) => { rd.push(*ev); rd.push(*ov); },
                        (Some(ev), None) => { rd.push(*ev); break; },
                        _ => break,
                    }
                }
             })
        },
        _ => {
            let ji: Vec<u8> = eb.iter().flat_map(|&b| vec![b, rng.gen()]).collect();
            let dl = Literal::byte_string(&ji);
            (quote! { j: &'a [u8], }, quote! { j: #dl, }, quote! { let rd: Vec<u8> = self.j.iter().step_by(2).cloned().collect(); })
        }
    };
    let d_b_i = Ident::new("db", Span::call_site());
    let dl_c = generate_obfuscated_decrypt(quote! { rd }, &d_b_i, &mut rng, ev);
    let expanded = quote! {{
        struct #s_n<'a> { #df key: u8, }
        impl<'a> #s_n<'a> {
            fn #m_n(&self) -> String {
                let #d_n = |id: u32, data: &[u8]| -> Vec<u8> {
                    match id {
                        #(#t_ids => { let mut data = data.to_vec(); #vt_c },)*
                        _ => data.to_vec()
                    }
                };
                let mut #d_b_i = { #rl #dl_c db };
                let mut #i_v = #d_b_i;
                #dc
            }
        }
        let instance = #s_n { #di key: #xk, };
        instance.#m_n()
    }};
    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_bits_manual(data: &[u8], bits: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc = 0u128;
        let mut count = 0u32;
        for &v in data {
            acc = (acc << bits) | (v as u128);
            count += bits;
            while count >= 8 {
                count -= 8;
                out.push((acc >> count) as u8);
                acc &= (1 << count) - 1;
            }
        }
        out
    }

    fn decode_bigint_manual(data: &[u8], base: u128) -> Vec<u8> {
        let mut leading_zeros = 0;
        for &v in data { if v == 0 { leading_zeros += 1; } else { break; } }
        let mut res = vec![0u32];
        for &v in &data[leading_zeros..] {
            let mut carry = v as u64;
            for digit in res.iter_mut() {
                let prod = (*digit as u64) * (base as u64) + carry;
                *digit = prod as u32;
                carry = prod >> 32;
            }
            while carry > 0 {
                res.push(carry as u32);
                carry >>= 32;
            }
        }
        let mut out = vec![0u8; leading_zeros];
        if !(res.len() == 1 && res[0] == 0) || data.len() == leading_zeros {
            let mut bytes_out = Vec::new();
            let rl = res.len();
            for (idx, &val) in res.iter().enumerate().rev() {
                let bytes = val.to_be_bytes();
                if idx == rl - 1 {
                     let mut skip = 0;
                     while skip < 4 && bytes[skip] == 0 { skip += 1; }
                     bytes_out.extend_from_slice(&bytes[skip..]);
                } else {
                    bytes_out.extend_from_slice(&bytes);
                }
            }
            if bytes_out.is_empty() && data.len() > leading_zeros {
                bytes_out.push(0);
            }
            out.extend(bytes_out);
        }
        out
    }

    fn decode_z85_manual(data: &[u8], base: u128, in_c: usize, out_c: usize) -> Vec<u8> {
        if data.is_empty() { return Vec::new(); }
        let padding = data[data.len() - 1] as usize;
        let main_data = &data[..data.len() - 1];
        let mut out = Vec::new();
        for chunk in main_data.chunks(in_c) {
            if chunk.len() < in_c { continue; }
            let mut val = 0u128;
            for &c in chunk {
                val = val * base + (c as u128);
            }
            for i in (0..out_c).rev() {
                out.push(((val >> (i * 8)) & 0xff) as u8);
            }
        }
        if out.len() >= padding {
            out.truncate(out.len() - padding);
        }
        out
    }

    #[test]
    fn test_random_pipelines() {
        let mut rng = thread_rng();
        let originals = vec![
            b"Simple Calculator".to_vec(),
            vec![0, 0, 1, 2, 3],
            vec![1, 2, 3, 0, 0],
            vec![0, 1, 0, 2, 0],
            b"A".to_vec(),
            b"".to_vec(),
        ];
        let pl = get_pipelines();
        for original in originals {
            for _ in 0..100 {
                let num_layers = rng.gen_range(1..=5);
                let mut layers = Vec::new();
                let mut data = original.clone();
                for _ in 0..num_layers {
                    let idx = rng.gen_range(0..pl.len());
                    layers.push(idx);
                    data = (pl[idx].encoder)(&data);
                }
                layers.reverse();
                let mut b_data = data;
                for &idx in &layers {
                    for step in &pl[idx].steps {
                        b_data = match step {
                            Primitive::Map(alphabet) => {
                                let mut map = [255u8; 256];
                                for (j, &c) in alphabet.iter().enumerate() { map[c as usize] = j as u8; }
                                let mut out = Vec::new();
                                for &b in &b_data { let v = map[b as usize]; if v != 255 { out.push(v); } }
                                out
                            },
                            Primitive::BitUnpack(bits) => decode_bits_manual(&b_data, *bits),
                            Primitive::BaseUnpack { base, in_c, out_c } => decode_z85_manual(&b_data, *base, *in_c, *out_c),
                            Primitive::BigInt(base) => decode_bigint_manual(&b_data, *base),
                        };
                    }
                }
                assert_eq!(b_data, original);
            }
        }
    }
}
