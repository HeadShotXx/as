use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use rand::Rng;

pub fn generate_storage_setup(rng: &mut impl Rng) -> TokenStream2 {
    match rng.gen_range(0..2) {
        0 => quote! {
            // Objective 3: Byte vector representation
            #[derive(Clone)]
            struct Storage(Vec<u8>);
            impl Storage {
                fn new() -> Self { Self(Vec::new()) }
                fn with_capacity(c: usize) -> Self { Self(Vec::with_capacity(c)) }
                fn push(&mut self, b: u8) { self.0.push(b); }
                fn len(&self) -> usize { self.0.len() }
                fn is_empty(&self) -> bool { self.0.is_empty() }
                fn clear(&mut self) { self.0.clear(); }
                fn get(&self, i: usize) -> u8 { self.0[i] }
                fn set(&mut self, i: usize, v: u8) { self.0[i] = v; }
                fn iter(&self) -> impl Iterator<Item = u8> + '_ { self.0.iter().copied() }
                fn extend_from_slice(&mut self, s: &[u8]) { self.0.extend_from_slice(s); }
                fn from_vec(v: Vec<u8>) -> Self { Self(v) }
                fn to_vec(&self) -> Vec<u8> { self.0.clone() }
                fn chunks(&self, size: usize) -> Vec<Vec<u8>> {
                    self.0.chunks(size).map(|c| c.to_vec()).collect()
                }
            }
        },
        _ => quote! {
            // Objective 3: Chunked word representation
            #[derive(Clone)]
            struct Storage {
                inner: Vec<u32>,
                len: usize,
            }
            impl Storage {
                fn new() -> Self { Self { inner: Vec::new(), len: 0 } }
                fn with_capacity(c: usize) -> Self { Self { inner: Vec::with_capacity((c + 3) / 4), len: 0 } }
                fn push(&mut self, b: u8) {
                    let w_idx = self.len / 4;
                    let b_idx = self.len % 4;
                    if b_idx == 0 { self.inner.push(0); }
                    self.inner[w_idx] |= (b as u32) << (b_idx * 8);
                    self.len += 1;
                }
                fn len(&self) -> usize { self.len }
                fn is_empty(&self) -> bool { self.len == 0 }
                fn clear(&mut self) { self.inner.clear(); self.len = 0; }
                fn get(&self, i: usize) -> u8 {
                    let word = self.inner[i / 4];
                    ((word >> ((i % 4) * 8)) & 0xff) as u8
                }
                fn set(&mut self, i: usize, v: u8) {
                    let w_idx = i / 4;
                    let b_idx = i % 4;
                    let mut word = self.inner[w_idx];
                    word &= !(0xff << (b_idx * 8));
                    word |= (v as u32) << (b_idx * 8);
                    self.inner[w_idx] = word;
                }
                fn iter(&self) -> impl Iterator<Item = u8> + '_ {
                    (0..self.len).map(move |i| self.get(i))
                }
                fn extend_from_slice(&mut self, s: &[u8]) {
                    for &b in s { self.push(b); }
                }
                fn from_vec(v: Vec<u8>) -> Self {
                    let mut s = Self::with_capacity(v.len());
                    s.extend_from_slice(&v);
                    s
                }
                fn to_vec(&self) -> Vec<u8> {
                    self.iter().collect()
                }
                fn chunks(&self, size: usize) -> Vec<Vec<u8>> {
                    let v = self.to_vec();
                    v.chunks(size).map(|c| c.to_vec()).collect()
                }
            }
        }
    }
}
