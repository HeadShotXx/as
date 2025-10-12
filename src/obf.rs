// src/obf.rs
use zeroize::Zeroize;
use std::ops::Deref;

/// ASCII85 decode (expects format "....:len")
pub fn ascii85_decode(s: &str) -> Option<Vec<u8>> {
    let mut parts = s.rsplitn(2, ':');
    let len_part = parts.next()?;
    let enc_part = parts.next()?;
    let out_len: usize = len_part.parse().ok()?;
    let encoded = enc_part.as_bytes();

    // The encoded length must be a multiple of 5 characters
    if encoded.len() % 5 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(out_len);
    let mut i = 0;
    while i < encoded.len() {
        let mut v: u32 = 0;
        for k in 0..5 {
            let c = encoded[i + k];
            if c < 33 || c > 117 {
                return None; // Invalid character
            }
            v = v.checked_mul(85)?.checked_add(c as u32 - 33)?;
        }
        out.extend_from_slice(&v.to_be_bytes());
        i += 5;
    }

    out.truncate(out_len);
    Some(out)
}


/* ----------------------
   ObfString & ObfBytes
   wrappers that zeroize on Drop
   ---------------------- */

/// Secure wrapper around deobfuscated bytes interpreted as UTF-8 string.
/// - Holds Vec<u8> plaintext in memory while alive.
/// - Implements Deref<Target=str> so you can use it like &str.
/// - On Drop, inner buffer is zeroized automatically.
pub struct ObfString {
    inner: Vec<u8>,
}

impl ObfString {
    /// Construct from already decrypted bytes. This is used by the macro expansion.
    #[inline(always)]
    pub fn from_decrypted_bytes(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Consume wrapper and return the inner Vec<u8>.
    /// *This prevents automatic zeroize on Drop* (caller becomes responsible).
    pub fn into_vec(mut self) -> Vec<u8> {
        // take inner, prevent Drop from zeroizing taken data
        let v = std::mem::take(&mut self.inner);
        std::mem::forget(self);
        v
    }

    /// Consume wrapper and return a String (unsafely converting bytes to String).
    /// Caller becomes responsible for zeroing if desired.
    /// Note: this does not zeroize automatically.
    pub fn into_string(mut self) -> String {
        let v = std::mem::take(&mut self.inner);
        std::mem::forget(self);
        // we assume original bytes are valid UTF-8 since obfuscator originates from literals
        unsafe { String::from_utf8_unchecked(v) }
    }

    /// Borrow as &str
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.inner) }
    }

    /// Zeroizes and clears internal buffer immediately (optional)
    pub fn zeroize_now(&mut self) {
        self.inner.zeroize();
        self.inner.clear();
    }
}

impl Deref for ObfString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for ObfString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for ObfString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfString")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl Drop for ObfString {
    fn drop(&mut self) {
        // zeroize the inner buffer when wrapper is dropped
        self.inner.zeroize();
    }
}

/// Secure wrapper around deobfuscated bytes
pub struct ObfBytes {
    inner: Vec<u8>,
}

impl ObfBytes {
    /// Construct from already decrypted bytes.
    #[inline(always)]
    pub fn from_decrypted_bytes(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Borrow as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Consume and return Vec<u8> (prevents automatic zeroize).
    pub fn into_vec(mut self) -> Vec<u8> {
        let v = std::mem::take(&mut self.inner);
        std::mem::forget(self);
        v
    }

    /// Zeroize now (optional)
    pub fn zeroize_now(&mut self) {
        self.inner.zeroize();
        self.inner.clear();
    }
}

impl Drop for ObfBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl AsRef<[u8]> for ObfBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::fmt::Debug for ObfBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfBytes").field("len", &self.inner.len()).finish()
    }
}