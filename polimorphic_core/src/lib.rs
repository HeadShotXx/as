use std::collections::HashMap;
use thiserror::Error;

const BASE36_ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    Base32,
    Base36,
    Base64,
    Base85,
    Base91,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("decoding error: {0}")]
    Decode(String),
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

type Decoder = fn(&str) -> Result<Vec<u8>, Error>;

lazy_static::lazy_static! {
    static ref DECODERS: HashMap<Encoding, Decoder> = {
        let mut m: HashMap<Encoding, Decoder> = HashMap::new();
        m.insert(Encoding::Base32, |s: &str| base32::decode(base32::Alphabet::RFC4648 { padding: true }, s).ok_or_else(|| Error::Decode("base32 decoding failed".to_string())));
        m.insert(Encoding::Base36, |s: &str| base_x::decode(BASE36_ALPHABET, s).map_err(|e| Error::Decode(e.to_string())));
        m.insert(Encoding::Base64, |s: &str| { use base64::Engine as _; base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| Error::Decode(e.to_string())) });
        m.insert(Encoding::Base85, |s: &str| base85::decode(s).ok_or_else(|| Error::Decode("base85 decoding failed".to_string())));
        m.insert(Encoding::Base91, |s: &str| Ok(base91::slice_decode(s.as_bytes())));
        m
    };
}

pub fn decode_and_decrypt(encrypted: &[u8], key: &[u8], encodings: &[Encoding]) -> Result<String, Error> {
    let mut decrypted_bytes = vec![0u8; encrypted.len()];
    for i in 0..encrypted.len() {
        decrypted_bytes[i] = encrypted[i] ^ key[i];
    }

    let mut current_bytes = decrypted_bytes;
    for encoding in encodings {
        let s = String::from_utf8(current_bytes)?;
        current_bytes = DECODERS[encoding](&s)?;
    }

    Ok(String::from_utf8(current_bytes)?)
}
