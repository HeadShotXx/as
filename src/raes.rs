use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use sha1::Sha1;
use rsa::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose, Engine as _};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rand::Rng;

pub struct Raes;

impl Raes {
    pub fn rsadecrypt(veri: &[u8], xmlkey: &str, _keysize: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let priv_key = Self::rsa_from_xml(xmlkey)?;
        let padding = Oaep::new::<Sha1>();
        let decrypted = priv_key.decrypt(padding, veri)?;
        Ok(decrypted)
    }

    pub fn rsaencrypt(veri: &[u8], xmlkey: &str, _keysize: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pub_key = Self::rsa_pub_from_xml(xmlkey)?;
        let padding = Oaep::new::<Sha1>();
        let mut rng = OsRng;
        let encrypted = pub_key.encrypt(&mut rng, padding, veri)?;
        Ok(encrypted)
    }

    pub fn generaterandomkey(keysize: usize) -> Vec<u8> {
        let mut rndkey = vec![0u8; keysize];
        let mut rng = OsRng;
        for i in 0..keysize {
            loop {
                let mut b = [0u8; 1];
                rng.fill_bytes(&mut b);
                if b[0] != 0 {
                    rndkey[i] = b[0];
                    break;
                }
            }
        }
        rndkey
    }

    pub fn reversebarray(yazi: &[u8]) -> Vec<u8> {
        let mut ters = yazi.to_vec();
        ters.reverse();
        ters
    }

    pub fn reversestring(yazi: &str) -> String {
        yazi.chars().rev().collect()
    }

    pub fn getrandomstring(size: usize) -> String {
        let ascchr = "qwertyuiopasdfghjklzxcvbnm";
        let mut rndmstr = String::new();
        let mut rng = rand::thread_rng();
        for _ in 0..=size {
            let idx = rng.gen_range(0..ascchr.len());
            rndmstr.push(ascchr.chars().nth(idx).unwrap());
        }
        rndmstr
    }

    pub fn rsa_from_xml(xml: &str) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut modulus = None;
        let mut exponent = None;
        let mut p = None;
        let mut q = None;
        let mut dp = None;
        let mut dq = None;
        let mut inverse_q = None;
        let mut d = None;

        let mut buf = Vec::new();
        let mut current_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                }
                Ok(Event::Text(e)) => {
                    let val = String::from_utf8_lossy(e.as_ref());
                    let bytes = general_purpose::STANDARD.decode(val.trim().as_bytes())?;
                    let n = rsa::BigUint::from_bytes_be(&bytes);
                    match current_tag.as_str() {
                        "Modulus" => modulus = Some(n),
                        "Exponent" => exponent = Some(n),
                        "P" => p = Some(n),
                        "Q" => q = Some(n),
                        "DP" => dp = Some(n),
                        "DQ" => dq = Some(n),
                        "InverseQ" => inverse_q = Some(n),
                        "D" => d = Some(n),
                        _ => {}
                    }
                }
                Ok(Event::End(_)) => {
                    current_tag.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(Box::new(e)),
                _ => {}
            }
            buf.clear();
        }

        let n = modulus.ok_or("Missing Modulus")?;
        let e = exponent.ok_or("Missing Exponent")?;
        let p = p.ok_or("Missing P")?;
        let q = q.ok_or("Missing Q")?;
        let d = d.ok_or("Missing D")?;
        let _dp = dp.ok_or("Missing DP")?;
        let _dq = dq.ok_or("Missing DQ")?;
        let _inverse_q = inverse_q.ok_or("Missing InverseQ")?;

        let priv_key = RsaPrivateKey::from_components(n, e, d, vec![p, q])?;
        priv_key.validate()?;
        Ok(priv_key)
    }

    pub fn rsa_pub_from_xml(xml: &str) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut modulus = None;
        let mut exponent = None;

        let mut buf = Vec::new();
        let mut current_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                }
                Ok(Event::Text(e)) => {
                    let val = String::from_utf8_lossy(e.as_ref());
                    let bytes = general_purpose::STANDARD.decode(val.trim().as_bytes())?;
                    let n = rsa::BigUint::from_bytes_be(&bytes);
                    match current_tag.as_str() {
                        "Modulus" => modulus = Some(n),
                        "Exponent" => exponent = Some(n),
                        _ => {}
                    }
                }
                Ok(Event::End(_)) => {
                    current_tag.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(Box::new(e)),
                _ => {}
            }
            buf.clear();
        }

        let n = modulus.ok_or("Missing Modulus")?;
        let e = exponent.ok_or("Missing Exponent")?;

        let pub_key = RsaPublicKey::new(n, e)?;
        Ok(pub_key)
    }
}
