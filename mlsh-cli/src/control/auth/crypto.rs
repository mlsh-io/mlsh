use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::RngCore;

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow!("invalid argon2 hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

const NONCE_LEN: usize = 12;

/// Encrypt with AES-256-GCM. Output is `nonce (12B) || ciphertext+tag`.
/// `key` must be 32 bytes.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = key_from_slice(key)?;
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("aes-gcm encrypt failed: {e}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(anyhow!("ciphertext too short"));
    }
    let key = key_from_slice(key)?;
    let cipher = Aes256Gcm::new(key);
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow!("aes-gcm decrypt failed: {e}"))
}

fn key_from_slice(key: &[u8]) -> Result<&Key<Aes256Gcm>> {
    if key.len() != 32 {
        return Err(anyhow!(
            "encryption key must be 32 bytes, got {}",
            key.len()
        ));
    }
    Ok(Key::<Aes256Gcm>::from_slice(key))
}

/// Load (or generate-and-persist) the 32-byte key used to wrap TOTP secrets at rest.
pub fn load_or_create_key(path: &std::path::Path) -> Result<[u8; 32]> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "key file {} has wrong length: {} (expected 32)",
                path.display(),
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_secret_file(path, &key)?;
    Ok(key)
}

#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut f, bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn aead_round_trip() {
        let key = [7u8; 32];
        let blob = encrypt(&key, b"totp-secret").unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), b"totp-secret");
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let mut blob = encrypt(&key, b"totp-secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(decrypt(&key, &blob).is_err());
    }
}
