use super::error::{Error, Result};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    OsRng.fill_bytes(&mut b);
    b
}
pub fn token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(32))
}
pub fn valid_token(t: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(t)
        .is_ok_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == t)
}
pub fn hash(t: &str) -> Vec<u8> {
    Sha256::digest(t.as_bytes()).to_vec()
}
pub fn csrf(t: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(t.as_bytes()).expect("HMAC accepts any key");
    mac.update(b"foltivo/session/csrf/v1");
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}
#[derive(Clone)]
pub struct Secrets(Aes256Gcm);
impl Secrets {
    pub fn new(encoded: &str) -> Result<Self> {
        let key = STANDARD.decode(encoded).map_err(|_| {
            Error::validation("AUTH_ENCRYPTION_KEY must encode exactly 32 random bytes.")
        })?;
        Ok(Self(Aes256Gcm::new_from_slice(&key).map_err(|_| {
            Error::validation("AUTH_ENCRYPTION_KEY must encode exactly 32 random bytes.")
        })?))
    }
    pub fn seal(&self, data: &[u8], purpose: &str) -> Result<Vec<u8>> {
        let mut nonce = random_bytes(12);
        let encrypted = self
            .0
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: data,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| Error::unavailable())?;
        nonce.extend(encrypted);
        Ok(nonce)
    }
    pub fn open(&self, data: &[u8], purpose: &str) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(Error::unavailable());
        }
        self.0
            .decrypt(
                Nonce::from_slice(&data[..12]),
                Payload {
                    msg: &data[12..],
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| Error::unavailable())
    }
}
#[derive(Clone)]
pub struct Passwords {
    slots: Arc<Semaphore>,
    dummy: Arc<String>,
}
fn argon() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 4, Some(32)).expect("fixed Argon2 parameters"),
    )
}
impl Passwords {
    pub async fn new() -> Result<Self> {
        let dummy = tokio::task::spawn_blocking(|| {
            argon()
                .hash_password(
                    b"unknown account dummy password",
                    &SaltString::generate(&mut OsRng),
                )
                .map(|h| h.to_string())
                .map_err(|_| Error::unavailable())
        })
        .await
        .map_err(|_| Error::unavailable())??;
        Ok(Self {
            slots: Arc::new(Semaphore::new(2)),
            dummy: Arc::new(dummy),
        })
    }
    pub async fn password_hash(&self, password: &str) -> Result<String> {
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| busy())?;
        let password = password.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            argon()
                .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                .map(|h| h.to_string())
                .map_err(|_| Error::unavailable())
        })
        .await
        .map_err(|_| Error::unavailable())?
    }
    pub async fn compare(&self, password: &str, encoded: &str) -> Result<bool> {
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| busy())?;
        let password = password.to_owned();
        let encoded = if encoded.is_empty() {
            self.dummy.to_string()
        } else {
            encoded.to_owned()
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let parsed = PasswordHash::new(&encoded).map_err(|_| Error::unavailable())?;
            match argon().verify_password(password.as_bytes(), &parsed) {
                Ok(()) => Ok(true),
                Err(argon2::password_hash::Error::Password) => Ok(false),
                Err(_) => Err(Error::unavailable()),
            }
        })
        .await
        .map_err(|_| Error::unavailable())?
    }
}
fn busy() -> Error {
    let mut e = Error::new(503, "busy", "Authentication is busy. Try again shortly.");
    e.retry_after = 2;
    e
}
pub fn email(v: &str) -> Result<String> {
    let v = v.trim().to_lowercase();
    if v.len() > 254
        || v.contains(['\r', '\n', ' '])
        || !v.contains('.')
        || !email_address::EmailAddress::is_valid(&v)
    {
        return Err(Error::validation("Enter a valid email address."));
    }
    Ok(v)
}
pub fn name(v: &str) -> Result<String> {
    let v = v.trim();
    if !(1..=100).contains(&v.chars().count()) {
        return Err(Error::validation(
            "Name must contain between 1 and 100 characters.",
        ));
    }
    if v.chars().any(char::is_control) {
        return Err(Error::validation("Name cannot contain control characters."));
    }
    Ok(v.into())
}
pub fn password(v: &str) -> Result<()> {
    if !(15..=128).contains(&v.chars().count()) {
        return Err(Error::validation(
            "Password must contain between 15 and 128 characters.",
        ));
    }
    Ok(())
}
pub fn identifier(v: &str) -> bool {
    uuid::Uuid::parse_str(v).is_ok_and(|id| id.to_string() == v)
}
