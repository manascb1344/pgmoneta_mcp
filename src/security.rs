// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::constant::{Encryption, MASTER_KEY_PATH};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::anyhow;
use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use cbc;
use hmac::Hmac;
use home::home_dir;
use pbkdf2::{pbkdf2, pbkdf2_hmac};
use rand::TryRngCore;
use scram::ScramClient;
use sha2::Sha256;
use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::{Zeroize, Zeroizing};

const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
const PBKDF2_ITERATIONS: u32 = 600_000;
const MAX_CIPHERTEXT_B64_LEN: usize = 1024 * 1024;

/// Handles cryptographic operations and secure communication.
///
/// This utility manages Base64 encoding/decoding, AES-256-GCM encryption/decryption
/// of stored credentials, master key lifecycle management, and SCRAM-SHA-256
/// authentication over the PostgreSQL wire protocol.
pub struct SecurityUtil {
    base64_engine: engine::GeneralPurpose,
}

impl SecurityUtil {
    /// Creates a new `SecurityUtil` with a standard Base64 engine.
    pub fn new() -> Self {
        Self {
            base64_engine: engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD),
        }
    }

    /// Encodes a byte slice into a Base64 string.
    pub fn base64_encode(&self, bytes: &[u8]) -> anyhow::Result<String> {
        Ok(self.base64_engine.encode(bytes))
    }

    /// Decodes a Base64 string back into a byte vector.
    pub fn base64_decode(&self, text: &str) -> anyhow::Result<Vec<u8>> {
        Ok(self.base64_engine.decode(text)?)
    }

    /// Loads the master key from the user's home directory (`~/.pgmoneta-mcp/master.key`).
    ///
    /// On Unix systems, this also ensures the key file has strict `0600` permissions.
    /// The returned key is wrapped in a `Zeroizing` container to ensure it is wiped
    /// from memory when dropped.
    pub fn load_master_key(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let home_path = home_dir().ok_or_else(|| anyhow!("Unable to find home path"))?;
        let key_path = home_path.join(MASTER_KEY_PATH);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path)?.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
            }
        }

        let key = fs::read_to_string(key_path)?;
        Ok(Zeroizing::new(self.base64_decode(key.trim())?))
    }

    /// Base64 encodes and writes a new master key to the user's home directory.
    ///
    /// On Unix systems, this ensures the file is created with secure `0600` permissions.
    pub fn write_master_key(&self, key: &str) -> anyhow::Result<()> {
        let home_path = home_dir().ok_or_else(|| anyhow!("Unable to find home path"))?;
        let key_path = home_path.join(MASTER_KEY_PATH);
        let key_encoded = self.base64_encode(key.as_bytes())?;
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)?;
            file.write_all(key_encoded.as_bytes())?;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            fs::write(key_path, &key_encoded)?;
            Ok(())
        }
    }

    /// Encrypts plaintext using AES-256-GCM and encodes the result (including nonce and salt) to Base64.
    pub fn encrypt_to_base64_string(
        &self,
        plain_text: &[u8],
        master_key: &[u8],
    ) -> anyhow::Result<String> {
        let (cipher_text, nonce_bytes, salt) = Self::encrypt_text_aes_gcm(plain_text, master_key)?;
        let mut bytes = Vec::new();
        // nonce + salt + cipher text
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend_from_slice(&salt);
        bytes.extend(cipher_text.iter());
        self.base64_encode(bytes.as_slice())
    }

    /// Decodes a Base64 string and decrypts the underlying AES-256-GCM ciphertext.
    pub fn decrypt_from_base64_string(
        &self,
        cipher_text: &str,
        master_key: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if cipher_text.len() > MAX_CIPHERTEXT_B64_LEN {
            return Err(anyhow!("Cipher text is too large"));
        }
        let cipher_text_bytes = self.base64_decode(cipher_text)?;
        if cipher_text_bytes.len() < SALT_LEN + NONCE_LEN {
            return Err(anyhow!("Not enough bytes to decrypt the text"));
        }
        let nonce: &[u8] = &cipher_text_bytes[..NONCE_LEN];
        let salt: &[u8] = &cipher_text_bytes[NONCE_LEN..NONCE_LEN + SALT_LEN];
        Self::decrypt_text_aes_gcm(
            &cipher_text_bytes[(NONCE_LEN + SALT_LEN)..],
            master_key,
            nonce,
            salt,
        )
    }

    /// Generate a random password of the specified length.
    /// Uses alphanumeric characters and common special characters.
    pub fn generate_password(&self, length: usize) -> anyhow::Result<String> {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                              abcdefghijklmnopqrstuvwxyz\
                              0123456789\
                              !@$%^&*()-_=+[{]}\\|:'\",<.>/?";

        let mut password = vec![0u8; length];
        let mut random_bytes = vec![0u8; length];

        rand::rngs::OsRng.try_fill_bytes(&mut random_bytes)?;

        for (i, byte) in random_bytes.iter().enumerate() {
            password[i] = CHARS[*byte as usize % CHARS.len()];
        }

        // Zero out random bytes for security
        random_bytes.zeroize();

        String::from_utf8(password)
            .map_err(|e| anyhow!("Generated password contains invalid UTF-8: {:?}", e))
    }
}

impl SecurityUtil {
    const KEY_USER: &'static str = "user";
    const KEY_DATABASE: &'static str = "database";
    const KEY_APP_NAME: &'static str = "application_name";
    const APP_PGMONETA: &'static str = "pgmoneta";
    const DB_ADMIN: &'static str = "admin";
    const MAGIC: i32 = 196608;
    const HEADER_OFFSET: usize = 9;

    const AUTH_OK: i32 = 0;
    const AUTH_SASL: i32 = 10;
    const AUTH_SASL_CONTINUE: i32 = 11;
    const AUTH_SASL_FINAL: i32 = 12;

    const MAX_PG_MESSAGE_LEN: usize = 64 * 1024;

    /// Reads a raw message frame from the PostgreSQL wire protocol stream.
    ///
    /// Extracts the 1-byte message type and the 4-byte length, then reads
    /// the corresponding payload payload.
    async fn read_message(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
        let msg_type = stream.read_u8().await?;

        let len = stream.read_u32().await? as usize;

        if !(4..=Self::MAX_PG_MESSAGE_LEN).contains(&len) {
            return Err(anyhow!("Invalid message length {}", len));
        }

        let mut payload = vec![0u8; len - 4];
        stream.read_exact(&mut payload).await?;

        let mut msg = Vec::with_capacity(1 + 4 + payload.len());
        msg.push(msg_type);
        msg.write_u32(len as u32).await?;
        msg.extend(&payload);
        Ok(msg)
    }

    /// Derives a 32-byte encryption key from the master key and salt using the `scrypt` KDF.
    fn derive_key(master_key: &[u8], salt: &[u8]) -> anyhow::Result<[u8; 32]> {
        let mut derived_key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(master_key, salt, PBKDF2_ITERATIONS, &mut derived_key)
            .map_err(|e| anyhow!("PBKDF2 failed: {:?}", e))?;
        Ok(derived_key)
    }

    /// Encrypts raw bytes using AES-256-GCM.
    ///
    /// AES-GCM (Galois/Counter Mode) is the recommended encryption method for native
    /// pgmoneta-mcp use cases. It provides both confidentiality and authentication,
    /// is more efficient, and is resistant to certain attacks that affect CBC mode.
    ///
    /// Automatically generates a secure random nonce and salt, derives the encryption key
    /// using PBKDF2, and returns the ciphertext alongside the generated nonce and salt.
    pub fn encrypt_text_aes_gcm(
        plaintext: &[u8],
        master_key: &[u8],
    ) -> anyhow::Result<(Vec<u8>, [u8; NONCE_LEN], [u8; SALT_LEN])> {
        // derive the key
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
        rand::rngs::OsRng.try_fill_bytes(&mut nonce_bytes)?;
        let mut derived_key_bytes = Self::derive_key(master_key, &salt)?;
        let derived_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key_bytes);

        let cipher = Aes256Gcm::new(derived_key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("AES encryption failed {:?}", e));

        derived_key_bytes.zeroize();

        Ok((ciphertext?, nonce_bytes, salt))
    }

    /// Decrypts AES-256-GCM ciphertext using the provided master key, nonce, and salt.
    ///
    /// This function decrypts data that was encrypted with `encrypt_text_aes_gcm`.
    /// AES-GCM provides authenticated encryption, ensuring both confidentiality
    /// and integrity of the data.
    pub fn decrypt_text_aes_gcm(
        ciphertext: &[u8],
        master_key: &[u8],
        nonce_bytes: &[u8],
        salt: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut derived_key_bytes = Self::derive_key(master_key, salt)?;
        let derived_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key_bytes);
        let cipher = Aes256Gcm::new(derived_key);

        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES decryption failed {:?}", e));
        derived_key_bytes.zeroize();

        plaintext
    }

    /// Connect to pgmoneta server using SCRAM-SHA-256 authentication.
    ///
    /// # Protocol Flow:
    /// 1. Sends the initial StartupMessage.
    /// 2. Receives an AuthenticationSASL response offering SCRAM-SHA-256.
    /// 3. Sends the SASLInitialResponse (`client_first`).
    /// 4. Receives the AuthenticationSASLContinue response (`server_first`).
    /// 5. Sends the SASLResponse (`client_final`).
    /// 6. Receives the AuthenticationSASLFinal response.
    /// 7. Awaits the final AuthenticationOk signal.
    pub async fn connect_to_server(
        host: &str,
        port: i32,
        username: &str,
        password: &str,
    ) -> anyhow::Result<TcpStream> {
        let scram = ScramClient::new(username, password, None);
        let address = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect(address).await?;

        let startup_msg = Self::create_startup_message(username).await?;
        stream.write_all(startup_msg.as_slice()).await?;

        let startup_resp = Self::read_message(&mut stream).await?;
        let n = startup_resp.len();
        if n < Self::HEADER_OFFSET || startup_resp[0] != b'R' {
            return Err(anyhow!(
                "Getting invalid startup response from server {:?}",
                &startup_resp[..]
            ));
        }
        let auth_type = i32::from_be_bytes(
            startup_resp[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid startup auth_type"))?,
        );
        match auth_type {
            Self::AUTH_OK => return Ok(stream),
            Self::AUTH_SASL => {
                let payload = &startup_resp[Self::HEADER_OFFSET..n];
                if !payload
                    .windows("SCRAM-SHA-256".len())
                    .any(|w| w == b"SCRAM-SHA-256")
                {
                    return Err(anyhow!("Server does not offer SCRAM-SHA-256"));
                }
            }
            _ => return Err(anyhow!("Unsupported auth type {}", auth_type)),
        }

        let (scram, client_first) = scram.client_first();
        let mut client_first_msg = Vec::new();
        let size = 1 + 4 + 13 + 4 + 1 + client_first.len();
        client_first_msg.write_u8(b'p').await?;
        client_first_msg.write_i32(size as i32).await?;
        client_first_msg
            .write_all("SCRAM-SHA-256".as_bytes())
            .await?;
        client_first_msg.write_all("\0\0\0\0 ".as_bytes()).await?;
        client_first_msg.write_all(client_first.as_bytes()).await?;
        stream.write_all(client_first_msg.as_slice()).await?;

        let server_first = Self::read_message(&mut stream).await?;
        let n = server_first.len();
        if n <= Self::HEADER_OFFSET || server_first[0] != b'R' {
            return Err(anyhow!(
                "Getting invalid server first message {:?}",
                &server_first[..]
            ));
        }
        let auth_type = i32::from_be_bytes(
            server_first[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid server first auth_type"))?,
        );
        if auth_type != Self::AUTH_SASL_CONTINUE {
            return Err(anyhow!("Unexpected auth type {}", auth_type));
        }
        let server_first_str = String::from_utf8(Vec::from(&server_first[Self::HEADER_OFFSET..n]))?;
        let scram = scram.handle_server_first(&server_first_str)?;

        let (scram, client_final) = scram.client_final();
        let mut client_final_msg = Vec::new();
        let size = 1 + 4 + client_final.len();
        client_final_msg.write_u8(b'p').await?;
        client_final_msg.write_i32(size as i32).await?;
        client_final_msg.write_all(client_final.as_bytes()).await?;
        stream.write_all(client_final_msg.as_slice()).await?;

        let server_final = Self::read_message(&mut stream).await?;
        let n = server_final.len();
        if n <= Self::HEADER_OFFSET || server_final[0] != b'R' {
            return Err(anyhow!(
                "Getting invalid server final message {:?}",
                &server_final[..]
            ));
        }
        let auth_type = i32::from_be_bytes(
            server_final[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid server final auth_type"))?,
        );
        if auth_type != Self::AUTH_SASL_FINAL {
            return Err(anyhow!("Unexpected auth type {}", auth_type));
        }
        let server_final_str = String::from_utf8(Vec::from(&server_final[Self::HEADER_OFFSET..n]))?;
        scram.handle_server_final(&server_final_str)?;

        let auth_success = Self::read_message(&mut stream).await?;
        let n = auth_success.len();
        if n == 0 || auth_success[0] == b'E' {
            return Err(anyhow!("Authentication failed"));
        }
        if n < Self::HEADER_OFFSET || auth_success[0] != b'R' {
            return Err(anyhow!("Unexpected auth success response"));
        }
        let auth_type = i32::from_be_bytes(
            auth_success[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid auth success auth_type"))?,
        );
        if auth_type != Self::AUTH_OK {
            return Err(anyhow!(
                "Authentication did not succeed (auth_type={})",
                auth_type
            ));
        }
        tracing::info!(
            host = host,
            port = port,
            username = username,
            "Authenticated with server"
        );
        Ok(stream)
    }

    /// Constructs the raw PostgreSQL wire protocol StartupMessage.
    ///
    /// The message includes protocol version identifiers alongside the user,
    /// database (`admin`), and application name (`pgmoneta`) parameters.
    async fn create_startup_message(username: &str) -> anyhow::Result<Vec<u8>> {
        let mut msg = Vec::new();
        let us = username.len();
        let ds = Self::DB_ADMIN.len();
        let size = 4 + 4 + 4 + 1 + us + 1 + 8 + 1 + ds + 1 + 17 + 9 + 1;
        msg.write_i32(size as i32).await?;
        msg.write_i32(Self::MAGIC).await?;
        msg.write_all(Self::KEY_USER.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(username.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::KEY_DATABASE.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::DB_ADMIN.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::KEY_APP_NAME.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::APP_PGMONETA.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_u8(b'\0').await?;
        Ok(msg)
    }
}

impl Default for SecurityUtil {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityUtil {
    fn encrypt_text_aes_cbc_with_master_key(
        plaintext: &[u8],
        encryption_mode: u8,
        master_key: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

        let key_len = match encryption_mode {
            Encryption::AES_256_CBC => 32,
            Encryption::AES_192_CBC => 24,
            Encryption::AES_128_CBC => 16,
            _ => return Err(anyhow!("Invalid encryption mode: {}", encryption_mode)),
        };

        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut salt)?;

        let mut derived = vec![0u8; key_len + 16];
        pbkdf2_hmac::<Sha256>(master_key, &salt, PBKDF2_ITERATIONS, &mut derived);

        let key = &derived[..key_len];
        let iv = &derived[key_len..];

        let mut buffer = plaintext.to_vec();
        // Reserve space for PKCS7 padding (up to one block size)
        let pad_len = 16 - (plaintext.len() % 16);
        buffer.extend(vec![0u8; pad_len]);

        match key_len {
            32 => Aes256CbcEnc::new(key.into(), iv.into())
                .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(
                    &mut buffer,
                    plaintext.len(),
                ),
            24 => Aes192CbcEnc::new(key.into(), iv.into())
                .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(
                    &mut buffer,
                    plaintext.len(),
                ),
            16 => Aes128CbcEnc::new(key.into(), iv.into())
                .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(
                    &mut buffer,
                    plaintext.len(),
                ),
            _ => unreachable!(),
        }
        .map_err(|e| anyhow!("AES CBC encryption failed: {:?}", e))?;

        let mut result = Vec::with_capacity(SALT_LEN + buffer.len());
        result.extend_from_slice(&salt);
        result.extend(buffer);

        Ok(result)
    }

    fn decrypt_text_aes_cbc_with_master_key(
        ciphertext: &[u8],
        encryption_mode: u8,
        master_key: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
        type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

        if ciphertext.len() <= SALT_LEN {
            return Err(anyhow!("Ciphertext too short"));
        }

        let key_len = match encryption_mode {
            Encryption::AES_256_CBC => 32,
            Encryption::AES_192_CBC => 24,
            Encryption::AES_128_CBC => 16,
            _ => return Err(anyhow!("Invalid encryption mode: {}", encryption_mode)),
        };

        let salt = &ciphertext[..SALT_LEN];
        let encrypted_data = &ciphertext[SALT_LEN..];

        let mut derived = vec![0u8; key_len + 16];
        pbkdf2_hmac::<Sha256>(master_key, salt, PBKDF2_ITERATIONS, &mut derived);

        let key = &derived[..key_len];
        let iv = &derived[key_len..];

        let mut buffer = encrypted_data.to_vec();
        let len = match key_len {
            32 => Aes256CbcDec::new(key.into(), iv.into())
                .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer),
            24 => Aes192CbcDec::new(key.into(), iv.into())
                .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer),
            16 => Aes128CbcDec::new(key.into(), iv.into())
                .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer),
            _ => unreachable!(),
        }
        .map_err(|e| anyhow!("AES CBC decryption failed: {:?}", e))?
        .len();

        buffer.truncate(len);
        Ok(buffer)
    }

    pub fn encrypt_text_aes_cbc(
        &self,
        plaintext: &[u8],
        encryption_mode: u8,
    ) -> anyhow::Result<Vec<u8>> {
        let master_key = self.load_master_key()?;
        Self::encrypt_text_aes_cbc_with_master_key(plaintext, encryption_mode, &master_key[..])
    }

    pub fn decrypt_text_aes_cbc(
        &self,
        ciphertext: &[u8],
        encryption_mode: u8,
    ) -> anyhow::Result<Vec<u8>> {
        let master_key = self.load_master_key()?;
        Self::decrypt_text_aes_cbc_with_master_key(ciphertext, encryption_mode, &master_key[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::Encryption;

    const CBC_TEST_MASTER_KEY: &[u8] = b"cbc_test_master_key_material";

    #[test]
    fn test_base64_encode_decode() {
        let sutil = SecurityUtil::new();
        let s = "123abc !@#$~<>?/";
        let text = s.as_bytes();
        let res = sutil.base64_encode(text).expect("Encode should succeed");
        let decoded_text = sutil.base64_decode(&res).expect("Decode should succeed");
        assert_eq!(decoded_text, text)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let sutil = SecurityUtil::new();
        let master_key = "test_master_key_!@#$~<>?/".as_bytes();
        let text = "test_text_123_!@#$~<>?/";
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_key)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_key)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes())
    }

    #[test]
    fn test_generate_password_default_length() {
        let sutil = SecurityUtil::new();
        let password = sutil
            .generate_password(64)
            .expect("Password generation should succeed");
        assert_eq!(password.len(), 64);
    }

    #[test]
    fn test_generate_password_custom_length() {
        let sutil = SecurityUtil::new();
        let password = sutil
            .generate_password(32)
            .expect("Password generation should succeed");
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_password_contains_valid_chars() {
        let sutil = SecurityUtil::new();
        let password = sutil
            .generate_password(100)
            .expect("Password generation should succeed");
        // Should only contain alphanumeric and special chars from the defined set.
        let valid_chars: std::collections::HashSet<char> =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$%^&*()-_=+[{]}\\|:'\"<,. />?"
                .chars()
                .collect();
        assert!(password.chars().all(|c| valid_chars.contains(&c)));
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let sutil = SecurityUtil::new();
        let master_key = "test_master_key".as_bytes();
        let text = "";
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_key)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_key)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_large_text() {
        let sutil = SecurityUtil::new();
        let master_key = "test_master_key".as_bytes();
        let text = "a".repeat(10000);
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_key)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_key)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let sutil = SecurityUtil::new();
        let master_key = "test_master_key".as_bytes();
        let text = "Hello 世界 🌍 Привет";
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_key)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_key)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let sutil = SecurityUtil::new();
        let master_key1 = "correct_key".as_bytes();
        let master_key2 = "wrong_key".as_bytes();
        let text = "secret_data";
        let encrypted = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_key1)
            .expect("Encryption should succeed");

        // Decryption with wrong key should fail
        let result = sutil.decrypt_from_base64_string(&encrypted, master_key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_aes_cbc() {
        let plaintext = b"Hello, World! This is a test for AES-CBC encryption.";

        let encrypted = SecurityUtil::encrypt_text_aes_cbc_with_master_key(
            plaintext,
            Encryption::AES_256_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("AES-256-CBC encryption should succeed");
        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, plaintext.to_vec());

        let decrypted = SecurityUtil::decrypt_text_aes_cbc_with_master_key(
            &encrypted,
            Encryption::AES_256_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("AES-256-CBC decryption should succeed");
        assert_eq!(decrypted, plaintext.to_vec());

        let encrypted = SecurityUtil::encrypt_text_aes_cbc_with_master_key(
            plaintext,
            Encryption::AES_192_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("AES-192-CBC encryption should succeed");
        let decrypted = SecurityUtil::decrypt_text_aes_cbc_with_master_key(
            &encrypted,
            Encryption::AES_192_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("AES-192-CBC decryption should succeed");
        assert_eq!(decrypted, plaintext.to_vec());

        let encrypted = SecurityUtil::encrypt_text_aes_cbc_with_master_key(
            plaintext,
            Encryption::AES_128_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("AES-128-CBC encryption should succeed");
        let decrypted = SecurityUtil::decrypt_text_aes_cbc_with_master_key(
            &encrypted,
            Encryption::AES_128_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("AES-128-CBC decryption should succeed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_aes_cbc_empty_data() {
        let plaintext: &[u8] = b"";

        let encrypted = SecurityUtil::encrypt_text_aes_cbc_with_master_key(
            plaintext,
            Encryption::AES_256_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("Encryption should succeed");
        let decrypted = SecurityUtil::decrypt_text_aes_cbc_with_master_key(
            &encrypted,
            Encryption::AES_256_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_aes_cbc_large_data() {
        let plaintext: Vec<u8> = vec![b'A'; 10000];

        let encrypted = SecurityUtil::encrypt_text_aes_cbc_with_master_key(
            &plaintext,
            Encryption::AES_256_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("Encryption should succeed");
        let decrypted = SecurityUtil::decrypt_text_aes_cbc_with_master_key(
            &encrypted,
            Encryption::AES_256_CBC,
            CBC_TEST_MASTER_KEY,
        )
        .expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }
}
