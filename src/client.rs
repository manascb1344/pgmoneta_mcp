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

mod info;

use super::configuration::CONFIG;
use super::constant::*;
use super::security::SecurityUtil;
use anyhow::anyhow;
use chrono::Local;
use serde::Serialize;
use std::fmt::Debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn parse_compression(compression: &str) -> u8 {
    match compression.to_lowercase().as_str() {
        "gzip" => Compression::GZIP,
        "zstd" => Compression::ZSTD,
        "lz4" => Compression::LZ4,
        "bzip2" => Compression::BZIP2,
        _ => Compression::NONE,
    }
}

fn parse_encryption(encryption: &str) -> u8 {
    match encryption.to_lowercase().as_str() {
        "aes_256_cbc" => Encryption::AES_256_CBC,
        "aes_192_cbc" => Encryption::AES_192_CBC,
        "aes_128_cbc" => Encryption::AES_128_CBC,
        _ => Encryption::NONE,
    }
}

/// Represents the header of a request sent to the pgmoneta server.
///
/// Contains metadata such as the command code, client version,
/// formatting preferences, and security settings.
#[derive(Serialize, Clone, Debug)]
struct RequestHeader {
    #[serde(rename = "Command")]
    command: u32,
    #[serde(rename = "ClientVersion")]
    client_version: String,
    #[serde(rename = "Output")]
    output_format: u8,
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "Compression")]
    compression: u8,
    #[serde(rename = "Encryption")]
    encryption: u8,
}

/// A wrapper structure that combines a request header with its specific payload.
///
/// This is the final serialized object sent over the TCP connection to pgmoneta.
#[derive(Serialize, Clone, Debug)]
struct PgmonetaRequest<R>
where
    R: Serialize + Clone + Debug,
{
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: R,
}

/// Handles network communication with the backend pgmoneta server.
///
/// This client manages the lifecycle of a request: building headers,
/// authenticating, opening a TCP stream, writing the payload, and reading the response.
pub struct PgmonetaClient;
impl PgmonetaClient {
    /// Constructs a standard request header for a given command.
    ///
    /// The header includes the current local timestamp and defaults to
    /// no encryption or compression, expecting a JSON response.
    fn build_request_header(command: u32) -> RequestHeader {
        let config = CONFIG.get().expect("Configuration should be enabled");
        let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();
        RequestHeader {
            command,
            client_version: CLIENT_VERSION.to_string(),
            output_format: Format::JSON,
            timestamp,
            compression: parse_compression(&config.pgmoneta.compression),
            encryption: parse_encryption(&config.pgmoneta.encryption),
        }
    }

    /// Establishes an authenticated TCP connection to the pgmoneta server.
    ///
    /// Looks up the provided `username` in the configuration to find the encrypted
    /// password, decrypts it using the master key, and initiates the connection.
    ///
    /// # Arguments
    /// * `username` - The admin username requesting the connection.
    ///
    /// # Returns
    /// An authenticated `TcpStream` ready for read/write operations.
    async fn connect_to_server(username: &str) -> anyhow::Result<TcpStream> {
        let config = CONFIG.get().expect("Configuration should be enabled");
        let security_util = SecurityUtil::new();

        if !config.admins.contains_key(username) {
            return Err(anyhow!(
                "request_backup_info: unable to find user {username}"
            ));
        }

        let password_encrypted = config
            .admins
            .get(username)
            .expect("Username should be found");
        let master_key = security_util.load_master_key()?;
        let password = String::from_utf8(
            security_util.decrypt_from_base64_string(password_encrypted, &master_key[..])?,
        )?;
        let stream = SecurityUtil::connect_to_server(
            &config.pgmoneta.host,
            config.pgmoneta.port,
            username,
            &password,
        )
        .await?;
        Ok(stream)
    }

    async fn write_request(
        request_str: &str,
        stream: &mut TcpStream,
        compression: u8,
        encryption: u8,
    ) -> anyhow::Result<()> {
        let security_util = SecurityUtil::new();

        let payload = if compression != Compression::NONE || encryption != Encryption::NONE {
            let mut data = request_str.as_bytes().to_vec();

            if compression != Compression::NONE {
                data = security_util.compress_data(&data, compression)?;
            }

            if encryption != Encryption::NONE {
                data = security_util.encrypt_aes_cbc_with_salt(&data, encryption)?;
            }

            security_util.base64_encode(&data)?
        } else {
            request_str.to_string()
        };

        stream.write_u8(compression).await?;
        stream.write_u8(encryption).await?;
        stream.write_all(payload.as_bytes()).await?;
        stream.write_u8(0).await?;
        Ok(())
    }

    async fn read_response(stream: &mut TcpStream) -> anyhow::Result<String> {
        let compression = stream.read_u8().await?;
        let encryption = stream.read_u8().await?;

        let mut buf = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if byte == 0 {
                break;
            }
            buf.push(byte);
        }

        let security_util = SecurityUtil::new();

        if compression != Compression::NONE || encryption != Encryption::NONE {
            let data = security_util.base64_decode(std::str::from_utf8(&buf)?)?;

            let decrypted = if encryption != Encryption::NONE {
                security_util.decrypt_aes_cbc_with_salt(&data, encryption)?
            } else {
                data
            };

            let decompressed = if compression != Compression::NONE {
                security_util.decompress_data(&decrypted, compression)?
            } else {
                decrypted
            };

            String::from_utf8(decompressed).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
        } else {
            String::from_utf8(buf).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
        }
    }

    /// End-to-end wrapper for sending a request to the pgmoneta server and awaiting its response.
    ///
    /// # Arguments
    /// * `username` - The admin username making the request.
    /// * `command` - The numeric command code (e.g., `Command::INFO`).
    /// * `request` - The specific request payload object.
    ///
    /// # Returns
    /// The raw string response from the pgmoneta server.
    async fn forward_request<R>(username: &str, command: u32, request: R) -> anyhow::Result<String>
    where
        R: Serialize + Clone + Debug,
    {
        let mut stream = Self::connect_to_server(username).await?;
        tracing::info!(username = username, "Connected to server");

        let header = Self::build_request_header(command);
        let compression = header.compression;
        let encryption = header.encryption;
        let request = PgmonetaRequest { request, header };

        let request_str = serde_json::to_string(&request)?;
        Self::write_request(&request_str, &mut stream, compression, encryption).await?;
        tracing::debug!(username = username, request = ?request, "Sent request to server");
        Self::read_response(&mut stream).await
    }
}
