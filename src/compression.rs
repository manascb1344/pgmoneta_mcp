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

use crate::constant::Compression;
use anyhow::anyhow;
use std::io::{Read, Write};

/// Utility for data compression and decompression operations.
///
/// This module provides wrapper functions for various compression algorithms
/// used for MCP <-> pgmoneta communication.
pub struct CompressionUtil;

impl CompressionUtil {
    /// Creates a new CompressionUtil instance.
    pub fn new() -> Self {
        Self
    }

    /// Compresses data using the specified compression algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - The uncompressed data bytes.
    /// * `algorithm` - The compression algorithm to use (use `Compression` constants).
    ///
    /// # Returns
    ///
    /// Returns the compressed data as a Vec<u8>, or an error if compression fails.
    pub fn compress(data: &[u8], algorithm: u8) -> anyhow::Result<Vec<u8>> {
        match algorithm {
            Compression::GZIP => Self::compress_gzip(data),
            Compression::ZSTD => Self::compress_zstd(data),
            Compression::LZ4 => Self::compress_lz4(data),
            Compression::BZIP2 => Self::compress_bzip2(data),
            Compression::NONE => Ok(data.to_vec()),
            _ => Err(anyhow!("Unknown compression algorithm: {}", algorithm)),
        }
    }

    /// Decompresses data using the specified compression algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - The compressed data bytes.
    /// * `algorithm` - The compression algorithm to use (use `Compression` constants).
    ///
    /// # Returns
    ///
    /// Returns the decompressed data as a Vec<u8>, or an error if decompression fails.
    pub fn decompress(data: &[u8], algorithm: u8) -> anyhow::Result<Vec<u8>> {
        match algorithm {
            Compression::GZIP => Self::decompress_gzip(data),
            Compression::ZSTD => Self::decompress_zstd(data),
            Compression::LZ4 => Self::decompress_lz4(data),
            Compression::BZIP2 => Self::decompress_bzip2(data),
            Compression::NONE => Ok(data.to_vec()),
            _ => Err(anyhow!("Unknown compression algorithm: {}", algorithm)),
        }
    }

    fn compress_gzip(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress_gzip(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use flate2::read::GzDecoder;

        let mut decoder = GzDecoder::new(data);
        let mut result = Vec::new();
        decoder.read_to_end(&mut result)?;
        Ok(result)
    }

    fn compress_zstd(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use zstd::stream::write::Encoder;

        let mut encoder = Encoder::new(Vec::new(), 3)?;
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress_zstd(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use zstd::stream::read::Decoder;

        let mut decoder = Decoder::new(data)?;
        let mut result = Vec::new();
        decoder.read_to_end(&mut result)?;
        Ok(result)
    }

    fn compress_lz4(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use lz4::EncoderBuilder;

        let mut encoder = EncoderBuilder::new().build(Vec::new())?;
        encoder.write_all(data)?;
        let (result, _) = encoder.finish();
        Ok(result)
    }

    fn decompress_lz4(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use lz4::Decoder;

        let mut decoder = Decoder::new(data)?;
        let mut result = Vec::new();
        decoder.read_to_end(&mut result)?;
        Ok(result)
    }

    fn compress_bzip2(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use bzip2::Compression;
        use bzip2::write::BzEncoder;

        let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress_bzip2(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use bzip2::read::BzDecoder;

        let mut decoder = BzDecoder::new(data);
        let mut result = Vec::new();
        decoder.read_to_end(&mut result)?;
        Ok(result)
    }
}

impl Default for CompressionUtil {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA: &[u8] =
        b"Hello, World! This is a test string for compression and decompression.";

    #[test]
    fn test_compress_decompress_gzip() {
        let compressed = CompressionUtil::compress(TEST_DATA, Compression::GZIP).unwrap();
        assert!(!compressed.is_empty());
        assert_ne!(compressed, TEST_DATA);

        let decompressed = CompressionUtil::decompress(&compressed, Compression::GZIP).unwrap();
        assert_eq!(decompressed, TEST_DATA);
    }

    #[test]
    fn test_compress_decompress_zstd() {
        let compressed = CompressionUtil::compress(TEST_DATA, Compression::ZSTD).unwrap();
        assert!(!compressed.is_empty());
        assert_ne!(compressed, TEST_DATA);

        let decompressed = CompressionUtil::decompress(&compressed, Compression::ZSTD).unwrap();
        assert_eq!(decompressed, TEST_DATA);
    }

    #[test]
    fn test_compress_decompress_lz4() {
        let compressed = CompressionUtil::compress(TEST_DATA, Compression::LZ4).unwrap();
        assert!(!compressed.is_empty());
        assert_ne!(compressed, TEST_DATA);

        let decompressed = CompressionUtil::decompress(&compressed, Compression::LZ4).unwrap();
        assert_eq!(decompressed, TEST_DATA);
    }

    #[test]
    fn test_compress_decompress_bzip2() {
        let compressed = CompressionUtil::compress(TEST_DATA, Compression::BZIP2).unwrap();
        assert!(!compressed.is_empty());
        assert_ne!(compressed, TEST_DATA);

        let decompressed = CompressionUtil::decompress(&compressed, Compression::BZIP2).unwrap();
        assert_eq!(decompressed, TEST_DATA);
    }

    #[test]
    fn test_compress_decompress_none() {
        let result = CompressionUtil::compress(TEST_DATA, Compression::NONE).unwrap();
        assert_eq!(result, TEST_DATA);

        let result = CompressionUtil::decompress(TEST_DATA, Compression::NONE).unwrap();
        assert_eq!(result, TEST_DATA);
    }

    #[test]
    fn test_empty_data() {
        let empty: &[u8] = b"";

        let compressed = CompressionUtil::compress(empty, Compression::ZSTD).unwrap();
        let decompressed = CompressionUtil::decompress(&compressed, Compression::ZSTD).unwrap();
        assert_eq!(decompressed, empty);
    }

    #[test]
    fn test_large_data() {
        let large_data: Vec<u8> = vec![b'A'; 10000];

        let compressed = CompressionUtil::compress(&large_data, Compression::ZSTD).unwrap();
        assert!(compressed.len() < large_data.len());

        let decompressed = CompressionUtil::decompress(&compressed, Compression::ZSTD).unwrap();
        assert_eq!(decompressed, large_data);
    }
}
