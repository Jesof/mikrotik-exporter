// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! RouterOS wire protocol helpers

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

// RouterOS protocol length encoding - intentional truncation is part of the wire format
#[allow(clippy::cast_possible_truncation)]
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x4000 {
        vec![((len >> 8) as u8) | 0x80, (len & 0xFF) as u8]
    } else if len < 0x0020_0000 {
        vec![
            ((len >> 16) as u8) | 0xC0,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else if len < 0x1000_0000 {
        vec![
            ((len >> 24) as u8) | 0xE0,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else {
        vec![
            ((len >> 32) as u8) | 0xF0,
            ((len >> 24) & 0xFF) as u8,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

pub(super) async fn read_length(
    stream: &mut TcpStream,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let first = stream.read_u8().await?;
    let len = if first & 0x80 == 0 {
        first as usize
    } else if first & 0xC0 == 0x80 {
        let second = stream.read_u8().await?;
        (((first & 0x3F) as usize) << 8) + second as usize
    } else if first & 0xE0 == 0xC0 {
        let second = stream.read_u8().await?;
        let third = stream.read_u8().await?;
        (((first & 0x1F) as usize) << 16) + ((second as usize) << 8) + third as usize
    } else if first & 0xF0 == 0xE0 {
        let second = stream.read_u8().await?;
        let third = stream.read_u8().await?;
        let fourth = stream.read_u8().await?;
        (((first & 0x0F) as usize) << 24)
            + ((second as usize) << 16)
            + ((third as usize) << 8)
            + fourth as usize
    } else {
        // five byte length
        let b2 = stream.read_u8().await?;
        let b3 = stream.read_u8().await?;
        let b4 = stream.read_u8().await?;
        let b5 = stream.read_u8().await?;
        ((first & 0x07) as usize) << 32
            | (b2 as usize) << 24
            | (b3 as usize) << 16
            | (b4 as usize) << 8
            | b5 as usize
    };
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_length_small() {
        assert_eq!(encode_length(0), vec![0]);
        assert_eq!(encode_length(1), vec![1]);
        assert_eq!(encode_length(127), vec![127]);
    }

    #[test]
    fn test_encode_length_medium() {
        assert_eq!(encode_length(128), vec![0x80, 0x80]);
        assert_eq!(encode_length(256), vec![0x81, 0x00]);
        assert_eq!(encode_length(0x3FFF), vec![0xBF, 0xFF]);
    }

    #[test]
    fn test_encode_length_large() {
        assert_eq!(encode_length(0x4000), vec![0xC0, 0x40, 0x00]);
        assert_eq!(encode_length(0x1F_FFFF), vec![0xDF, 0xFF, 0xFF]);
    }
}
