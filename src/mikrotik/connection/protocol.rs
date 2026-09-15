// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::prelude::{AppError, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) fn encode_length(len: usize) -> Result<Vec<u8>> {
    let value =
        u32::try_from(len).map_err(|_| AppError::Protocol("word length exceeds 32 bits".into()))?;
    let bytes = value.to_be_bytes();
    Ok(if value < 0x80 {
        vec![bytes[3]]
    } else if value < 0x4000 {
        vec![bytes[2] | 0x80, bytes[3]]
    } else if value < 0x0020_0000 {
        vec![bytes[1] | 0xC0, bytes[2], bytes[3]]
    } else if value < 0x1000_0000 {
        vec![bytes[0] | 0xE0, bytes[1], bytes[2], bytes[3]]
    } else {
        vec![0xF0, bytes[0], bytes[1], bytes[2], bytes[3]]
    })
}

pub(super) async fn read_length<R: AsyncRead + Unpin>(stream: &mut R) -> Result<usize> {
    let first = stream.read_u8().await.map_err(length_io_error)?;
    let (mut value, remaining) = match first {
        0x00..=0x7F => (u32::from(first), 0),
        0x80..=0xBF => (u32::from(first & 0x3F), 1),
        0xC0..=0xDF => (u32::from(first & 0x1F), 2),
        0xE0..=0xEF => (u32::from(first & 0x0F), 3),
        0xF0 => (0, 4),
        _ => return Err(AppError::Protocol("reserved word length prefix".into())),
    };
    for _ in 0..remaining {
        value = (value << 8) | u32::from(stream.read_u8().await.map_err(length_io_error)?);
    }
    usize::try_from(value)
        .map_err(|_| AppError::Protocol("word length exceeds platform limit".into()))
}

fn length_io_error(source: std::io::Error) -> AppError {
    AppError::Transport {
        operation: "read word length",
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_length, read_length};
    use crate::prelude::AppError;
    use proptest::prelude::*;

    #[tokio::test]
    async fn test_length_boundaries_use_production_decoder() {
        for (value, expected) in [
            (0, vec![0]),
            (0x7F, vec![0x7F]),
            (0x80, vec![0x80, 0x80]),
            (0x3FFF, vec![0xBF, 0xFF]),
            (0x4000, vec![0xC0, 0x40, 0]),
            (0x001F_FFFF, vec![0xDF, 0xFF, 0xFF]),
            (0x0020_0000, vec![0xE0, 0x20, 0, 0]),
            (0x0FFF_FFFF, vec![0xEF, 0xFF, 0xFF, 0xFF]),
            (0x1000_0000, vec![0xF0, 0x10, 0, 0, 0]),
            (0xFFFF_FFFF, vec![0xF0, 0xFF, 0xFF, 0xFF, 0xFF]),
        ] {
            assert_eq!(encode_length(value).unwrap(), expected);
            assert_eq!(read_length(&mut expected.as_slice()).await.unwrap(), value);
            for end in 0..expected.len() {
                assert!(matches!(
                    read_length(&mut &expected[..end]).await,
                    Err(AppError::Transport { .. })
                ));
            }
        }
    }

    #[tokio::test]
    async fn test_reserved_lengths_rejected_without_reading_more_bytes() {
        for prefix in 0xF1..=0xFF {
            assert!(matches!(
                read_length(&mut [prefix].as_slice()).await,
                Err(AppError::Protocol(_))
            ));
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_unencodable_length_returns_error() {
        assert!(encode_length(0x1_0000_0000).is_err());
    }

    proptest! {
        #[test]
        fn test_length_roundtrip(value in any::<u32>()) {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let value = usize::try_from(value).unwrap();
            let encoded = encode_length(value).unwrap();
            let decoded = runtime.block_on(read_length(&mut encoded.as_slice())).unwrap();
            prop_assert_eq!(decoded, value);
        }
    }
}
