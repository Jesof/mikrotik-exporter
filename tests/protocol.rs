// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use mikrotik_exporter::encode_length;

#[test]
fn test_encode_length() {
    assert_eq!(encode_length(0x7F), vec![0x7F]);
    assert_eq!(encode_length(0x80), vec![0x80, 0x80]);
    assert_eq!(encode_length(0x4000 - 1), vec![0xBF, 0xFF]);
    assert_eq!(encode_length(0x4000), vec![0xC0, 0x40, 0x00]);
}

#[test]
fn test_encode_length_boundary_values() {
    // 1-byte: 0..0x80
    assert_eq!(encode_length(0).len(), 1);
    assert_eq!(encode_length(0x7F).len(), 1);

    // 2-byte: 0x80..0x4000
    assert_eq!(encode_length(0x80).len(), 2);
    assert_eq!(encode_length(0x3FFF).len(), 2);

    // 3-byte: 0x4000..0x20_0000
    assert_eq!(encode_length(0x4000).len(), 3);
    assert_eq!(encode_length(0x1F_FFFF).len(), 3);

    // 4-byte: 0x20_0000..0x1000_0000
    assert_eq!(encode_length(0x0020_0000).len(), 4);
    assert_eq!(encode_length(0x0FFF_FFFF).len(), 4);

    // 5-byte: 0x1000_0000+
    assert_eq!(encode_length(0x1000_0000).len(), 5);
    assert_eq!(encode_length(0xFFFF_FFFF).len(), 5);
}

#[test]
fn test_encode_length_known_values() {
    assert_eq!(encode_length(0), vec![0x00]);
    assert_eq!(encode_length(1), vec![0x01]);
    assert_eq!(encode_length(127), vec![0x7F]);
    assert_eq!(encode_length(128), vec![0x80, 0x80]);
    assert_eq!(encode_length(256), vec![0x81, 0x00]);
    assert_eq!(encode_length(0x0020_0000), vec![0xE0, 0x20, 0x00, 0x00]);
}

/// Decode length from bytes, mirroring `RouterOsConnection::read_length`.
/// Used only for roundtrip verification.
fn decode_length(bytes: &[u8]) -> usize {
    let first = bytes[0];
    if first & 0x80 == 0 {
        first as usize
    } else if first & 0xC0 == 0x80 {
        (((first & 0x3F) as usize) << 8) + bytes[1] as usize
    } else if first & 0xE0 == 0xC0 {
        (((first & 0x1F) as usize) << 16) + ((bytes[1] as usize) << 8) + bytes[2] as usize
    } else if first & 0xF0 == 0xE0 {
        (((first & 0x0F) as usize) << 24)
            + ((bytes[1] as usize) << 16)
            + ((bytes[2] as usize) << 8)
            + bytes[3] as usize
    } else {
        ((first & 0x07) as usize) << 32
            | (bytes[1] as usize) << 24
            | (bytes[2] as usize) << 16
            | (bytes[3] as usize) << 8
            | bytes[4] as usize
    }
}

#[test]
fn test_encode_decode_roundtrip() {
    let test_values: Vec<usize> = vec![
        0,
        1,
        0x7E,
        0x7F,
        0x80,
        0x81,
        0xFF,
        0x100,
        0x3FFE,
        0x3FFF,
        0x4000,
        0x4001,
        0xFFFF,
        0x1F_FFFE,
        0x1F_FFFF,
        0x0020_0000,
        0x0020_0001,
        0x0FFF_FFFE,
        0x0FFF_FFFF,
        0x1000_0000,
        0x1000_0001,
        0x7FFF_FFFF,
        0xFFFF_FFFF,
    ];

    for &value in &test_values {
        let encoded = encode_length(value);
        let decoded = decode_length(&encoded);
        assert_eq!(
            decoded, value,
            "Roundtrip failed for {value:#X}: encoded as {encoded:?}, decoded as {decoded:#X}"
        );
    }
}
