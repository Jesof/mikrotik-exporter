// Тест кодирования длины по правилам RouterOS API (локальная копия логики)
#[test]
fn test_encode_length() {
    fn encode_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x4000 {
            vec![((len >> 8) as u8) | 0x80, (len & 0xFF) as u8]
        } else if len < 0x200000 {
            vec![
                ((len >> 16) as u8) | 0xC0,
                ((len >> 8) & 0xFF) as u8,
                (len & 0xFF) as u8,
            ]
        } else if len < 0x10000000 {
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

    assert_eq!(encode_length(0x7F), vec![0x7F]);
    assert_eq!(encode_length(0x80), vec![0x80, 0x80]);
    assert_eq!(encode_length(0x4000 - 1), vec![0xBF, 0xFF]);
    assert_eq!(encode_length(0x4000), vec![0xC0, 0x40, 0x00]);
}
