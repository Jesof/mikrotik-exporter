// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

pub(crate) fn parse_uptime_to_seconds(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().ok();
    }
    let mut rest = s;
    let mut total = 0u64;
    let mut previous_unit = u64::MAX;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let value = rest[..digits].parse::<u64>().ok()?;
        rest = &rest[digits..];
        if let Some(clock_tail) = rest.strip_prefix(':') {
            if previous_unit <= 3600 {
                return None;
            }
            let parts: Vec<_> = clock_tail.split(':').collect();
            let clock = match parts.as_slice() {
                [seconds] => value
                    .checked_mul(60)?
                    .checked_add(parse_clock_part(seconds)?)?,
                [minutes, seconds] => value
                    .checked_mul(3600)?
                    .checked_add(parse_clock_part(minutes)?.checked_mul(60)?)?
                    .checked_add(parse_clock_part(seconds)?)?,
                _ => return None,
            };
            return total.checked_add(clock);
        }
        let unit = match rest.as_bytes().first()? {
            b'w' => 604_800,
            b'd' => 86_400,
            b'h' => 3600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        if unit >= previous_unit {
            return None;
        }
        total = total.checked_add(value.checked_mul(unit)?)?;
        previous_unit = unit;
        rest = &rest[1..];
    }
    Some(total)
}

fn parse_clock_part(s: &str) -> Option<u64> {
    if s.len() != 2 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|n| *n < 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duration_formats() {
        for (input, expected) in [
            ("1d2h3m4s", 93784),
            ("05:23:10", 19390),
            ("23:10", 1390),
            ("1w2d03:04:05", 788_645),
            ("0s", 0),
            ("120", 120),
        ] {
            assert_eq!(parse_uptime_to_seconds(input), Some(expected), "{input}");
        }
    }

    #[test]
    fn test_duration_rejects_invalid_and_overflow() {
        for input in [
            "",
            "garbage",
            "1x",
            "1h2",
            "1m1h",
            "1s1s",
            "1::2",
            "01:60:00",
            "1:xx",
            "18446744073709551615w",
        ] {
            assert_eq!(parse_uptime_to_seconds(input), None, "{input}");
        }
    }
}
