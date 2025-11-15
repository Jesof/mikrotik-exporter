//! Utility functions for metrics processing

/// Parse MikroTik uptime string to seconds
///
/// Accepts formats like: 1d2h3m4s, 2w1d, 05:23:10, 1h5m, 30s
pub fn parse_uptime_to_seconds(s: &str) -> u64 {
    // Accept formats like 1d2h3m4s, 2w1d, 05:23:10, 1h5m, 30s
    if s.contains(':') {
        // HH:MM:SS or MM:SS
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 3 {
            let h = parts[0].parse::<u64>().unwrap_or(0);
            let m = parts[1].parse::<u64>().unwrap_or(0);
            let sec = parts[2].parse::<u64>().unwrap_or(0);
            return h * 3600 + m * 60 + sec;
        } else if parts.len() == 2 {
            let m = parts[0].parse::<u64>().unwrap_or(0);
            let sec = parts[1].parse::<u64>().unwrap_or(0);
            return m * 60 + sec;
        }
    }
    let mut total = 0u64;
    let mut num = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
            continue;
        }
        if num.is_empty() {
            continue;
        }
        let value = num.parse::<u64>().unwrap_or(0);
        let unit_seconds = match ch {
            'w' => 7 * 24 * 3600,
            'd' => 24 * 3600,
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => 0,
        };
        total += value * unit_seconds;
        num.clear();
    }
    if !num.is_empty() {
        // trailing number without unit -> seconds
        total += num.parse::<u64>().unwrap_or(0);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uptime() {
        assert_eq!(parse_uptime_to_seconds("1d2h3m4s"), 93784);
        assert_eq!(parse_uptime_to_seconds("1h5m"), 3900);
        assert_eq!(parse_uptime_to_seconds("30s"), 30);
        assert_eq!(parse_uptime_to_seconds("05:23:10"), 19390);
        assert_eq!(parse_uptime_to_seconds("23:10"), 1390);
    }
}
