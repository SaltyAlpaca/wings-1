use std::sync::LazyLock;

pub fn draw_progress_bar(width: usize, current: f64, total: f64) -> String {
    let progress_percentage = (current / total) * 100.0;
    let formatted_percentage = if progress_percentage.is_nan() {
        "0.00%"
    } else {
        &format!("{:.2}%", progress_percentage)
    };

    let completed_width = std::cmp::min(
        (progress_percentage / 100.0 * width as f64).round() as usize,
        width,
    );
    let remaining_width = width - completed_width;

    let bar = if completed_width == width {
        "=".repeat(width)
    } else {
        format!(
            "{}{}{}",
            "=".repeat(completed_width),
            ">",
            " ".repeat(remaining_width.saturating_sub(1))
        )
    };

    format!("[{bar}] {formatted_percentage}")
}

pub fn parse_content_disposition_filename(header: &str) -> Option<String> {
    static RE_STAR: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)filename\*=utf-8''([^;]+)").unwrap());

    if let Some(caps) = RE_STAR.captures(header) {
        let encoded_filename = &caps[1];

        if let Ok(decoded) = percent_encoding::percent_decode_str(encoded_filename).decode_utf8() {
            return Some(decoded.into_owned());
        }
    }

    static RE_LEGACY: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r#"(?i)filename="?([^";]+)"?"#).unwrap());

    if let Some(caps) = RE_LEGACY.captures(header) {
        return Some(caps[1].to_string());
    }

    None
}

#[inline]
pub fn is_valid_utf8_slice(s: &[u8]) -> bool {
    let mut idx = s.len();
    while idx > s.len().saturating_sub(4) {
        if str::from_utf8(&s[..idx]).is_ok() {
            return true;
        }

        idx -= 1;
    }

    false
}
