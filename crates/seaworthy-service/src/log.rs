//! Log-line sanitization for the run loop's error lines. Each seaworthy
//! crate keeps its own copy of these few lines (no shared utility crate),
//! with the same meaning everywhere.

/// Render an attacker-controlled string safe for ONE log line: strips
/// EVERY ASCII control character (C0 `0x00`–`0x1F` and DEL `0x7F`), so a
/// hostile value can neither forge extra log entries (CR/LF) nor
/// manipulate the terminal that renders them via ESC-borne ANSI
/// sequences, bell, or NUL.
///
/// The filter is ASCII-only by design: non-ASCII code points (Unicode
/// bidi/format marks such as U+202E included) PASS THROUGH. They are
/// legitimate text (names, messages); a renderer that must neutralize them
/// for display does that itself, the same way it handles any other
/// presentation concern.
///
/// Sanitizing is the RENDERER's job: values keep their raw form; only
/// human-facing log lines pass through here.
#[must_use]
pub(crate) fn line_safe(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::line_safe;

    #[test]
    fn line_safe_strips_every_ascii_control_character() {
        assert_eq!(line_safe("plain"), "plain");
        assert_eq!(line_safe("a\r\nb\nc\rd"), "abcd");
        assert_eq!(
            line_safe("store down\r\nFORGED-LOG-LINE"),
            "store downFORGED-LOG-LINE"
        );
        // Every C0 control and DEL goes: no ANSI escapes, no bell, no NUL.
        assert_eq!(line_safe("a\u{7}b\u{1b}[31mc\u{0}d\u{7f}"), "ab[31mcd");
        assert_eq!(line_safe("\u{1f}\u{0}\u{7f}"), "");
    }

    #[test]
    fn line_safe_leaves_printables_and_non_ascii_untouched() {
        // Trim/normalization is not its job.
        assert_eq!(line_safe(" keep spaces "), " keep spaces ");
        assert_eq!(line_safe("émile — ü"), "émile — ü");
        // Deliberate: non-ASCII bidi/format marks (U+202E here) pass
        // through, legitimate text the filter never claims to neutralize.
        assert_eq!(line_safe("a\u{202e}b"), "a\u{202e}b");
    }
}
