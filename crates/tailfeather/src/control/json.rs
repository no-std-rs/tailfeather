//! Writing JSON into a fixed buffer.
//!
//! # Why not serde
//!
//! `serde-json-core` would do this, and is the obvious answer. It is not taken
//! because the outbound side of this protocol is three fixed document shapes,
//! written once, and serde would pull derive machinery into a dependency tree
//! that currently has none of it — for the firmware as well as the harness.
//! Around a hundred lines of writer beats that.
//!
//! Reading is a different problem: map responses are large, variable, and
//! streamed, and that gets a real parser.
//!
//! # Shape
//!
//! A depth-tracked writer that inserts commas itself. The alternative — leaving
//! separators to the caller — produces documents that are wrong only in the
//! branches nobody exercised.

use core::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// The document did not fit the buffer.
    Overflow,
    /// More nesting than [`MAX_DEPTH`].
    TooDeep,
}

impl core::fmt::Display for JsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Overflow => "the JSON document did not fit its buffer",
            Self::TooDeep => "JSON nesting too deep",
        })
    }
}

/// Deeper than any document this crate produces, with room to spare.
pub const MAX_DEPTH: usize = 8;

/// Builds a JSON document in a caller-supplied buffer.
pub struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
    /// For each open object or array, whether anything has been written into it
    /// yet — which is what decides whether the next item needs a comma.
    empty: [bool; MAX_DEPTH],
    depth: usize,
    /// Sticky, so a caller may write a whole document and check once at the end
    /// rather than after every field.
    failed: Option<JsonError>,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self {
            out,
            len: 0,
            empty: [true; MAX_DEPTH],
            depth: 0,
            failed: None,
        }
    }

    /// The finished document, or the first error that occurred.
    pub fn finish(self) -> Result<&'a [u8], JsonError> {
        match self.failed {
            Some(e) => Err(e),
            None => Ok(&self.out[..self.len]),
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        let end = self.len + bytes.len();
        if end > self.out.len() {
            self.failed = Some(JsonError::Overflow);
            return;
        }
        self.out[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    /// Emit the comma this position needs, if any.
    fn separate(&mut self) {
        if self.depth == 0 {
            return;
        }
        if self.empty[self.depth - 1] {
            self.empty[self.depth - 1] = false;
        } else {
            self.raw(b",");
        }
    }

    fn push_depth(&mut self) {
        if self.depth >= MAX_DEPTH {
            self.failed = Some(JsonError::TooDeep);
            return;
        }
        self.empty[self.depth] = true;
        self.depth += 1;
    }

    fn pop_depth(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    pub fn begin_object(&mut self) -> &mut Self {
        self.separate();
        self.raw(b"{");
        self.push_depth();
        self
    }

    pub fn end_object(&mut self) -> &mut Self {
        self.pop_depth();
        self.raw(b"}");
        self
    }

    pub fn begin_array(&mut self) -> &mut Self {
        self.separate();
        self.raw(b"[");
        self.push_depth();
        self
    }

    pub fn end_array(&mut self) -> &mut Self {
        self.pop_depth();
        self.raw(b"]");
        self
    }

    /// Start a named member. The value must follow immediately.
    pub fn key(&mut self, name: &str) -> &mut Self {
        self.separate();
        self.string_literal(name);
        self.raw(b":");
        // A key is a separator's worth of punctuation, not an item, so the
        // value that follows must not emit another comma.
        if self.depth > 0 {
            self.empty[self.depth - 1] = true;
        }
        self
    }

    pub fn str(&mut self, value: &str) -> &mut Self {
        self.separate();
        self.string_literal(value);
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.separate();
        let mut buffer = heapless::String::<20>::new();
        let _ = write!(buffer, "{value}");
        self.raw(buffer.as_bytes());
        self
    }

    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.separate();
        self.raw(if value { b"true" } else { b"false" });
        self
    }

    pub fn null(&mut self) -> &mut Self {
        self.separate();
        self.raw(b"null");
        self
    }

    /// A pre-rendered value, for something already in JSON form.
    pub fn raw_value(&mut self, value: &str) -> &mut Self {
        self.separate();
        self.raw(value.as_bytes());
        self
    }

    pub fn field_str(&mut self, name: &str, value: &str) -> &mut Self {
        self.key(name).str(value)
    }

    pub fn field_u64(&mut self, name: &str, value: u64) -> &mut Self {
        self.key(name).u64(value)
    }

    pub fn field_bool(&mut self, name: &str, value: bool) -> &mut Self {
        self.key(name).bool(value)
    }

    /// Write a quoted, escaped string.
    ///
    /// Only the escapes JSON requires: the two structural characters and
    /// everything below 0x20. Anything else, including all of UTF-8, is passed
    /// through — `\u` escaping non-ASCII would be legal but pointless, and the
    /// server reads UTF-8 either way.
    fn string_literal(&mut self, value: &str) {
        self.raw(b"\"");
        let bytes = value.as_bytes();
        let mut start = 0;
        for (i, &byte) in bytes.iter().enumerate() {
            let escape: &[u8] = match byte {
                b'"' => b"\\\"",
                b'\\' => b"\\\\",
                b'\n' => b"\\n",
                b'\r' => b"\\r",
                b'\t' => b"\\t",
                0x00..=0x1f => b"",
                _ => continue,
            };
            self.raw(&bytes[start..i]);
            if escape.is_empty() {
                // The remaining control characters have no short form.
                let mut buffer = heapless::String::<8>::new();
                let _ = write!(buffer, "\\u{byte:04x}");
                self.raw(buffer.as_bytes());
            } else {
                self.raw(escape);
            }
            start = i + 1;
        }
        self.raw(&bytes[start..]);
        self.raw(b"\"");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(buffer: &mut [u8], build: impl FnOnce(&mut Writer<'_>)) -> &str {
        let mut writer = Writer::new(buffer);
        build(&mut writer);
        let bytes = writer.finish().unwrap();
        core::str::from_utf8(bytes).unwrap()
    }

    #[test]
    fn writes_a_nested_document_with_the_commas_in_the_right_places() {
        let mut buffer = [0u8; 256];
        let text = rendered(&mut buffer, |w| {
            w.begin_object()
                .field_u64("Version", 131)
                .field_str("NodeKey", "nodekey:aa")
                .key("Auth")
                .begin_object()
                .field_str("AuthKey", "hskey-auth-x")
                .end_object()
                .field_bool("Ephemeral", false)
                .key("Routes")
                .begin_array()
                .str("0.0.0.0/0")
                .str("::/0")
                .end_array()
                .end_object();
        });
        assert_eq!(
            text,
            r#"{"Version":131,"NodeKey":"nodekey:aa","Auth":{"AuthKey":"hskey-auth-x"},"Ephemeral":false,"Routes":["0.0.0.0/0","::/0"]}"#
        );
    }

    #[test]
    fn an_empty_object_or_array_is_still_well_formed() {
        let mut buffer = [0u8; 64];
        let text = rendered(&mut buffer, |w| {
            w.begin_object()
                .key("Empty")
                .begin_object()
                .end_object()
                .key("None")
                .begin_array()
                .end_array()
                .end_object();
        });
        assert_eq!(text, r#"{"Empty":{},"None":[]}"#);
    }

    #[test]
    fn strings_are_escaped_so_a_hostname_cannot_break_the_document() {
        let mut buffer = [0u8; 128];
        let text = rendered(&mut buffer, |w| {
            w.begin_object()
                .field_str("Hostname", "we\"ird\\\nname\u{1}")
                .end_object();
        });
        assert_eq!(text, r#"{"Hostname":"we\"ird\\\nname\u0001"}"#);
    }

    #[test]
    fn utf8_passes_through_unescaped() {
        let mut buffer = [0u8; 64];
        let text = rendered(&mut buffer, |w| {
            w.begin_object().field_str("Hostname", "café").end_object();
        });
        assert_eq!(text, r#"{"Hostname":"café"}"#);
    }

    #[test]
    fn overflow_is_reported_once_rather_than_producing_a_truncated_document() {
        // Truncated JSON is the dangerous outcome: it can still parse as
        // something, just not what was meant.
        let mut buffer = [0u8; 16];
        let mut writer = Writer::new(&mut buffer);
        writer
            .begin_object()
            .field_str("a", "a value far too long for this buffer")
            .end_object();
        assert_eq!(writer.finish(), Err(JsonError::Overflow));
    }
}
