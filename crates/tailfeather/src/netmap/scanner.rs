//! An incremental JSON scanner.
//!
//! # Why this is hand-written
//!
//! `picojson` was the intended dependency and does not fit. Its `PushParser`
//! takes `'input` as a *struct* lifetime parameter — `write(&mut self, data:
//! &'input [u8])` — so every chunk ever fed to one parser must be borrowed for
//! the same lifetime. In practice that means they must all be alive at once,
//! which means holding the whole document. That is precisely the property this
//! crate exists to avoid, and the borrow checker rejects the alternative
//! outright rather than letting it become a latent memory problem.
//!
//! Its pull-based `StreamParser` avoids that by owning a `Reader`, but a `Reader`
//! must block, and the bytes here arrive from an async HTTP/2 stream.
//!
//! So the tokeniser is ours. It is a byte-at-a-time state machine with a fixed
//! buffer, and the boundary was drawn so this swap cost nothing above it: the
//! netmap logic in [`crate::netmap::parser`] consumes [`Token`]s and never knew which
//! tokeniser produced them.
//!
//! # What it holds
//!
//! One token. Strings accumulate into a fixed buffer and are emitted whole, so
//! the only size that matters is the longest single string — not the number of
//! peers and not the document length. Everything else is a state enum and a
//! container stack bounded by nesting depth.

use crate::netmap::{CapacityError, Error, MAX_STRING};

/// How deeply a MapResponse may nest. The deepest real path is
/// `DERPMap.Regions.<id>.Nodes[].<field>`, which is five.
pub const MAX_DEPTH: usize = 16;

/// One JSON token.
#[derive(Debug, PartialEq)]
pub enum Token<'a> {
    StartObject,
    EndObject,
    StartArray,
    EndArray,
    /// A member name. Distinguished from [`Token::Str`] by position, which is
    /// the only thing that separates them in JSON.
    Key(&'a str),
    Str(&'a str),
    /// Integers only. Every number in a MapResponse is an id, a port or a
    /// region. Other numeric forms are reported without floating-point parsing.
    Int(i64),
    /// A fraction, exponent, or integer outside i64. Never silently coerce a
    /// security constraint such as SSH session duration to zero.
    OtherNumber,
    Bool(bool),
    Null,
}

#[derive(Clone, Copy, PartialEq)]
enum Container {
    /// `expecting_key` is what tells a member name from a string value.
    Object {
        expecting_key: bool,
    },
    Array,
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    /// Expecting a value, or a member name inside an object.
    Value,
    InString,
    Escape,
    /// Collecting the four hex digits of a `\u` escape.
    Unicode(u8),
    InNumber,
    /// Collecting `true`, `false` or `null`.
    InLiteral,
    /// A value has ended; expecting a comma or a closing bracket.
    AfterValue,
    ExpectColon,
}

pub struct Scanner {
    state: State,
    stack: heapless::Vec<Container, MAX_DEPTH>,
    buffer: heapless::Vec<u8, MAX_STRING>,
    /// Accumulates a `\uXXXX` escape.
    code_point: u32,
    /// A high surrogate awaiting its partner.
    pending_surrogate: Option<u16>,
    /// Set once the outermost value has been closed.
    done: bool,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub const fn new() -> Self {
        Self {
            state: State::Value,
            stack: heapless::Vec::new(),
            buffer: heapless::Vec::new(),
            code_point: 0,
            pending_surrogate: None,
            done: false,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.state = State::Value;
        self.stack.clear();
        self.buffer.clear();
        self.code_point = 0;
        self.pending_surrogate = None;
        self.done = false;
    }

    /// Whether the document has been closed.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Feed bytes, emitting a token for each one completed.
    ///
    /// Chunks may split anywhere, including inside a string, a number or an
    /// escape sequence.
    pub fn push(
        &mut self,
        bytes: &[u8],
        mut on_token: impl FnMut(Token<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            // A number or a literal ends at the first byte that is not part of
            // it, and that byte still has to be processed — so `advance` says
            // whether it was consumed.
            let advance = self.step(byte, &mut on_token)?;
            if advance {
                index += 1;
            }
        }
        Ok(())
    }

    /// Finish the document, flushing a trailing number or literal.
    ///
    /// A bare number at the top level — which nothing here produces, but which
    /// is legal JSON — has no delimiter after it.
    pub fn finish(
        &mut self,
        mut on_token: impl FnMut(Token<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self.state {
            State::InNumber => self.emit_number(&mut on_token)?,
            State::InLiteral => self.emit_literal(&mut on_token)?,
            State::Value | State::AfterValue => {}
            // Anything else means the document stopped mid-token.
            _ => return Err(Error::Json),
        }
        if !self.stack.is_empty() {
            return Err(Error::Json);
        }
        Ok(())
    }

    /// Process one byte. Returns whether it was consumed.
    fn step(
        &mut self,
        byte: u8,
        on_token: &mut impl FnMut(Token<'_>) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        match self.state {
            State::Value => {
                if byte.is_ascii_whitespace() {
                    return Ok(true);
                }
                match byte {
                    b'{' => {
                        self.open(Container::Object {
                            expecting_key: true,
                        })?;
                        on_token(Token::StartObject)?;
                    }
                    b'[' => {
                        self.open(Container::Array)?;
                        on_token(Token::StartArray)?;
                    }
                    // An empty container closes without ever holding a value.
                    b'}' | b']' => return self.close(byte, on_token).map(|()| true),
                    b'"' => {
                        self.buffer.clear();
                        self.state = State::InString;
                    }
                    b'-' | b'0'..=b'9' => {
                        self.buffer.clear();
                        self.push_byte(byte)?;
                        self.state = State::InNumber;
                    }
                    b't' | b'f' | b'n' => {
                        self.buffer.clear();
                        self.push_byte(byte)?;
                        self.state = State::InLiteral;
                    }
                    _ => return Err(Error::Json),
                }
                Ok(true)
            }

            State::InString => {
                match byte {
                    b'"' => {
                        // A high surrogate with no partner is not a character,
                        // and letting it through would produce a string that is
                        // silently missing one.
                        if self.pending_surrogate.is_some() {
                            return Err(Error::Json);
                        }
                        let is_key = matches!(
                            self.stack.last(),
                            Some(Container::Object {
                                expecting_key: true
                            })
                        );
                        let text = core::str::from_utf8(&self.buffer).map_err(|_| Error::Json)?;
                        if is_key {
                            on_token(Token::Key(text))?;
                            self.set_expecting_key(false);
                            self.state = State::ExpectColon;
                        } else {
                            on_token(Token::Str(text))?;
                            self.state = State::AfterValue;
                        }
                    }
                    b'\\' => self.state = State::Escape,
                    // Unescaped control characters are not legal in a JSON
                    // string, and accepting them would let a malformed document
                    // through unnoticed.
                    0x00..=0x1f => return Err(Error::Json),
                    _ => self.push_byte(byte)?,
                }
                Ok(true)
            }

            State::Escape => {
                let literal = match byte {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        self.code_point = 0;
                        self.state = State::Unicode(0);
                        return Ok(true);
                    }
                    _ => return Err(Error::Json),
                };
                self.push_byte(literal)?;
                self.state = State::InString;
                Ok(true)
            }

            State::Unicode(seen) => {
                let digit = match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => return Err(Error::Json),
                };
                self.code_point = self.code_point << 4 | digit as u32;
                if seen < 3 {
                    self.state = State::Unicode(seen + 1);
                    return Ok(true);
                }
                self.finish_escape()?;
                Ok(true)
            }

            State::InNumber => {
                if matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                    self.push_byte(byte)?;
                    return Ok(true);
                }
                self.emit_number(on_token)?;
                // Not consumed: this byte delimits the number and still has to
                // be read as whatever it is.
                Ok(false)
            }

            State::InLiteral => {
                if byte.is_ascii_alphabetic() {
                    self.push_byte(byte)?;
                    return Ok(true);
                }
                self.emit_literal(on_token)?;
                Ok(false)
            }

            State::AfterValue => {
                if byte.is_ascii_whitespace() {
                    return Ok(true);
                }
                match byte {
                    b',' => {
                        if let Some(Container::Object { .. }) = self.stack.last() {
                            self.set_expecting_key(true);
                        }
                        self.state = State::Value;
                        Ok(true)
                    }
                    b'}' | b']' => self.close(byte, on_token).map(|()| true),
                    _ => Err(Error::Json),
                }
            }

            State::ExpectColon => {
                if byte.is_ascii_whitespace() {
                    return Ok(true);
                }
                if byte != b':' {
                    return Err(Error::Json);
                }
                self.state = State::Value;
                Ok(true)
            }
        }
    }

    /// Turn a completed `\uXXXX` into UTF-8, pairing surrogates.
    fn finish_escape(&mut self) -> Result<(), Error> {
        let value = self.code_point as u16;
        // A code point outside the basic plane is written as two escapes, and
        // neither half is a character on its own.
        if (0xd800..0xdc00).contains(&value) {
            self.pending_surrogate = Some(value);
            self.state = State::InString;
            return Ok(());
        }
        let scalar = if (0xdc00..0xe000).contains(&value) {
            let high = self.pending_surrogate.take().ok_or(Error::Json)?;
            0x1_0000 + ((high as u32 - 0xd800) << 10) + (value as u32 - 0xdc00)
        } else {
            if self.pending_surrogate.take().is_some() {
                return Err(Error::Json);
            }
            value as u32
        };
        let character = char::from_u32(scalar).ok_or(Error::Json)?;
        let mut encoded = [0u8; 4];
        for byte in character.encode_utf8(&mut encoded).as_bytes() {
            self.push_byte(*byte)?;
        }
        self.state = State::InString;
        Ok(())
    }

    fn emit_number(
        &mut self,
        on_token: &mut impl FnMut(Token<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let text = core::str::from_utf8(&self.buffer).map_err(|_| Error::Json)?;
        let token = match text.parse::<i64>() {
            Ok(value) => Token::Int(value),
            Err(_) => Token::OtherNumber,
        };
        on_token(token)?;
        self.state = State::AfterValue;
        Ok(())
    }

    fn emit_literal(
        &mut self,
        on_token: &mut impl FnMut(Token<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let token = match self.buffer.as_slice() {
            b"true" => Token::Bool(true),
            b"false" => Token::Bool(false),
            b"null" => Token::Null,
            _ => return Err(Error::Json),
        };
        on_token(token)?;
        self.state = State::AfterValue;
        Ok(())
    }

    fn open(&mut self, container: Container) -> Result<(), Error> {
        self.stack
            .push(container)
            .map_err(|_| Error::Full(CapacityError::ParserDepth))?;
        self.state = State::Value;
        Ok(())
    }

    fn close(
        &mut self,
        byte: u8,
        on_token: &mut impl FnMut(Token<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let container = self.stack.pop().ok_or(Error::Json)?;
        match (byte, container) {
            (b'}', Container::Object { .. }) => on_token(Token::EndObject)?,
            (b']', Container::Array) => on_token(Token::EndArray)?,
            // A bracket closing the wrong kind of container means the document
            // is malformed, not that the nesting can be guessed.
            _ => return Err(Error::Json),
        }
        self.state = State::AfterValue;
        if self.stack.is_empty() {
            self.done = true;
        }
        Ok(())
    }

    fn set_expecting_key(&mut self, expecting: bool) {
        if let Some(Container::Object { expecting_key }) = self.stack.last_mut() {
            *expecting_key = expecting;
        }
    }

    /// Add a byte to the token being built.
    ///
    /// Overflow is an error rather than a truncation: a silently shortened node
    /// key parses as nothing, and a shortened name is displayed as fact.
    fn push_byte(&mut self, byte: u8) -> Result<(), Error> {
        self.buffer
            .push(byte)
            .map_err(|_| Error::Full(CapacityError::String))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render a document's tokens as short strings, feeding it `chunk` bytes at
    /// a time.
    fn tokens(document: &str, chunk: usize) -> heapless::Vec<heapless::String<64>, 64> {
        let mut out = heapless::Vec::new();
        let mut scanner = Scanner::new();
        let mut record = |token: Token<'_>| -> Result<(), Error> {
            use core::fmt::Write as _;
            let mut text = heapless::String::<64>::new();
            match token {
                Token::StartObject => text.push_str("{").unwrap(),
                Token::EndObject => text.push_str("}").unwrap(),
                Token::StartArray => text.push_str("[").unwrap(),
                Token::EndArray => text.push_str("]").unwrap(),
                Token::Key(k) => write!(text, "k:{k}").unwrap(),
                Token::Str(s) => write!(text, "s:{s}").unwrap(),
                Token::Int(i) => write!(text, "i:{i}").unwrap(),
                Token::OtherNumber => text.push_str("number").unwrap(),
                Token::Bool(b) => write!(text, "b:{b}").unwrap(),
                Token::Null => text.push_str("null").unwrap(),
            }
            out.push(text).unwrap();
            Ok(())
        };
        for piece in document.as_bytes().chunks(chunk.max(1)) {
            scanner.push(piece, &mut record).unwrap();
        }
        scanner.finish(&mut record).unwrap();
        out
    }

    fn joined(document: &str, chunk: usize) -> heapless::String<512> {
        let mut text = heapless::String::new();
        for token in tokens(document, chunk) {
            if !text.is_empty() {
                text.push(' ').unwrap();
            }
            text.push_str(&token).unwrap();
        }
        text
    }

    #[test]
    fn scans_the_shape_a_map_response_has() {
        let document = r#"{"Node":{"ID":3,"Online":true},"Peers":[{"Key":"nodekey:aa"}],"X":null}"#;
        assert_eq!(
            joined(document, usize::MAX).as_str(),
            "{ k:Node { k:ID i:3 k:Online b:true } k:Peers [ { k:Key s:nodekey:aa } ] k:X null }"
        );
    }

    /// The property everything else depends on: chunk boundaries are arbitrary,
    /// because they come from HTTP/2 framing and have nothing to do with JSON.
    #[test]
    fn the_tokens_are_the_same_however_the_input_is_split() {
        let document = r#"{"a":[1,-2,3000],"b":{"c":"x y","d":false},"e":null,"f":"é\n"}"#;
        let reference = joined(document, usize::MAX);
        for chunk in 1..=document.len() {
            assert_eq!(
                joined(document, chunk),
                reference,
                "split every {chunk} bytes"
            );
        }
    }

    #[test]
    fn a_key_is_told_from_a_string_by_position_alone() {
        // The only difference in JSON, and getting it wrong makes every value
        // look like a field name.
        assert_eq!(joined(r#"{"a":"b"}"#, 1).as_str(), "{ k:a s:b }");
        assert_eq!(joined(r#"["a","b"]"#, 1).as_str(), "[ s:a s:b ]");
        // Nested: the inner object's first string is a key again.
        assert_eq!(
            joined(r#"{"a":{"b":"c"}}"#, 1).as_str(),
            "{ k:a { k:b s:c } }"
        );
    }

    #[test]
    fn escapes_are_decoded_including_surrogate_pairs() {
        assert_eq!(joined(r#"["a\"b"]"#, 1).as_str(), "[ s:a\"b ]");
        assert_eq!(joined(r#"["a\\b"]"#, 1).as_str(), "[ s:a\\b ]");
        // The solidus escape is optional on output but must be accepted.
        assert_eq!(joined(r#"["a\/b"]"#, 1).as_str(), "[ s:a/b ]");
        assert_eq!(joined(r#"["a\tb"]"#, 1).as_str(), "[ s:a\tb ]");
        assert_eq!(joined(r#"["café"]"#, 1).as_str(), "[ s:café ]");
        // A code point outside the basic plane arrives as two escapes, and
        // neither half is a character on its own.
        assert_eq!(joined(r#"["💬"]"#, 1).as_str(), "[ s:💬 ]");
    }

    #[test]
    fn numbers_end_at_their_delimiter() {
        // A number has no terminator of its own, so the byte that ends it must
        // still be read as whatever it is.
        assert_eq!(joined(r#"[1,23]"#, 1).as_str(), "[ i:1 i:23 ]");
        assert_eq!(joined(r#"{"a":1}"#, 1).as_str(), "{ k:a i:1 }");
        // Fractions are legal JSON; nothing we read uses one, so it is
        // discarded rather than rejected.
        assert_eq!(joined(r#"[1.5]"#, 1).as_str(), "[ number ]");
    }

    #[test]
    fn empty_containers_are_scanned() {
        assert_eq!(
            joined(r#"{"a":[],"b":{}}"#, 1).as_str(),
            "{ k:a [ ] k:b { } }"
        );
    }

    #[test]
    fn malformed_documents_are_refused() {
        fn scan(document: &str) -> Result<(), Error> {
            let mut scanner = Scanner::new();
            scanner.push(document.as_bytes(), |_| Ok(()))?;
            scanner.finish(|_| Ok(()))
        }

        // Mismatched brackets must not be guessed at.
        assert_eq!(scan(r#"{"a":1]"#), Err(Error::Json));
        assert_eq!(scan(r#"[1,2}"#), Err(Error::Json));
        // Unterminated.
        assert_eq!(scan(r#"{"a":"#), Err(Error::Json));
        assert_eq!(scan(r#"{"a"#), Err(Error::Json));
        // A missing colon, and a stray one.
        assert_eq!(scan(r#"{"a" 1}"#), Err(Error::Json));
        // Literals must be spelled correctly.
        assert_eq!(scan(r#"[tru]"#), Err(Error::Json));
        // A raw control character inside a string is not legal.
        assert_eq!(scan("[\"a\nb\"]"), Err(Error::Json));
        // A lone surrogate is not a character.
        assert_eq!(scan(r#"["\ud83d"]"#), Err(Error::Json));
    }

    #[test]
    fn a_string_longer_than_the_buffer_is_refused_rather_than_truncated() {
        // A truncated node key parses as nothing; a truncated name would be
        // displayed as fact.
        let mut document = heapless::String::<{ MAX_STRING * 2 }>::new();
        document.push_str("[\"").unwrap();
        for _ in 0..MAX_STRING + 1 {
            document.push('x').unwrap();
        }
        document.push_str("\"]").unwrap();

        let mut scanner = Scanner::new();
        assert_eq!(
            scanner.push(document.as_bytes(), |_| Ok(())),
            Err(Error::Full(CapacityError::String))
        );
    }

    #[test]
    fn nesting_deeper_than_the_stack_is_refused() {
        let mut document = heapless::String::<128>::new();
        for _ in 0..MAX_DEPTH + 1 {
            document.push('[').unwrap();
        }
        let mut scanner = Scanner::new();
        assert_eq!(
            scanner.push(document.as_bytes(), |_| Ok(())),
            Err(Error::Full(CapacityError::ParserDepth))
        );
    }
}
