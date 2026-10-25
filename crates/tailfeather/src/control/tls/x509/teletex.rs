//! Bounded decoding of the basic T.61 (1988) graphic repertoire for X.509 DNs.
//!
//! Mapping: ITU-T T.61, Figure 2, Tables 1–2 and Annex B, Figure B-1:
//! <https://www.itu.int/rec/T-REC-T.61-198811-S/en>
//! Prefix accents are emitted after their base as Unicode combining scalars.
//! Optional national repertoires, escape/shift sequences and presentation
//! controls are unsupported and rejected, never interpreted as UTF-8/Latin-1.

#[derive(Clone)]
pub(super) struct TeletexChars<'a> {
    remaining: &'a [u8],
    pending: [char; 2],
    pending_len: usize,
    pending_offset: usize,
}

impl<'a> TeletexChars<'a> {
    pub(super) fn new(input: &'a [u8]) -> Option<Self> {
        let result = Self {
            remaining: input,
            pending: ['\0'; 2],
            pending_len: 0,
            pending_offset: 0,
        };
        // Validate the complete byte sequence before equality can terminate
        // early. No invalid suffix may disappear behind iterator exhaustion.
        let mut check = result.clone();
        while check.next_checked().ok()?.is_some() {}
        Some(result)
    }

    fn take_byte(&mut self) -> Result<u8, ()> {
        let (&value, rest) = self.remaining.split_first().ok_or(())?;
        self.remaining = rest;
        Ok(value)
    }

    fn next_checked(&mut self) -> Result<Option<char>, ()> {
        if self.pending_offset < self.pending_len {
            let value = self.pending[self.pending_offset];
            self.pending_offset += 1;
            return Ok(Some(value));
        }
        self.pending_len = 0;
        self.pending_offset = 0;
        if self.remaining.is_empty() {
            return Ok(None);
        }
        let mut byte = self.take_byte()?;
        let underline = byte == 0xcc;
        if underline {
            byte = self.take_byte()?;
        }
        let value = if let Some((combining, spacing, letters)) = accent(byte) {
            let base = self.take_byte()?;
            if base == b' ' {
                spacing
            } else {
                if !letters.contains(&base) {
                    return Err(());
                }
                self.pending[0] = combining;
                self.pending_len = 1;
                char::from(base)
            }
        } else {
            graphic(byte).ok_or(())?
        };
        if underline {
            self.pending[self.pending_len] = '\u{332}';
            self.pending_len += 1;
        }
        Ok(Some(value))
    }
}

impl Iterator for TeletexChars<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        // Construction validates the complete immutable input.
        self.next_checked().ok().flatten()
    }
}

fn accent(byte: u8) -> Option<(char, char, &'static [u8])> {
    Some(match byte {
        0xc1 => ('\u{300}', '`', b"AEIOUaeiou"),
        0xc2 => ('\u{301}', '´', b"ACEILNORSUYZacegilnorsuyz"),
        0xc3 => ('\u{302}', '^', b"ACEGHIJOSUWYaceghijosuwy"),
        0xc4 => ('\u{303}', '~', b"AINOUainou"),
        0xc5 => ('\u{304}', '¯', b"AEIOUaeiou"),
        0xc6 => ('\u{306}', '˘', b"AGUagu"),
        0xc7 => ('\u{307}', '˙', b"CEGIZcegz"),
        // 0xc9 is the deprecated 1980 umlaut code retained by T.61 (1988).
        0xc8 | 0xc9 => ('\u{308}', '¨', b"AEIOUYaeiouy"),
        0xca => ('\u{30a}', '˚', b"AUau"),
        0xcb => ('\u{327}', '¸', b"CGKLNRSTcklnrst"),
        0xcd => ('\u{30b}', '˝', b"OUou"),
        0xce => ('\u{328}', '˛', b"AEIUaeiu"),
        0xcf => ('\u{30c}', 'ˇ', b"CDELNRSTZcdelnrstz"),
        _ => return None,
    })
}

fn graphic(byte: u8) -> Option<char> {
    Some(match byte {
        // T.61 Figure 2 note 4: receive the legacy primary aliases for
        // NUMBER SIGN and CURRENCY SIGN, too. 0x24 is not DOLLAR SIGN.
        0x24 | 0xa8 => '¤',
        0x20..=0x5b | 0x5d | 0x5f | 0x61..=0x7a | 0x7c => char::from(byte),
        0xa1 => '¡',
        0xa2 => '¢',
        0xa3 => '£',
        0xa4 => '$',
        0xa5 => '¥',
        0xa6 => '#',
        0xa7 => '§',
        0xab => '«',
        0xb0 => '°',
        0xb1 => '±',
        0xb2 => '²',
        0xb3 => '³',
        0xb4 => '×',
        0xb5 => 'µ',
        0xb6 => '¶',
        0xb7 => '·',
        0xb8 => '÷',
        0xbb => '»',
        0xbc => '¼',
        0xbd => '½',
        0xbe => '¾',
        0xbf => '¿',
        0xe0 => 'Ω',
        0xe1 => 'Æ',
        // RFC 1345's T.61 table names 0xe2 D- (ETH), not D/ (D WITH
        // STROKE). T.61 LD62 shares the printed glyph, but Unicode folding
        // distinguishes the two letters: ETH folds to U+00F0, not U+0111.
        0xe2 => 'Ð',
        0xe3 => 'ª',
        0xe4 => 'Ħ',
        0xe6 => 'Ĳ',
        0xe7 => 'Ŀ',
        0xe8 => 'Ł',
        0xe9 => 'Ø',
        0xea => 'Œ',
        0xeb => 'º',
        0xec => 'Þ',
        0xed => 'Ŧ',
        0xee => 'Ŋ',
        0xef => 'ŉ',
        0xf0 => 'ĸ',
        0xf1 => 'æ',
        0xf2 => 'đ',
        0xf3 => 'ð',
        0xf4 => 'ħ',
        0xf5 => 'ı',
        0xf6 => 'ĳ',
        0xf7 => 'ŀ',
        0xf8 => 'ł',
        0xf9 => 'ø',
        0xfa => 'œ',
        0xfb => 'ß',
        0xfc => 'þ',
        0xfd => 'ŧ',
        0xfe => 'ŋ',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphic_repertoire_and_prefix_diacritics_decode_without_allocation() {
        let cases: &[(&[u8], &str)] = &[
            (b"Example CA", "Example CA"),
            (b"Root|CA", "Root|CA"),
            (&[0xc1, b'A'], "A\u{300}"),
            (&[0xc2, b'e'], "e\u{301}"),
            (&[0xc2, b'g'], "g\u{301}"),
            (&[0xc3, b'C'], "C\u{302}"),
            (&[0xc4, b'n'], "n\u{303}"),
            (&[0xc5, b'E'], "E\u{304}"),
            (&[0xc6, b'G'], "G\u{306}"),
            (&[0xc7, b'Z'], "Z\u{307}"),
            (&[0xcc, 0xc8, b'u'], "u\u{308}\u{332}"),
            // T.61 §3.2.3.9 allows underline on any repertoire graphic,
            // including Space; the narrower DCE/XDS profile is not used.
            (&[0xcc, 0x24], "¤\u{332}"),
            (&[0xcc, 0xe1], "Æ\u{332}"),
            (&[0xcc, b' '], " \u{332}"),
            (&[0xc9, b'A'], "A\u{308}"),
            (&[0xca, b'a'], "a\u{30a}"),
            (&[0xcb, b'T'], "T\u{327}"),
            (&[0xcb, b'G'], "G\u{327}"),
            (&[0xcd, b'O'], "O\u{30b}"),
            (&[0xce, b'I'], "I\u{328}"),
            (&[0xcf, b'L'], "L\u{30c}"),
            (&[0xc1, b' '], "`"),
            (&[0xc2, b' '], "´"),
            (&[0xa3, 0xe1, 0xe2, 0xf3, 0xfb], "£ÆÐðß"),
            (&[b'#', 0xa6, b'$', 0xa8, 0xa4], "##¤¤$"),
        ];
        for &(input, expected) in cases {
            assert!(
                TeletexChars::new(input).unwrap().eq(expected.chars()),
                "{input:x?}"
            );
        }
    }

    #[test]
    fn invalid_truncated_and_optional_encodings_are_rejected() {
        let cases: &[&[u8]] = &[
            &[0xc2],
            &[0xc2, b'b'],
            &[0xc2, b'G'],
            &[0xcb, b'g'],
            &[0xc2, b'e', 0xc2],
            &[0xc0, b'A'],
            &[0xc7, b'i'],
            &[0xcc],
            &[0xcc, 0xcc, b'A'],
            &[0xcc, 0xc2],
            &[0xc2, 0xc8, b'e'],
            &[0xff],
            &[0xa0],
            &[0xd0],
            b"\\",
            &[0],
            &[0x1b, b'(', b'B'],
            &[0xc3, 0xa9], // UTF-8 é is not a valid T.61 accent/base pair.
        ];
        for input in cases {
            assert!(TeletexChars::new(input).is_none(), "{input:x?}");
        }
    }
}
