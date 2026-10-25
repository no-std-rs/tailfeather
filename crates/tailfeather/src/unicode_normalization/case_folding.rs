use super::case_folding_tables::{FULL, SIMPLE};

/// Default, locale-independent Unicode 17 full folding, with at most three
/// output scalars per input scalar. All state is bounded and borrowed.
pub(crate) struct CaseFold<I> {
    input: I,
    pending: core::str::Chars<'static>,
}

impl<I: Iterator<Item = char>> CaseFold<I> {
    pub(crate) fn new(input: I) -> Self {
        Self {
            input,
            pending: "".chars(),
        }
    }

    pub(crate) fn get_ref(&self) -> &I {
        &self.input
    }
}

impl<I: Iterator<Item = char>> Iterator for CaseFold<I> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if let Some(value) = self.pending.next() {
            return Some(value);
        }
        let value = self.input.next()?;
        if let Ok(index) = FULL.binary_search_by_key(&value, |&(key, _)| key) {
            self.pending = FULL[index].1.chars();
            return self.pending.next();
        }
        let code = value as u32;
        let index = SIMPLE.partition_point(|&(start, _, _, _)| start <= code);
        if index != 0 {
            let (start, end, step, delta) = SIMPLE[index - 1];
            if code <= end && (code - start).is_multiple_of(u32::from(step)) {
                // The generated UCD mappings always produce Unicode scalars.
                return char::from_u32((i64::from(code) + i64::from(delta)) as u32);
            }
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_folding_matches_every_unicode_17_mapping() {
        let fixture = include_str!("CaseFolding-17.0.0.txt");
        let mut expected = std::collections::BTreeMap::new();
        for line in fixture.lines() {
            let fields: std::vec::Vec<_> = line.split('#').next().unwrap().split(';').collect();
            if fields.len() < 3 || !matches!(fields[1].trim(), "C" | "F") {
                continue;
            }
            let input = char::from_u32(u32::from_str_radix(fields[0].trim(), 16).unwrap()).unwrap();
            let output: std::string::String = fields[2]
                .split_whitespace()
                .map(|code| char::from_u32(u32::from_str_radix(code, 16).unwrap()).unwrap())
                .collect();
            expected.insert(input, output);
        }
        // Check every unmapped scalar too: stride ranges must never fold gaps.
        for value in (0..=0x10ffff).filter_map(char::from_u32) {
            let actual: std::string::String = CaseFold::new(core::iter::once(value)).collect();
            let identity: std::string::String = core::iter::once(value).collect();
            assert_eq!(
                actual,
                *expected.get(&value).unwrap_or(&identity),
                "{value:?}"
            );
        }
        assert_eq!(
            CaseFold::new("Iİı".chars()).collect::<std::string::String>(),
            "ii\u{307}ı"
        );
    }
}
