//! HPACK's static table (RFC 7541 Appendix A).
//!
//! Sixty-one entries every HTTP/2 endpoint is assumed to know. Index 0 is
//! unused, so the table is 1-based, and dynamic-table entries continue from 62 —
//! an off-by-one here shifts every header the server sends.

/// `(name, value)`. An empty value means the entry names a header whose value
/// must be given literally.
pub const ENTRIES: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// The first index a dynamic-table entry can take.
pub const DYNAMIC_BASE: usize = ENTRIES.len() + 1;

/// Look up a 1-based static index.
pub fn get(index: usize) -> Option<(&'static str, &'static str)> {
    if index == 0 {
        return None;
    }
    ENTRIES.get(index - 1).copied()
}

/// Find an entry matching both name and value, for the most compact encoding.
pub fn find(name: &str, value: &str) -> Option<usize> {
    ENTRIES
        .iter()
        .position(|(n, v)| *n == name && *v == value)
        .map(|i| i + 1)
}

/// Find an entry matching the name alone.
pub fn find_name(name: &str) -> Option<usize> {
    ENTRIES.iter().position(|(n, _)| *n == name).map(|i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_the_length_and_shape_the_rfc_defines() {
        assert_eq!(ENTRIES.len(), 61);
        assert_eq!(DYNAMIC_BASE, 62);
        // Boundaries, where an off-by-one would show up.
        assert_eq!(get(1), Some((":authority", "")));
        assert_eq!(get(2), Some((":method", "GET")));
        assert_eq!(get(61), Some(("www-authenticate", "")));
        assert_eq!(get(62), None);
        // Index 0 is not an entry: the encoding uses it as a marker.
        assert_eq!(get(0), None);
    }

    #[test]
    fn lookups_find_the_indices_the_rfc_examples_use() {
        assert_eq!(find(":method", "GET"), Some(2));
        assert_eq!(find(":path", "/"), Some(4));
        assert_eq!(find(":scheme", "http"), Some(6));
        assert_eq!(find(":status", "200"), Some(8));
        assert_eq!(find_name(":authority"), Some(1));
        assert_eq!(find_name("content-type"), Some(31));
        assert_eq!(find(":method", "PUT"), None);
    }
}
