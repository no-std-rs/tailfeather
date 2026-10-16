//! Parsing and stable hashing of a control-server authority.

use heapless::String;

use crate::tunnel::crypto;

/// Maximum control/DERP hostname length retained by the allocation-free stack.
pub const HOST_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Scheme,
    Host,
    Path,
    Port,
    Capacity,
}

/// A normalized HTTPS authority suitable for DNS/TCP and state binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    host: String<HOST_CAPACITY>,
    port: u16,
    secure: bool,
    digest: [u8; 16],
}

impl Authority {
    /// Parse an HTTPS URL. HTTP is accepted only when `allow_plaintext` is
    /// explicitly true, which firmware exposes solely through its test-only
    /// feature.
    pub fn parse(url: &str, allow_plaintext: bool) -> Result<Self, Error> {
        let (secure, rest, default_port) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest, 443)
        } else if allow_plaintext {
            let rest = url.strip_prefix("http://").ok_or(Error::Scheme)?;
            (false, rest, 80)
        } else {
            return Err(Error::Scheme);
        };

        let authority = match rest.find('/') {
            Some(index) if rest[index..].chars().all(|c| c == '/') => &rest[..index],
            Some(_) => return Err(Error::Path),
            None => rest,
        };
        if authority.is_empty()
            || authority.contains('@')
            || authority.contains('?')
            || authority.contains('#')
        {
            return Err(Error::Host);
        }
        // Bracketed IPv6 is deliberately unsupported by the IPv4 milestone.
        if authority.starts_with('[') {
            return Err(Error::Host);
        }
        let (host_text, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| Error::Port)?;
                if port == 0 {
                    return Err(Error::Port);
                }
                (host, port)
            }
            None => (authority, default_port),
        };
        if !valid_host(host_text) {
            return Err(Error::Host);
        }
        let mut host = String::<HOST_CAPACITY>::new();
        for byte in host_text.bytes() {
            host.push((byte as char).to_ascii_lowercase())
                .map_err(|_| Error::Capacity)?;
        }

        let mut normalized = String::<160>::new();
        normalized
            .push_str(if secure { "https://" } else { "http://" })
            .map_err(|_| Error::Capacity)?;
        normalized
            .push_str(host.as_str())
            .map_err(|_| Error::Capacity)?;
        if port != default_port {
            use core::fmt::Write as _;
            write!(normalized, ":{port}").map_err(|_| Error::Capacity)?;
        }
        let hash = crypto::hash(&[normalized.as_bytes()]);
        let mut digest = [0; 16];
        digest.copy_from_slice(&hash[..16]);
        Ok(Self {
            host,
            port,
            secure,
            digest,
        })
    }

    pub fn host(&self) -> &str {
        self.host.as_str()
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn is_secure(&self) -> bool {
        self.secure
    }
    pub fn digest(&self) -> [u8; 16] {
        self.digest
    }
}

fn valid_host(host: &str) -> bool {
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return host.parse::<core::net::Ipv4Addr>().is_ok();
    }
    !host.is_empty()
        && host.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_is_stable() {
        let a = Authority::parse("https://Control.Example:443/", false).unwrap();
        let b = Authority::parse("https://control.example", false).unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.host(), "control.example");
        assert_eq!(a.port(), 443);
    }

    #[test]
    fn authority_changes_are_detectable() {
        let a = Authority::parse("https://one.example", false).unwrap();
        let b = Authority::parse("https://two.example", false).unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn plaintext_and_paths_fail_closed() {
        assert_eq!(
            Authority::parse("http://headscale.test", false),
            Err(Error::Scheme)
        );
        assert!(Authority::parse("http://headscale.test:8080", true).is_ok());
        assert_eq!(
            Authority::parse("https://example.test/api", false),
            Err(Error::Path)
        );
        for invalid in [
            "https://two..labels",
            "https://-leading.example",
            "https://trailing-.example",
            "https://a................................................................com",
        ] {
            assert_eq!(Authority::parse(invalid, false), Err(Error::Host));
        }
        assert!(Authority::parse("https://192.0.2.1", false).is_ok());
    }
}
