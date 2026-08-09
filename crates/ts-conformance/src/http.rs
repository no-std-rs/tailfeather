//! A minimal blocking HTTP/1.1 GET, so the suite needs no HTTP dependency.
//!
//! The lab speaks plain HTTP, and the only requests made here are simple GETs
//! against it. Pulling in an HTTP client and tracking its API churn would buy
//! nothing. Talking to a TLS control server — which real Tailscale requires —
//! is a separate problem the suite reports as unimplemented rather than
//! papering over.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct Response {
    pub status: u16,
    pub body: String,
}

/// Fetch `url`, which must be `http://host:port/path`.
pub fn get(url: &str) -> Result<Response, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only plain http is supported here, got {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };

    let mut stream = TcpStream::connect(authority).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("timeout: {e}"))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&raw).into_owned();

    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed response: no header terminator".to_string())?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "malformed response: no status code".to_string())?;

    Ok(Response {
        status,
        body: body.to_string(),
    })
}
