//! The Linux harness uses the same transport-independent HTTP/2 session as
//! firmware; only its TCP/TLS adapter is platform-specific.

pub type H2Error = tailfeather::control::transport::Error<crate::net::NetError>;
pub type Http2<'r> = tailfeather::control::transport::Http2<crate::net::TcpStream<'r>>;
