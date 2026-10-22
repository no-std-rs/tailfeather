use std::{io, sync::Arc};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self,
        pki_types::{CertificateDer, ServerName},
    },
};
pub struct Stream(tokio_rustls::client::TlsStream<tokio::net::TcpStream>);
pub async fn connect(
    socket: crate::net::TcpStream,
    host: &str,
    ca: &[u8],
    _: &mut [u8],
    _: &mut [u8],
) -> io::Result<Stream> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if !ca.is_empty() {
        roots
            .add(CertificateDer::from(ca.to_vec()))
            .map_err(|_| io::Error::other("invalid control CA"))?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::other("invalid TLS hostname"))?;
    TlsConnector::from(Arc::new(config))
        .connect(name, socket.0)
        .await
        .map(Stream)
}
impl embedded_io_async::ErrorType for Stream {
    type Error = io::Error;
}
impl embedded_io_async::Read for Stream {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        tokio::io::AsyncReadExt::read(&mut self.0, out).await
    }
}
impl embedded_io_async::Write for Stream {
    async fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        tokio::io::AsyncWriteExt::write(&mut self.0, input).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        tokio::io::AsyncWriteExt::flush(&mut self.0).await
    }
}
