# Local zssh patch

Source: the published `zssh` 0.4.2 crate from
<https://static.crates.io/crates/zssh/zssh-0.4.2.crate>, by Thomas Bénéteau,
licensed under MIT. Upstream: <https://github.com/TomCrypto/zssh>.
Cargo publication is disabled for this local copy.

We retain this crypto generation to share Tailfeather's SHA-256, Curve25519,
ChaCha20, and Poly1305 dependencies. Version 0.5's upgraded crypto would introduce
a second set of implementations. The wrapper remains a separate thin crate.

Local changes:

- Backport the window-aware copying write path from zssh 0.5.0: wait for space
  **before** copying application data into the shared packet buffer, split to
  the available window, and report a closed channel. Otherwise processing a
  window-adjust/rekey packet can overwrite the response being retried.
- Reject additional session channels instead of queuing work the application
  will never serve.
- Reject channel opens with a zero maximum packet size.
- Finish both halves of the channel-close handshake before returning to the
  caller. Closing TCP earlier can truncate buffered output in older OpenSSH
  clients. A received close is acknowledged without sending more channel data.
- Acquire the zero-copy writer asynchronously, before exposing its buffer, and
  cap the buffer to available window credit. Sending never polls into a filled
  payload. This local API change requires `channel.stdout().await?` (likewise
  `stderr` and `writer`); the Tailfeather wrapper uses copying writes.

`//crates/tailfeather-ssh:openssh_test` covers a response larger than OpenSSH's
initial receive window, short underlying writes, and normal console operation.
