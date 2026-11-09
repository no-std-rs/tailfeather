# Loopback lab TLS fixture

Test-only PKI for the unprivileged live labs (`//tests/lab:taildrop_live`): a
lab CA (`ca.pem`, `ca.der`) and a server certificate for `IP:127.0.0.1`
(`server.pem`, `server.key`) it signed, both valid for 20 years so the lab
needs no certificate tooling at run time. The CA's private key was discarded
after signing.

The lab terminates TLS for Headscale control and DERP on loopback with this
certificate, because the Tailfeather reactor only speaks HTTPS control. The
server key is public by design; nothing outside the lab may trust this CA.
