# ESP exit-lab TLS fixture

Test-only PKI for `//tests/lab:esp_exit_tls`: a lab CA (`ca.pem`, `ca.der`) and
a `control.lab` server certificate (`control.pem`, `control.key`) it signed,
both valid for 20 years so the lab needs no certificate tooling at run time.
The CA's private key was discarded after signing.

The CA is pinned only into the `esp_gateway_firmware_emulab_tls` lab image. The
server key is public by design; nothing outside the lab may trust this CA.
