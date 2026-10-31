# Changelog

## [0.2.1](https://github.com/no-std-rs/tailfeather/compare/tailfeather-v0.2.0...tailfeather-v0.2.1) (2026-10-31)


### Bug Fixes

* **runtime:** preserve map progress and relay packet order ([#30](https://github.com/no-std-rs/tailfeather/issues/30)) ([c8f7ad9](https://github.com/no-std-rs/tailfeather/commit/c8f7ad964c96ec175b00cab6a4a7aa0671f9de5f))

## [0.2.0](https://github.com/no-std-rs/tailfeather/compare/tailfeather-v0.1.0...tailfeather-v0.2.0) (2026-10-26)


### Features

* **web:** forward remote loopback links and OAuth callbacks ([#27](https://github.com/no-std-rs/tailfeather/issues/27)) ([29eb1ef](https://github.com/no-std-rs/tailfeather/commit/29eb1ef93fdd4df1dc5f1d99e8b0a898e0abc69f))
* **gateway:** implement bounded IPv6 exit forwarding ([#25](https://github.com/no-std-rs/tailfeather/issues/25)) ([545286f](https://github.com/no-std-rs/tailfeather/commit/545286fa870ead690b2be70f786aae8357174fc1))
* **net:** unify local discovery, packet devices and session lifecycle ([#22](https://github.com/no-std-rs/tailfeather/issues/22)) ([c898c83](https://github.com/no-std-rs/tailfeather/commit/c898c8366bb2e619eeb02739e3e8e9c3ce43752c))
* **tls:** support explicit trust anchor sets ([746ee2b](https://github.com/no-std-rs/tailfeather/commit/746ee2b6f7aa72886d28dfddc5b5c33fdf15a30d))
* share an allocation-free async runtime across Tokio and Embassy ([#19](https://github.com/no-std-rs/tailfeather/issues/19)) ([b2d1914](https://github.com/no-std-rs/tailfeather/commit/b2d19148441f3d29333c0216debcc1142f4d9d9e))
* add portable hosted Tailfeather sessions ([#15](https://github.com/no-std-rs/tailfeather/issues/15)) ([0c60b9f](https://github.com/no-std-rs/tailfeather/commit/0c60b9f928fbc20dfdf7c55c4eaf4b6b42811915))
* add a compact Tailscale SSH console ([#7](https://github.com/no-std-rs/tailfeather/issues/7)) ([3e02732](https://github.com/no-std-rs/tailfeather/commit/3e02732bf63263f8dda96d843904fcbac6fc0526))

### Bug Fixes

* **tls:** compare Unicode and Teletex distinguished names ([#24](https://github.com/no-std-rs/tailfeather/issues/24)) ([0f1b1f4](https://github.com/no-std-rs/tailfeather/commit/0f1b1f4e613aa713832fe493b4c640b9bdc63ee9))
* **tls:** verify IPv6 certificate subject identities ([cce23da](https://github.com/no-std-rs/tailfeather/commit/cce23daa60da18c178fa6847154a3516d7602c67))
* **tls:** consume bounded application record writer ([11a59ea](https://github.com/no-std-rs/tailfeather/commit/11a59ea93681604661d373cbc881319a9bff6287))
* **derp:** preserve TLS reads while relay writes progress ([e8f899f](https://github.com/no-std-rs/tailfeather/commit/e8f899f70b091a6463bfb84cccea47f783faa746))
* **disco:** preserve healthy direct paths on candidate updates ([#18](https://github.com/no-std-rs/tailfeather/issues/18)) ([5778937](https://github.com/no-std-rs/tailfeather/commit/5778937199a2969ad695ffdda4a343245dd2cfb5))
* accept hosted DERP coordinates and verify Tailscale SSH ([#9](https://github.com/no-std-rs/tailfeather/issues/9)) ([f34118d](https://github.com/no-std-rs/tailfeather/commit/f34118d67d40050851258d5a3484dcfc6e8fc034))
* validate SSH handshakes and dual-stack authorization ([#8](https://github.com/no-std-rs/tailfeather/issues/8)) ([a285dbe](https://github.com/no-std-rs/tailfeather/commit/a285dbe7b37d6df87513838e7f84247e7668f93f))

## [0.1.0](https://github.com/no-std-rs/tailfeather/compare/tailfeather-v0.0.1...tailfeather-v0.1.0) (2026-10-18)


### Features

* **ci:** add independent Runnerless crate releases and web channels ([#2](https://github.com/no-std-rs/tailfeather/issues/2)) ([272f564](https://github.com/no-std-rs/tailfeather/commit/272f5644d81d795d8b87d224fbb64d93cee08cde))
* **web:** remember SSH accounts and simplify connection controls ([1952304](https://github.com/no-std-rs/tailfeather/commit/195230425e53342f2dc85734bbbc47a323e82244))
* **web:** publish browser client to GitHub Pages ([61fcc11](https://github.com/no-std-rs/tailfeather/commit/61fcc116db9bb384aa90d3e421de181ad6a218f7))
* add gateway, hosted control transport, and browser SSH ([3341274](https://github.com/no-std-rs/tailfeather/commit/3341274bf75dd50d0ff41ec2a4c091be282ff7fb))

### Bug Fixes

* **web:** handle Ctrl slash and name SSH tabs after peers ([c4c7a4e](https://github.com/no-std-rs/tailfeather/commit/c4c7a4e9266a660539d4d7555086e6f8562fb58a))

## 0.0.1

Initial [public release](https://github.com/no-std-rs/tailfeather/releases/tag/tailfeather-v0.0.1).
