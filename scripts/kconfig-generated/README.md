# Pinned Kconfig generated sources

These files are generated from Linux 6.12.91's `scripts/kconfig/lexer.l` and
`parser.y` using flex 2.6.4 and bison 3.8.2. They let the pinned libkrunfw
support artifact build on minimal CI runners without relying on ambient parser
generator packages. Regenerate all three together when the pinned Linux source
changes; do not edit them by hand.
