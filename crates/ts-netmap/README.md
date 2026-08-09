# ts-netmap

A streaming, allocation-free parser for Tailscale `MapResponse` messages.

A map connection is a long poll carrying a sequence of length-prefixed JSON
documents. Even a small tailnet produces documents too large to buffer on an
ESP32, so this crate retains only the current token, the object under
construction, and bounded state that the node will use.

## Pipeline

| Type | Responsibility |
|---|---|
| `FrameReader` | separates little-endian length-prefixed responses |
| `Scanner` | tokenizes JSON across arbitrary input boundaries |
| `Parser` | applies tokens to the retained network state |
| `Netmap` | peers, local addresses, and DERP regions used by the node |

`Parser::push` accepts any chunk size, including a split in the middle of a
UTF-8 escape or field name. `Parser::finish` validates that the document ended
cleanly.

## Full maps and deltas

The first response describes the network; later responses usually contain only
changes. The parser applies whole-peer replacements, field patches, and removals
without discarding peers omitted from a delta.

Fields a headless gateway does not act on—such as user profiles and packet
filters—are skipped rather than retained in a shadow desktop data model.

## Bounds

The defaults retain 32 peers, four addresses per node, eight allowed prefixes,
eight candidate endpoints, and a bounded DERP map. A capacity overflow is an
error, never a silently incomplete network view. The peer capacity is a const
generic when a target needs a different tradeoff.

Tests split captured maps at arbitrary byte boundaries and cover deltas,
escapes, malformed input, framing, and every configured capacity limit.

See the [repository README](../../README.md) for the complete stack.

## License

MIT OR Apache-2.0, at your option.
