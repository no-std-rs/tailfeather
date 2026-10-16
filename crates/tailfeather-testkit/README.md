# tailfeather-testkit

Std-only offline checks for `tailfeather`. The internal package embeds only
synthetic, sanitized fixtures with recorded provenance and hashes.

```sh
tailfeather-testkit list
tailfeather-testkit check --json
tailfeather-testkit check --json --expect expected.json
```
