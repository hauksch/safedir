# safedir

Resolve recipients in the German justice ERV (elektronischer Rechtsverkehr) by
**SAFE-ID** or **Dienststellen-ID** — offline-first, in Rust.

`safedir` turns a SAFE-ID (the immutable identity of a postbox in the
federated SAFE directories: Justiz, BRAK, BNotK, BStBK) into everything an
OSCI sender needs:

- the recipient's **OSCI intermediary URL**,
- the **intermediary / recipient / reader encryption certificates**,
- display data (name, address, profession, roles),
- an **advisory addressability verdict** ("may this sender role address that
  postbox?").

It is the directory-resolution counterpart to
[rosci](https://github.com/hauksch/rosci) (OSCI transport): rosci moves the
message, safedir decides *where and to whom*.

The full research background — standards, specs, legal framework, ecosystem —
lives in [`docs/SAFE-register-research.md`](docs/SAFE-register-research.md);
the primary specifications are archived under `docs/specs/`.

## Status

Pre-1.0. Scope of v1:

- ✅ SAFE-ID parsing/validation (format + SHA-256 check digits per the
  Abbildungsvorschrift, including legacy pre-2016/2017 formats)
- ✅ `SafeEntry` model after the SAFE search standard v1.5 attribute table
- ✅ Offline backends: versioned `safe.json` extract + in-memory
- ✅ Advisory addressability matrix (role pairs, postbox states)
- ✅ SPML 2.0 / SOAP client for the VAS behind the `vas` feature —
  **mock-tested only**: the live VAS endpoint requires registration with the
  BLK-AG IT-Standards (`it-standards@justiz.de`); credentials stay
  configurable.
- ❌ Out of scope (deliberately): OSCI transport, VHN 2, XJustiz, EGVP
  container assembly.

## CLI

```sh
# Fully offline: parse + checksum verification
safedir check DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d

# Resolve from a local extract (default file: safe.json, env SAFEDIR_FILE)
safedir lookup DE.Justiz.dbf… --file safe.json --json
safedir lookup dienststellen:301125T --file safe.json

# Lint an extract (schema, checksums, duplicate IDs, cert parseability)
safedir validate safe.json

# Advisory verdict for a sender role
safedir addressable egvp_beA dienststellen:301125T
```

Exit codes: `0` ok · `2` usage/config/parse · `3` not found · `4` directory,
extract, or network issues.

With the `vas` feature (default in the CLI), `lookup` can go live instead of
reading an extract:

```sh
safedir lookup DE.Justiz.… \
    --vas-url https://vas.example/soap \
    --vas-identity client.pem \   # mutual-TLS identity (key + cert)
    --vas-ca vas-root.pem          # extra CA to trust, if needed
```

⚠ The VAS endpoint and its credentials are handed out via the BLK-AG
IT-Standards registration procedure (`it-standards@justiz.de`) — the client
is mock-tested only until you have them.

## The extract format (`safe.json`)

Same philosophy as rosci's `dvdv.json`: a local, versioned snapshot produced
by a party with legitimate directory access — no online traces, no
credentials in the loop.

```json
{
  "$format": 1,
  "entries": [
    {
      "safe_id": "DE.Justiz.…",
      "directory": "justiz",
      "name": "Amtsgericht Bonn",
      "ort": "Bonn",
      "plz": "53111",
      "roles": ["egvp_justiz"],
      "dienststellen_ids": ["301125T"],
      "osci": {
        "intermediary_url": "https://…/entry",
        "intermediary_cipher_cert": "-----BEGIN CERTIFICATE-----…",
        "recipient_cipher_certs": ["-----BEGIN CERTIFICATE-----…"]
      }
    }
  ]
}
```

## Library

```rust
use safedir::prelude::*;

let dir = ExtractResolver::from_path("safe.json")?;
let entry = dir
    .lookup_safe_id(&"DE.Justiz.…".parse()?)?
    .ok_or(NotFound)?;
println!("{}", entry.osci.intermediary_url);
```

## Safety disclaimer

The addressability module reproduces the visibility matrix from the BLK-AG
*Drittprodukte* requirements paper as an **advisory client-side guard**. It is
not a security boundary: OSCI intermediaries do not enforce role rules, and
whether the production VAS filters results by requester role is not publicly
documented. Always re-resolve immediately before sending (requirement A14).

## License

MIT. The research report and archived specs in `docs/` belong to their
respective publishers.
