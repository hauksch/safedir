# safedir

[![CI](https://github.com/hauksch/safedir/actions/workflows/ci.yml/badge.svg)](https://github.com/hauksch/safedir/actions/workflows/ci.yml)
[![Supply chain](https://github.com/hauksch/safedir/actions/workflows/audit.yml/badge.svg)](https://github.com/hauksch/safedir/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![deps: cargo-deny](https://img.shields.io/badge/dependencies-cargo--deny%20%2B%20SBOM-success.svg)](deny.toml)

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
canonical download locations for every specification it builds on are in
[`docs/SPECIFICATIONS.md`](docs/SPECIFICATIONS.md) (the documents themselves
are copyrighted by their publishers and are not vendored here). The internal
code audit and its remediation history are documented in
[`docs/AUDIT-2026-10-11.md`](docs/AUDIT-2026-10-11.md).

## Status

Pre-1.0. Scope of v1:

- ✅ SAFE-ID parsing/validation (format + SHA-256 check digits per the
  Abbildungsvorschrift, including legacy pre-2016/2017 formats)
- ✅ `SafeEntry` model after the SAFE search standard v1.5 attribute table
- ✅ Offline backends: versioned `safe.json` extract + in-memory
- ✅ Advisory addressability matrix, transcribed from the verified §5.3
  visibility table
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
safedir lookup DE.Justiz.… --file safe.json --json
safedir lookup dienststellen:301125T --file safe.json

# Lint an extract (schema, checksums, duplicate IDs, cert parseability)
safedir validate safe.json

# Advisory verdict for a sender role
safedir addressable egvp_beA dienststellen:301125T
```

Exit codes: `0` ok · `2` usage/config/parse · `3` not found · `4` directory,
extract, or network issues (and: not/conditionally addressable via `addressable`).

With the `vas` feature (default in the CLI), `lookup` can go live instead of
reading an extract:

```sh
safedir lookup DE.Justiz.… \
    --vas-url https://vas.example/soap \
    --vas-identity client.pem \
    --vas-ca vas-root.pem
```

⚠ The VAS endpoint and its credentials are handed out via the BLK-AG
IT-Standards registration procedure (`it-standards@justiz.de`) — the client
is mock-tested only until you have them.

## The extract format (`safe.json`)

Same philosophy as rosci's `dvdv.json`: a local, versioned snapshot produced
by a party with legitimate directory access — no online traces, no
credentials in the loop. A working sample (built around a throwaway test
certificate) lives in [`examples/safe.sample.json`](examples/safe.sample.json).

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

```rust,ignore
use safedir::prelude::*;

let dir = ExtractResolver::from_path("safe.json")?;
let entry = dir
    .lookup_safe_id(&"DE.Justiz.…".parse()?)?
    .expect("entry found");
println!("{}", entry.osci.intermediary_url);
```

## Safety disclaimer

The addressability module reproduces the visibility matrix from the BLK-AG
*Drittprodukte* requirements paper as an **advisory client-side guard**. It is
not a security boundary: OSCI intermediaries do not enforce role rules, and
whether the production VAS filters results by requester role is not publicly
documented. Always re-resolve immediately before sending (requirement A14).

## Security & supply chain

- Vulnerable and yanked dependencies, license violations, and unknown
  registries fail the build ([`deny.toml`](deny.toml)); the check runs in CI
  on every push and weekly thereafter.
- A CycloneDX SBOM is generated from the lockfile and attached as a workflow
  artifact of the [supply-chain job](.github/workflows/audit.yml).
- Dependency updates arrive as Dependabot pull requests only — nothing is
  auto-merged.
- Found something sensitive? Please use GitHub's *private* vulnerability
  reporting instead of opening a public issue.

## License

MIT. The research report and specification link list in `docs/` describe
documents that belong to their respective publishers.
