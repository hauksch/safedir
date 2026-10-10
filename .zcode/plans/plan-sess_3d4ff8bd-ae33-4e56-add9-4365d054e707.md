# safedir v1 — Implementation Plan

## Mission
A Rust workspace that resolves German justice ERV recipients by SAFE-ID (and Dienststellen-ID) into everything an OSCI sender needs: intermediary URL, intermediary/recipient/reader encryption certificates, display data, role values, and an advisory addressability verdict. Consumer: rosci (`--to safe:` scheme via its `DvdvDirectory`-style seam). Transport, VHN, XJustiz are explicitly **out of scope** for v1.

## Confirmed scope decisions
1. **Library + thin CLI** (workspace `crates/safedir` + `crates/safedir-cli`, mirroring rosci conventions).
2. **Live SPML/VAS client in v1**, behind a `vas` feature flag, mock-tested only (endpoint/auth configurable; real access requires BLK-AG registration — documented, not implemented).
3. **Lean addressability module** — research verdict: the VAS publicly enforces only parameter legality (A4); result shaping is via *client-supplied* role filters (A6–A8, a duty on send/receive software); the visibility matrix lives in the *client requirements* paper; OSCI intermediaries enforce no role rules; and our extract/in-memory backends have no server at all. So safedir ships the matrix as an **advisory client-side guard**, documented as such.
4. **VHN 2 / XJustiz / erv-message: out of scope** (later crate/phase when EGVP-profile messaging is tackled).

## Library: `crates/safedir`
- **`safe_id`** — `SafeId` type: modern format `DE.<Domain>.<UUID>.<4-hex-checkdigits>` (domains: `BRAK`, `BEN_PROD`, `BNotK_Produktiv`, `Justiz`, `Other(String)`) plus legacy patterns (`safe-sp1-<ms>-<n>`, `govello-…`, `safe-prod-…`). Checksum per Abbildungsvorschrift V2: first two bytes of SHA-256 over the lowercased normalized ID, hex. `FromStr`/`Display`/serde/`Eq`/`Hash`; constructive error detailing which component failed.
- **`dienststellen`** — `DienststellenId` newtype; wire prefix `Dienststellen-ID:` for lookup requests (per search standard §6).
- **`entry`** — `SafeEntry` typed after the v1.5 attribute table (Vorname, Name/Organisation, Berufsbezeichnung, Kanzlei, Abteilung, address fields, phone, SAFE-ID, Dienststellen-IDs, role values, directory origin Justiz/BRAK/BNotK/BStBK). Certificates modeled as a **set** (`CertRef`: raw DER/PEM bytes, fingerprint, parsed validity window when the `x509` feature is on, opaque otherwise) — never a single field (10-cert overlap reality, §5.5 of the report).
- **`roles`** — `RoleValue` enum: `egvp_justiz, egvp_bea, egvp_ben, egvp_best, egvp_bebpo, egvp_ebo, ozg_postfach, egvp_buerger, egvp_behoerde, buerger_hin, buerger_rueck, zuzu, egvp_test, zertifikatswechsel`, `Other(String)`.
- **`addressability`** — const visibility matrix from the requirements paper §5.3; `Addressability::{Addressable, NotAddressable(reason), Conditional(EboPlus, GerichtsvollzieherException…)}`; entry state machine: Active / Inactive(ERR20) / CertificateChange (sole `zertifikatswechsel`) / CertsExpired(at `now`, A9 semantics). Pure functions, table-driven, `#[doc]`-marked advisory.
- **`resolver`** — trait `SafeDirectory`: `lookup_safe_id`, `lookup_dienststellen`, `search(SearchQuery)`; `SearchQuery` models allowed parameters + search kinds (begins-with/contains/equals with min-length rules) so illegal queries are unrepresentable where practical.
- **`error`** — thiserror taxonomy: `Config`, `Parse`, `Extract`, `Directory(ErrCode)`, `Network`, `Addressability`; `ErrCode` typed ERR10–ERR100 with the standard's German messages.
- **Backends**:
  - `InMemoryResolver` (tests, embedded use).
  - `ExtractResolver` (default): reads a versioned **`safe.json`** extract — array of entries with inline PEM certs, `"$format": 1`; same offline-first philosophy as rosci's `dvdv.json`; format documented in docs + validated by CLI.
  - `SpmlResolver` (feature `vas`, async): two request types per SPML 2.0 — (a) **`lookupRequest`** by `psoID` (SAFE-ID, or `Dienststellen-ID:` prefix per the standard's printed example — fully specified), with the exact namespace set (`urn:oasis:names:tc:SPML:2:0*`, `urn:liberty:id-sis-pp:200505`, `urn:de:egov:names:safe:1.0:*`, FIM/beA extensions) and `returnData="everything"`; (b) **`searchRequest`** with an SPML Query/DSML expression tree (`and` combinators, substring `initial/any` vs `equalityMatch` per the "Art der Suche" column) plus role filters — constructed per the public OASIS SPML 2.0 spec since the SAFE standard prints only lookup XML; mock-driven so dialect adjustments after credential access are cheap. Parses `…Response` PSO data into `SafeEntry`, surfaces the 100-hit cap and typed ERR10–ERR100 codes. reqwest+rustls, client-cert TLS configurable, tested only against a local mock VAS; docs point to the Projektbüro (`it-standards@justiz.de`) for real access.

## CLI: `crates/safedir-cli`
- `safedir check <SAFE-ID>` — parse + checksum, fully offline.
- `safedir lookup <SAFE-ID | dienststellen:301125T>` — `--file safe.json` (default) or `--vas-url/--vas-cert` (feature-gated); prints entry or `--json`.
- `safedir validate <extract.json>` — extract linting (schema, cert parse, charset, duplicate SAFE-IDs).
- `safedir addressable <sender-role> <id-or-file-entry>` — advisory verdict with reason.
- Exit codes 0/2/3/4/5 in rosci's spirit (ok / usage-config / not-found / directory-ERR / internal); env `SAFEDIR_*` only, no config files, no state.

## Tests & CI
- Golden vectors: all SAFE-IDs from the Abbildungsvorschrift (modern + legacy), tampered-checksum rejections, Dienststellen-ID example `301125T`.
- Table-driven visibility tests transcribed from requirements §5.3 prose (incl. eBO-plus exception cases, MJP↔eBO exclusion).
- Extract format round-trip + parser fuzzing.
- Mock VAS (wiremock) replaying the standard's literal lookup XML example plus crafted search responses and every ERR code; request-XML namespace assertions.
- Proptest checksum round-trips; default test runs touch no network (rosci ground rule).
- CI (GitHub Actions): fmt, clippy -D warnings, test, cargo-deny; edition 2024, MSRV = current stable, documented; MIT license (match rosci).

## Milestones
- **M1**: workspace scaffold, CI, `safe_id` + `dienststellen` + errors, CLI `check`. Publishable 0.1.0.
- **M2**: `entry`, `roles`, extract + memory backends, `addressability`, CLI `lookup`/`validate`/`addressable`.
- **M3**: `vas` feature — `lookupRequest` + `searchRequest` builder, mock VAS suite, credentials/acquisition docs.
- **M4** (separate PR to hauksch/rosci): `SafeDirectory` impl over extract, `--to safe:<SAFE-ID>` and `--to safe:dienststellen:<ID>` schemes, mapping `SafeEntry` → rosci's `--intermediary/--intermediary-cert/--to cert:/--decrypter-cert` contract.

## Post-v1 (explicitly deferred)
VHN 2 parse/verify, XJustiz types (xsd-parser), EGVP container assembly (`erv-message`), XRepository Werteliste snapshot tooling, REST daemon, crates.io publication of the name (verify availability of `safedir` first — could not be checked from the sandbox).

## Known risks
- SPML `searchRequest` dialect has freedoms beyond the printed lookup example → builder stays mock-driven and cheap to adjust; `lookup` (the SAFE-ID core path) is fully specified by example.
- Real VAS may enforce requester-role filtering server-side (unpublished) → our matrix stays advisory; document the possibility.
- `zertifikatswechsel` is admin practice, not in the search standard → modeled as entry state derived from roles, flagged in docs.