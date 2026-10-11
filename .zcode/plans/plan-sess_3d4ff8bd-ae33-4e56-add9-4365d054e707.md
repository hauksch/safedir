# safedir remediation plan (post-audit)

Record the full audit first: write the consolidated findings to `docs/AUDIT-2026-10-11.md` (severity, file:line, fix status tracked there), then fix in three phases, each ending with the full gate (fmt, clippy -D warnings, tests default + all-features) and a git commit.

## Phase 1 — correctness of the VAS XML pipeline + quick fixes (no spec decisions needed)
1. `vas/spml.rs` fragment reconstruction: push `Event::Text` bytes **verbatim** (already escaped); keep `xml_escape` only for synthesized markup/attributes. `vas/idsispp.rs`: call `t.unescape()` when accumulating leaf text (fall back to lossy UTF-8).
2. Depth-scope the response state machine: honor `data` only as a direct child of `pso`, `psoID`/`pso` only at their depth; ignore same-local-name elements inside the payload.
3. Stop silently dropping data: `parse_profile` failures, unparseable role values, and undecodable certs accumulate into a `Vec<String>` of warnings surfaced on `SearchOutcome` (new `warnings` field) and, for `lookup_safe_id`, into the `DirectoryFailure`/entry-warnings path; `lookup_safe_id` takes the **first** pso and errors if more than one.
4. Fix the telefon XPath to `urn:liberty:id-sis-pp:msgTechnology:pots` (Anlage c) + mock-test assertion.
5. `ErrCode::from_message_text`: scan **all** `ERR` occurrences (`match_indices`), longest-prefix catalogue match (`ERR1007` → `ERR100`? no — catalogue-exact with documented longest-prefix rule), plus unit tests for `ERROR:`-prefixed text, multiple codes, bare `ERR`.
6. `InMemoryResolver::search`: return `Err(Error::Directory(Err40, …))` when hits > 100 (A16/A17), aligning with the VAS backend; regression test at exactly 100/101 hits.
7. CLI: route every remaining output through the pipe-safe `out()` helper (cmd_check modern branch, `--json` lookup, print_entry tail, validate/addressable lines); `--json` lookup prints one JSON array.
8. Tests: entity-encoded fixtures (`M&#252;ller`, `&amp;`) through mock VAS end-to-end; stray `<data>`-inside-payload adversarial response.

## Phase 2 — spec alignment (verification, then code)
1. **Matrix verification first**: layout-aware `pdftotext -layout` of §5.3 (p. 19) of the Anforderungspapier; decode the ±-grid with column offsets; cross-check every cell against §5.3 prose; document the decoded matrix in the research report. Then fix `allowed_receivers`: prose-settled now (add `BuergerRueck` to the eBO/MJP arm; remove `EgvpBehoerde` from it; add `BuergerHin/Rueck` to the besondere arm and expand/confirm GV rows *only if* the table confirms); add the missing test cells (incl. `Other`/`Zuzu` senders, receiver with only `Other`).
2. `SearchQuery` parameter set per the v1.5 table: add `beruf` (contains ≥ 5); remove `abteilung`/`land`/`telefon`/`mobil` from the *builder* (keep fields reading them from extracts/entries), correct the doc-comment minimums; enforce A4 in `SearchQuery::matches` itself (empty query matches nothing) so `Default`-constructed queries can't dump the directory; add `SearchQuery::validate()` re-check for hand-built queries.
3. `EntryState`: include the intermediary certificate in expiry evaluation; not-yet-valid → own state mapped to `NotAddressable(reason)`; zero recipient+reader certs → `CertsExpired`-like `NoCerts` state; require a valid *recipient* cert for `Active` (reader-only no longer suffices). Tests for each branch (the `any_future` branch is currently never executed).
4. `safe_id`: classify the domain segment case-insensitively (canonical-spelling match), dispatch on case-insensitive `DE.` prefix (kills the dead `Country` arm's confusion), require exactly 3 legacy parts (or validated alnum middles), validate `Domain::Other` in `compose` (non-empty, `is_domain_char`, not shadowing a known spelling), length cap (~120 chars) before allocating. Decide + document raw-vs-canonical `Eq` semantics; make `lookup_safe_id` compare case-insensitively so blessed case variants resolve.

## Phase 3 — robustness & hygiene
1. `vas/client.rs`: on non-2xx still parse the body (SOAP Fault extraction: `faultcode`/`faultstring`/`detail` texts into `error_text` in spml.rs); enforce `https` scheme with an explicit loopback escape hatch for tests; `redirect(Policy::none())`.
2. Extract hardening: `#[serde(deny_unknown_fields)]` on all three structs; `ExtractResolver::from_path` runs `validate()` and refuses duplicates/empty-role entries (with an opt-out flag); `from_entries` takes provenance; real URL parsing (scheme + host); `into_entries` errors carry the cert-field label; empty-PEM-body rejection in `decode_pem_body`.
3. `CertRef::__test_with_validity` → `#[cfg(test)] pub(crate)`; serde `Deserialize` recomputes the fingerprint when absent; document that stored validity is trusted.
4. `roles.rs`: drop the unbacked `__` rejection; keep charset rule; document mixed-case emission (or switch to §5.3 lowercase tokens) — verify against VAS data when access exists; preserve unparseable role tokens as `Other` instead of dropping in idsispp.
5. Error taxonomy: `#[source]` chains for Network/Extract (typed sources), map Network → 4 documented, add a genuine internal-invariant → 5 or drop code 5 from docs/README.
6. CI: add `cargo check -p safedir --no-default-features`, `-p safedir-cli --no-default-features` (un-deads the vas fallback), and an MSRV 1.85 job; mock server: read timeout, non-empty capture assertions with context, no bare `[0]` unwrap.
7. Docs: README gains the `--vas-*` flags and the exit-code truth; audit file updated with resolution status per finding.

## Explicit non-fixes (accepted)
- Advisory nature of the matrix (documented, not a security boundary); `Cow` allocations in `Other(_)` tokens; extract file-size caps (serde's depth limit suffices for now — revisit if extracts become untrusted input); `x509`/`vas` default-on feature strategy (documented in README instead).

Each phase lands as one commit with the audit file updated; no behavior change ships without a test that would have caught it.