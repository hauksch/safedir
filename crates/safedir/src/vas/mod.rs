//! Live SPML 2.0 / SOAP client for the *Virtueller Attribut-Service* (VAS).
//!
//! **Read this before relying on it.** The SAFE search standard v1.5 prints
//! exactly one wire example — the `lookupRequest` with a `Dienststellen-ID`
//! `psoID` (§6). The `searchRequest` dialect is constructed here per the
//! public OASIS SPML 2.0 / DSMLv2 query model and the standard's semantic
//! rules, but it has **never been validated against the production VAS**:
//! the endpoint URL and its authentication are handed out only via the
//! registration procedure of the BLK-AG IT-Standards
//! (`it-standards@justiz.de`). Everything here is covered by mock-server
//! tests that encode our best reading of the specs; treat divergences found
//! with real credentials as cheap builder adjustments, not redesigns.

mod client;
mod idsispp;
mod spml;

pub use client::{SpmlConfig, SpmlResolver};
