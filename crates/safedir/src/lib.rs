//! # safedir
//!
//! Resolve recipients in the German justice *elektronischer Rechtsverkehr*
//! (ERV) by **SAFE-ID** or **Dienststellen-ID**.
//!
//! The federated SAFE directories ("Secure Access to Federated
//! E-Justice/E-Government") hold, for every postbox on the EGVP
//! infrastructure (beA, beN, beSt, beBPo, eBO, MJP, justice postboxes), the
//! data an OSCI sender needs: the URL of the recipient's OSCI intermediary,
//! the intermediary/recipient/reader encryption certificates, display data
//! and role values. This crate models those entries and resolves them —
//! offline from a versioned extract file, or live against the central
//! *Virtueller Attribut-Service* (VAS) via OASIS SPML 2.0 (feature `vas`).
//!
//! Primary sources (download locations in `docs/SPECIFICATIONS.md`):
//!
//! - *Standard für die Suche in den SAFE-Verzeichnissen der
//!   ERV-Kommunikationsinfrastruktur*, v1.5, BLK-AG IT-Standards, 21 May
//!   2026 — attribute table, search semantics, error codes.
//! - *SAFE-ID — Abbildungsvorschrift V2*, July 2017 — ID formats and check
//!   digits.
//! - *Teilnahme von Drittanwendungen am OSCI-gestützten elektronischen
//!   Rechtsverkehr — Anforderungen*, v1.8, 20 Apr 2022 — SAFE role model and
//!   visibility rules.
//!
//! ## Non-goals
//!
//! OSCI transport (see the `rosci` project), VHN 2, XJustiz, and EGVP
//! message-container assembly are deliberately out of scope.
//!
//! ## Caveats
//!
//! The [`addressability`] module is an *advisory* client-side guard, not a
//! security boundary. Requirement A14 of the Drittprodukte paper obliges
//! senders to re-check directory registration immediately before every send:
//! never cache resolution results across send cycles.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod addressability;
pub mod backends;
pub mod dienststellen;
pub mod entry;
pub mod error;
pub mod extract;
pub mod resolver;
pub mod roles;
pub mod safe_id;

#[cfg(feature = "vas")]
pub mod vas;

/// Convenient re-exports for common use.
pub mod prelude {
    pub use crate::addressability::{Addressability, addressability};
    pub use crate::backends::{ExtractResolver, InMemoryResolver};
    pub use crate::dienststellen::DienststellenId;
    pub use crate::entry::{CertRef, Directory, EntryState, OsciEndpoint, SafeEntry};
    pub use crate::error::{ErrCode, Error};
    pub use crate::extract::ExtractFile;
    pub use crate::resolver::{SafeDirectory, SearchOutcome, SearchQuery, SearchTerm};
    pub use crate::roles::RoleValue;
    pub use crate::safe_id::{Domain, SafeId};
}
