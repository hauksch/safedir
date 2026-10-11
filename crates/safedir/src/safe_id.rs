//! SAFE-ID parsing and validation.
//!
//! Source: *SAFE-ID — Abbildungsvorschrift, Stand Juli 2017* (BLK-AG
//! IT-Standards; see `docs/SPECIFICATIONS.md` for the download location).
//!
//! ## Modern format (since 2016/2017)
//!
//! ```text
//! DE.<Domain>.<UUID>.<checkdigits>
//! ```
//!
//! e.g. `DE.BNotK_Produktiv.024565fc-8d9d-11e3-aa83-2c768a4f9bf4.85ed`.
//! Domains: `DE.BRAK` (beA), `DE.BEN_PROD` (beN), `DE.Justiz` (SAFE public),
//! `DE.BNotK_Produktiv`.
//!
//! **Check digits:** the last segment is the first two bytes of the SHA-256
//! hash over the *lowercased* ID without the check-digit segment, hex-coded:
//!
//! ```text
//! sha256("de.bnotk_produktiv.024565fc-8d9d-11e3-aa83-2c768a4f9bf4")[0..2].hex()
//!   == "85ed"
//! ```
//!
//! ## Legacy format (pre-2016/2017, still valid)
//!
//! ```text
//! <prefix>-<epoch-millis>-<sequence>
//! ```
//!
//! e.g. `safe-sp1-1357225160794-021568182`, `govello-1235989964420-000174375`,
//! `safe-prod-1498121242459-016499869`. Legacy IDs carry no check digits.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

use crate::error::ParseSafeIdError;

/// Hard cap on accepted ID length; real SAFE-IDs are ≤ ~60 characters.
pub(crate) const MAX_ID_LEN: usize = 120;

/// The SAFE domain (Verzeichnisdienst) an identity belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Domain {
    /// Rechtsanwälte (beA) — `DE.BRAK`.
    Brak,
    /// Notare (beN) — `DE.BEN_PROD`.
    BenProd,
    /// Notariat, productive domain — `DE.BNotK_Produktiv`.
    BNotkProduktiv,
    /// Justiz / SAFE public — `DE.Justiz`.
    Justiz,
    /// Any other (future) domain; kept verbatim.
    Other(String),
}

impl Domain {
    /// Canonical segment as it appears inside a SAFE-ID.
    #[must_use]
    pub fn as_segment(&self) -> &str {
        match self {
            Self::Brak => "BRAK",
            Self::BenProd => "BEN_PROD",
            Self::BNotkProduktiv => "BNotK_Produktiv",
            Self::Justiz => "Justiz",
            Self::Other(s) => s,
        }
    }

    /// The four established federated directories.
    #[must_use]
    pub fn directory(&self) -> crate::entry::Directory {
        match self {
            Self::Brak => crate::entry::Directory::Brak,
            Self::BenProd | Self::BNotkProduktiv => crate::entry::Directory::Bnotk,
            Self::Justiz => crate::entry::Directory::Justiz,
            Self::Other(_) => crate::entry::Directory::Unknown,
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_segment())
    }
}

/// Structural classification of a SAFE-ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// `DE.<Domain>.<UUID>.<checkdigits>` (Abbildungsvorschrift V2).
    Modern {
        /// SAFE domain segment.
        domain: Domain,
        /// Canonical (lowercase) UUID segment.
        uuid: String,
        /// The two check-digit bytes.
        checksum: [u8; 2],
    },
    /// `<prefix>-<epoch-millis>-<sequence>` (pre-2016/2017), no check digits.
    Legacy {
        /// e.g. `safe-sp1`, `govello`, `safe-prod`.
        prefix: String,
    },
}

/// A validated SAFE-ID. The raw string is preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SafeId {
    raw: String,
    kind: IdKind,
}

impl SafeId {
    /// The ID as supplied (surrounding whitespace trimmed at parse time).
    ///
    /// Equality is raw-string exact: case variants of one logical identity
    /// are distinct values, though lookups compare case-insensitively.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Structural classification.
    #[must_use]
    pub fn kind(&self) -> &IdKind {
        &self.kind
    }

    /// Domain segment, if the ID uses the modern format.
    #[must_use]
    pub fn domain(&self) -> Option<&Domain> {
        match &self.kind {
            IdKind::Modern { domain, .. } => Some(domain),
            IdKind::Legacy { .. } => None,
        }
    }

    /// Directory this ID lives in (`None` for unknown domains / legacy IDs).
    #[must_use]
    pub fn directory(&self) -> Option<crate::entry::Directory> {
        self.domain().map(Domain::directory)
    }

    /// Compute the check digits for an ID body (everything before the final
    /// `.` + checksum segment): first two bytes of SHA-256 over the
    /// lowercased body, hex-coded.
    #[must_use]
    pub fn checksum_of_body(body: &str) -> [u8; 2] {
        let hash = Sha256::digest(body.to_ascii_lowercase().as_bytes());
        [hash[0], hash[1]]
    }

    /// Construct a modern-format ID from domain and UUID, computing the
    /// check digits.
    ///
    /// # Errors
    ///
    /// [`ParseSafeIdError::BadUuid`] if the UUID segment is malformed.
    pub fn compose(domain: &Domain, uuid: &str) -> Result<Self, ParseSafeIdError> {
        if !is_valid_uuid(uuid) {
            return Err(ParseSafeIdError::BadUuid);
        }
        let uuid = uuid.to_ascii_lowercase();
        // Canonicalize/reject Other domains so compose() output always
        // re-parses to an equal value.
        let domain = canonical_domain(domain)?;
        let domain_seg = domain.as_segment();
        let body = format!("DE.{domain_seg}.{uuid}");
        let [a, b] = Self::checksum_of_body(&body);
        let raw = format!("{body}.{a:02x}{b:02x}");
        Ok(Self {
            kind: IdKind::Modern {
                domain: domain.clone(),
                uuid,
                checksum: [a, b],
            },
            raw,
        })
    }
}

impl fmt::Display for SafeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for SafeId {
    type Err = ParseSafeIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.trim();
        if raw.is_empty() {
            return Err(ParseSafeIdError::Empty);
        }
        if raw.chars().any(char::is_whitespace) {
            return Err(ParseSafeIdError::Whitespace);
        }
        if raw.len() > MAX_ID_LEN {
            return Err(ParseSafeIdError::TooLong { limit: MAX_ID_LEN });
        }
        // Distinguishing rule: the modern format starts with a case-
        // insensitive "DE." prefix; legacy IDs contain no dots. Byte-wise
        // compare: slicing `raw[..3]` would panic on multi-byte chars.
        let modern = raw.len() >= 3
            && raw
                .as_bytes()
                .get(..3)
                .is_some_and(|b| b.eq_ignore_ascii_case(b"DE."));
        if modern {
            parse_modern(raw)
        } else {
            parse_legacy(raw)
        }
    }
}

impl Serialize for SafeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SafeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn parse_modern(raw: &str) -> Result<SafeId, ParseSafeIdError> {
    let segments: Vec<&str> = raw.split('.').collect();
    if segments.len() != 4 {
        return Err(ParseSafeIdError::ModernSegments {
            found: segments.len(),
        });
    }
    if !segments[0].eq_ignore_ascii_case("DE") {
        return Err(ParseSafeIdError::Country {
            found: segments[0].to_owned(),
        });
    }
    let domain_seg = segments[1];
    if domain_seg.is_empty() || !domain_seg.chars().all(is_domain_char) {
        return Err(ParseSafeIdError::BadDomain {
            found: domain_seg.to_owned(),
        });
    }
    let uuid = segments[2];
    if !is_valid_uuid(uuid) {
        return Err(ParseSafeIdError::BadUuid);
    }
    let checksum = segments[3];
    if checksum.len() != 4 || !checksum.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ParseSafeIdError::BadChecksumFormat {
            found: checksum.to_owned(),
        });
    }
    // Classify case-insensitively so `de.brak.…` still routes to the BRAK
    // directory instead of `Other`/`Unknown`.
    let domain = if domain_seg.eq_ignore_ascii_case("BRAK") {
        Domain::Brak
    } else if domain_seg.eq_ignore_ascii_case("BEN_PROD") {
        Domain::BenProd
    } else if domain_seg.eq_ignore_ascii_case("BNotK_Produktiv") {
        Domain::BNotkProduktiv
    } else if domain_seg.eq_ignore_ascii_case("Justiz") {
        Domain::Justiz
    } else {
        Domain::Other(domain_seg.to_owned())
    };
    // Check digits are computed over the lowercased body (domain included).
    let body = format!("DE.{domain_seg}.{uuid}");
    let [a, b] = SafeId::checksum_of_body(&body);
    let given = checksum.to_ascii_lowercase();
    let expected = format!("{a:02x}{b:02x}");
    if !given.eq_ignore_ascii_case(&expected) {
        return Err(ParseSafeIdError::ChecksumMismatch {
            expected,
            found: given,
        });
    }
    Ok(SafeId {
        raw: raw.to_owned(),
        kind: IdKind::Modern {
            domain,
            uuid: uuid.to_ascii_lowercase(),
            checksum: [a, b],
        },
    })
}

fn parse_legacy(raw: &str) -> Result<SafeId, ParseSafeIdError> {
    let parts: Vec<&str> = raw.split('-').collect();
    if parts.len() < 3 {
        return Err(ParseSafeIdError::LegacyShape {
            found: raw.to_owned(),
        });
    }
    let prefix = parts[0];
    if prefix.len() < 3 || !prefix.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ParseSafeIdError::LegacyPrefix {
            found: prefix.to_owned(),
        });
    }
    // Middle segments (if any) must be non-empty alphanumeric — no empty
    // segments, no control characters.
    for seg in &parts[1..parts.len() - 2] {
        if seg.is_empty() || !seg.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ParseSafeIdError::LegacyShape {
                found: raw.to_owned(),
            });
        }
    }
    // The last two segments must be numeric (epoch millis, sequence).
    for seg in &parts[parts.len() - 2..] {
        if seg.is_empty() || !seg.chars().all(|c| c.is_ascii_digit()) {
            return Err(ParseSafeIdError::LegacyShape {
                found: raw.to_owned(),
            });
        }
    }
    Ok(SafeId {
        raw: raw.to_owned(),
        kind: IdKind::Legacy {
            prefix: prefix.to_owned(),
        },
    })
}

fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Map an `Other` domain that merely re-spells a known one onto the known
/// variant; reject structurally impossible ones.
fn canonical_domain(domain: &Domain) -> Result<Domain, ParseSafeIdError> {
    if let Domain::Other(seg) = domain {
        for known in [
            Domain::Brak,
            Domain::BenProd,
            Domain::BNotkProduktiv,
            Domain::Justiz,
        ] {
            if seg.eq_ignore_ascii_case(known.as_segment()) {
                return Ok(known);
            }
        }
        if seg.is_empty() || seg.len() > 64 || !seg.chars().all(is_domain_char) {
            return Err(ParseSafeIdError::BadDomain { found: seg.clone() });
        }
    }
    Ok(domain.clone())
}

fn is_valid_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors, verbatim from the Abbildungsvorschrift V2 (July 2017).
    const MODERN: &[&str] = &[
        "DE.BNotK_Produktiv.024565fc-8d9d-11e3-aa83-2c768a4f9bf4.85ed",
        "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
        "DE.BEN_PROD.1526d642-90bf-4547-ab41-201f5a069046.39c5",
    ];
    const LEGACY: &[&str] = &[
        "safe-sp1-1357225160794-021568182",
        "govello-1235989964420-000174375",
        "safe-prod-1498121242459-016499869",
    ];

    #[test]
    fn parses_modern_golden_ids() {
        for id in MODERN {
            let parsed: SafeId = id.parse().expect(id);
            assert_eq!(parsed.as_str(), *id);
            assert!(matches!(parsed.kind(), IdKind::Modern { .. }), "{id}");
        }
    }

    #[test]
    fn parses_legacy_golden_ids() {
        for id in LEGACY {
            let parsed: SafeId = id.parse().expect(id);
            assert!(matches!(parsed.kind(), IdKind::Legacy { .. }), "{id}");
            assert!(parsed.domain().is_none());
        }
    }

    #[test]
    fn rejects_tampered_checksum() {
        let id = "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334e"; // 334d expected
        let err = id.parse::<SafeId>().unwrap_err();
        assert!(matches!(
            err,
            ParseSafeIdError::ChecksumMismatch {
                ref expected,
                ref found,
            } if expected == "334d" && found == "334e"
        ));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "  ",
            "DE.BRAK.not-a-uuid.334d",
            "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b",
            "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.ZZ",
            "DE..bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
            "XX.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
            "safe",
            "safe-sp1-notanumber-021568182",
        ] {
            assert!(bad.parse::<SafeId>().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn checksum_is_case_insensitive_over_body() {
        // Same UUID/domain with differing case must still validate: the
        // checksum is computed over the lowercased body.
        let upper = "DE.BRAK.BDDA0CD6-CCDD-44A1-A42C-F13CED17235B.334d";
        assert!(upper.parse::<SafeId>().is_ok());
    }

    #[test]
    fn compose_round_trip() {
        let id = SafeId::compose(&Domain::Justiz, "DBF3D18A-5C6E-4A0B-9F1E-2A7C8E4D1B30").unwrap();
        let body = "DE.Justiz.dbf3d18a-5c6e-4a0b-9f1e-2a7c8e4d1b30";
        let [a, b] = SafeId::checksum_of_body(body);
        assert_eq!(id.as_str(), format!("{body}.{a:02x}{b:02x}"));
        assert_eq!(id.as_str().parse::<SafeId>().unwrap(), id);
    }

    #[test]
    fn unknown_domain_round_trips() {
        let id: SafeId = "DE.Steuerberaterkammer.024565fc-8d9d-11e3-aa83-2c768a4f9bf4.b1eb"
            .parse()
            .unwrap();
        match id.domain() {
            Some(Domain::Other(s)) => assert_eq!(s, "Steuerberaterkammer"),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn case_variants_classify_into_known_directories() {
        for (raw, expected) in [
            (
                "de.brak.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
                Domain::Brak,
            ),
            (
                "DE.brak.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
                Domain::Brak,
            ),
            (
                "DE.JUSTIZ.dbf3d18a-5c6e-4a0b-9f1e-2a7c8e4d1b30.10dd",
                Domain::Justiz,
            ),
        ] {
            let id: SafeId = raw.parse().unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(id.domain(), Some(&expected), "{raw}");
        }
    }

    #[test]
    fn legacy_rejects_garbage_middles() {
        assert!("safe--123-456".parse::<SafeId>().is_err());
        assert!("safe-a$b-123-456".parse::<SafeId>().is_err());
        // Valid extra middle segment still accepted.
        assert!(
            "safe-sp1-x1-1357225160794-021568182"
                .parse::<SafeId>()
                .is_ok()
        );
    }

    #[test]
    fn rejects_oversized_input() {
        let huge = format!("{}{}", "a".repeat(200), "-123-456");
        assert!(matches!(
            huge.parse::<SafeId>(),
            Err(ParseSafeIdError::TooLong { limit: 120 })
        ));
    }

    #[test]
    fn compose_validates_other_domains() {
        assert!(SafeId::compose(&Domain::Other("".into()), UUID).is_err());
        assert!(SafeId::compose(&Domain::Other("BA D".into()), UUID).is_err());
        assert!(SafeId::compose(&Domain::Other("a.b".into()), UUID).is_err());
        // Re-spelling of a known domain canonicalizes.
        let id = SafeId::compose(&Domain::Other("brak".into()), UUID).unwrap();
        assert_eq!(id.domain(), Some(&Domain::Brak));
        assert_eq!(id.as_str().parse::<SafeId>().unwrap(), id);
    }

    const UUID: &str = "bdda0cd6-ccdd-44a1-a42c-f13ced17235b";

    #[test]
    fn rejects_non_ascii_without_panicking() {
        // '€' spans bytes 1..=3: a naive raw[..3] slice would panic.
        for input in ["a€bc", "€€€€", "ü", "äöü-123-456"] {
            let _ = input.parse::<SafeId>(); // may err, must not panic
        }
        assert!("a€bc".parse::<SafeId>().is_err());
    }

    #[test]
    fn serde_round_trip() {
        let id: SafeId = MODERN[1].parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", MODERN[1]));
        let back: SafeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
