//! The `SafeEntry` model — one directory entry per postbox.
//!
//! Fields follow the attribute table of the SAFE search standard v1.5
//! (section 4), certificates are modeled as a *set* per role because the
//! SAFE identity administration supports up to ten concurrent certificates
//! per user (certificate-changeover overlap; see research report §5.5).

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dienststellen::DienststellenId;
use crate::error::Error;
use crate::roles::RoleValue;
use crate::safe_id::SafeId;

/// Which of the four federated directories an entry lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Directory {
    /// SAFE public (Justiz): courts, authorities, beBPo, eBO, MJP.
    Justiz,
    /// SAFE-BRAK: lawyers.
    Brak,
    /// SAFE-BNotK: notaries.
    Bnotk,
    /// SAFE-BStBK: tax advisors.
    Bstbk,
    /// Unknown / other.
    #[default]
    Unknown,
}

impl Directory {
    /// Lowercase token used in extracts and JSON.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Justiz => "justiz",
            Self::Brak => "brak",
            Self::Bnotk => "bnotk",
            Self::Bstbk => "bstbk",
            Self::Unknown => "unknown",
        }
    }
}

/// A reference to an X.509 encryption certificate: PEM text plus derived
/// metadata. Validity is populated when the `x509` feature is active;
/// otherwise it stays `None` and expiry checks degrade gracefully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertRef {
    /// PEM armor (`-----BEGIN CERTIFICATE-----` …).
    pub pem: String,
    /// SHA-256 over the DER body, lower-case hex, `aa:bb:…`-free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// `notBefore` as Unix seconds (requires the `x509` feature).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    /// `notAfter` as Unix seconds (requires the `x509` feature).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
}

impl CertRef {
    /// Build from PEM text: decodes the body, computes the SHA-256
    /// fingerprint and (with the `x509` feature) the validity window.
    ///
    /// # Errors
    ///
    /// [`Error::Extract`] if the PEM armor is missing or the body is not
    /// valid base64. Structural X.509 problems only clear the validity
    /// window — the certificate bytes themselves stay opaque by design.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let (fingerprint, not_before, not_after) = inspect_pem(pem)?;
        Ok(Self {
            pem: pem.to_owned(),
            fingerprint: Some(fingerprint),
            not_before,
            not_after,
        })
    }

    /// DER bytes, decoded on demand.
    #[must_use]
    pub fn der(&self) -> Option<Vec<u8>> {
        pem_body(&self.pem).and_then(decode_pem_body)
    }

    /// Is the certificate valid at the given Unix timestamp (best effort)?
    /// `None` when the validity window is unknown.
    #[must_use]
    pub fn valid_at(&self, now_unix: i64) -> Option<bool> {
        match (self.not_before, self.not_after) {
            (Some(nb), Some(na)) => Some(now_unix >= nb && now_unix <= na),
            _ => None,
        }
    }

    /// Test-only constructor with an explicit validity window.
    #[doc(hidden)]
    pub fn __test_with_validity(pem: &str, not_before: i64, not_after: i64) -> Self {
        Self {
            pem: pem.to_owned(),
            fingerprint: inspect_pem(pem).ok().map(|(f, _, _)| f),
            not_before: Some(not_before),
            not_after: Some(not_after),
        }
    }
}

fn pem_body(pem: &str) -> Option<&str> {
    let start = pem.find("-----BEGIN CERTIFICATE-----")? + "-----BEGIN CERTIFICATE-----".len();
    let end = pem.find("-----END CERTIFICATE-----")?;
    (end > start).then(|| &pem[start..end])
}

/// Decode a PEM body: strip *all* whitespace (multi-line armor included)
/// before base64 decoding.
fn decode_pem_body(body: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .ok()
}

fn inspect_pem(pem: &str) -> Result<(String, Option<i64>, Option<i64>), Error> {
    let body = pem_body(pem).ok_or_else(|| {
        Error::Extract("certificate is missing PEM armor (BEGIN/END CERTIFICATE)".to_owned())
    })?;
    let der = decode_pem_body(body)
        .ok_or_else(|| Error::Extract("certificate body is not valid base64".to_owned()))?;
    let fingerprint = hex_lower(&Sha256::digest(&der));
    let (nb, na) = parse_validity(&der);
    Ok((fingerprint, nb, na))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(feature = "x509")]
fn parse_validity(der: &[u8]) -> (Option<i64>, Option<i64>) {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => {
            let nb = cert.validity().not_before.timestamp();
            let na = cert.validity().not_after.timestamp();
            (Some(nb), Some(na))
        }
        Err(_) => (None, None),
    }
}

#[cfg(not(feature = "x509"))]
fn parse_validity(_der: &[u8]) -> (Option<i64>, Option<i64>) {
    (None, None)
}

/// The OSCI connection data a sender needs for this postbox: where to
/// deliver (intermediary) and which keys to encrypt to. Mirrors the
/// `MsgContact[osci12Postbox]/Extension/OsciMsgParameter` attributes of the
/// search standard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsciEndpoint {
    /// URL of the recipient's OSCI intermediary (`IntermedAddress`).
    pub intermediary_url: String,
    /// Intermediary encryption certificate (`IntermedEncryptKey`) — the
    /// outer envelope key.
    pub intermediary_cipher: CertRef,
    /// Recipient encryption certificates (`RecipientEncryptKey`).
    #[serde(default)]
    pub recipient_cipher: Vec<CertRef>,
    /// Reader encryption certificates (`ReaderEncryptKey`); often identical
    /// to the recipient's in EGVP (Leser ≡ Empfänger merged).
    #[serde(default)]
    pub reader_cipher: Vec<CertRef>,
}

/// Operational state of a postbox, derived from roles and certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntryState {
    /// Addressable.
    Active,
    /// No role values at all — analogous to ERR20 (inactive).
    Inactive,
    /// Sole role is `zertifikatswechsel`: shielded for certificate
    /// changeover (admin practice; see research report §5.5).
    CertificateChange,
    /// All known encryption certificates have expired at the reference
    /// time. Mirrors the directories' A9 behaviour of silently hiding such
    /// entries.
    CertsExpired,
    /// Certificate validity unknown (no `x509` feature / unparsed certs):
    /// expiry cannot be judged.
    CertsUnknown,
}

/// One SAFE directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeEntry {
    /// SAFE-ID (`/safe.id`).
    pub safe_id: SafeId,
    /// Which federated directory the entry lives in.
    #[serde(default)]
    pub directory: Directory,
    /// Given name(s) (`/CommonName/AnalyzedName/FN`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vorname: Option<String>,
    /// Last name / organisation name (`/CommonName/AnalyzedName/SN`).
    pub name: String,
    /// Verified profession (BRAK/BNotK/BStBK/Justiz directories).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beruf: Option<String>,
    /// Kanzlei name (only RAE and Steuerberater).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kanzlei: Option<String>,
    /// Abteilung/Fachbereich (`AlternativeOrganization`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abteilung: Option<String>,
    /// Street (`/AddressCard/Address/Extension/StreetName`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strasse: Option<String>,
    /// House number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hausnummer: Option<String>,
    /// Postal code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plz: Option<String>,
    /// City.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ort: Option<String>,
    /// Federal state (not present in BRAK/BStBK directories, nor for
    /// MJP/eBO).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundesland: Option<String>,
    /// Country.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub land: Option<String>,
    /// Phone (`pots`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telefon: Option<String>,
    /// Mobile (`cellPhone`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobil: Option<String>,
    /// Dienststellen-IDs (SAFE public only, cardinality 1..n).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dienststellen_ids: Vec<DienststellenId>,
    /// Role values.
    #[serde(default)]
    pub roles: Vec<RoleValue>,
    /// OSCI routing data.
    pub osci: OsciEndpoint,
    /// Parse-time diagnostics (dropped role tokens, undecodable
    /// certificates, …) — surfaced so degradation is never silent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl SafeEntry {
    /// Does the entry carry a given role?
    #[must_use]
    pub fn has_role(&self, role: RoleValue) -> bool {
        self.roles.contains(&role)
    }

    /// Derive the operational state at a reference time (Unix seconds).
    ///
    /// Certificate logic: if any recipient *or* reader certificate is valid
    /// at `now`, the entry counts as cert-wise usable. If every cert with a
    /// known window has expired and none is valid, `CertsExpired`. If no
    /// window is known at all, `CertsUnknown`.
    #[must_use]
    pub fn state(&self, now_unix: i64) -> EntryState {
        if self.roles.is_empty() {
            return EntryState::Inactive;
        }
        if self.roles.len() == 1 && self.roles[0] == RoleValue::Zertifikatswechsel {
            return EntryState::CertificateChange;
        }
        let certs = self
            .osci
            .recipient_cipher
            .iter()
            .chain(&self.osci.reader_cipher);
        let mut any_valid = false;
        let mut any_known = false;
        let mut any_future = false;
        for c in certs {
            match c.valid_at(now_unix) {
                Some(true) => any_valid = true,
                Some(false) => {
                    any_known = true;
                    if c.not_before.is_some_and(|nb| now_unix < nb) {
                        any_future = true;
                    }
                }
                None => {}
            }
        }
        if any_valid {
            EntryState::Active
        } else if !any_known {
            EntryState::CertsUnknown
        } else if any_future {
            // Not yet valid: same bucket as unknown for our purposes.
            EntryState::CertsUnknown
        } else {
            EntryState::CertsExpired
        }
    }
}

/// Test support: a self-signed throwaway certificate (CN=Test
/// Intermediary, O=safedir tests, C=DE, valid 2026-10-10 … 2036-10-07).
/// Public key material only.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDYzCCAkugAwIBAgIUTnJAO9HFDyzIA5o/QRFja/vjmrIwDQYJKoZIhvcNAQEL\nBQAwQTEaMBgGA1UEAwwRVGVzdCBJbnRlcm1lZGlhcnkxFjAUBgNVBAoMDXNhZmVk\naXIgdGVzdHMxCzAJBgNVBAYTAkRFMB4XDTI2MTAxMDE1MDUzM1oXDTM2MTAwNzE1\nMDUzM1owQTEaMBgGA1UEAwwRVGVzdCBJbnRlcm1lZGlhcnkxFjAUBgNVBAoMDXNh\nZmVkaXIgdGVzdHMxCzAJBgNVBAYTAkRFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAvA+sNTmMQzSADkkzL+cjNfq+Y/XJtOB/2k38IT8L6ZIUye45eHSt\nkETvT5UwkFxthcl1uoAMtf7exFYBlixS+6BzqP3MlfLlMbTs9YGgc/d2vHHTM7cU\nkz5+mEEIF5/n7ENrH/qIiVlcljHglexufyHEO8LPiFEdVxyqApj3e2uVhzr9C9AB\n7b7Bu6u0NRYO4aikWQiusXTF8kcRadm8MfdWWxWKmirlt8Lvy6Qcbs7OnGNrWCBs\nIvlo9xaXUeqKKQoASQ5jeVNpkRxIIqaHDBun2Vg4RPh1ZY9qqxG9PngNXPA+W9TN\ni0LNsi/bXQi12rd5op330rNH5Cg2EP4hkwIDAQABo1MwUTAdBgNVHQ4EFgQU5o1O\ndfXglnLm1gvLQKsZui0By0EwHwYDVR0jBBgwFoAU5o1OdfXglnLm1gvLQKsZui0B\ny0EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAseri+QeKD1N8\nWr4Qm4YFMxoHisTbgfYaqY78d5UBJaRnwkiALOxWbO+N/ukPG2sVIY4QM1h0ZlyV\nhrcEN2w0tYsgahuSLj6onERi2P8GbBFoU8xjRFtVOECi09plAbRYf1ErIBN5hjQH\nUuvc6k/0bnJ/UwcGzjIU1ZIJd7l93Gz1QuU46ro5xXByCJSuxge2Z1QTu9vQ6qdT\njavwPpFhJmXwD0NQEoaUE1SAo4bh51L6lpd2RNCBYW4Dy9YxF731zzejozs+SzHr\nr5RnCA4gBzCUrRZ4/Piy1Ve5iQxYO7AyGlpdYktTtuM5n4nxPY7duGY+5JCmDOX/\nQn7qxQYMyw==\n-----END CERTIFICATE-----\n";
}

#[cfg(test)]
mod tests {
    use super::test_support::TEST_CERT_PEM;
    use super::*;

    fn entry(state_roles: &[RoleValue], nb: i64, na: i64) -> SafeEntry {
        SafeEntry {
            safe_id: "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"
                .parse()
                .unwrap(),
            directory: Directory::Brak,
            vorname: None,
            name: "Test".into(),
            beruf: None,
            kanzlei: None,
            abteilung: None,
            strasse: None,
            hausnummer: None,
            plz: None,
            ort: None,
            bundesland: None,
            land: None,
            telefon: None,
            mobil: None,
            dienststellen_ids: Vec::new(),
            roles: state_roles.to_vec(),
            osci: OsciEndpoint {
                intermediary_url: "https://osci.example/entry".into(),
                intermediary_cipher: CertRef::__test_with_validity(TEST_CERT_PEM, nb, na),
                recipient_cipher: vec![CertRef::__test_with_validity(TEST_CERT_PEM, nb, na)],
                reader_cipher: vec![],
            },
            warnings: Vec::new(),
        }
    }

    #[test]
    fn state_reflects_roles_and_certs() {
        let now = 1_760_000_000; // ~Oct 2025
        let active = entry(&[RoleValue::EgvpJustiz], now - 100, now + 100);
        assert_eq!(active.state(now), EntryState::Active);

        let expired = entry(&[RoleValue::EgvpJustiz], now - 200, now - 100);
        assert_eq!(expired.state(now), EntryState::CertsExpired);

        let no_roles = entry(&[], now - 100, now + 100);
        assert_eq!(no_roles.state(now), EntryState::Inactive);

        let cert_change = entry(&[RoleValue::Zertifikatswechsel], now - 100, now + 100);
        assert_eq!(cert_change.state(now), EntryState::CertificateChange);

        // Sole zertifikatswechsel plus another role is NOT the shield state.
        let mixed = entry(
            &[RoleValue::Zertifikatswechsel, RoleValue::EgvpJustiz],
            now - 100,
            now + 100,
        );
        assert_eq!(mixed.state(now), EntryState::Active);
    }

    #[test]
    fn certref_fingerprint_is_stable() {
        // Two different PEMs → different fingerprints; same → equal.
        let a = CertRef::from_pem(TEST_CERT_PEM).expect("dummy body must be base64");
        assert!(a.fingerprint.is_some());
        let b = CertRef::from_pem(TEST_CERT_PEM).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn certref_rejects_missing_armor() {
        assert!(CertRef::from_pem("not a pem").is_err());
    }
}
