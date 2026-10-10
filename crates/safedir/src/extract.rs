//! The `safe.json` extract format — an offline snapshot of directory
//! entries, philosophically identical to rosci's `dvdv.json`.
//!
//! Produced by a party with legitimate directory access (or hand-curated),
//! consumed locally: no online traces, no credentials in the loop. The
//! format is versioned via `"$format"`; this crate reads and writes
//! version 1.

use serde::{Deserialize, Serialize};

use crate::dienststellen::DienststellenId;
use crate::entry::{CertRef, Directory, OsciEndpoint, SafeEntry};
use crate::error::Error;
use crate::roles::RoleValue;
use crate::safe_id::SafeId;

/// Current extract format version.
pub const FORMAT_VERSION: u8 = 1;

/// The whole extract file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractFile {
    /// Format marker, currently `1`.
    #[serde(rename = "$format")]
    pub format: u8,
    /// Optional provenance note (generator, date, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// The entries.
    pub entries: Vec<ExtractEntry>,
}

/// One entry in extract form (all certificates as inline PEM).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractEntry {
    /// SAFE-ID.
    pub safe_id: SafeId,
    /// Directory of origin: `justiz` / `brak` / `bnotk` / `bstbk` /
    /// `unknown`.
    #[serde(default)]
    pub directory: Directory,
    /// Name / organisation name.
    pub name: String,
    /// Given name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vorname: Option<String>,
    /// Profession.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beruf: Option<String>,
    /// Kanzlei.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kanzlei: Option<String>,
    /// Abteilung/Fachbereich.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abteilung: Option<String>,
    /// Street.
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
    /// Federal state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundesland: Option<String>,
    /// Country.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub land: Option<String>,
    /// Phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telefon: Option<String>,
    /// Mobile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobil: Option<String>,
    /// Dienststellen-IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dienststellen_ids: Vec<DienststellenId>,
    /// Role values.
    #[serde(default)]
    pub roles: Vec<RoleValue>,
    /// OSCI routing data.
    pub osci: ExtractOsci,
}

/// OSCI routing data in extract form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractOsci {
    /// Intermediary URL.
    pub intermediary_url: String,
    /// Intermediary encryption certificate (PEM).
    pub intermediary_cipher_cert: String,
    /// Recipient encryption certificates (PEM).
    #[serde(default)]
    pub recipient_cipher_certs: Vec<String>,
    /// Reader encryption certificates (PEM).
    #[serde(default)]
    pub reader_cipher_certs: Vec<String>,
}

/// A single validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Index of the offending entry (or `None` for file-level issues).
    pub entry: Option<usize>,
    /// Field name.
    pub field: &'static str,
    /// Human-readable problem.
    pub message: String,
}

impl std::str::FromStr for ExtractFile {
    type Err = Error;

    /// Parse from JSON text.
    ///
    /// # Errors
    ///
    /// [`Error::Extract`] on malformed JSON or a wrong format version.
    fn from_str(text: &str) -> Result<Self, Error> {
        let file: Self = serde_json::from_str(text)
            .map_err(|e| Error::Extract(format!("malformed extract: {e}")))?;
        if file.format != FORMAT_VERSION {
            return Err(Error::Extract(format!(
                "unsupported extract format {} (this crate reads version {FORMAT_VERSION})",
                file.format
            )));
        }
        Ok(file)
    }
}

impl ExtractFile {
    /// Parse from a file path.
    ///
    /// # Errors
    ///
    /// See [`ExtractFile::from_str`]; IO problems surface as
    /// [`Error::Config`].
    pub fn from_path(path: &std::path::Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        text.parse()
    }

    /// Serialize to pretty JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Extract`] on serialization failure.
    pub fn to_string_pretty(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::Extract(format!("cannot serialize extract: {e}")))
    }

    /// Validate: certificates parse, entries have names/roles, SAFE-IDs are
    /// unique, intermediary URLs look like URLs. Returns all findings.
    #[must_use]
    pub fn validate(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        for (i, e) in self.entries.iter().enumerate() {
            if !seen_ids.insert(e.safe_id.as_str().to_owned()) {
                issues.push(Issue {
                    entry: Some(i),
                    field: "safe_id",
                    message: format!("duplicate SAFE-ID {}", e.safe_id),
                });
            }
            if e.name.trim().is_empty() {
                issues.push(Issue {
                    entry: Some(i),
                    field: "name",
                    message: "name must not be empty".into(),
                });
            }
            if e.roles.is_empty() {
                issues.push(Issue {
                    entry: Some(i),
                    field: "roles",
                    message: "no role values (entry would be inactive, ERR20)".into(),
                });
            }
            if !e.osci.intermediary_url.starts_with("http") {
                issues.push(Issue {
                    entry: Some(i),
                    field: "osci.intermediary_url",
                    message: format!("not an HTTP(S) URL: {:?}", e.osci.intermediary_url),
                });
            }
            for (field, pem) in std::iter::once((
                "osci.intermediary_cipher_cert",
                &e.osci.intermediary_cipher_cert,
            ))
            .chain(
                e.osci
                    .recipient_cipher_certs
                    .iter()
                    .map(|p| ("osci.recipient_cipher_certs", p))
                    .chain(
                        e.osci
                            .reader_cipher_certs
                            .iter()
                            .map(|p| ("osci.reader_cipher_certs", p)),
                    ),
            ) {
                if CertRef::from_pem(pem).is_err() {
                    issues.push(Issue {
                        entry: Some(i),
                        field,
                        message: "certificate is not parseable PEM".into(),
                    });
                }
            }
            if e.osci.recipient_cipher_certs.is_empty() && e.osci.reader_cipher_certs.is_empty() {
                issues.push(Issue {
                    entry: Some(i),
                    field: "osci.recipient_cipher_certs",
                    message: "no recipient or reader certificates — the postbox cannot be \
                              encrypted for"
                        .into(),
                });
            }
        }
        issues
    }

    /// Convert into typed entries. Fails on the first structurally invalid
    /// entry (unparseable certificate).
    ///
    /// # Errors
    ///
    /// [`Error::Extract`] with entry index and reason.
    pub fn into_entries(self) -> Result<Vec<SafeEntry>, Error> {
        self.entries
            .into_iter()
            .enumerate()
            .map(|(i, e)| {
                let conv = |pem: &str| {
                    CertRef::from_pem(pem)
                        .map_err(|err| Error::Extract(format!("entry {i}: {err}")))
                };
                Ok(SafeEntry {
                    safe_id: e.safe_id,
                    directory: e.directory,
                    vorname: e.vorname,
                    name: e.name,
                    beruf: e.beruf,
                    kanzlei: e.kanzlei,
                    abteilung: e.abteilung,
                    strasse: e.strasse,
                    hausnummer: e.hausnummer,
                    plz: e.plz,
                    ort: e.ort,
                    bundesland: e.bundesland,
                    land: e.land,
                    telefon: e.telefon,
                    mobil: e.mobil,
                    dienststellen_ids: e.dienststellen_ids,
                    roles: e.roles,
                    osci: OsciEndpoint {
                        intermediary_url: e.osci.intermediary_url,
                        intermediary_cipher: conv(&e.osci.intermediary_cipher_cert)?,
                        recipient_cipher: e
                            .osci
                            .recipient_cipher_certs
                            .iter()
                            .map(|p| conv(p))
                            .collect::<Result<Vec<_>, _>>()?,
                        reader_cipher: e
                            .osci
                            .reader_cipher_certs
                            .iter()
                            .map(|p| conv(p))
                            .collect::<Result<Vec<_>, _>>()?,
                    },
                })
            })
            .collect()
    }

    /// Build an extract file from typed entries (inverse of
    /// [`ExtractFile::into_entries`]).
    #[must_use]
    pub fn from_entries(entries: Vec<SafeEntry>) -> Self {
        Self {
            format: FORMAT_VERSION,
            provenance: None,
            entries: entries
                .into_iter()
                .map(|e| ExtractEntry {
                    safe_id: e.safe_id,
                    directory: e.directory,
                    name: e.name,
                    vorname: e.vorname,
                    beruf: e.beruf,
                    kanzlei: e.kanzlei,
                    abteilung: e.abteilung,
                    strasse: e.strasse,
                    hausnummer: e.hausnummer,
                    plz: e.plz,
                    ort: e.ort,
                    bundesland: e.bundesland,
                    land: e.land,
                    telefon: e.telefon,
                    mobil: e.mobil,
                    dienststellen_ids: e.dienststellen_ids,
                    roles: e.roles,
                    osci: ExtractOsci {
                        intermediary_url: e.osci.intermediary_url,
                        intermediary_cipher_cert: e.osci.intermediary_cipher.pem,
                        recipient_cipher_certs: e
                            .osci
                            .recipient_cipher
                            .into_iter()
                            .map(|c| c.pem)
                            .collect(),
                        reader_cipher_certs: e
                            .osci
                            .reader_cipher
                            .into_iter()
                            .map(|c| c.pem)
                            .collect(),
                    },
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> String {
        let cert = crate::entry::test_support::TEST_CERT_PEM.replace('\n', "\\n");
        format!(
            r#"{{
  "$format": 1,
  "entries": [
    {{
      "safe_id": "DE.Justiz.dbf3d18a-5c6e-4a0b-9f1e-2a7c8e4d1b30.10dd",
      "directory": "justiz",
      "name": "Amtsgericht Bonn",
      "ort": "Bonn",
      "plz": "53111",
      "dienststellen_ids": ["301125T"],
      "roles": ["egvp_justiz"],
      "osci": {{
        "intermediary_url": "https://intermediaer.justiz.example/entry",
        "intermediary_cipher_cert": "{cert}",
        "recipient_cipher_certs": ["{cert}"]
      }}
    }}
  ]
}}"#
        )
    }

    #[test]
    fn parses_validates_and_converts() {
        let file: ExtractFile = sample_json().parse().expect("parses");
        assert!(file.validate().is_empty(), "{:?}", file.validate());
        let entries = file.into_entries().expect("converts");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.name, "Amtsgericht Bonn");
        assert_eq!(
            e.dienststellen_ids[0].wire_form(),
            "Dienststellen-ID:301125T"
        );
        assert!(e.has_role(RoleValue::EgvpJustiz));
        assert!(e.osci.recipient_cipher[0].fingerprint.is_some());
    }

    #[test]
    fn round_trip() {
        let file: ExtractFile = sample_json().parse().unwrap();
        let entries = file.clone().into_entries().unwrap();
        let file2 = ExtractFile::from_entries(entries);
        assert_eq!(file, file2);
    }

    #[test]
    fn rejects_wrong_format_version() {
        let bad = r#"{ "$format": 99, "entries": [] }"#;
        assert!(bad.parse::<ExtractFile>().is_err());
    }

    #[test]
    fn validation_flags_duplicates_and_bad_certs() {
        let mut file: ExtractFile = sample_json().parse().unwrap();
        file.entries.push(file.entries[0].clone());
        file.entries[0].osci.intermediary_cipher_cert = "garbage".into();
        let issues = file.validate();
        assert!(
            issues
                .iter()
                .any(|i| i.field == "safe_id" && i.entry == Some(1))
        );
        assert!(
            issues
                .iter()
                .any(|i| i.field == "osci.intermediary_cipher_cert" && i.entry == Some(0))
        );
    }
}
