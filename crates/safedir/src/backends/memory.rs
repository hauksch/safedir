//! In-memory backend for tests and embedded use.

use crate::dienststellen::DienststellenId;
use crate::entry::SafeEntry;
use crate::error::Error;
use crate::resolver::{MAX_HITS, SafeDirectory, SearchOutcome, SearchQuery};
use crate::safe_id::SafeId;

/// A directory held in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryResolver {
    entries: Vec<SafeEntry>,
}

impl InMemoryResolver {
    /// Empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Directory from entries.
    #[must_use]
    pub fn from_entries<I: IntoIterator<Item = SafeEntry>>(entries: I) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the directory empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl SafeDirectory for InMemoryResolver {
    fn lookup_safe_id(&self, id: &SafeId) -> Result<Option<SafeEntry>, Error> {
        Ok(self
            .entries
            .iter()
            .find(|e| e.safe_id.as_str() == id.as_str())
            .cloned())
    }

    fn lookup_dienststellen(&self, id: &DienststellenId) -> Result<Vec<SafeEntry>, Error> {
        Ok(self
            .entries
            .iter()
            .filter(|e| {
                e.dienststellen_ids
                    .iter()
                    .any(|d| d.as_str() == id.as_str())
            })
            .cloned()
            .collect())
    }

    fn search(&self, query: &SearchQuery) -> Result<SearchOutcome, Error> {
        let mut entries: Vec<SafeEntry> = self
            .entries
            .iter()
            .filter(|e| query.matches(e))
            .cloned()
            .collect();
        // A15/A16: more than MAX_HITS hits must not be returned silently —
        // for local backends we truncate and add the ERR40 note.
        let mut notes = Vec::new();
        if entries.len() > MAX_HITS {
            entries.truncate(MAX_HITS);
            notes.push(crate::error::ErrCode::Err40);
        }
        Ok(SearchOutcome { entries, notes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::test_support::TEST_CERT_PEM;
    use crate::entry::{CertRef, Directory, OsciEndpoint};
    use crate::roles::RoleValue;

    fn entry(name: &str, ort: &str, roles: &[RoleValue]) -> SafeEntry {
        SafeEntry {
            safe_id: SafeId::compose(
                &crate::safe_id::Domain::Justiz,
                &format!("dbf3d18a-5c6e-4a0b-9f1e-2a7c8e4d1b{}", name.len()),
            )
            .unwrap(),
            directory: Directory::Justiz,
            vorname: None,
            name: name.into(),
            beruf: None,
            kanzlei: None,
            abteilung: None,
            strasse: None,
            hausnummer: None,
            plz: None,
            ort: Some(ort.into()),
            bundesland: None,
            land: None,
            telefon: None,
            mobil: None,
            dienststellen_ids: vec!["301125T".parse().unwrap()],
            roles: roles.to_vec(),
            osci: OsciEndpoint {
                intermediary_url: "https://x/".into(),
                intermediary_cipher: CertRef::__test_with_validity(TEST_CERT_PEM, 0, 9_999_999_999),
                recipient_cipher: vec![CertRef::__test_with_validity(
                    TEST_CERT_PEM,
                    0,
                    9_999_999_999,
                )],
                reader_cipher: vec![],
            },
        }
    }

    #[test]
    fn lookup_and_search() {
        let dir = InMemoryResolver::from_entries([
            entry("Amtsgericht Bonn", "Bonn", &[RoleValue::EgvpJustiz]),
            entry("Landgericht Bonn", "Bonn", &[RoleValue::EgvpJustiz]),
            entry("Rechtsanwalt Müller", "Köln", &[RoleValue::EgvpBea]),
        ]);
        let id = dir
            .lookup_dienststellen(&"301125T".parse().unwrap())
            .unwrap()
            .first()
            .unwrap()
            .safe_id
            .clone();
        assert!(dir.lookup_safe_id(&id).unwrap().is_some());
        assert!(
            dir.lookup_safe_id(&"safe-prod-1498121242459-016499869".parse().unwrap())
                .unwrap()
                .is_none()
        );

        let q = SearchQuery::builder()
            .ort_contains("Bonn")
            .unwrap()
            .with_roles(&[RoleValue::EgvpJustiz])
            .build()
            .unwrap();
        let out = dir.search(&q).unwrap();
        assert_eq!(out.entries.len(), 2);
        assert!(out.notes.is_empty());
    }
}
