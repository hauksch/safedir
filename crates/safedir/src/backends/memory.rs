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
            .find(|e| e.safe_id.as_str().eq_ignore_ascii_case(id.as_str()))
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
        if query.is_empty() {
            return Err(Error::InvalidQuery(
                "search without parameters is not possible (A4)".into(),
            ));
        }
        let count = self.entries.iter().filter(|e| query.matches(e)).count();
        if count > MAX_HITS {
            // A15–A17: more than MAX_HITS hits are NOT returned; the
            // requester gets the ERR40 error and must narrow the query.
            return Err(Error::Directory(
                crate::error::ErrCode::Err40,
                crate::error::ErrCode::Err40.message().to_owned(),
            ));
        }
        let entries: Vec<SafeEntry> = self
            .entries
            .iter()
            .filter(|e| query.matches(e))
            .cloned()
            .collect();
        Ok(SearchOutcome {
            entries,
            notes: Vec::new(),
            warnings: Vec::new(),
        })
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
                &format!("dbf3d18a-5c6e-4a0b-9f1e-2a7c8e4d1b{:02x}", name.len()),
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
            warnings: Vec::new(),
        }
    }

    #[test]
    fn search_errors_above_the_100_hit_cap() {
        let entries: Vec<SafeEntry> = (0..101)
            .map(|i| {
                let mut e = entry(&format!("Gericht {i}"), "Bonn", &[RoleValue::EgvpJustiz]);
                e.safe_id = crate::safe_id::SafeId::compose(
                    &crate::safe_id::Domain::Justiz,
                    &format!("{:08x}-5c6e-4a0b-9f1e-2a7c8e4d1b{:02x}", i, i),
                )
                .unwrap();
                e
            })
            .collect();
        let dir = InMemoryResolver::from_entries(entries);

        let q = SearchQuery::builder()
            .ort_contains("Bonn")
            .unwrap()
            .build()
            .unwrap();
        match dir.search(&q) {
            Err(Error::Directory(crate::error::ErrCode::Err40, _)) => {}
            other => panic!("expected ERR40, got {other:?}"),
        }

        // Exactly 100 hits is fine.
        let entries: Vec<SafeEntry> = (0..100)
            .map(|i| {
                let mut e = entry(&format!("Gericht {i}"), "Bonn", &[RoleValue::EgvpJustiz]);
                e.safe_id = crate::safe_id::SafeId::compose(
                    &crate::safe_id::Domain::Justiz,
                    &format!("{:08x}-5c6e-4a0b-9f1e-2a7c8e4d1c{:02x}", i, i),
                )
                .unwrap();
                e
            })
            .collect();
        let dir = InMemoryResolver::from_entries(entries);
        let out = dir.search(&q).unwrap();
        assert_eq!(out.entries.len(), 100);
        assert!(out.warnings.is_empty());
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
