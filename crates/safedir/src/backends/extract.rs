//! Offline backend over a `safe.json` extract file.

use std::path::{Path, PathBuf};

use crate::dienststellen::DienststellenId;
use crate::entry::SafeEntry;
use crate::error::Error;
use crate::extract::ExtractFile;
use crate::resolver::{SafeDirectory, SearchOutcome, SearchQuery};
use crate::safe_id::SafeId;

/// A [`SafeDirectory`] backed by a local extract file (see
/// [`crate::extract`]). Immutable once loaded.
#[derive(Debug, Clone)]
pub struct ExtractResolver {
    path: Option<PathBuf>,
    inner: crate::backends::InMemoryResolver,
}

impl ExtractResolver {
    /// Load from a path, **strictly**: the extract is validated first
    /// (duplicates, roles, URLs, cert parseability) and any issue is an
    /// error. See [`ExtractResolver::from_path_lenient`] to skip the
    /// lint.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when unreadable, [`Error::Extract`] when
    /// malformed, validation fails, or an entry fails to convert.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::load(path, true)
    }

    /// Load from a path without running [`ExtractFile::validate`].
    ///
    /// # Errors
    ///
    /// See [`ExtractResolver::from_path`].
    pub fn from_path_lenient(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::load(path, false)
    }

    fn load(path: impl AsRef<Path>, strict: bool) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = ExtractFile::from_path(path)?;
        if strict {
            let issues = file.validate();
            if let Some(first) = issues.first() {
                return Err(Error::Extract(format!(
                    "{}: entry {:?}, field {}: {} ({} issues in total)",
                    path.display(),
                    first.entry,
                    first.field,
                    first.message,
                    issues.len()
                )));
            }
        }
        Ok(Self {
            path: Some(path.to_path_buf()),
            inner: crate::backends::InMemoryResolver::from_entries(file.into_entries()?),
        })
    }
}

impl std::str::FromStr for ExtractResolver {
    type Err = Error;

    /// Load from JSON text.
    ///
    /// # Errors
    ///
    /// See [`ExtractResolver::from_path`].
    fn from_str(text: &str) -> Result<Self, Error> {
        let file: ExtractFile = text.parse()?;
        Ok(Self {
            path: None,
            inner: crate::backends::InMemoryResolver::from_entries(file.into_entries()?),
        })
    }
}

impl ExtractResolver {
    /// Where this extract was loaded from, if known.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Is the extract empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl SafeDirectory for ExtractResolver {
    fn lookup_safe_id(&self, id: &SafeId) -> Result<Option<SafeEntry>, Error> {
        self.inner.lookup_safe_id(id)
    }

    fn lookup_dienststellen(&self, id: &DienststellenId) -> Result<Vec<SafeEntry>, Error> {
        self.inner.lookup_dienststellen(id)
    }

    fn search(&self, query: &SearchQuery) -> Result<SearchOutcome, Error> {
        self.inner.search(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_and_lookup() {
        let cert = crate::entry::test_support::TEST_CERT_PEM.replace('\n', "\\n");
        let json = format!(
            r#"{{
  "$format": 1,
  "entries": [
    {{
      "safe_id": "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
      "name": "Rechtsanwalt Example",
      "roles": ["egvp_beA"],
      "osci": {{
        "intermediary_url": "https://bea-intermediaer.example/entry",
        "intermediary_cipher_cert": "{cert}",
        "recipient_cipher_certs": ["{cert}"]
      }}
    }}
  ]
}}"#
        );
        let dir: ExtractResolver = json.parse().unwrap();
        assert_eq!(dir.len(), 1);
        let id: crate::safe_id::SafeId = "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"
            .parse()
            .unwrap();
        let e = dir.lookup_safe_id(&id).unwrap().expect("found");
        assert_eq!(e.name, "Rechtsanwalt Example");
    }
}
