//! The `SafeDirectory` abstraction and the SAFE search semantics.

use crate::dienststellen::DienststellenId;
use crate::entry::SafeEntry;
use crate::error::Error;
use crate::roles::RoleValue;
use crate::safe_id::SafeId;

/// Maximum number of hits per search (standard v1.5, A15–A17).
pub const MAX_HITS: usize = 100;

/// How a search term matches (standard v1.5, section 2 A2 "Art der Suche").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SearchKind {
    /// "beginnt mit Teilstring" (prefix).
    BeginsWith,
    /// "beinhaltet Teilstring" (contains; multiple words are ANDed per A2).
    Contains,
    /// "entspricht Suchparameter" (equals; case-insensitive per A11).
    Equals,
}

/// A search term: matching kind plus value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SearchTerm {
    /// Matching kind.
    pub kind: SearchKind,
    /// Term value.
    pub value: String,
}

impl SearchTerm {
    /// Does this term match a field value?
    ///
    /// Case-insensitive (A11); `Contains` with multiple words matches iff
    /// every whitespace-separated word occurs (A2).
    #[must_use]
    pub fn matches(&self, field: &str) -> bool {
        let field = field.to_lowercase();
        match self.kind {
            SearchKind::Equals => field == self.value.to_lowercase(),
            SearchKind::BeginsWith => field.starts_with(&self.value.to_lowercase()),
            SearchKind::Contains => self
                .value
                .split_whitespace()
                .map(str::to_lowercase)
                .all(|w| field.contains(&w)),
        }
    }
}

/// A structured search query. Only allowed parameters exist as fields; the
/// builder enforces the per-attribute minimum lengths (A14) — with the
/// documented exception: a too-short `name` term silently becomes an exact
/// search instead of an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchQuery {
    /// Vorname (contains ≥ 2 chars).
    pub vorname: Option<SearchTerm>,
    /// Name/Organisation (contains ≥ 2 chars; shorter ⇒ exact search).
    pub name: Option<SearchTerm>,
    /// Kanzlei (contains/equals/begins ≥ 3 chars).
    pub kanzlei: Option<SearchTerm>,
    /// Abteilung/Fachbereich (contains ≥ 3 chars; not in BRAK/BNotK/BStBK).
    pub abteilung: Option<SearchTerm>,
    /// Straße (contains ≥ 3 chars).
    pub strasse: Option<SearchTerm>,
    /// Hausnummer (contains ≥ 1 char).
    pub hausnummer: Option<SearchTerm>,
    /// Postleitzahl (begins ≥ 1 char).
    pub plz: Option<SearchTerm>,
    /// Ort (contains ≥ 2 chars).
    pub ort: Option<SearchTerm>,
    /// Bundesland (equals; not in BRAK/BStBK directories).
    pub bundesland: Option<SearchTerm>,
    /// Land (equals).
    pub land: Option<SearchTerm>,
    /// Telefonnummer (contains ≥ 5 chars).
    pub telefon: Option<SearchTerm>,
    /// Mobiltelefonnummer (contains ≥ 5 chars).
    pub mobil: Option<SearchTerm>,
    /// Exact SAFE-ID match (allowed in `search` since standard v1.1).
    pub safe_id: Option<SafeId>,
    /// Exact Dienststellen-ID match (SAFE public only).
    pub dienststellen_id: Option<DienststellenId>,
    /// Role filters: entries matching *any* of them qualify (Oder-Suche,
    /// A7/A8); they also steer which federated directory is searched.
    pub roles: Vec<RoleValue>,
}

impl SearchQuery {
    /// Start building a query.
    #[must_use]
    pub fn builder() -> SearchQueryBuilder {
        SearchQueryBuilder {
            query: SearchQuery::default(),
        }
    }

    /// Does an entry satisfy this query? (AND across parameters, A11.)
    #[must_use]
    pub fn matches(&self, entry: &SafeEntry) -> bool {
        let text = |t: &Option<SearchTerm>, f: Option<&str>| {
            // A term against a field the entry does not carry cannot match.
            t.as_ref().map(|t| f.is_some_and(|f| t.matches(f)))
        };
        let checks = [
            text(&self.vorname, entry.vorname.as_deref()),
            text(&self.name, Some(entry.name.as_str())),
            text(&self.kanzlei, entry.kanzlei.as_deref()),
            text(&self.abteilung, entry.abteilung.as_deref()),
            text(&self.strasse, entry.strasse.as_deref()),
            text(&self.hausnummer, entry.hausnummer.as_deref()),
            text(&self.plz, entry.plz.as_deref()),
            text(&self.ort, entry.ort.as_deref()),
            text(&self.bundesland, entry.bundesland.as_deref()),
            text(&self.land, entry.land.as_deref()),
            text(&self.telefon, entry.telefon.as_deref()),
            text(&self.mobil, entry.mobil.as_deref()),
        ];
        if checks.contains(&Some(false)) {
            return false;
        }
        if let Some(id) = &self.safe_id {
            if id.as_str() != entry.safe_id.as_str() {
                return false;
            }
        }
        if let Some(ds) = &self.dienststellen_id {
            if !entry
                .dienststellen_ids
                .iter()
                .any(|d| d.as_str() == ds.as_str())
            {
                return false;
            }
        }
        if !self.roles.is_empty() && !entry.roles.iter().any(|r| self.roles.contains(r)) {
            return false;
        }
        true
    }
}

fn set_term(
    slot: &mut Option<SearchTerm>,
    kind: SearchKind,
    value: &str,
    min: usize,
    field: &str,
) -> Result<(), Error> {
    let n = value.trim().chars().count();
    if n == 0 {
        return Err(Error::InvalidQuery(format!("{field}: empty term")));
    }
    if n < min {
        return Err(Error::InvalidQuery(format!(
            "{field}: needs at least {min} characters (ERR30)"
        )));
    }
    *slot = Some(SearchTerm {
        kind,
        value: value.trim().to_owned(),
    });
    Ok(())
}

/// Builder for [`SearchQuery`] enforcing the standard's minimum lengths.
#[derive(Debug, Clone)]
pub struct SearchQueryBuilder {
    query: SearchQuery,
}

impl SearchQueryBuilder {
    /// Name/Organisation, contains. Below 2 characters this *degrades to an
    /// exact search* per A14 instead of failing.
    pub fn name_contains(mut self, v: &str) -> Result<Self, Error> {
        let n = v.trim().chars().count();
        if n == 0 {
            return Err(Error::InvalidQuery("name: empty term".into()));
        }
        let kind = if n < 2 {
            SearchKind::Equals
        } else {
            SearchKind::Contains
        };
        self.query.name = Some(SearchTerm {
            kind,
            value: v.trim().to_owned(),
        });
        Ok(self)
    }

    /// Vorname, contains ≥ 2.
    pub fn vorname_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.vorname,
            SearchKind::Contains,
            v,
            2,
            "vorname",
        )?;
        Ok(self)
    }

    /// Kanzlei, contains ≥ 3.
    pub fn kanzlei_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.kanzlei,
            SearchKind::Contains,
            v,
            3,
            "kanzlei",
        )?;
        Ok(self)
    }

    /// Abteilung/Fachbereich, contains ≥ 3.
    pub fn abteilung_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.abteilung,
            SearchKind::Contains,
            v,
            3,
            "abteilung",
        )?;
        Ok(self)
    }

    /// Ort, contains ≥ 2.
    pub fn ort_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(&mut self.query.ort, SearchKind::Contains, v, 2, "ort")?;
        Ok(self)
    }

    /// Straße, contains ≥ 3.
    pub fn strasse_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.strasse,
            SearchKind::Contains,
            v,
            3,
            "strasse",
        )?;
        Ok(self)
    }

    /// Hausnummer, contains ≥ 1.
    pub fn hausnummer_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.hausnummer,
            SearchKind::Contains,
            v,
            1,
            "hausnummer",
        )?;
        Ok(self)
    }

    /// Postleitzahl, begins ≥ 1.
    pub fn plz_begins(mut self, v: &str) -> Result<Self, Error> {
        set_term(&mut self.query.plz, SearchKind::BeginsWith, v, 1, "plz")?;
        Ok(self)
    }

    /// Bundesland, equals.
    pub fn bundesland(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.bundesland,
            SearchKind::Equals,
            v,
            1,
            "bundesland",
        )?;
        Ok(self)
    }

    /// Land, equals.
    pub fn land(mut self, v: &str) -> Result<Self, Error> {
        set_term(&mut self.query.land, SearchKind::Equals, v, 1, "land")?;
        Ok(self)
    }

    /// Telefon, contains ≥ 5.
    pub fn telefon_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.telefon,
            SearchKind::Contains,
            v,
            5,
            "telefon",
        )?;
        Ok(self)
    }

    /// Mobil, contains ≥ 5.
    pub fn mobil_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(&mut self.query.mobil, SearchKind::Contains, v, 5, "mobil")?;
        Ok(self)
    }

    /// Exact SAFE-ID.
    pub fn safe_id(mut self, id: SafeId) -> Self {
        self.query.safe_id = Some(id);
        self
    }

    /// Exact Dienststellen-ID.
    pub fn dienststellen_id(mut self, id: DienststellenId) -> Self {
        self.query.dienststellen_id = Some(id);
        self
    }

    /// Add role filters (OR semantics).
    pub fn with_roles(mut self, roles: &[RoleValue]) -> Self {
        self.query.roles.extend_from_slice(roles);
        self
    }

    /// Finish. Fails if the query has no parameters at all (A4).
    pub fn build(self) -> Result<SearchQuery, Error> {
        let q = &self.query;
        let any = q.vorname.is_some()
            || q.name.is_some()
            || q.kanzlei.is_some()
            || q.abteilung.is_some()
            || q.strasse.is_some()
            || q.hausnummer.is_some()
            || q.plz.is_some()
            || q.ort.is_some()
            || q.bundesland.is_some()
            || q.land.is_some()
            || q.telefon.is_some()
            || q.mobil.is_some()
            || q.safe_id.is_some()
            || q.dienststellen_id.is_some()
            || !q.roles.is_empty();
        if !any {
            return Err(Error::InvalidQuery(
                "search without parameters is not possible (A4)".into(),
            ));
        }
        Ok(self.query)
    }
}

/// Result of a search: entries plus advisory notes (e.g. `ERR100` when one
/// of the federated directories was unreachable and the list may be
/// incomplete).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SearchOutcome {
    /// Matching entries (capped at [`MAX_HITS`]).
    pub entries: Vec<SafeEntry>,
    /// Directory hints that belong to the result set (A5).
    pub notes: Vec<crate::error::ErrCode>,
}

/// A source of SAFE directory data.
pub trait SafeDirectory {
    /// Fetch a single entry by SAFE-ID. `Ok(None)` when the ID is unknown.
    ///
    /// # Errors
    ///
    /// [`Error::Directory`] for typed directory failures; other variants
    /// for configuration/network problems.
    fn lookup_safe_id(&self, id: &SafeId) -> Result<Option<SafeEntry>, Error>;

    /// Fetch all entries carrying a Dienststellen-ID (SAFE public).
    ///
    /// # Errors
    ///
    /// See [`SafeDirectory::lookup_safe_id`].
    fn lookup_dienststellen(&self, id: &DienststellenId) -> Result<Vec<SafeEntry>, Error>;

    /// Structured search.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidQuery`] never — queries are validated at build time;
    /// directory-side violations surface as [`Error::Directory`].
    fn search(&self, query: &SearchQuery) -> Result<SearchOutcome, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_matching_semantics() {
        let t = |kind: SearchKind, v: &str| SearchTerm {
            kind,
            value: v.to_owned(),
        };
        // Case-insensitivity (A11)
        assert!(t(SearchKind::Equals, "AG BONN").matches("ag bonn"));
        // Multi-word contains is ANDed per word (A2)
        assert!(
            t(SearchKind::Contains, "Rechtsanwaltskammer Hamm")
                .matches("Rechtsanwaltskammer für den Oberlandesgerichtsbezirk Hamm")
        );
        assert!(
            !t(SearchKind::Contains, "Kammer Hamm Ulm")
                .matches("Rechtsanwaltskammer für den Oberlandesgerichtsbezirk Hamm")
        );
        assert!(t(SearchKind::BeginsWith, "3011").matches("301125"));
        assert!(!t(SearchKind::BeginsWith, "25").matches("301125"));
    }

    #[test]
    fn builder_enforces_minimums() {
        assert!(SearchQuery::builder().vorname_contains("a").is_err());
        assert!(SearchQuery::builder().ort_contains("b").is_err());
        assert!(SearchQuery::builder().telefon_contains("1234").is_err());
        assert!(SearchQuery::builder().build().is_err());
        // Short name degrades to exact (A14)
        let q = SearchQuery::builder()
            .name_contains("a")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(q.name.unwrap().kind, SearchKind::Equals);
    }
}
