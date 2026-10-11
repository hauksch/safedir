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
    /// Berufsbezeichnung (contains ≥ 5 chars, v1.5 table).
    pub beruf: Option<SearchTerm>,
    /// Name/Organisation (contains ≥ 2 chars; shorter ⇒ exact search).
    pub name: Option<SearchTerm>,
    /// Kanzlei (contains/equals/begins ≥ 3 chars).
    pub kanzlei: Option<SearchTerm>,
    /// Abteilung/Fachbereich. NOT a v1.5 search parameter (ERR10 at the
    /// VAS); kept for entry data — local backends can match on it.
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
    /// Land. NOT a v1.5 search parameter (ERR10 at the VAS); kept for
    /// entry data.
    pub land: Option<SearchTerm>,
    /// Telefonnummer. NOT a v1.5 search parameter (ERR10 at the VAS);
    /// kept for entry data.
    pub telefon: Option<SearchTerm>,
    /// Mobiltelefonnummer. NOT a v1.5 search parameter (ERR10 at the
    /// VAS); kept for entry data.
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
    /// An empty query (A4) matches nothing.
    #[must_use]
    pub fn matches(&self, entry: &SafeEntry) -> bool {
        if self.is_empty() {
            return false;
        }
        let text = |t: &Option<SearchTerm>, f: Option<&str>| {
            // A term against a field the entry does not carry cannot match.
            t.as_ref().map(|t| f.is_some_and(|f| t.matches(f)))
        };
        let checks = [
            text(&self.vorname, entry.vorname.as_deref()),
            text(&self.beruf, entry.beruf.as_deref()),
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
        if let Some(id) = &self.safe_id
            && !id.as_str().eq_ignore_ascii_case(entry.safe_id.as_str())
        {
            return false;
        }
        if let Some(ds) = &self.dienststellen_id
            && !entry
                .dienststellen_ids
                .iter()
                .any(|d| d.as_str().eq_ignore_ascii_case(ds.as_str()))
        {
            return false;
        }
        if !self.roles.is_empty()
            && !entry.roles.iter().any(|r| {
                self.roles
                    .iter()
                    .any(|q| q.token().eq_ignore_ascii_case(&r.token()))
            })
        {
            return false;
        }
        true
    }

    /// Is the query empty (no parameters, no role filters)? A4 forbids
    /// empty searches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vorname.is_none()
            && self.beruf.is_none()
            && self.name.is_none()
            && self.kanzlei.is_none()
            && self.abteilung.is_none()
            && self.strasse.is_none()
            && self.hausnummer.is_none()
            && self.plz.is_none()
            && self.ort.is_none()
            && self.bundesland.is_none()
            && self.land.is_none()
            && self.telefon.is_none()
            && self.mobil.is_none()
            && self.safe_id.is_none()
            && self.dienststellen_id.is_none()
            && self.roles.is_empty()
    }

    /// Re-check a hand-built query against the standard's rules (the
    /// builder enforces them; public fields do not):
    /// - A4: empty queries and queries consisting *only* of non-searchable
    ///   parameters are rejected (the VAS would answer ERR10);
    /// - per-attribute minimum lengths (ERR30);
    /// - per-attribute kind legality (ERR50): the § 4 table prescribes
    ///   exactly one "Art der Suche" per attribute;
    /// - A14: a hand-built `name` term below 2 characters is coerced to an
    ///   exact search.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidQuery`] naming the offending field.
    pub fn validate(&mut self) -> Result<(), Error> {
        if self.is_empty() {
            return Err(Error::InvalidQuery(
                "search without parameters is not possible (A4)".into(),
            ));
        }
        // Which fields are non-searchable (no "search" column in § 4)?
        let non_searchable_set = self.abteilung.is_some() as usize
            + self.land.is_some() as usize
            + self.telefon.is_some() as usize
            + self.mobil.is_some() as usize;
        let searchable_set = self.vorname.is_some() as usize
            + self.beruf.is_some() as usize
            + self.name.is_some() as usize
            + self.kanzlei.is_some() as usize
            + self.strasse.is_some() as usize
            + self.hausnummer.is_some() as usize
            + self.plz.is_some() as usize
            + self.ort.is_some() as usize
            + self.bundesland.is_some() as usize
            + self.safe_id.is_some() as usize
            + self.dienststellen_id.is_some() as usize
            + (!self.roles.is_empty()) as usize;
        if searchable_set == 0 && non_searchable_set > 0 {
            return Err(Error::InvalidQuery(format!(
                "search contains non-searchable parameters only: {:?} (A1/A4, ERR10)",
                ["abteilung", "land", "telefon", "mobil"]
                    .into_iter()
                    .filter(|f| match *f {
                        "abteilung" => self.abteilung.is_some(),
                        "land" => self.land.is_some(),
                        "telefon" => self.telefon.is_some(),
                        _ => self.mobil.is_some(),
                    })
                    .collect::<Vec<_>>()
            )));
        }
        // A14: hand-built short Contains name degrades to exact.
        if let Some(t) = &mut self.name
            && t.kind == SearchKind::Contains
            && t.value.trim().chars().count() < 2
        {
            t.kind = SearchKind::Equals;
        }
        let mins: [(&str, &Option<SearchTerm>, usize); 8] = [
            ("vorname", &self.vorname, 2),
            ("name", &self.name, 1),
            ("beruf", &self.beruf, 5),
            ("kanzlei", &self.kanzlei, 3),
            ("strasse", &self.strasse, 3),
            ("hausnummer", &self.hausnummer, 1),
            ("plz", &self.plz, 1),
            ("ort", &self.ort, 2),
        ];
        for (field, term, min) in mins {
            if let Some(t) = term
                && t.value.trim().chars().count() < min
            {
                return Err(Error::InvalidQuery(format!(
                    "{field}: needs at least {min} characters (ERR30)"
                )));
            }
        }
        // Kind legality per the § 4 table (ERR50).
        let kind_checks: [(&str, &Option<SearchTerm>, &[SearchKind]); 8] = [
            ("vorname", &self.vorname, &[SearchKind::Contains]),
            (
                "name",
                &self.name,
                &[SearchKind::Contains, SearchKind::Equals],
            ),
            ("beruf", &self.beruf, &[SearchKind::Contains]),
            (
                "kanzlei",
                &self.kanzlei,
                &[
                    SearchKind::Contains,
                    SearchKind::Equals,
                    SearchKind::BeginsWith,
                ],
            ),
            ("strasse", &self.strasse, &[SearchKind::Contains]),
            ("hausnummer", &self.hausnummer, &[SearchKind::Contains]),
            ("plz", &self.plz, &[SearchKind::BeginsWith]),
            ("ort", &self.ort, &[SearchKind::Contains]),
        ];
        for (field, term, allowed) in kind_checks {
            if let Some(t) = term
                && !allowed.contains(&t.kind)
            {
                return Err(Error::InvalidQuery(format!(
                    "{field}: search kind {:?} is not allowed for this element (ERR50)",
                    t.kind
                )));
            }
        }
        Ok(())
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

    /// Berufsbezeichnung, contains ≥ 5.
    pub fn beruf_contains(mut self, v: &str) -> Result<Self, Error> {
        set_term(&mut self.query.beruf, SearchKind::Contains, v, 5, "beruf")?;
        Ok(self)
    }

    /// Postleitzahl, begins ≥ 1.
    pub fn plz_begins(mut self, v: &str) -> Result<Self, Error> {
        set_term(&mut self.query.plz, SearchKind::BeginsWith, v, 1, "plz")?;
        Ok(self)
    }

    /// Bundesland, equals.
    pub fn bundesland_equals(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.bundesland,
            SearchKind::Equals,
            v,
            1,
            "bundesland",
        )?;
        Ok(self)
    }

    /// Kanzlei, equals (≥ 3).
    pub fn kanzlei_equals(mut self, v: &str) -> Result<Self, Error> {
        set_term(&mut self.query.kanzlei, SearchKind::Equals, v, 3, "kanzlei")?;
        Ok(self)
    }

    /// Kanzlei, begins ≥ 3.
    pub fn kanzlei_begins(mut self, v: &str) -> Result<Self, Error> {
        set_term(
            &mut self.query.kanzlei,
            SearchKind::BeginsWith,
            v,
            3,
            "kanzlei",
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
            || q.beruf.is_some()
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
        let mut query = self.query;
        query.validate()?;
        Ok(query)
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
    /// Non-fatal diagnostics (skipped result objects, degraded parses) —
    /// surfaced so nothing is ever dropped silently.
    pub warnings: Vec<String>,
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
