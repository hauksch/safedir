//! Error taxonomy.
//!
//! Exit-code-flavoured in the spirit of rosci: configuration/usage problems,
//! parse problems, extract problems, typed directory errors (`ERR10`–`ERR100`
//! from the SAFE search standard, section 7 anlage a)), network problems.

use thiserror::Error;

/// Detailed failure reasons while parsing a SAFE-ID.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ParseSafeIdError {
    /// Empty input.
    #[error("empty SAFE-ID")]
    Empty,
    /// Embedded whitespace.
    #[error("SAFE-ID contains whitespace")]
    Whitespace,
    /// Modern format must consist of exactly four dot-separated segments.
    #[error("modern format needs 4 dot-separated segments, found {found}")]
    ModernSegments {
        /// Number of segments actually found.
        found: usize,
    },
    /// Country prefix must be `DE`.
    #[error("country segment must be \"DE\", found {found:?}")]
    Country {
        /// What was found instead.
        found: String,
    },
    /// Domain segment failed the character rule.
    #[error("malformed domain segment {found:?}")]
    BadDomain {
        /// The offending segment.
        found: String,
    },
    /// UUID segment is not 8-4-4-4-12 hex.
    #[error("malformed UUID segment")]
    BadUuid,
    /// Check-digit segment is not four hex characters.
    #[error("malformed check digits {found:?}")]
    BadChecksumFormat {
        /// The offending segment.
        found: String,
    },
    /// Check digits do not match the SHA-256-derived value.
    #[error("checksum mismatch: expected {expected}, found {found}")]
    ChecksumMismatch {
        /// Expected lower-case hex check digits.
        expected: String,
        /// Found check digits.
        found: String,
    },
    /// Legacy format violated `<prefix>-<digits>-<digits>`.
    #[error("malformed legacy ID {found:?}")]
    LegacyShape {
        /// The full offending input.
        found: String,
    },
    /// Legacy prefix failed the character rule.
    #[error("malformed legacy prefix {found:?}")]
    LegacyPrefix {
        /// The offending prefix.
        found: String,
    },
}

/// Top-level error of the crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid configuration (bad endpoint URL, unreadable key material, …).
    #[error("configuration error: {0}")]
    Config(String),
    /// A SAFE-ID (or Dienststellen-ID) failed to parse or validate.
    #[error("invalid id: {0}")]
    ParseId(#[from] ParseSafeIdError),
    /// A Dienststellen-ID failed to parse.
    #[error("invalid Dienststellen-ID: {0}")]
    ParseDienststellen(String),
    /// A role value is not known (kept verbatim as `Other`, but e.g. an
    /// extract declared a syntactically impossible role token).
    #[error("invalid role value: {0}")]
    ParseRole(String),
    /// A search query violates the standard's rules (A1/A2/A4/A14).
    #[error("invalid search query: {0}")]
    InvalidQuery(String),
    /// The extract file is malformed or fails validation.
    #[error("extract error: {0}")]
    Extract(String),
    /// The directory returned a typed error from the standard's catalogue.
    #[error("directory error {0}: {1}")]
    Directory(ErrCode, String),
    /// The directory returned an untyped failure message.
    #[error("directory failure: {0}")]
    DirectoryFailure(String),
    /// Transport-level problem talking to the directory.
    #[error("network error: {0}")]
    Network(String),
    /// Operation not supported by this backend/build.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl Error {
    /// Suggested process exit code, mirroring the CLI contract:
    /// `2` usage/config, `4` directory/extract, `5` internal.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) | Self::InvalidQuery(_) => 2,
            Self::ParseId(_)
            | Self::ParseDienststellen(_)
            | Self::ParseRole(_)
            | Self::Extract(_) => 2,
            Self::Directory(_, _) | Self::DirectoryFailure(_) => 4,
            Self::Network(_) => 4,
            Self::Unsupported(_) => 4,
        }
    }
}

/// Typed directory error codes, transcribed from *Standard für die Suche in
/// den SAFE-Verzeichnissen der ERV-Kommunikationsinfrastruktur* v1.5,
/// section 7 anlage a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
#[non_exhaustive]
pub enum ErrCode {
    /// Search contained an attribute that is not an allowed search parameter.
    #[error("ERR10")]
    Err10,
    /// Attribute `Kanzlei` does not exist in SAFE public (justiz).
    #[error("ERR11")]
    Err11,
    /// Attribute `Abteilung/Fachbereich` (resp. "zu Händen von") does not
    /// exist in the BRAK/BNotK/BStBK directories.
    #[error("ERR12")]
    Err12,
    /// Attribute `Bundesland` does not exist in the BRAK/BStBK directories.
    #[error("ERR13")]
    Err13,
    /// Attribute `Dienststellen-ID` only exists in SAFE public.
    #[error("ERR14")]
    Err14,
    /// The postbox is inactive: the role value is not activated.
    #[error("ERR20")]
    Err20,
    /// Search parameter below the minimum number of characters.
    #[error("ERR30")]
    Err30,
    /// More than 100 hits; the query must be narrowed.
    #[error("ERR40")]
    Err40,
    /// The chosen search option is not allowed for this element.
    #[error("ERR50")]
    Err50,
    /// The "Art der Suche" was not honoured.
    #[error("ERR60")]
    Err60,
    /// The search request is syntactically invalid.
    #[error("ERR70")]
    Err70,
    /// One of the SAFE directories was unreachable; the result may be
    /// incomplete.
    #[error("ERR100")]
    Err100,
}

impl ErrCode {
    /// The standard's German hint message for display to end users
    /// (requirement: ERV-SES must show these).
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Err10 => {
                "Zu Ihrer Suche gibt es keinen Treffer, da die Suche nach diesem \
                            Attribut nicht möglich ist. Bitte erstellen Sie eine neue Suchanfrage."
            }
            Self::Err11 => {
                "Das Suchergebnis enthält keine Treffer zu nachfolgenden \
                            Postfachinhabern, da die Suche nach „Kanzlei“ für diese \
                            Postfachinhaber nicht möglich ist."
            }
            Self::Err12 => {
                "Das Suchergebnis enthält keine besonderen Postfächer, da die Suche \
                            nach „Abteilung/Fachbereich“ bzw. „zu Händen von“ nicht möglich ist."
            }
            Self::Err13 => {
                "Das Suchergebnis enthält keine besonderen Postfächer, da die Suche \
                            nach „Bundesland“ nicht möglich ist."
            }
            Self::Err14 => {
                "Das Suchergebnis enthält keine besonderen Postfächer, da die Suche \
                            nach der „Dienststellen-ID“ nicht möglich ist."
            }
            Self::Err20 => {
                "Das Postfach ist vorübergehend nicht adressierbar, da der \
                            Rollenwert nicht freigeschaltet ist."
            }
            Self::Err30 => {
                "Die Suchanfrage enthielt zu wenig Zeichen. Bitte erstellen Sie \
                            eine neue Suchanfrage."
            }
            Self::Err40 => {
                "Die Anzahl der gefundenen Ergebnisse ist größer als 100. Bitte \
                            konkretisieren Sie Ihre Suchanfrage."
            }
            Self::Err50 => {
                "Die gewählte Suchoption ist für dieses Element nicht zugelassen. \
                            Bitte erstellen Sie eine neue Suchanfrage."
            }
            Self::Err60 => "Die gewählte Suchart wurde nicht beachtet.",
            Self::Err70 => {
                "Die Suchanfrage kann technisch nicht ausgewertet werden. Bitte \
                            erstellen Sie eine neue Suchanfrage."
            }
            Self::Err100 => {
                "Die Ergebnisliste ist möglicherweise nicht vollständig, da eines \
                             der SAFE-Verzeichnisse nicht erreichbar war."
            }
        }
    }

    /// Extract the first *catalogue* `ERRnn` code from free-form directory
    /// text. All occurrences of the substring `ERR` are examined (so text
    /// like `"ERROR: … ERR70"` still finds `ERR70`), and the digit run must
    /// match a catalogue entry exactly — `ERR1007` does *not* match
    /// `ERR100` (documented rule: exact catalogue tokens only).
    #[must_use]
    pub fn from_message_text(text: &str) -> Option<(Self, String)> {
        for (start, _) in text.match_indices("ERR") {
            let digits: String = text[start + 3..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            let code = match digits.as_str() {
                "10" => Self::Err10,
                "11" => Self::Err11,
                "12" => Self::Err12,
                "13" => Self::Err13,
                "14" => Self::Err14,
                "20" => Self::Err20,
                "30" => Self::Err30,
                "40" => Self::Err40,
                "50" => Self::Err50,
                "60" => Self::Err60,
                "70" => Self::Err70,
                "100" => Self::Err100,
                _ => continue,
            };
            return Some((code, text.to_owned()));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ErrCode;

    #[test]
    fn finds_code_behind_err_word() {
        // "ERROR:" must not swallow a later real code.
        let (code, _) = ErrCode::from_message_text("ERROR: see ERR70").unwrap();
        assert_eq!(code, ErrCode::Err70);
    }

    #[test]
    fn first_catalogue_code_wins() {
        let (code, _) = ErrCode::from_message_text("ERR30 vor ERR40").unwrap();
        assert_eq!(code, ErrCode::Err30);
    }

    #[test]
    fn non_catalogue_digit_runs_are_skipped() {
        // ERR1007 is not a catalogue token; scanning continues.
        let (code, _) = ErrCode::from_message_text("ERR1007 dann ERR40").unwrap();
        assert_eq!(code, ErrCode::Err40);
    }

    #[test]
    fn bare_err_and_errless_text_find_nothing() {
        assert!(ErrCode::from_message_text("ERR am Ende").is_none());
        assert!(ErrCode::from_message_text("kein Code").is_none());
        assert!(ErrCode::from_message_text("").is_none());
    }

    #[test]
    fn err100_is_found() {
        let (code, _) = ErrCode::from_message_text("x ERR100 y").unwrap();
        assert_eq!(code, ErrCode::Err100);
    }
}
