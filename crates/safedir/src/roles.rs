//! SAFE role values (Rollenwerte).
//!
//! Source: *Teilnahme von Drittanwendungen am OSCI-gestützten
//! elektronischen Rechtsverkehr — Anforderungen* v1.8 (20 Apr 2022),
//! section 5.3, plus the administrative `zertifikatswechsel` value
//! documented in the Länder/BNotK ident-admin guides (see the research
//! report §5.5) — the latter is practice, not part of the search standard.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// A SAFE role value attached to a directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RoleValue {
    /// Courts, prosecutions, JVA (`egvp_justiz`).
    EgvpJustiz,
    /// besonderes elektronisches Anwaltspostfach (`egvp_beA`).
    EgvpBea,
    /// besonderes elektronisches Notarpostfach (`egvp_beN`).
    EgvpBen,
    /// besonderes elektronisches Steuerberaterpostfach (`egvp_beSt`).
    EgvpBest,
    /// besonderes elektronisches Behördenpostfach (`egvp_beBPo`).
    EgvpBebpo,
    /// elektronisches Bürger- und Organisationenpostfach (`egvp_ebo`).
    EgvpEbo,
    /// OZG-Nutzerkonto postbox, i.e. MJP (`ozg_postfach`).
    OzgPostfach,
    /// ERV participants without a secure transmission path
    /// (`egvp_buerger`).
    EgvpBuerger,
    /// Legacy role for authorities (`egvp_behoerde`); only historical
    /// constellations.
    EgvpBehoerde,
    /// Gerichtsvollzieher, one-way to citizen postboxes (`buerger_hin`).
    BuergerHin,
    /// Gerichtsvollzieher, with replies possible (`buerger_rueck`).
    BuergerRueck,
    /// eBO organizations consenting to general electronic service
    /// (§ 173 Abs. 4 S. 3 ZPOZustZustG) — additive to `egvp_ebo`.
    Zuzu,
    /// Test postboxes; visible only among themselves (`egvp_test`).
    EgvpTest,
    /// Administrative shield state during certificate changeover — *not*
    /// part of the search standard's catalogue; when it is the *sole* role,
    /// the postbox is unaddressable.
    Zertifikatswechsel,
    /// A role value not covered by this crate's version of the catalogue;
    /// kept verbatim for forward compatibility. The addressability matrix
    /// treats it conservatively (no visibility).
    Other(String),
}

impl RoleValue {
    /// Canonical token as used on the wire and in extracts.
    #[must_use]
    pub fn token(&self) -> Cow<'static, str> {
        match self {
            Self::EgvpJustiz => Cow::Borrowed("egvp_justiz"),
            Self::EgvpBea => Cow::Borrowed("egvp_beA"),
            Self::EgvpBen => Cow::Borrowed("egvp_beN"),
            Self::EgvpBest => Cow::Borrowed("egvp_beSt"),
            Self::EgvpBebpo => Cow::Borrowed("egvp_beBPo"),
            Self::EgvpEbo => Cow::Borrowed("egvp_ebo"),
            Self::OzgPostfach => Cow::Borrowed("ozg_postfach"),
            Self::EgvpBuerger => Cow::Borrowed("egvp_buerger"),
            Self::EgvpBehoerde => Cow::Borrowed("egvp_behoerde"),
            Self::BuergerHin => Cow::Borrowed("buerger_hin"),
            Self::BuergerRueck => Cow::Borrowed("buerger_rueck"),
            Self::Zuzu => Cow::Borrowed("zuzu"),
            Self::EgvpTest => Cow::Borrowed("egvp_test"),
            Self::Zertifikatswechsel => Cow::Borrowed("zertifikatswechsel"),
            Self::Other(s) => Cow::Owned(s.clone()),
        }
    }

    /// Short human description.
    #[must_use]
    pub fn description(&self) -> Cow<'static, str> {
        match self {
            Self::EgvpJustiz => Cow::Borrowed("Justiz (Gerichte, Staatsanwaltschaften, JVA)"),
            Self::EgvpBea => Cow::Borrowed("besonderes elektronisches Anwaltspostfach (beA)"),
            Self::EgvpBen => Cow::Borrowed("besonderes elektronisches Notarpostfach (beN)"),
            Self::EgvpBest => {
                Cow::Borrowed("besonderes elektronisches Steuerberaterpostfach (beSt)")
            }
            Self::EgvpBebpo => Cow::Borrowed("besonderes elektronisches Behördenpostfach (beBPo)"),
            Self::EgvpEbo => {
                Cow::Borrowed("elektronisches Bürger- und Organisationenpostfach (eBO)")
            }
            Self::OzgPostfach => {
                Cow::Borrowed("Postfach- und Versanddienst eines OZG-Nutzerkontos (MJP)")
            }
            Self::EgvpBuerger => Cow::Borrowed("ERV ohne sicheren Übermittlungsweg"),
            Self::EgvpBehoerde => Cow::Borrowed("Behörde (historische Rolle)"),
            Self::BuergerHin => Cow::Borrowed("Gerichtsvollzieher (einseitig an Bürgerpostfächer)"),
            Self::BuergerRueck => Cow::Borrowed("Gerichtsvollzieher (mit Rückkanal)"),
            Self::Zuzu => Cow::Borrowed("Zustimmung eBO-Organisation zur allgemeinen Zustellung"),
            Self::EgvpTest => Cow::Borrowed("Testpostfach (nur untereinander sichtbar)"),
            Self::Zertifikatswechsel => {
                Cow::Borrowed("Sperrung während Zertifikatswechsel (Admin-Praxis)")
            }
            Self::Other(s) => Cow::Owned(format!("unbekannter Rollenwert {s:?}")),
        }
    }
}

impl fmt::Display for RoleValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token())
    }
}

impl FromStr for RoleValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        // Role tokens are case-sensitive in the wild, but forgiving parsing
        // costs nothing and matches the search's case-insensitivity.
        for candidate in [
            Self::EgvpJustiz,
            Self::EgvpBea,
            Self::EgvpBen,
            Self::EgvpBest,
            Self::EgvpBebpo,
            Self::EgvpEbo,
            Self::OzgPostfach,
            Self::EgvpBuerger,
            Self::EgvpBehoerde,
            Self::BuergerHin,
            Self::BuergerRueck,
            Self::Zuzu,
            Self::EgvpTest,
            Self::Zertifikatswechsel,
        ] {
            if t.eq_ignore_ascii_case(&candidate.token()) {
                return Ok(candidate);
            }
        }
        // Unknown-but-well-formed tokens are preserved (forward
        // compatibility); structurally impossible ones are rejected.
        if !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Ok(Self::Other(t.to_owned()));
        }
        Err(Error::ParseRole(format!("unknown role value {t:?}")))
    }
}

impl Serialize for RoleValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.token())
    }
}

impl<'de> Deserialize<'de> for RoleValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_tokens() {
        assert_eq!("egvp_beA".parse::<RoleValue>().unwrap(), RoleValue::EgvpBea);
        assert_eq!(
            "egvp_best".parse::<RoleValue>().unwrap(),
            RoleValue::EgvpBest
        );
        assert_eq!(
            "zertifikatswechsel".parse::<RoleValue>().unwrap(),
            RoleValue::Zertifikatswechsel
        );
    }

    #[test]
    fn round_trips_display() {
        for token in [
            "egvp_justiz",
            "egvp_beA",
            "egvp_beN",
            "egvp_beSt",
            "egvp_beBPo",
            "egvp_ebo",
            "ozg_postfach",
            "egvp_buerger",
            "egvp_behoerde",
            "buerger_hin",
            "buerger_rueck",
            "zuzu",
            "egvp_test",
            "zertifikatswechsel",
        ] {
            let v: RoleValue = token.parse().unwrap();
            assert_eq!(v.token(), token, "display must round-trip");
        }
    }

    #[test]
    fn unknown_tokens_are_preserved() {
        let v: RoleValue = "egvp_zukunft_2030".parse().unwrap();
        assert_eq!(v.token(), "egvp_zukunft_2030");
        assert!(matches!(v, RoleValue::Other(_)));
        // Double underscores are fine (no rule against them).
        assert!("egvp_x__y".parse::<RoleValue>().is_ok());
        // Structurally impossible tokens are rejected.
        assert!("not a token!".parse::<RoleValue>().is_err());
        assert!("".parse::<RoleValue>().is_err());
    }
}
