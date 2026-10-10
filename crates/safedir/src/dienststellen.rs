//! Dienststellen-IDs — the unique identifiers of courts and prosecution
//! offices.
//!
//! They are maintained as *Werteliste Typ 3* in the XJustiz standard and
//! published in the XRepository (e.g. `301125T`). The SAFE search standard
//! §6 specifies a lookup by Dienststellen-ID using the literal wire prefix
//! `Dienststellen-ID:` inside the SPML `psoID` element.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// Wire prefix mandated by the search standard §6 for Dienststellen-ID
/// lookups.
pub const WIRE_PREFIX: &str = "Dienststellen-ID:";

/// A Dienststellen-ID (court / prosecution office identifier).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DienststellenId(String);

impl DienststellenId {
    /// The bare identifier (no wire prefix).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The wire form used in SPML `psoID` lookups:
    /// `Dienststellen-ID:301125T`.
    #[must_use]
    pub fn wire_form(&self) -> String {
        format!("{WIRE_PREFIX}{}", self.0)
    }
}

impl fmt::Display for DienststellenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DienststellenId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        // Be forgiving about an already-prefixed form.
        let bare = trimmed.strip_prefix(WIRE_PREFIX).unwrap_or(trimmed);
        if bare.is_empty() {
            return Err(Error::ParseDienststellen("empty".to_owned()));
        }
        if bare
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
        {
            return Err(Error::ParseDienststellen(format!(
                "illegal characters in {bare:?}"
            )));
        }
        Ok(Self(bare.to_owned()))
    }
}

impl Serialize for DienststellenId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DienststellenId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_wires() {
        let id: DienststellenId = "301125T".parse().unwrap();
        assert_eq!(id.as_str(), "301125T");
        assert_eq!(id.wire_form(), "Dienststellen-ID:301125T");
    }

    #[test]
    fn accepts_prefixed_input() {
        let id: DienststellenId = "Dienststellen-ID:301125T".parse().unwrap();
        assert_eq!(id.as_str(), "301125T");
    }

    #[test]
    fn rejects_garbage() {
        assert!("".parse::<DienststellenId>().is_err());
        assert!("a b".parse::<DienststellenId>().is_err());
        assert!("a:b".parse::<DienststellenId>().is_err());
    }
}
