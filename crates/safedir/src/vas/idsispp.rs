//! Liberty ID-SIS-PP profile → [`SafeEntry`] mapping.
//!
//! The SAFE directories exchange their attribute set in a Liberty ID-SIS-PP
//! (Person Profile) payload extended by `EJusticeAttributes`. The XPaths of
//! the search standard v1.5 (section 4, anlage c) translate to this element
//! tree (local names; prefixes are ignored):
//!
//! ```text
//! PP
//! ├── CommonName/AnalyzedName/{FN, SN}
//! ├── AddressCard/Address/{PostalCode, L, St, C}
//! │   └── Extension/{StreetName, HouseNumber}
//! ├── MsgContact[MsgTechnology ~ osci12Postbox]
//! │   ├── MsgAccount            (postbox address, informational)
//! │   └── Extension/OsciMsgParameter/{IntermedAddress, IntermedEncryptKey,
//! │                                    RecipientEncryptKey, ReaderEncryptKey}
//! ├── MsgContact[MsgTechnology ~ pots|cellPhone]/MsgAccount   (phone)
//! └── Extension/EJusticeAttributes/{ProfessionProperty, Kanzlei,
//!     AlternativeOrganization, ExternalID, Roles/RoleValue}
//! ```
//!
//! The `*EncryptKey` elements carry base64-encoded DER certificates; they
//! are re-armored as PEM so [`crate::entry::CertRef`] can process them.

use base64::Engine;
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::dienststellen::DienststellenId;
use crate::entry::{CertRef, Directory, OsciEndpoint, SafeEntry};
use crate::error::Error;
use crate::roles::RoleValue;
use crate::safe_id::SafeId;

const TECH_POTS: &str = ":msgTechnology:pots";
const TECH_CELL: &str = ":msgTechnology:cellPhone";
const TECH_OSCI: &str = "osci12Postbox";

/// Parse one profile payload. `pso_id` supplies the SAFE-ID (the standard's
/// `/safe.id`).
///
/// # Errors
///
/// [`Error::Extract`] when the SAFE-ID does not parse or no OSCI endpoint
/// with an intermediary certificate is present — both make the entry
/// unusable for sending.
pub fn parse_profile(pso_id: &str, profile_xml: &str) -> Result<SafeEntry, Error> {
    let safe_id: SafeId = pso_id
        .parse()
        .map_err(|e| Error::Extract(format!("psoID is not a valid SAFE-ID: {e}")))?;

    let mut p = Prof::default();
    let mut warnings: Vec<String> = Vec::new();
    let mut reader = Reader::from_str(profile_xml);
    // No reader-level trimming: text events are split at entity references,
    // and trimming each fragment would eat entity-adjacent whitespace.
    // Leaves trim where they need it.

    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut contact_tech: Vec<String> = Vec::new(); // stack of active MsgContact technologies

    loop {
        let ev = reader
            .read_event()
            .map_err(|e| Error::Network(format!("cannot parse profile: {e}")))?;
        match ev {
            Event::Start(e) => {
                let local = local_name(&e);
                if local == "MsgContact" {
                    let tech = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.as_ref() == b"MsgTechnology")
                        .map(|a| String::from_utf8_lossy(&a.value).into_owned())
                        .unwrap_or_default();
                    contact_tech.push(tech);
                }
                text.clear();
                path.push(local);
            }
            Event::Empty(_) => {
                // Self-closing elements carry no text and no children.
            }
            Event::Text(t) => {
                // quick-xml hands out escaped content; unescape to real
                // text (entity-encoded umlauts, &amp;, …).
                let raw = String::from_utf8_lossy(&t).into_owned();
                let unescaped = match quick_xml::escape::unescape(&raw) {
                    Ok(u) => u.into_owned(),
                    Err(_) => raw,
                };
                text.push_str(&unescaped);
            }
            Event::CData(t) => {
                text.push_str(&String::from_utf8_lossy(&t));
            }
            Event::GeneralRef(r) => {
                let content = String::from_utf8_lossy(&r).into_owned();
                text.push_str(&crate::vas::spml::resolve_reference(&content));
            }
            Event::End(_) => {
                if let Some(local) = path.pop() {
                    if local == "MsgContact" {
                        contact_tech.pop();
                    }
                    assign(
                        &mut p,
                        &path,
                        &local,
                        text.trim(),
                        contact_tech.last(),
                        &mut warnings,
                    );
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }

    let Some(intermediary_url) = p.intermed_address.clone() else {
        return Err(Error::Extract(
            "profile carries no OSCI intermediary address".to_owned(),
        ));
    };
    let Some(intermediary_cipher) = p.intermed_encrypt_key.clone() else {
        return Err(Error::Extract(
            "profile carries no intermediary encryption certificate".to_owned(),
        ));
    };
    let osci = OsciEndpoint {
        intermediary_url,
        intermediary_cipher,
        recipient_cipher: p.recipient_encrypt_keys.clone(),
        reader_cipher: p.reader_encrypt_keys.clone(),
    };
    Ok(SafeEntry {
        directory: safe_id.directory().unwrap_or(Directory::Unknown),
        safe_id,
        vorname: p.fn_.take().filter(|s| !s.is_empty()),
        name: p.sn.take().unwrap_or_default(),
        beruf: p.profession.take(),
        kanzlei: p.kanzlei.take(),
        abteilung: p.alternative_organization.take(),
        strasse: p.street_name.take(),
        hausnummer: p.house_number.take(),
        plz: p.postal_code.take(),
        ort: p.l.take(),
        bundesland: p.st.take(),
        land: p.c.take(),
        telefon: p.telefon.take(),
        mobil: p.mobil.take(),
        dienststellen_ids: p
            .external_ids
            .iter()
            .filter_map(|s| match s.parse::<DienststellenId>() {
                Ok(id) => Some(id),
                Err(_) => {
                    warnings.push(format!("unparseable Dienststellen-ID {s:?} ignored"));
                    None
                }
            })
            .collect::<Vec<DienststellenId>>(),
        roles: p.roles.clone(),
        osci,
        warnings,
    })
}

#[derive(Default)]
struct Prof {
    fn_: Option<String>,
    sn: Option<String>,
    street_name: Option<String>,
    house_number: Option<String>,
    postal_code: Option<String>,
    l: Option<String>,
    st: Option<String>,
    c: Option<String>,
    telefon: Option<String>,
    mobil: Option<String>,
    profession: Option<String>,
    kanzlei: Option<String>,
    alternative_organization: Option<String>,
    external_ids: Vec<String>,
    roles: Vec<RoleValue>,
    intermed_address: Option<String>,
    intermed_encrypt_key: Option<CertRef>,
    recipient_encrypt_keys: Vec<CertRef>,
    reader_encrypt_keys: Vec<CertRef>,
}

/// Route a leaf by the last meaningful ancestors. `ancestors` excludes the
/// leaf itself; `tech` is the innermost active `MsgContact` technology.
/// Anything unusable (role tokens, certificates) records a warning instead
/// of being dropped silently.
fn assign(
    p: &mut Prof,
    ancestors: &[String],
    leaf: &str,
    text: &str,
    tech: Option<&String>,
    warnings: &mut Vec<String>,
) {
    if text.is_empty() {
        return;
    }
    let tail = |n: usize| -> String {
        ancestors[ancestors.len().saturating_sub(n)..]
            .to_vec()
            .join("/")
    };
    match leaf {
        "FN" if tail(2) == "CommonName/AnalyzedName" => p.fn_ = Some(text.to_owned()),
        "SN" if tail(2) == "CommonName/AnalyzedName" => p.sn = Some(text.to_owned()),
        "StreetName" if tail(2) == "Address/Extension" => {
            p.street_name = Some(text.to_owned());
        }
        "HouseNumber" if tail(2) == "Address/Extension" => {
            p.house_number = Some(text.to_owned());
        }
        "PostalCode" if tail(1) == "Address" => p.postal_code = Some(text.to_owned()),
        "L" if tail(1) == "Address" => p.l = Some(text.to_owned()),
        "St" if tail(1) == "Address" => p.st = Some(text.to_owned()),
        "C" if tail(1) == "Address" => p.c = Some(text.to_owned()),
        "MsgAccount" => {
            if let Some(t) = tech {
                if t.contains(TECH_POTS) {
                    p.telefon = Some(text.to_owned());
                } else if t.contains(TECH_CELL) {
                    p.mobil = Some(text.to_owned());
                }
            }
        }
        "ProfessionProperty" if tail(1) == "EJusticeAttributes" => {
            p.profession = Some(text.to_owned());
        }
        "Kanzlei" if tail(1) == "EJusticeAttributes" => p.kanzlei = Some(text.to_owned()),
        "AlternativeOrganization" if tail(1) == "EJusticeAttributes" => {
            p.alternative_organization = Some(text.to_owned());
        }
        "ExternalID" if tail(1) == "EJusticeAttributes" => {
            p.external_ids.push(text.to_owned());
        }
        "RoleValue" if tail(2) == "EJusticeAttributes/Roles" => match text.parse::<RoleValue>() {
            Ok(role) => {
                if !p.roles.contains(&role) {
                    p.roles.push(role);
                }
            }
            Err(_) => warnings.push(format!("unparseable role value {text:?} ignored")),
        },
        // OSCI parameters only inside an osci12Postbox contact.
        "IntermedAddress" => {
            if tech.is_some_and(|t| t.contains(TECH_OSCI)) {
                p.intermed_address = Some(text.to_owned());
            }
        }
        "IntermedEncryptKey" | "RecipientEncryptKey" | "ReaderEncryptKey" => {
            if !tech.is_some_and(|t| t.contains(TECH_OSCI)) {
                return;
            }
            match cert_from_base64(text) {
                Some(cert) => match leaf {
                    "IntermedEncryptKey" => p.intermed_encrypt_key = Some(cert),
                    "RecipientEncryptKey" => p.recipient_encrypt_keys.push(cert),
                    _ => p.reader_encrypt_keys.push(cert),
                },
                None => warnings.push(format!("{leaf}: undecodable certificate ignored")),
            }
        }
        _ => {}
    }
}

/// Re-armor base64 DER certificate text as PEM and fingerprint it.
fn cert_from_base64(b64: &str) -> Option<CertRef> {
    let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .ok()?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    CertRef::from_pem(&pem).ok()
}

fn local_name(e: &quick_xml::events::BytesStart<'_>) -> String {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    match name.split_once(':') {
        Some((_, local)) => local.to_owned(),
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(cert_b64: &str) -> String {
        format!(
            "<pp:PP xmlns:pp=\"urn:liberty:id-sis-pp:200505\">\
<pp:CommonName><pp:AnalyzedName><pp:FN>Max</pp:FN><pp:SN>Mustermann</pp:SN></pp:AnalyzedName></pp:CommonName>\
<pp:AddressCard><pp:Address><pp:PostalCode>53111</pp:PostalCode><pp:L>Bonn</pp:L><pp:St>Nordrhein-Westfalen</pp:St><pp:C>DE</pp:C>\
<pp:Extension><pp:StreetName>Am Hof</pp:StreetName><pp:HouseNumber>1a</pp:HouseNumber></pp:Extension></pp:Address></pp:AddressCard>\
<pp:MsgContact MsgTechnology=\"urn:de:egov:names:safe:1.0:idsis-pp:msgTechnology:osci12Postbox\">\
<pp:MsgAccount>postfach@justiz</pp:MsgAccount>\
<pp:Extension><safe:OsciMsgParameter xmlns:safe=\"urn:de:egov:names:safe:1.0:id-sispp:extension\">\
<safe:IntermedAddress>https://intermediaer.example/entry</safe:IntermedAddress>\
<safe:IntermedEncryptKey>{cert_b64}</safe:IntermedEncryptKey>\
<safe:RecipientEncryptKey>{cert_b64}</safe:RecipientEncryptKey>\
<safe:ReaderEncryptKey>{cert_b64}</safe:ReaderEncryptKey>\
</safe:OsciMsgParameter></pp:Extension></pp:MsgContact>\
<pp:Extension><safe:EJusticeAttributes xmlns:safe=\"urn:de:egov:names:safe:1.0:id-sispp:extension\">\
<safe:ProfessionProperty>Rechtsanwalt</safe:ProfessionProperty><safe:Kanzlei>Kanzlei am Hof</safe:Kanzlei>\
<safe:ExternalID>301125T</safe:ExternalID>\
<safe:Roles><safe:RoleValue>egvp_beA</safe:RoleValue></safe:Roles>\
</safe:EJusticeAttributes></pp:Extension>\
</pp:PP>"
        )
    }

    fn cert_b64() -> String {
        use base64::Engine;
        let pem = crate::entry::test_support::TEST_CERT_PEM;
        let body = pem
            .split("-----BEGIN CERTIFICATE-----")
            .nth(1)
            .and_then(|s| s.split("-----END CERTIFICATE-----").next())
            .unwrap();
        let cleaned: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .unwrap();
        base64::engine::general_purpose::STANDARD
            .encode(&der)
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn maps_all_attributes() {
        let entry = parse_profile(
            "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
            &profile(&cert_b64()),
        )
        .expect("profile maps");
        assert_eq!(entry.vorname.as_deref(), Some("Max"));
        assert_eq!(entry.name, "Mustermann");
        assert_eq!(entry.ort.as_deref(), Some("Bonn"));
        assert_eq!(entry.plz.as_deref(), Some("53111"));
        assert_eq!(entry.bundesland.as_deref(), Some("Nordrhein-Westfalen"));
        assert_eq!(entry.land.as_deref(), Some("DE"));
        assert_eq!(entry.strasse.as_deref(), Some("Am Hof"));
        assert_eq!(entry.hausnummer.as_deref(), Some("1a"));
        assert_eq!(
            entry.osci.intermediary_url,
            "https://intermediaer.example/entry"
        );
        assert_eq!(entry.osci.recipient_cipher.len(), 1);
        assert!(entry.osci.intermediary_cipher.fingerprint.is_some());
        assert_eq!(entry.beruf.as_deref(), Some("Rechtsanwalt"));
        assert_eq!(entry.kanzlei.as_deref(), Some("Kanzlei am Hof"));
        assert_eq!(entry.dienststellen_ids.len(), 1);
        assert_eq!(entry.dienststellen_ids[0].as_str(), "301125T");
        assert!(entry.has_role(RoleValue::EgvpBea));
    }

    #[test]
    fn rejects_profile_without_osci_endpoint() {
        assert!(
            parse_profile(
                "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
                "<PP><CommonName><AnalyzedName><SN>X</SN></AnalyzedName></CommonName></PP>"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_safe_id() {
        assert!(parse_profile("not-a-safe-id", &profile(&cert_b64())).is_err());
    }
}
