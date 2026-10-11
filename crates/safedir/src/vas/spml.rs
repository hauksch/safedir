//! SPML 2.0 request construction and response parsing.
//!
//! Namespaces follow the standard's printed example:
//!
//! - SOAP 1.1: `http://schemas.xmlsoap.org/soap/envelope/` (the example
//!   uses an `S:` prefix; SOAP 1.1 is what OSCI 1.2 and SPML deployments
//!   use),
//! - SPML core: `urn:oasis:names:tc:SPML:2:0` (+ `…:search` for iterator
//!   extensions),
//! - DSMLv2: `urn:oasis:names:tc:DSML:2:0:core` (query expressions),
//! - Liberty ID-SIS-PP profile data: `urn:liberty:id-sis-pp:200505`,
//! - SAFE extensions: `urn:de:egov:names:safe:1.0:…`.

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::entry::SafeEntry;
use crate::error::{ErrCode, Error};

/// SPML target of the SAFE "egvpdata" profile realm, from the standard's
/// example.
pub const TARGET_ID: &str = "urn:de:egov:names:safe:1.0:spml:2.0:targetid:egvpdata:id-sispp";

/// Liberty ID-SIS-PP namespace.
pub const PP_NS: &str = "urn:liberty:id-sis-pp:200505";

/// DSMLv2 namespace.
pub const DSML_NS: &str = "urn:oasis:names:tc:DSML:2:0:core";

/// Escape XML text/attribute content.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn envelope(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">\
<S:Body>{body}</S:Body>\
</S:Envelope>"
    )
}

/// Build a `lookupRequest` for the given `psoID` (a SAFE-ID or the
/// `Dienststellen-ID:` wire form), mirroring the standard's §6 example.
#[must_use]
pub fn lookup_request(pso_id: &str) -> String {
    envelope(&format!(
        "<lookupRequest xmlns=\"urn:oasis:names:tc:SPML:2:0\" \
executionMode=\"synchronous\" requestID=\"lookup\" returnData=\"everything\">\
<psoID ID=\"{}\" targetID=\"{TARGET_ID}\"/>\
</lookupRequest>",
        xml_escape(pso_id)
    ))
}

/// Build a `searchRequest` encoding a [`crate::resolver::SearchQuery`]:
/// an `<and>` of DSML substring / equality expressions over the attribute
/// XPaths, plus role filters (`<or>` across roles per A7/A8).
///
/// `Contains` terms are emitted as one `<dsml:any>` per whitespace-separated
/// word — the AND-per-word semantics of A2.
#[must_use]
pub fn search_request(query: &crate::resolver::SearchQuery) -> String {
    use crate::resolver::SearchKind as K;

    let mut operands = String::new();

    let mut push_term = |xpath: &str, term: &Option<crate::resolver::SearchTerm>| {
        let Some(t) = term else { return };
        match t.kind {
            K::Equals => operands.push_str(&format!(
                "<dsml:equalityMatch name=\"{xpath}\"><dsml:value>{}</dsml:value>\
</dsml:equalityMatch>",
                xml_escape(&t.value)
            )),
            K::BeginsWith => operands.push_str(&format!(
                "<dsml:substrings name=\"{xpath}\"><dsml:initial>{}</dsml:initial>\
</dsml:substrings>",
                xml_escape(&t.value)
            )),
            K::Contains => {
                operands.push_str(&format!("<dsml:substrings name=\"{xpath}\">"));
                for word in t.value.split_whitespace() {
                    operands.push_str(&format!("<dsml:any>{}</dsml:any>", xml_escape(word)));
                }
                operands.push_str("</dsml:substrings>");
            }
        }
    };

    push_term("/CommonName/AnalyzedName/FN", &query.vorname);
    push_term("/CommonName/AnalyzedName/SN", &query.name);
    push_term("/Extension/EJusticeAttributes/Kanzlei", &query.kanzlei);
    push_term(
        "/Extension/EJusticeAttributes/AlternativeOrganization",
        &query.abteilung,
    );
    push_term("/AddressCard/Address/Extension/StreetName", &query.strasse);
    push_term(
        "/AddressCard/Address/Extension/HouseNumber",
        &query.hausnummer,
    );
    push_term("/AddressCard/Address/PostalCode", &query.plz);
    push_term("/AddressCard/Address/L", &query.ort);
    push_term("/AddressCard/Address/St", &query.bundesland);
    push_term("/AddressCard/Address/C", &query.land);
    push_term(
        "/MsgContact[MsgTechnology=\"urn:liberty:id-sis-pp:msgTechnology:pots\"]/MsgAccount",
        &query.telefon,
    );
    push_term(
        "/MsgContact[MsgTechnology=\"urn:de:egov:names:fim:1.0:idsis-pp:msgTechnology:cellPhone\"]/MsgAccount",
        &query.mobil,
    );
    if let Some(id) = &query.safe_id {
        operands.push_str(&format!(
            "<dsml:equalityMatch name=\"/safe.id\"><dsml:value>{}</dsml:value>\
</dsml:equalityMatch>",
            xml_escape(id.as_str())
        ));
    }
    if let Some(ds) = &query.dienststellen_id {
        operands.push_str(&format!(
            "<dsml:equalityMatch name=\"/Extension/EJusticeAttributes/ExternalID\">\
<dsml:value>{}</dsml:value></dsml:equalityMatch>",
            xml_escape(ds.as_str())
        ));
    }

    let role_filter = if query.roles.is_empty() {
        String::new()
    } else {
        let clauses: String = query
            .roles
            .iter()
            .map(|r| {
                format!(
                    "<dsml:equalityMatch name=\"/Extension/EJusticeAttributes/Roles/RoleValue\">\
<dsml:value>{}</dsml:value></dsml:equalityMatch>",
                    xml_escape(&r.token())
                )
            })
            .collect();
        if query.roles.len() == 1 {
            clauses
        } else {
            format!("<or>{clauses}</or>")
        }
    };

    let combined = format!("<and>{operands}{role_filter}</and>");

    envelope(&format!(
        "<searchRequest xmlns=\"urn:oasis:names:tc:SPML:2:0\" \
xmlns:spmlsearch=\"urn:oasis:names:tc:SPML:2:0:search\" xmlns:dsml=\"{DSML_NS}\" \
executionMode=\"synchronous\" requestID=\"search\" returnData=\"everything\">\
<query namespace=\"{PP_NS}\" targetID=\"{TARGET_ID}\" scope=\"pso\">{combined}</query>\
</searchRequest>"
    ))
}

/// Parsed SPML response.
#[derive(Debug, Clone, PartialEq)]
pub enum SpmlResponse {
    /// Success with zero or more result objects plus response-level
    /// warnings (e.g. unparseable result objects that were skipped).
    Success(Vec<SafeEntry>, Vec<String>),
    /// Failure, with a typed code when an `ERRnn` token was found.
    Failure(Option<ErrCode>, String),
}

/// Parse a `lookupResponse` / `searchResponse` SOAP body.
///
/// Matching is on *local* element names (namespace prefixes vary between
/// deployments), **depth-scoped** so that payload elements coincidentally
/// named `data`/`pso`/`psoID` cannot hijack the state machine: `psoID` and
/// `data` only count as direct children of `pso`, and `pso` only at the
/// response's child level. The profile payload under `data` is rebuilt
/// verbatim (quick-xml hands out already-escaped text) and interpreted by
/// [`crate::vas::idsispp`]. Self-closing elements are handled.
pub fn parse_response(xml: &str) -> Result<SpmlResponse, Error> {
    let mut reader = Reader::from_str(xml);
    // No reader-level trimming: text events are split at entity references,
    // and trimming each fragment would eat entity-adjacent whitespace.
    // Leaves trim where they need it.

    let mut status: Option<String> = None;
    let mut error_text = String::new();
    let mut entries: Vec<SafeEntry> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Level bookkeeping: an element's *own* level is the number of open
    // elements including itself (Envelope = 1, …). Structural elements are
    // only honoured at their exact relative level so payload elements with
    // coincidental local names (`data`, `pso`, …) cannot hijack the state
    // machine.
    let mut level: usize = 0;
    let mut response_level: Option<usize> = None;
    let mut pso_level: Option<usize> = None;
    let mut data_level: Option<usize> = None;
    let mut in_data = false;
    let mut data_buf = String::new();
    let mut current_pso_id: Option<String> = None;
    let mut in_error_message = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                level += 1;
                let local = local_name_start(&e);
                if in_data {
                    // Inside the profile payload: rebuild markup verbatim;
                    // structural names are ignored here.
                    push_start_tag(&mut data_buf, &e, false);
                } else if matches!(local.as_str(), "lookupResponse" | "searchResponse") {
                    response_level = Some(level);
                    if let Some(v) = attr(&e, "status") {
                        status = Some(v);
                    }
                } else if local == "pso" && response_level.is_some_and(|rl| level == rl + 1) {
                    pso_level = Some(level);
                    current_pso_id = None;
                } else if local == "psoID" && pso_level.is_some_and(|pl| level == pl + 1) {
                    if let Some(v) = attr(&e, "ID") {
                        current_pso_id = Some(v);
                    }
                } else if local == "data" && pso_level.is_some_and(|pl| level == pl + 1) {
                    in_data = true;
                    data_level = Some(level);
                    data_buf.clear();
                } else if matches!(
                    local.as_str(),
                    "errorMessage" | "error" | "faultstring" | "faultcode" | "detail"
                ) {
                    in_error_message = true;
                }
            }
            Ok(Event::Empty(e)) => {
                let local = local_name_start(&e);
                if in_data {
                    push_start_tag(&mut data_buf, &e, true);
                } else if local == "psoID" && pso_level.is_some_and(|pl| level == pl) {
                    // A self-closing psoID would sit one level below pso.
                    if let Some(v) = attr(&e, "ID") {
                        current_pso_id = Some(v);
                    }
                }
            }
            Ok(Event::Text(t)) => {
                // NOTE: quick-xml text is already escaped — push verbatim.
                let raw = String::from_utf8_lossy(&t).into_owned();
                if in_data {
                    data_buf.push_str(&raw);
                } else if in_error_message {
                    let unescaped = match quick_xml::escape::unescape(&raw) {
                        Ok(u) => u.into_owned(),
                        Err(_) => raw,
                    };
                    error_text.push_str(&unescaped);
                }
            }
            Ok(Event::CData(t)) => {
                if in_data {
                    data_buf.push_str("<![CDATA[");
                    data_buf.push_str(&String::from_utf8_lossy(&t));
                    data_buf.push_str("]]>");
                }
            }
            Ok(Event::GeneralRef(r)) => {
                // Character/entity references arrive as separate events;
                // re-emit them verbatim so the escaped form survives.
                if in_data {
                    data_buf.push('&');
                    data_buf.push_str(&String::from_utf8_lossy(&r));
                    data_buf.push(';');
                } else if in_error_message {
                    error_text.push_str(&resolve_reference(&String::from_utf8_lossy(&r)));
                }
            }
            Ok(Event::End(e)) => {
                let closing_level = level;
                level = level.saturating_sub(1);
                let local = local_name_end(&e);
                if in_data {
                    if data_level == Some(closing_level) && local == "data" {
                        // Closing the real `</data>` (direct child of pso).
                        in_data = false;
                        data_level = None;
                        match current_pso_id.take() {
                            Some(id) => match crate::vas::idsispp::parse_profile(&id, &data_buf) {
                                Ok(entry) => entries.push(entry),
                                Err(err) => {
                                    warnings.push(format!("pso {id}: profile unusable: {err}"));
                                }
                            },
                            None => {
                                warnings.push("pso without psoID: profile skipped".to_owned());
                            }
                        }
                        data_buf.clear();
                    } else {
                        data_buf.push_str("</");
                        data_buf.push_str(&String::from_utf8_lossy(e.name().as_ref()));
                        data_buf.push('>');
                    }
                } else {
                    match local.as_str() {
                        "pso" if pso_level == Some(closing_level) => {
                            pso_level = None;
                        }
                        "errorMessage" | "error" | "faultstring" | "faultcode" | "detail" => {
                            in_error_message = false;
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(Error::Network(format!("cannot parse SPML response: {e}")));
            }
        }
    }

    match status.as_deref() {
        Some("success") | Some("pending") => Ok(SpmlResponse::Success(entries, warnings)),
        Some("failure") | None => {
            if let Some((code, msg)) = ErrCode::from_message_text(&error_text) {
                return Ok(SpmlResponse::Failure(Some(code), msg));
            }
            // Fall back to scanning the whole document for ERR tokens.
            if let Some((code, msg)) = ErrCode::from_message_text(xml) {
                return Ok(SpmlResponse::Failure(Some(code), msg));
            }
            let msg = if error_text.trim().is_empty() {
                "SPML failure without message".to_owned()
            } else {
                error_text.trim().to_owned()
            };
            Ok(SpmlResponse::Failure(None, msg))
        }
        Some(other) => Ok(SpmlResponse::Failure(
            None,
            format!("unexpected SPML status {other:?}"),
        )),
    }
}

/// Rebuild a start tag (with re-escaped attribute values) into a fragment
/// buffer; `self_closing` emits `<tag … />`.
fn push_start_tag(buf: &mut String, e: &quick_xml::events::BytesStart<'_>, self_closing: bool) {
    buf.push('<');
    buf.push_str(&String::from_utf8_lossy(e.name().as_ref()));
    for a in e.attributes().flatten() {
        buf.push(' ');
        buf.push_str(&String::from_utf8_lossy(a.key.as_ref()));
        buf.push_str("=\"");
        buf.push_str(&xml_escape(&String::from_utf8_lossy(&a.value)));
        buf.push('"');
    }
    buf.push_str(if self_closing { " />" } else { ">" });
}

/// Resolve a general reference's content (between `&` and `;`) to its
/// replacement text: numeric character references, the five predefined
/// entities, anything else verbatim as `&content;`.
pub(crate) fn resolve_reference(content: &str) -> String {
    if let Some(num) = content.strip_prefix('#') {
        let code = if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            num.parse::<u32>().ok()
        };
        if let Some(c) = code.and_then(char::from_u32) {
            return c.to_string();
        }
    }
    match content {
        "amp" => "&".to_owned(),
        "lt" => "<".to_owned(),
        "gt" => ">".to_owned(),
        "quot" => "\"".to_owned(),
        "apos" => "'".to_owned(),
        _ => format!("&{content};"),
    }
}

fn attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name.as_bytes())
        .map(|a| String::from_utf8_lossy(&a.value).into_owned())
}

fn local_name_start(e: &quick_xml::events::BytesStart<'_>) -> String {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    match name.split_once(':') {
        Some((_, local)) => local.to_owned(),
        None => name,
    }
}

fn local_name_end(e: &quick_xml::events::BytesEnd<'_>) -> String {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    match name.split_once(':') {
        Some((_, local)) => local.to_owned(),
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_request_mirrors_standard_example() {
        let xml = lookup_request("Dienststellen-ID:301125T");
        assert!(xml.contains("<S:Envelope"));
        assert!(xml.contains("lookupRequest"));
        assert!(xml.contains("executionMode=\"synchronous\""));
        assert!(xml.contains("requestID=\"lookup\""));
        assert!(xml.contains("returnData=\"everything\""));
        assert!(xml.contains("urn:oasis:names:tc:SPML:2:0"));
        assert!(xml.contains("Dienststellen-ID:301125T"));
        assert!(xml.contains(TARGET_ID));
    }

    #[test]
    fn search_request_encodes_terms_and_roles() {
        let query = crate::resolver::SearchQuery::builder()
            .name_contains("Rechtsanwaltskammer Hamm")
            .unwrap()
            .ort_contains("Bonn")
            .unwrap()
            .with_roles(&[crate::roles::RoleValue::EgvpJustiz])
            .build()
            .unwrap();
        let xml = search_request(&query);
        assert!(xml.contains("searchRequest"));
        assert!(xml.contains(&format!("xmlns:dsml=\"{DSML_NS}\"")));
        assert!(xml.contains("/CommonName/AnalyzedName/SN"));
        // A2: one <any> per word.
        assert!(xml.contains("<dsml:any>Rechtsanwaltskammer</dsml:any><dsml:any>Hamm</dsml:any>"));
        assert!(xml.contains("/AddressCard/Address/L"));
        assert!(xml.contains("egvp_justiz"));
    }

    #[test]
    fn escapes_values() {
        assert_eq!(xml_escape("a<b&c\"d"), "a&lt;b&amp;c&quot;d");
    }

    #[test]
    fn parses_failure_with_err_code() {
        let xml = "<?xml version=\"1.0\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body>\
<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"failure\">\
<error><errorMessage>ERR20 Das Postfach ist vor&#252;bergehend nicht adressierbar.</errorMessage></error>\
</lookupResponse></S:Body></S:Envelope>";
        match parse_response(xml).unwrap() {
            SpmlResponse::Failure(Some(ErrCode::Err20), _) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_success_and_selfclosing_psoid() {
        let cert_b64 = base64_of_test_cert();
        let xml = format!(
            "<?xml version=\"1.0\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body>\
<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"success\">\
<pso><psoID ID=\"DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d\" targetID=\"x\"/>\
<data><PP xmlns=\"urn:liberty:id-sis-pp:200505\">\
<CommonName><AnalyzedName><FN>Max</FN><SN>Mustermann</SN></AnalyzedName></CommonName>\
<MsgContact MsgTechnology=\"urn:de:egov:names:safe:1.0:idsis-pp:msgTechnology:osci12Postbox\">\
<Extension><OsciMsgParameter>\
<IntermedAddress>https://intermediaer.example/entry</IntermedAddress>\
<IntermedEncryptKey>{cert_b64}</IntermedEncryptKey>\
<RecipientEncryptKey>{cert_b64}</RecipientEncryptKey>\
<ReaderEncryptKey>{cert_b64}</ReaderEncryptKey>\
</OsciMsgParameter></Extension></MsgContact>\
<Extension><EJusticeAttributes><Roles><RoleValue>egvp_beA</RoleValue></Roles>\
</EJusticeAttributes></Extension>\
</PP></data></pso>\
</lookupResponse></S:Body></S:Envelope>"
        );
        match parse_response(&xml).unwrap() {
            SpmlResponse::Success(entries, warnings) => {
                assert!(warnings.is_empty(), "{warnings:?}");
                assert_eq!(entries.len(), 1);
                let e = &entries[0];
                assert_eq!(e.name, "Mustermann");
                assert_eq!(
                    e.safe_id.as_str(),
                    "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"
                );
                assert_eq!(
                    e.osci.intermediary_url,
                    "https://intermediaer.example/entry"
                );
                assert!(e.has_role(crate::roles::RoleValue::EgvpBea));
                assert!(e.osci.recipient_cipher[0].fingerprint.is_some());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn entity_encoded_text_survives_round_trip() {
        let cert_b64 = base64_of_test_cert();
        let xml = format!(
            "<?xml version=\"1.0\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body>\
<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"success\">\
<pso><psoID ID=\"DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d\" targetID=\"x\"/>\
<data><PP xmlns=\"urn:liberty:id-sis-pp:200505\">\
<CommonName><AnalyzedName><SN>M&#252;ller</SN></AnalyzedName></CommonName>\
<MsgContact MsgTechnology=\"urn:de:egov:names:safe:1.0:idsis-pp:msgTechnology:osci12Postbox\">\
<Extension><OsciMsgParameter>\
<IntermedAddress>https://intermediaer.example/entry</IntermedAddress>\
<IntermedEncryptKey>{cert_b64}</IntermedEncryptKey>\
</OsciMsgParameter></Extension></MsgContact>\
</PP></data></pso>\
</lookupResponse></S:Body></S:Envelope>"
        );
        match parse_response(&xml).unwrap() {
            SpmlResponse::Success(entries, warnings) => {
                assert!(warnings.is_empty());
                assert_eq!(entries[0].name, "Müller");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn stray_data_element_in_payload_cannot_hijack_state() {
        let cert_b64 = base64_of_test_cert();
        let xml = format!(
            "<?xml version=\"1.0\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body>\
<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"success\">\
<pso><psoID ID=\"DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d\" targetID=\"x\"/>\
<data><PP xmlns=\"urn:liberty:id-sis-pp:200505\">\
<CommonName><AnalyzedName><SN>Mustermann</SN></AnalyzedName></CommonName>\
<Adversarial><data><psoID ID=\"DE.Justiz.deadbeef-dead-beef-dead-beefdeadbeef.0000\"/>\
<pso><data>hijack</data></pso></data></Adversarial>\
<MsgContact MsgTechnology=\"urn:de:egov:names:safe:1.0:idsis-pp:msgTechnology:osci12Postbox\">\
<Extension><OsciMsgParameter>\
<IntermedAddress>https://real.example/entry</IntermedAddress>\
<IntermedEncryptKey>{cert_b64}</IntermedEncryptKey>\
</OsciMsgParameter></Extension></MsgContact>\
</PP></data></pso>\
</lookupResponse></S:Body></S:Envelope>"
        );
        match parse_response(&xml).unwrap() {
            SpmlResponse::Success(entries, warnings) => {
                assert!(warnings.is_empty());
                assert_eq!(
                    entries.len(),
                    1,
                    "adversarial names must not drop the entry"
                );
                assert_eq!(entries[0].name, "Mustermann");
                assert_eq!(
                    entries[0].osci.intermediary_url,
                    "https://real.example/entry"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unusable_profile_becomes_warning_not_silence() {
        let xml = "<?xml version=\"1.0\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body>\
<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"success\">\
<pso><psoID ID=\"not-a-safe-id\" targetID=\"x\"/>\
<data><PP xmlns=\"urn:liberty:id-sis-pp:200505\"/></data></pso>\
</lookupResponse></S:Body></S:Envelope>";
        match parse_response(xml).unwrap() {
            SpmlResponse::Success(entries, warnings) => {
                assert!(entries.is_empty());
                assert_eq!(warnings.len(), 1);
                assert!(warnings[0].contains("not-a-safe-id"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn telefon_xpath_uses_liberty_urn() {
        let query = crate::resolver::SearchQuery::builder()
            .telefon_contains("+49228")
            .unwrap()
            .build()
            .unwrap();
        let xml = search_request(&query);
        assert!(xml.contains("urn:liberty:id-sis-pp:msgTechnology:pots"));
        assert!(!xml.contains("fim:1.0:idsis-pp:msgTechnology:pots"));
    }

    fn base64_of_test_cert() -> String {
        use base64::Engine;
        let pem = crate::entry::test_support::TEST_CERT_PEM;
        let body = pem
            .split("-----BEGIN CERTIFICATE-----")
            .nth(1)
            .and_then(|s| s.split("-----END CERTIFICATE-----").next())
            .unwrap();
        let cleaned: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
            .unwrap()
    }
}
