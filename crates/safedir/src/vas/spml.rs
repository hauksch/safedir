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
        "/MsgContact[MsgTechnology=\"urn:de:egov:names:fim:1.0:idsis-pp:msgTechnology:pots\"]/MsgAccount",
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
    /// Success with zero or more result objects.
    Success(Vec<SafeEntry>),
    /// Failure, with a typed code when an `ERRnn` token was found.
    Failure(Option<ErrCode>, String),
}

/// Parse a `lookupResponse` / `searchResponse` SOAP body.
///
/// Matching is on *local* element names (namespace prefixes vary between
/// deployments); the profile payload under `data` is interpreted by
/// [`crate::vas::idsispp`]. Self-closing elements are handled.
pub fn parse_response(xml: &str) -> Result<SpmlResponse, Error> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text_start = true;
    reader.config_mut().trim_text_end = true;

    let mut status: Option<String> = None;
    let mut error_text = String::new();
    let mut entries: Vec<SafeEntry> = Vec::new();

    let mut in_data = false;
    let mut data_buf = String::new();
    let mut current_pso_id: Option<String> = None;
    let mut in_pso = false;
    let mut in_error_message = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local = local_name_start(&e);
                match local.as_str() {
                    "lookupResponse" | "searchResponse" => {
                        if let Some(v) = attr(&e, "status") {
                            status = Some(v);
                        }
                    }
                    "pso" => {
                        in_pso = true;
                        current_pso_id = None;
                    }
                    "psoID" => {
                        if in_pso {
                            if let Some(v) = attr(&e, "ID") {
                                current_pso_id = Some(v);
                            }
                        }
                    }
                    "data" => {
                        if in_pso {
                            in_data = true;
                            data_buf.clear();
                        }
                    }
                    "errorMessage" | "error" => in_error_message = true,
                    _ => {}
                }
                // Reconstruct the markup of the profile fragment so the
                // profile parser sees real XML, not concatenated text.
                if in_data && local != "data" {
                    push_start_tag(&mut data_buf, &e);
                }
            }
            Ok(Event::Empty(e)) => {
                let local = local_name_start(&e);
                if local == "psoID" && in_pso {
                    if let Some(v) = attr(&e, "ID") {
                        current_pso_id = Some(v);
                    }
                } else if in_data {
                    push_start_tag(&mut data_buf, &e);
                    data_buf.push('/');
                    data_buf.push('>');
                }
            }
            Ok(Event::Text(t)) => {
                let text = String::from_utf8_lossy(&t).into_owned();
                if in_data {
                    data_buf.push_str(&xml_escape(&text));
                } else if in_error_message {
                    error_text.push_str(&text);
                }
            }
            Ok(Event::CData(t)) => {
                if in_data {
                    data_buf.push_str("<![CDATA[");
                    data_buf.push_str(&String::from_utf8_lossy(&t));
                    data_buf.push_str("]]>");
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name_end(&e);
                if in_data && local != "data" {
                    data_buf.push_str("</");
                    data_buf.push_str(&String::from_utf8_lossy(e.name().as_ref()));
                    data_buf.push('>');
                }
                match local.as_str() {
                    "data" => {
                        if in_data {
                            in_data = false;
                            if let Some(id) = current_pso_id.take() {
                                if let Ok(entry) =
                                    crate::vas::idsispp::parse_profile(&id, &data_buf)
                                {
                                    entries.push(entry);
                                }
                            }
                            data_buf.clear();
                        }
                    }
                    "pso" => in_pso = false,
                    "errorMessage" | "error" => in_error_message = false,
                    _ => {}
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
        Some("success") | Some("pending") => Ok(SpmlResponse::Success(entries)),
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
/// buffer.
fn push_start_tag(buf: &mut String, e: &quick_xml::events::BytesStart<'_>) {
    buf.push('<');
    buf.push_str(&String::from_utf8_lossy(e.name().as_ref()));
    for a in e.attributes().flatten() {
        buf.push(' ');
        buf.push_str(&String::from_utf8_lossy(a.key.as_ref()));
        buf.push_str("=\"");
        buf.push_str(&xml_escape(&String::from_utf8_lossy(&a.value)));
        buf.push('"');
    }
    buf.push('>');
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
            SpmlResponse::Success(entries) => {
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
