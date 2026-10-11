//! Mock-VAS integration tests for the `vas` feature.
//!
//! A tiny std-only HTTP server on 127.0.0.1 replays canned SPML responses
//! and captures request bodies; no network ever leaves loopback.

#![cfg(feature = "vas")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use safedir::error::{ErrCode, Error};
use safedir::resolver::{SafeDirectory, SearchQuery};
use safedir::safe_id::SafeId;

const CERT_B64_SINGLE_LINE: &str = "MIIDYzCCAkugAwIBAgIUTnJAO9HFDyzIA5o/QRFja/vjmrIwDQYJKoZIhvcNAQELBQAwQTEaMBgGA1UEAwwRVGVzdCBJbnRlcm1lZGlhcnkxFjAUBgNVBAoMDXNhZmVkaXIgdGVzdHMxCzAJBgNVBAYTAkRFMB4XDTI2MTAxMDE1MDUzM1oXDTM2MTAwNzE1MDUzM1owQTEaMBgGA1UEAwwRVGVzdCBJbnRlcm1lZGlhcnkxFjAUBgNVBAoMDXNhZmVkaXIgdGVzdHMxCzAJBgNVBAYTAkRFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvA+sNTmMQzSADkkzL+cjNfq+Y/XJtOB/2k38IT8L6ZIUye45eHStkETvT5UwkFxthcl1uoAMtf7exFYBlixS+6BzqP3MlfLlMbTs9YGgc/d2vHHTM7cUkz5+mEEIF5/n7ENrH/qIiVlcljHglexufyHEO8LPiFEdVxyqApj3e2uVhzr9C9AB7b7Bu6u0NRYO4aikWQiusXTF8kcRadm8MfdWWxWKmirlt8Lvy6Qcbs7OnGNrWCBsIvlo9xaXUeqKKQoASQ5jeVNpkRxIIqaHDBun2Vg4RPh1ZY9qqxG9PngNXPA+W9TNi0LNsi/bXQi12rd5op330rNH5Cg2EP4hkwIDAQABo1MwUTAdBgNVHQ4EFgQU5o1OdfXglnLm1gvLQKsZui0By0EwHwYDVR0jBBgwFoAU5o1OdfXglnLm1gvLQKsZui0By0EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAseri+QeKD1N8Wr4Qm4YFMxoHisTbgfYaqY78d5UBJaRnwkiALOxWbO+N/ukPG2sVIY4QM1h0ZlyVhrcEN2w0tYsgahuSLj6onERi2P8GbBFoU8xjRFtVOECi09plAbRYf1ErIBN5hjQHUuvc6k/0bnJ/UwcGzjIU1ZIJd7l93Gz1QuU46ro5xXByCJSuxge2Z1QTu9vQ6qdTjavwPpFhJmXwD0NQEoaUE1SAo4bh51L6lpd2RNCBYW4Dy9YxF731zzejozs+SzHrr5RnCA4gBzCUrRZ4/Piy1Ve5iQxYO7AyGlpdYktTtuM5n4nxPY7duGY+5JCmDOX/Qn7qxQYMyw==";

fn pso(safe_id: &str, name: &str, ort: &str, role: &str) -> String {
    format!(
        "<pso><psoID ID=\"{safe_id}\" targetID=\"urn:de:egov:names:safe:1.0:spml:2.0:targetid:egvpdata:id-sispp\"/>\
<data><PP xmlns=\"urn:liberty:id-sis-pp:200505\">\
<CommonName><AnalyzedName><SN>{name}</SN></AnalyzedName></CommonName>\
<AddressCard><Address><L>{ort}</L></Address></AddressCard>\
<MsgContact MsgTechnology=\"urn:de:egov:names:safe:1.0:idsis-pp:msgTechnology:osci12Postbox\">\
<Extension><OsciMsgParameter>\
<IntermedAddress>https://intermediaer.example/entry</IntermedAddress>\
<IntermedEncryptKey>{CERT_B64_SINGLE_LINE}</IntermedEncryptKey>\
<RecipientEncryptKey>{CERT_B64_SINGLE_LINE}</RecipientEncryptKey>\
<ReaderEncryptKey>{CERT_B64_SINGLE_LINE}</ReaderEncryptKey>\
</OsciMsgParameter></Extension></MsgContact>\
<Extension><EJusticeAttributes><Roles><RoleValue>{role}</RoleValue></Roles>\
<ExternalID>301125T</ExternalID></EJusticeAttributes></Extension>\
</PP></data></pso>"
    )
}

fn soap(body_inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body>{body_inner}</S:Body></S:Envelope>"
    )
}

fn lookup_success() -> String {
    soap(&format!(
        "<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"success\">{}</lookupResponse>",
        pso(
            "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
            "Mustermann",
            "Köln",
            "egvp_beA"
        )
    ))
}

fn lookup_err20() -> String {
    soap(
        "<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"failure\">\
<error><errorMessage>ERR20 Das Postfach ist vor&#252;bergehend nicht adressierbar.</errorMessage></error>\
</lookupResponse>",
    )
}

fn search_success() -> String {
    soap(&format!(
        "<searchResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"success\">{}{}</searchResponse>",
        pso(
            "DE.Justiz.dbf3d18a-5c6e-4a0b-9f1e-2a7c8e4d1b30.10dd",
            "Amtsgericht Bonn",
            "Bonn",
            "egvp_justiz"
        ),
        pso(
            "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
            "Rechtsanwalt Mustermann",
            "Bonn",
            "egvp_beA"
        )
    ))
}

struct MockVas {
    endpoint: String,
    captured: Arc<Mutex<Vec<String>>>,
}

fn spawn_mock(responses: Vec<String>) -> MockVas {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            // read headers
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(header_end) = find_header_end(&buf) {
                            let body_len = content_length(&buf[..header_end]);
                            if buf.len() >= header_end + body_len {
                                break;
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
            if let Some(header_end) = find_header_end(&buf) {
                let body = String::from_utf8_lossy(&buf[header_end..]).into_owned();
                cap.lock().unwrap().push(body);
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    MockVas {
        endpoint: format!("http://{addr}/vas"),
        captured,
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers).to_ascii_lowercase();
    text.lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn resolver(endpoint: &str) -> safedir::vas::SpmlResolver {
    safedir::vas::SpmlResolver::new(safedir::vas::SpmlConfig::new(endpoint)).unwrap()
}

#[test]
fn lookup_maps_entry_and_request_matches_standard_shape() {
    let mock = spawn_mock(vec![lookup_success()]);
    let dir = resolver(&mock.endpoint);
    let id: SafeId = "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"
        .parse()
        .unwrap();
    let entry = dir.lookup_safe_id(&id).unwrap().expect("entry found");
    assert_eq!(entry.name, "Mustermann");
    assert_eq!(entry.ort.as_deref(), Some("Köln"));
    assert!(entry.has_role(safedir::roles::RoleValue::EgvpBea));
    assert_eq!(
        entry.osci.intermediary_url,
        "https://intermediaer.example/entry"
    );
    assert!(entry.osci.recipient_cipher[0].fingerprint.is_some());
    assert_eq!(entry.dienststellen_ids[0].as_str(), "301125T");

    let body = mock
        .captured
        .lock()
        .unwrap()
        .first()
        .expect("captured request body")
        .clone();
    assert!(!body.is_empty());
    assert!(body.contains("<S:Envelope"));
    assert!(body.contains("lookupRequest"));
    assert!(body.contains("urn:oasis:names:tc:SPML:2:0"));
    assert!(body.contains("returnData=\"everything\""));
    assert!(body.contains("DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"));
    assert!(body.contains("urn:de:egov:names:safe:1.0:spml:2.0:targetid:egvpdata:id-sispp"));
}

#[test]
fn lookup_dienststellen_uses_wire_prefix() {
    let mock = spawn_mock(vec![lookup_success()]);
    let dir = resolver(&mock.endpoint);
    let hits = dir
        .lookup_dienststellen(&"301125T".parse().unwrap())
        .unwrap();
    assert!(!hits.is_empty());
    let body = mock
        .captured
        .lock()
        .unwrap()
        .first()
        .expect("captured request body")
        .clone();
    assert!(body.contains("Dienststellen-ID:301125T"));
}

#[test]
fn typed_error_surfaced() {
    let mock = spawn_mock(vec![lookup_err20()]);
    let dir = resolver(&mock.endpoint);
    let id: SafeId = "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"
        .parse()
        .unwrap();
    match dir.lookup_safe_id(&id) {
        Err(Error::Directory(ErrCode::Err20, _)) => {}
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn entity_encoded_profile_text_maps_to_plain_strings() {
    let inner = pso(
        "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d",
        "M&#252;ller &amp; S&#246;hne",
        "K&#246;ln",
        "egvp_beA",
    );
    let mock = spawn_mock(vec![soap(&format!(
        "<lookupResponse xmlns=\"urn:oasis:names:tc:SPML:2:0\" status=\"success\">{inner}</lookupResponse>"
    ))]);
    let dir = resolver(&mock.endpoint);
    let id: SafeId = "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"
        .parse()
        .unwrap();
    let entry = dir.lookup_safe_id(&id).unwrap().expect("entry");
    assert_eq!(entry.name, "Müller & Söhne");
    assert_eq!(entry.ort.as_deref(), Some("Köln"));
    assert!(entry.warnings.is_empty());
}

#[test]
fn http_500_with_fault_body_surfaces_typed_code() {
    // One-shot raw server answering 500 with a SOAP Fault.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 200 {
                        break;
                    }
                }
            }
        }
        let fault = "<?xml version=\"1.0\"?>\
<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body><S:Fault><faultcode>S:Server</faultcode><faultstring>ERR40 Die Anzahl der gefundenen Ergebnisse ist gr&#246;&#223;er als 100.</faultstring></S:Fault></S:Body></S:Envelope>";
        let resp = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            fault.len(),
            fault
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
    });
    let dir = safedir::vas::SpmlResolver::new(safedir::vas::SpmlConfig::new(format!(
        "http://{addr}/vas"
    )))
    .unwrap();
    let id: SafeId = "DE.BRAK.bdda0cd6-ccdd-44a1-a42c-f13ced17235b.334d"
        .parse()
        .unwrap();
    match dir.lookup_safe_id(&id) {
        Err(Error::Directory(ErrCode::Err40, _)) => {}
        other => panic!("unexpected {other:?}"),
    }
    handle.join().unwrap();
}

#[test]
fn search_encodes_query_and_maps_results() {
    let mock = spawn_mock(vec![search_success()]);
    let dir = resolver(&mock.endpoint);
    let query = SearchQuery::builder()
        .ort_contains("Bonn")
        .unwrap()
        .with_roles(&[safedir::roles::RoleValue::EgvpJustiz])
        .build()
        .unwrap();
    let outcome = dir.search(&query).unwrap();
    assert_eq!(outcome.entries.len(), 2);
    assert!(outcome.entries.iter().any(|e| e.name == "Amtsgericht Bonn"));

    let body = mock
        .captured
        .lock()
        .unwrap()
        .first()
        .expect("captured request body")
        .clone();
    assert!(body.contains("searchRequest"));
    assert!(body.contains("/AddressCard/Address/L"));
    assert!(body.contains("Bonn"));
    assert!(body.contains("/Extension/EJusticeAttributes/Roles/RoleValue"));
    assert!(body.contains("egvp_justiz"));
    assert!(body.contains("urn:oasis:names:tc:DSML:2:0:core"));
}
