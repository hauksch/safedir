//! The blocking SPML/VAS HTTP client.

use std::time::Duration;

use crate::dienststellen::DienststellenId;
use crate::entry::SafeEntry;
use crate::error::Error;
use crate::resolver::{SafeDirectory, SearchOutcome, SearchQuery};
use crate::safe_id::SafeId;
use crate::vas::spml::{self, SpmlResponse};

/// Configuration for the VAS client.
#[derive(Debug, Clone)]
pub struct SpmlConfig {
    /// VAS endpoint URL, e.g. handed out by the BLK-AG registration
    /// procedure. Must be reachable over TLS.
    pub endpoint: String,
    /// Optional client identity (PEM bundle with private key + certificate)
    /// for mutual TLS.
    pub client_identity_pem: Option<String>,
    /// Optional additional CA (PEM) to trust for the endpoint.
    pub ca_pem: Option<String>,
    /// Request timeout.
    pub timeout: Duration,
}

impl SpmlConfig {
    /// Default configuration for an endpoint (30 s timeout, no client
    /// identity).
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client_identity_pem: None,
            ca_pem: None,
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the mutual-TLS client identity (PEM with key + cert).
    #[must_use]
    pub fn with_client_identity(mut self, pem: impl Into<String>) -> Self {
        self.client_identity_pem = Some(pem.into());
        self
    }

    /// Trust an additional CA (PEM).
    #[must_use]
    pub fn with_ca(mut self, pem: impl Into<String>) -> Self {
        self.ca_pem = Some(pem.into());
        self
    }

    /// Set the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// A [`SafeDirectory`] talking to the VAS via SPML 2.0 over SOAP.
///
/// Blocking by design: the [`SafeDirectory`] trait is synchronous, and the
/// primary consumers (CLI, rosci) work in request/response flows. The HTTP
/// machinery lives inside `reqwest::blocking`.
#[derive(Debug, Clone)]
pub struct SpmlResolver {
    config: SpmlConfig,
    client: reqwest::blocking::Client,
}

impl SpmlResolver {
    /// Build from configuration.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for an invalid endpoint or unusable key material.
    pub fn new(config: SpmlConfig) -> Result<Self, Error> {
        // TLS-only, with an explicit loopback escape hatch for the mock
        // test server; redirects are never followed (a cross-host redirect
        // would re-present the mutual-TLS identity to a third party).
        // The check runs on the *parsed* URL: string-prefix matching would
        // let `HTTP://…` (scheme case) or `http://localhost.evil.example`
        // through and leak the mutual-TLS identity over plain HTTP.
        let is_loopback_http = config.endpoint.starts_with("http://")
            && reqwest::Url::parse(&config.endpoint)
                .ok()
                .filter(|u| match u.host_str() {
                    Some("localhost") | Some("::1") => true,
                    Some(h) => h
                        .parse::<std::net::Ipv4Addr>()
                        .is_ok_and(|ip| ip.is_loopback()),
                    _ => false,
                })
                .is_some();
        if !config.endpoint.starts_with("https://") && !is_loopback_http {
            return Err(Error::Config(format!(
                "VAS endpoint must use https (loopback http allowed for tests): {}",
                config.endpoint
            )));
        }
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("safedir/", env!("CARGO_PKG_VERSION")));
        if let Some(ca) = &config.ca_pem {
            let cert = reqwest::Certificate::from_pem(ca.as_bytes())
                .map_err(|e| Error::Config(format!("invalid CA PEM: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }
        if let Some(id) = &config.client_identity_pem {
            let identity = reqwest::Identity::from_pem(id.as_bytes())
                .map_err(|e| Error::Config(format!("invalid client identity PEM: {e}")))?;
            builder = builder.identity(identity);
        }
        let client = builder
            .build()
            .map_err(|e| Error::Config(format!("cannot build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }

    fn post(&self, request_xml: &str) -> Result<SpmlResponse, Error> {
        let response = self
            .client
            .post(&self.config.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "text/xml; charset=utf-8")
            .body(request_xml.to_owned())
            .send()
            .map_err(|e| Error::Network(format!("VAS request failed: {e}")))?;
        let status = response.status();
        // Bounded read: the timeout bounds time, not bytes.
        const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
        let body = response
            .text()
            .map_err(|e| Error::Network(format!("cannot read VAS response: {e}")))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Network(format!(
                "VAS response exceeds {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        if !status.is_success() {
            // SOAP servers answer 500 with a Fault body that may still
            // carry a typed ERR code — try to parse before giving up.
            return match spml::parse_response(&body) {
                Ok(SpmlResponse::Failure(Some(code), msg)) => Err(Error::Directory(code, msg)),
                Ok(SpmlResponse::Failure(None, msg)) if !msg.trim().is_empty() => {
                    Err(Error::DirectoryFailure(format!("HTTP {status}: {msg}")))
                }
                _ => Err(Error::Network(format!(
                    "VAS answered with HTTP {status}: {}",
                    truncate(&body, 300)
                ))),
            };
        }
        spml::parse_response(&body)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

impl SpmlResolver {
    fn into_outcome(response: SpmlResponse) -> Result<SearchOutcome, Error> {
        match response {
            SpmlResponse::Success(entries, warnings) => Ok(SearchOutcome {
                entries,
                notes: Vec::new(),
                warnings,
            }),
            SpmlResponse::Failure(Some(code), msg) => Err(Error::Directory(code, msg)),
            SpmlResponse::Failure(None, msg) => Err(Error::DirectoryFailure(msg)),
        }
    }
}

impl SafeDirectory for SpmlResolver {
    fn lookup_safe_id(&self, id: &SafeId) -> Result<Option<SafeEntry>, Error> {
        let response = self.post(&spml::lookup_request(id.as_str()))?;
        match response {
            SpmlResponse::Success(mut entries, warnings) => {
                if entries.len() > 1 {
                    return Err(Error::DirectoryFailure(format!(
                        "lookup for {} returned {} result objects (expected at most one){}",
                        id.as_str(),
                        entries.len(),
                        if warnings.is_empty() {
                            String::new()
                        } else {
                            format!("; warnings: {}", warnings.join("; "))
                        }
                    )));
                }
                if entries.is_empty() && !warnings.is_empty() {
                    // A success response whose only result object was
                    // unusable is a defect, not "not found".
                    return Err(Error::DirectoryFailure(warnings.join("; ")));
                }
                Ok(entries.pop())
            }
            SpmlResponse::Failure(Some(code), msg) => Err(Error::Directory(code, msg)),
            SpmlResponse::Failure(None, msg) => Err(Error::DirectoryFailure(msg)),
        }
    }

    fn lookup_dienststellen(&self, id: &DienststellenId) -> Result<Vec<SafeEntry>, Error> {
        let response = self.post(&spml::lookup_request(&id.wire_form()))?;
        match response {
            SpmlResponse::Success(entries, warnings) => {
                // Dienststellen-IDs have cardinality 1..n on an entry, but a
                // single lookup must still return at most one PSO.
                if entries.len() > 1 {
                    return Err(Error::DirectoryFailure(format!(
                        "lookup for {} returned {} result objects (expected at most one){}",
                        id.wire_form(),
                        entries.len(),
                        if warnings.is_empty() {
                            String::new()
                        } else {
                            format!("; warnings: {}", warnings.join("; "))
                        }
                    )));
                }
                Ok(entries)
            }
            SpmlResponse::Failure(Some(code), msg) => Err(Error::Directory(code, msg)),
            SpmlResponse::Failure(None, msg) => Err(Error::DirectoryFailure(msg)),
        }
    }

    fn search(&self, query: &SearchQuery) -> Result<SearchOutcome, Error> {
        let response = self.post(&spml::search_request(query))?;
        Self::into_outcome(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plain_http_outside_loopback() {
        let err = SpmlResolver::new(SpmlConfig::new("http://vas.example/soap")).unwrap_err();
        assert!(err.to_string().contains("https"));
        // Loopback http is allowed (mock tests).
        assert!(SpmlResolver::new(SpmlConfig::new("http://127.0.0.1:9/soap")).is_ok());
        assert!(SpmlResolver::new(SpmlConfig::new("https://vas.example/soap")).is_ok());
        // Bypass attempts must fail closed.
        assert!(SpmlResolver::new(SpmlConfig::new("HTTP://vas.example/soap")).is_err());
        assert!(SpmlResolver::new(SpmlConfig::new("http://localhost.evil.example/soap")).is_err());
        assert!(SpmlResolver::new(SpmlConfig::new("http://127.0.0.1.evil.example/soap")).is_err());
        assert!(
            SpmlResolver::new(SpmlConfig::new("http://localhost:8080@evil.example/soap")).is_err()
        );
    }
}
