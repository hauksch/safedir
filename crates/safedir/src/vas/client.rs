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
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
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
        if !response.status().is_success() {
            return Err(Error::Network(format!(
                "VAS answered with HTTP {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .map_err(|e| Error::Network(format!("cannot read VAS response: {e}")))?;
        spml::parse_response(&body)
    }

    fn into_outcome(response: SpmlResponse) -> Result<SearchOutcome, Error> {
        match response {
            SpmlResponse::Success(entries) => Ok(SearchOutcome {
                entries,
                notes: Vec::new(),
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
            SpmlResponse::Success(mut entries) => Ok(entries.pop()),
            SpmlResponse::Failure(Some(code), msg) => Err(Error::Directory(code, msg)),
            SpmlResponse::Failure(None, msg) => Err(Error::DirectoryFailure(msg)),
        }
    }

    fn lookup_dienststellen(&self, id: &DienststellenId) -> Result<Vec<SafeEntry>, Error> {
        let response = self.post(&spml::lookup_request(&id.wire_form()))?;
        match response {
            SpmlResponse::Success(entries) => Ok(entries),
            SpmlResponse::Failure(Some(code), msg) => Err(Error::Directory(code, msg)),
            SpmlResponse::Failure(None, msg) => Err(Error::DirectoryFailure(msg)),
        }
    }

    fn search(&self, query: &SearchQuery) -> Result<SearchOutcome, Error> {
        let response = self.post(&spml::search_request(query))?;
        Self::into_outcome(response)
    }
}
