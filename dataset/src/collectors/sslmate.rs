use crate::database::{Cache, DBState, DatabaseError};
use reqwest::StatusCode;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tldextract::TldExtractor;

#[derive(Debug, Error)]
pub enum SslMateError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Database (Cache) Error: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("TLD Extract error: {0}")]
    TLDExtract(#[from] tldextract::TldExtractError),

    #[error("SSL Mate Ratelimit Reached")]
    RateLimited,
}

pub type SslMateResponse = Vec<SslMateResponseElement>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SslMateResponseElement {
    id: String,

    tbs_sha256: String,

    cert_sha256: String,

    dns_names: Vec<String>,

    pubkey_sha256: String,

    issuer: Issuer,

    not_before: String,

    not_after: String,

    revoked: bool,

    cert_der: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Issuer {
    friendly_name: String,

    pubkey_sha256: String,

    name: String,
}

pub struct SslMateClient {
    client: Arc<ClientWithMiddleware>,
    cache: Cache<SslMateResponse>,
    api_key: String,
    tld_extractor: Arc<TldExtractor>,
}

impl SslMateClient {
    pub async fn new(
        client: Arc<ClientWithMiddleware>,
        api_key: String,
        memory: bool,
        db_state: Arc<DBState>,
        tld_extractor: Arc<TldExtractor>,
    ) -> Self {
        Self {
            api_key,
            client,
            tld_extractor,
            cache: Cache::new(memory, db_state, "ssl_mate".to_string())
                .await
                .expect("Should be able to create cache"),
        }
    }

    /// Gets certs for a specified domain
    pub async fn get_certs(&self, domain: &str) -> Result<SslMateResponse, SslMateError> {
        let cache_value = self
            .cache
            .get_from_cache(domain.to_string())
            .await
            .unwrap_or_default();

        if let Some(value) = cache_value {
            return Ok(value);
        }

        let extractor_info = self.tld_extractor.extract(domain)?;

        // Only include subdomains if url is on root of domain
        let include_subdomains = extractor_info.subdomain.is_none();

        let response_res = self
            .client
            .get(format!(
                "https://api.certspotter.com/v1/issuances\
                ?domain={}&include_subdomains={}&expand=dns_names&expand=issuer&expand=cert_der",
                include_subdomains, domain
            ))
            .bearer_auth(&self.api_key)
            .send()
            .await?
            .error_for_status();

        // Give special error if ratelimited
        if let Err(reqwest_err) = response_res {
            if let Some(status) = reqwest_err.status() {
                if status.as_u16() == 429 {
                    return Err(SslMateError::RateLimited);
                }
            }

            return Err(reqwest_err.into());
        }

        let response = response_res?.json().await?;

        self.cache
            .add_to_cache(domain.to_string(), &response)
            .await?;

        Ok(response)
    }
}
