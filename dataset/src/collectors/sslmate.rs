use crate::database::{Cache, DBState, DatabaseError};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tldextract::TldResult;
use tracing::{debug, error, instrument, trace};

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
    rate_limited: AtomicU64,
}

impl SslMateClient {
    pub async fn new(
        client: Arc<ClientWithMiddleware>,
        api_key: String,
        memory: bool,
        db_state: Arc<DBState>,
    ) -> Self {
        Self {
            api_key,
            client,
            cache: Cache::new(memory, db_state, "ssl_mate".to_string())
                .await
                .expect("Should be able to create cache"),
            rate_limited: AtomicU64::new(0),
        }
    }

    pub(crate) fn rate_limited(&self) -> bool {
        trace!("Checking if ratelimited");
        let last_limited = self.rate_limited.load(Ordering::Acquire);
        debug!("Got last limited time of {}", last_limited);

        if last_limited == 0 {
            false
        } else {
            let now = SystemTime::now();

            let unix_time_sec = now
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            trace!("Current time is {}", unix_time_sec);

            unix_time_sec - last_limited > 600
        }
    }

    /// Gets certs for a specified domain
    #[instrument(skip(self))]
    pub async fn get_certs(
        &self,
        domain: &str,
        extractor_info: TldResult,
    ) -> Result<SslMateResponse, SslMateError> {
        if self.rate_limited() {
            return Err(SslMateError::RateLimited);
        }

        let cache_value = self.cache.get_from_cache(domain).await.unwrap_or_default();

        if let Some(value) = cache_value {
            return Ok(value);
        }

        // Only include subdomains if url is on root of domain
        let include_subdomains = extractor_info.subdomain.is_none();

        let response_res = self
            .client
            .get(format!(
                "https://api.certspotter.com/v1/issuances\
                ?domain={}&include_subdomains={}&expand=dns_names&expand=issuer&expand=cert_der",
                domain, include_subdomains
            ))
            .bearer_auth(&self.api_key)
            .send()
            .await?
            .error_for_status();

        // Give special error if ratelimited
        if let Err(reqwest_err) = response_res {
            if let Some(status) = reqwest_err.status() {
                if status.as_u16() == 429 {
                    let now = SystemTime::now();

                    let unix_time_sec = now
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs();

                    self.rate_limited.store(unix_time_sec, Ordering::Release);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Cache;
    use crate::database::tests::get_test_db_state;
    use crate::{get_reqwest_middleware_client, get_ssl_mate_client};
    use tldextract::TldResult;

    #[tokio::test]
    /// Test whether the ssl_mate cache works
    async fn test_sslmate_cache() {
        let test_db_state = get_test_db_state().await;
        let db_state = test_db_state.db_state.clone();
        let client = get_reqwest_middleware_client();

        let test_cache: Cache<SslMateResponse> =
            Cache::new(true, db_state.clone(), "test_sslmate".to_string())
                .await
                .expect("Should be able to create test cache");

        let mut ssl_client = get_ssl_mate_client(client, true, db_state.clone()).await;

        ssl_client.cache = test_cache;

        let test_domain = "example.com";
        let mock_response = vec![SslMateResponseElement {
            id: "test-id".to_string(),
            tbs_sha256: "test-tbs-sha".to_string(),
            cert_sha256: "test-cert-sha".to_string(),
            dns_names: vec!["example.com".to_string(), "www.example.com".to_string()],
            pubkey_sha256: "test-pubkey-sha".to_string(),
            issuer: Issuer {
                friendly_name: "Test CA".to_string(),
                pubkey_sha256: "test-issuer-pubkey-sha".to_string(),
                name: "Test Certification Authority".to_string(),
            },
            not_before: "2023-01-01T00:00:00Z".to_string(),
            not_after: "2024-01-01T00:00:00Z".to_string(),
            revoked: false,
            cert_der: "test-cert-der".to_string(),
        }];

        ssl_client
            .cache
            .add_to_cache(test_domain.to_string(), &mock_response)
            .await
            .expect("Should be able to add to cache");

        // Create a mock TldResult for the test
        let mock_tld_result = TldResult {
            domain: Some("example".to_string()),
            subdomain: None,
            suffix: Some("com".to_string()),
        };

        let lookup_result = ssl_client.get_certs(test_domain, mock_tld_result).await;

        assert!(lookup_result.is_ok(), "Lookup should succeed");
        let certs = lookup_result.unwrap();
        assert_eq!(certs.len(), 1, "Should retrieve one certificate");
        assert_eq!(certs[0].id, "test-id", "Certificate ID should match");
        assert_eq!(certs[0].dns_names.len(), 2, "Should have two DNS names");
    }
}
