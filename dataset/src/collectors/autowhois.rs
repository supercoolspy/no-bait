use crate::collectors::DomainInfoClient;
use crate::database::{Cache, DBState, DatabaseError, DomainInfo};
use async_trait::async_trait;
use reqwest_middleware::ClientWithMiddleware;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{error, instrument};

#[derive(Debug, Error)]
pub enum AutoWhoisError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Database (Cache) Error: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("TLD Extract error: {0}")]
    TLDExtract(#[from] tldextract::TldExtractError),

    #[error("AutoWhois Ratelimit Reached")]
    RateLimited,
}

pub struct AutoWhoisClient {
    client: Arc<ClientWithMiddleware>,
    cache: Cache<Value>,
    rate_limited: AtomicU64,
    api_key: String,
}

impl AutoWhoisClient {
    pub async fn new(
        client: Arc<ClientWithMiddleware>,
        api_key: String,
        memory: bool,
        db_state: Arc<DBState>,
    ) -> Self {
        Self {
            api_key,
            client,
            rate_limited: AtomicU64::new(0),
            cache: Cache::new(memory, db_state, "auto_whois".to_string())
                .await
                .expect("Should be able to create cache"),
        }
    }
}

#[async_trait]
impl DomainInfoClient for AutoWhoisClient {
    /// Gets whois info for a specified domain from AutoWhois
    #[instrument(skip(self), err)]
    async fn get_info(
        &self,
        root: &str,
    ) -> Result<DomainInfo, Box<dyn std::error::Error + Send + Sync>> {
        let cache_value = self.cache.get_from_cache(root).await.unwrap_or_default();

        if let Some(value) = cache_value {
            return Ok(DomainInfo::AutoWhoisInfo(value));
        }

        let response_res = self
            .client
            .get(format!(
                "https://api.autowhois.com/?key={}&domain={}",
                &self.api_key, root
            ))
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

                    self.rate_limited.store(unix_time_sec, Ordering::Relaxed);

                    return Err(Box::new(AutoWhoisError::RateLimited));
                }
            }

            return Err(reqwest_err.into());
        }

        let response: Value = response_res?.json().await?;

        self.cache.add_to_cache(root.to_string(), &response).await?;

        Ok(DomainInfo::AutoWhoisInfo(response))
    }

    fn rate_limited(&self) -> bool {
        let last_limited = self.rate_limited.load(Ordering::Relaxed);

        if last_limited == 0 {
            false
        } else {
            let now = SystemTime::now();

            let unix_time_sec = now
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            last_limited + 60 >= unix_time_sec
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Cache;
    use crate::database::tests::get_test_db_state;
    use crate::get_reqwest_middleware_client;
    use serde_json::json;

    #[tokio::test]
    /// Test whether the autowhois cache works
    async fn test_autowhois_cache() {
        let test_db_state = get_test_db_state().await;
        let db_state = test_db_state.db_state.clone();
        let client = get_reqwest_middleware_client();

        let test_cache: Cache<Value> =
            Cache::new(true, db_state.clone(), "test_autowhois".to_string())
                .await
                .expect("Should be able to create test cache");

        let mut autowhois_client =
            AutoWhoisClient::new(client, "test_api_key".to_string(), true, db_state.clone()).await;

        autowhois_client.cache = test_cache;

        let test_domain = "example.com";
        let mock_response = json!({
            "domain": "example.com",
            "creation_date": "1995-08-14T04:00:00Z",
            "expiration_date": "2024-08-13T04:00:00Z",
            "registrar": "Test Registrar, Inc.",
            "status": "active"
        });

        autowhois_client
            .cache
            .add_to_cache(test_domain.to_string(), &mock_response)
            .await
            .expect("Should be able to add to cache");

        let lookup_result = autowhois_client.get_info(test_domain).await;

        assert!(lookup_result.is_ok(), "Lookup should succeed");
        if let DomainInfo::AutoWhoisInfo(whois_data) = lookup_result.unwrap() {
            assert_eq!(whois_data["domain"], "example.com", "Domain should match");
            assert_eq!(
                whois_data["registrar"], "Test Registrar, Inc.",
                "Registrar should match"
            );
        } else {
            panic!("Expected AutoWhoisInfo but got something else");
        }
    }
}
