use crate::collectors::DomainInfoClient;
use crate::database::{Cache, DBState, DatabaseError, DomainInfo};
use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, trace};
use whois_that::WhoisError;
use whois_that::whois::Whois;

#[derive(Error, Debug)]
pub(crate) enum WhoIsError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("TLD Extract error: {0}")]
    TLDExtract(#[from] tldextract::TldExtractError),

    #[error("Whois lookup error {0}")]
    WhoIsLookupError(#[from] WhoisError),

    #[error("Database (Cache) Error: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("No whois found (attempt to switch to rdap)")]
    NoWhois,
}

pub struct WhoisClient {
    whois: Whois,
    cache: Cache<String>,
}

impl WhoisClient {
    pub async fn new(memory: bool, db_state: Arc<DBState>) -> Self {
        let whois = Whois::builder()
            .build()
            .expect("Should be able to load default");
        debug!("Loaded Whois server data");

        Self {
            whois,
            cache: Cache::new(memory, db_state, "whois".to_string())
                .await
                .expect("Should be able to create cache"),
        }
    }
}

#[async_trait]
impl DomainInfoClient for WhoisClient {
    #[instrument(skip(self), err)]
    async fn get_info(
        &self,
        root: &str,
    ) -> Result<DomainInfo, Box<dyn std::error::Error + Send + Sync>> {
        trace!("Getting whois info");

        trace!("Checking if response in cache");
        let cache_value = self.cache.get_from_cache(root).await.unwrap_or_default();

        if cache_value.is_some() {
            trace!("Whois Response in cache");
            return Ok(DomainInfo::WhoisInfo(
                cache_value.expect("Cache value should exist"),
            ));
        }
        trace!("Whois Response not in cache");

        let info = self.whois.lookup_domain_info(root);
        trace!("Server: {:?}", info);

        if info.is_none() {
            return Err(WhoIsError::NoWhois.into());
        }

        let info = info.unwrap();

        let whois_data = self.whois.lookup(info).await?;

        self.cache
            .add_to_cache(root.to_string(), &whois_data)
            .await?;

        Ok(DomainInfo::WhoisInfo(whois_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Cache;
    use crate::database::tests::get_test_db_state;

    #[tokio::test]
    /// Test whether the whois cache is working correctly
    async fn test_whois_cache() {
        let test_db_state = get_test_db_state().await;
        let db_state = test_db_state.db_state.clone();

        let test_cache: Cache<String> =
            Cache::new(true, db_state.clone(), "test_whois".to_string())
                .await
                .expect("Should be able to create test cache");

        let mut client = WhoisClient::new(true, db_state.clone()).await;

        client.cache = test_cache;

        let test_domain = "example.com";
        let test_whois_response =
            "Domain Name: example.com\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN".to_string();

        client
            .cache
            .add_to_cache(test_domain.to_string(), &test_whois_response)
            .await
            .expect("Should be able to add to cache");

        let lookup_result = client.get_info(test_domain).await;

        assert!(lookup_result.is_ok(), "Lookup should succeed");

        if let DomainInfo::WhoisInfo(whois_data) = lookup_result.unwrap() {
            assert_eq!(
                whois_data, test_whois_response,
                "Retrieved response should match inserted response"
            );
        } else {
            panic!("Expected WhoisInfo but got something else");
        }
    }
}
