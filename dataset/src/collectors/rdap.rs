use crate::collectors::DomainInfoClient;
use crate::database::{Cache, DBState, DatabaseError, DomainInfo};
use async_trait::async_trait;
use icann_rdap_client::http::{ClientConfig, create_client};
use icann_rdap_client::iana::MemoryBootstrapStore;
use icann_rdap_client::rdap::{QueryType, rdap_bootstrapped_request, rdap_url_request};
use icann_rdap_common::prelude::{Link, ObjectCommonFields, RdapResponse};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, trace};

#[derive(Error, Debug)]
pub enum RDAPError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("RDAP Client error: {0}")]
    RDAPClient(#[from] icann_rdap_client::RdapClientError),

    #[error("Database (Cache) Error: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("TLD Extract error: {0}")]
    TLDExtract(#[from] tldextract::TldExtractError),

    #[error("No Domain Parsable {0}")]
    NoDomain(String),

    #[error("No href on link")]
    NoHREF,
}

pub struct RDAPClient {
    rdap_client: icann_rdap_client::http::Client,
    store: MemoryBootstrapStore,
    cache: Cache<RdapResponse>,
}

impl RDAPClient {
    pub async fn new(memory: bool, db_state: Arc<DBState>) -> Self {
        let config = ClientConfig::default();

        let client = create_client(&config).expect("Should be able to create client");

        let store = MemoryBootstrapStore::new();

        Self {
            rdap_client: client,
            store,
            cache: Cache::new(memory, db_state, "rdap".to_string())
                .await
                .expect("Should be able to create cache"),
        }
    }
}

#[async_trait]
impl DomainInfoClient for RDAPClient {
    /// Gets RDAP info for a domain
    #[instrument(skip(self), err)]
    async fn get_info(
        &self,
        root: &str,
    ) -> Result<DomainInfo, Box<dyn std::error::Error + Send + Sync>> {
        let query = QueryType::from_str(root)?;

        trace!("Checking if response in cache");
        let cache_value = self.cache.get_from_cache(root).await.unwrap_or_default();

        if let Some(cache_value) = cache_value {
            trace!("RDAP Response in cache");
            return Ok(DomainInfo::RDAPInfo(cache_value));
        }
        trace!("RDAP Response not in cache");

        let response = rdap_bootstrapped_request(&query, &self.rdap_client, &self.store, |reg| {
            trace!("fetching {reg:?}")
        })
        .await?;

        if let RdapResponse::Domain(domain) = response.rdap {
            debug!("Got as domain");
            let links = domain.links();
            trace!("Links: {:?}", links);

            // Related should work for now but may not in the future
            let link_op: Option<Link> = links
                .iter()
                .find(|link| link.is_relation("related"))
                .cloned();
            trace!("Related link: {:?}", link_op);

            let data = if let Some(link) = link_op {
                trace!("Related domain found");
                let location = link.href.ok_or(RDAPError::NoHREF)?;

                let res = rdap_url_request(&location, &self.rdap_client).await?;
                res.rdap
            } else {
                trace!("Related domain not found, assuming special domain");
                RdapResponse::Domain(domain)
            };

            self.cache.add_to_cache(root.to_string(), &data).await?;

            Ok(DomainInfo::RDAPInfo(data))
        } else {
            Err(RDAPError::NoDomain(root.to_string()).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Cache;
    use crate::database::tests::get_test_db_state;
    use icann_rdap_common::prelude::{Domain, RdapResponse};
    use url::Url;

    #[tokio::test]
    /// Test whether the rdap cache works
    async fn test_rdap_cache() {
        let test_db_state = get_test_db_state().await;
        let db_state = test_db_state.db_state.clone();

        let test_cache: Cache<RdapResponse> = Cache::new(
            true, // use memory cache
            db_state.clone(),
            "test_rdap".to_string(),
        )
        .await
        .expect("Should be able to create test cache");

        let mut client = RDAPClient::new(true, db_state.clone()).await;

        client.cache = test_cache;

        let test_domain = "example.dev";

        let mock_domain = Domain::builder()
            .ldh_name("example.dev")
            .handle("EXAMPLE.DEV")
            .status("active")
            .link(
                Link::builder()
                    .value("https://rdap.example.com/domain/example.dev")
                    .href(Url::parse("https://rdap.example.com/domain/example.dev").unwrap())
                    .rel("self")
                    .media_type("application/rdap+json")
                    .build(),
            )
            .build();

        let test_rdap_response = RdapResponse::Domain(Box::from(mock_domain));

        client
            .cache
            .add_to_cache(test_domain.to_string(), &test_rdap_response)
            .await
            .expect("Should be able to add to cache");

        let lookup_result = client.get_info(test_domain).await;

        assert!(lookup_result.is_ok(), "Lookup should succeed");

        if let DomainInfo::RDAPInfo(rdap_response) = lookup_result.unwrap() {
            if let RdapResponse::Domain(domain) = rdap_response {
                assert_eq!(
                    domain.ldh_name(),
                    Some("example.dev"),
                    "Domain name should match"
                );
                assert_eq!(
                    domain.handle(),
                    Some("EXAMPLE.DEV"),
                    "Domain handle should match"
                );
                assert!(
                    domain.status().contains(&"active".to_string()),
                    "Domain status should be active"
                );

                // Verify the link is preserved
                let links = domain.links();
                assert!(!links.is_empty(), "Domain should have links");

                if let Some(link) = links.iter().find(|l| l.is_relation("self")) {
                    assert_eq!(
                        link.href.as_deref(),
                        Some("https://rdap.example.com/domain/example.dev"),
                        "Self link URL should match"
                    );
                } else {
                    panic!("Domain should have a self link");
                }
            } else {
                panic!("Should have retrieved a domain response");
            }
        } else {
            panic!("Expected RDAP info but got something else");
        }
    }
}
