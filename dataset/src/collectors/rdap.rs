use crate::database::{Cache, DBState, DatabaseError};
use icann_rdap_client::http::{ClientConfig, create_client};
use icann_rdap_client::iana::MemoryBootstrapStore;
use icann_rdap_client::{
    iana::BootstrapStore,
    rdap::{QueryType, rdap_bootstrapped_request, rdap_url_request},
};
use icann_rdap_common::prelude::{Link, ObjectCommonFields, RdapResponse};
use libsql::AuthAction::Select;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, trace};
use url::Url;

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

    #[error("No Root Domain Parsable {0}")]
    NoRoot(Url),

    #[error("No related link")]
    NoRelated,

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

    /// Per most registry's usage guidlines, automated access is not allowed, so this shouldn't be used without permission
    #[instrument(skip(self), err)]
    pub(crate) async fn get_rdap_data(&self, url: Url) -> Result<RdapResponse, RDAPError> {
        let query = QueryType::from_str(url.domain().ok_or(RDAPError::NoRoot(url.clone()))?)?;

        trace!("Checking if response in cache");
        let cache_value = (&self.cache).get_from_cache(url.to_string()).await?;

        if cache_value.is_some() {
            trace!("RDAP Response in cache");
            return Ok(cache_value.expect("Cache value should exist"));
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

            if link_op.is_none() {
                return Err(RDAPError::NoRelated);
            }

            let link = link_op.unwrap();
            let location = link.href.ok_or(RDAPError::NoHREF)?;

            let res = rdap_url_request(&location, &self.rdap_client).await?;
            let data = res.rdap;

            (&self.cache).add_to_cache(url.to_string(), &data).await?;

            Ok(data)
        } else {
            Err(RDAPError::NoRoot(url))
        }
    }
}
