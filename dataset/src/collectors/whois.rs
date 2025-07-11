use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, trace};
use url::Url;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use crate::database::{Cache, DBState, DatabaseError};
use crate::WHOIS_SERVERS;

#[derive(Error, Debug)]
pub(crate) enum WhoIsError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("No Root Domain Parsable {0}")]
    NoRoot(Url),

    #[error("Whois lookup error {0}")]
    WhoIsLookupError(#[from] whois_rust::WhoIsError),

    #[error("Database (Cache) Error: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("No whois found (attempt to switch to rdap)")]
    NoWhois,
}

pub struct WhoisClient {
    whois: WhoIs,
    cache: Cache<String>
}

impl WhoisClient {
    pub async fn new(
        memory: bool, db_state: Arc<DBState>
    ) -> Self {
        let whois = WhoIs::from_string(WHOIS_SERVERS).expect("Should be able to load servers");
        debug!("Loaded Whois server data");

        Self {
            whois,
            cache: Cache::new(memory, db_state, "whois".to_string()).await.expect("Should be able to create cache")
        }
    }

    #[instrument(skip(self), err)]
    pub async fn get_whois_domain(&self, url: &Url) -> Result<String, WhoIsError> {
        trace!("Getting whois info");
        let domain = url.domain().ok_or(WhoIsError::NoRoot(url.clone()))?;
        debug!("Domain: {}", domain);

        trace!("Checking if response in cache");
        let cache_value = (&self.cache).get_from_cache(url.to_string()).await?;

        if cache_value.is_some() {
            trace!("Whois Response in cache");
            return Ok(cache_value.expect("Cache value should exist"))
        }
        trace!("Whois Response not in cache");

        let server = self.whois.get_server_by_tld(domain);
        trace!("Server: {:?}", server);

        if server.is_none() {
            return Err(WhoIsError::NoWhois);
        }

        let server = server.unwrap();

        let mut options = WhoIsLookupOptions::from_string(domain)?;

        options.server = Some(server.clone());
        trace!("Whois lookup options: {:?}", options);

        let whois_data_res = self.whois.lookup_async(options).await;

        if whois_data_res.as_ref().is_err_and(|e| match e {
            whois_rust::WhoIsError::MapError(message) => {
                **message == *"No whois server is known for this kind of object."
            }
            _ => false,
        }) {
            return Err(WhoIsError::NoWhois);
        }

        let whois_data = whois_data_res?;

        (&self.cache).add_to_cache(domain.to_string(), &whois_data).await?;

        Ok(whois_data)
    }

}