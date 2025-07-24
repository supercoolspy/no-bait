use crate::database::{Cache, DBState, DatabaseError};
use std::sync::Arc;
use thiserror::Error;
use tldextract::TldExtractor;
use tracing::{debug, instrument, trace};
use url::Url;
use whois_that::whois::Whois;
use whois_that::WhoisError;

#[derive(Error, Debug)]
pub(crate) enum WhoIsError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("TLD Extract error: {0}")]
    TLDExtract(#[from] tldextract::TldExtractError),

    #[error("No Domain Parsable {0}")]
    NoDomain(Url),

    #[error("No Root Domain Parsable {0}")]
    NoRoot(Url),

    #[error("No Suffix Parsable {0}")]
    NoSuffix(Url),

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
    tld_extractor: Arc<TldExtractor>,
}

impl WhoisClient {
    pub async fn new(
        memory: bool,
        db_state: Arc<DBState>,
        tld_extractor: Arc<TldExtractor>,
    ) -> Self {
        let whois = Whois::builder()
            .build()
            .expect("Should be able to load default");
        debug!("Loaded Whois server data");

        Self {
            whois,
            cache: Cache::new(memory, db_state, "whois".to_string())
                .await
                .expect("Should be able to create cache"),
            tld_extractor,
        }
    }

    #[instrument(skip(self), err)]
    pub async fn get_whois_domain(&self, url: &Url) -> Result<String, WhoIsError> {
        trace!("Getting whois info");
        let domain = url.host_str().ok_or(WhoIsError::NoDomain(url.clone()))?;
        debug!("Domain: {}", domain);

        let extractor_info = self.tld_extractor.extract(domain)?;
        let root = &format!(
            "{}.{}",
            extractor_info
                .domain
                .ok_or(WhoIsError::NoRoot(url.clone()))?,
            extractor_info
                .suffix
                .ok_or(WhoIsError::NoSuffix(url.clone()))?
        );

        trace!("Checking if response in cache");
        let cache_value = (&self.cache)
            .get_from_cache(url.to_string())
            .await
            .unwrap_or_default();

        if cache_value.is_some() {
            trace!("Whois Response in cache");
            return Ok(cache_value.expect("Cache value should exist"));
        }
        trace!("Whois Response not in cache");

        let info = self.whois.lookup_domain_info(root);
        trace!("Server: {:?}", info);

        if info.is_none() {
            return Err(WhoIsError::NoWhois);
        }

        let info = info.unwrap();

        let whois_data = self.whois.lookup(info).await?;

        (&self.cache)
            .add_to_cache(domain.to_string(), &whois_data)
            .await?;

        Ok(whois_data)
    }
}
