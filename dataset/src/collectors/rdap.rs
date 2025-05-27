use std::str::FromStr;

use icann_rdap_client::{
    http::create_client,
    iana::BootstrapStore,
    rdap::{QueryType, rdap_bootstrapped_request, rdap_url_request},
};
use icann_rdap_common::prelude::{Link, ObjectCommonFields, RdapResponse};
use log::debug;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum RDAPError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("RDAP Client error: {0}")]
    RDAPClient(#[from] icann_rdap_client::RdapClientError),

    #[error("No Root Domain Parsable {0}")]
    NoRoot(url::Url),

    #[error("No related link")]
    NoRelated,

    #[error("No href on link")]
    NoHREF,
}

/// Per google's usage guidlines, automated access is not allowed, so this shouldn't be used without permission
pub(crate) async fn get_rdap_data(
    rdap_client: icann_rdap_client::http::Client,
    store: impl BootstrapStore,
    url: Url,
) -> Result<RdapResponse, RDAPError> {
    let query = QueryType::from_str(url.domain().ok_or(RDAPError::NoRoot(url.clone()))?)?;

    let response = rdap_bootstrapped_request(&query, &rdap_client, &store, |reg| {
        debug!("fetching {reg:?}")
    })
    .await?;

    if let RdapResponse::Domain(domain) = response.rdap {
        let links = domain.links();

        // Related should work for now but may not in the future
        let link_op: Option<Link> = links
            .iter()
            .filter(|link| link.is_relation("related"))
            .take(1)
            .last()
            .cloned();

        if link_op.is_none() {
            return Err(RDAPError::NoRelated);
        }

        let link = link_op.unwrap();
        let location = link.href.ok_or(RDAPError::NoHREF)?;

        let res = rdap_url_request(&location, &rdap_client).await?;
        let data = res.rdap;

        Ok(data)
    } else {
        Err(RDAPError::NoRoot(url))
    }
}
