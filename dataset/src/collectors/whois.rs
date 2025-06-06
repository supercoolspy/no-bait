use thiserror::Error;
use url::Url;
use whois_rust::{WhoIs, WhoIsLookupOptions};

#[derive(Error, Debug)]
pub(crate) enum WhoIsError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("No Root Domain Parsable {0}")]
    NoRoot(url::Url),

    #[error("Whois lookup error {0}")]
    WhoIsLookupError(#[from] whois_rust::WhoIsError),

    #[error("No whois found (attempt to switch to rdap)")]
    NoWhois,
}

#[derive(Debug)]
pub(crate) struct WhoIsInfo {
    pub(crate) url: Url,
    pub(crate) whois_data: String,
}

fn get_subdomain(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let parts: Vec<&str> = host.split('.').collect();

    // Return the subdomain if there are at least 3 parts (e.g., sub.domain.com)
    if parts.len() > 2 {
        Some(parts[..parts.len() - 2].join("."))
    } else {
        None
    }
}

pub(crate) async fn get_whois_domain(whois: &WhoIs, url: Url) -> Result<WhoIsInfo, WhoIsError> {
    let domain = url.domain().ok_or(WhoIsError::NoRoot(url.clone()))?;

    let whois_data_res = whois
        .lookup_async(WhoIsLookupOptions::from_string(domain)?)
        .await;

    if whois_data_res.as_ref().is_err_and(|e| match e {
        whois_rust::WhoIsError::MapError(message) => {
            **message == *"No whois server is known for this kind of object."
        }
        _ => false,
    }) {
        return Err(WhoIsError::NoWhois);
    }

    let whois_data = whois_data_res?;

    Ok(WhoIsInfo {
        url,
        whois_data,
    })
}
