use clap::{Args, Subcommand};
use thiserror::Error;
use url::Url;
use whois_rust::{WhoIs, WhoIsLookupOptions};

#[derive(Error, Debug)]
pub(crate) enum WhoIsError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Url Parsing error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("No Root Domain Parsable {0}")]
    NoRoot(url::Url),

    #[error("Whois lookup error {0}")]
    WhoIsLookupError(#[from] whois_rust::WhoIsError),
}

#[derive(Debug)]
pub(crate) struct WhoIsInfo {
    pub(crate) domain: String,
    pub(crate) subdomain: Option<String>,
    pub(crate) path: Option<String>,
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

pub(crate) async fn get_whois_domain(whois: &WhoIs, url: String) -> Result<WhoIsInfo, WhoIsError> {
    let url_info = Url::parse(&url)?;
    let domain = url_info
        .domain()
        .ok_or(WhoIsError::NoRoot(url_info.clone()))?;

    let whois_data = whois
        .lookup_async(WhoIsLookupOptions::from_string(domain)?)
        .await?;

    Ok(WhoIsInfo {
        domain: domain.to_string(),
        subdomain: get_subdomain(&url_info),
        path: Some(url_info.path().to_string()),
        whois_data,
    })
}
