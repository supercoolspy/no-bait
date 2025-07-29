use crate::collectors::whois::WhoisClient;
use crate::collectors::{DomainInfoClient, TldConvertError, TldUrl};
use clap::Args;
use std::error::Error;
use thiserror::Error;
use tldextract::{TldExtractError, TldExtractor};
use tracing::instrument;
use url::Url;

#[derive(Args, Debug)]
pub(crate) struct WhoIsCommand {
    website: String,
}

#[derive(Debug, Error)]
pub enum WhoisCommandError {
    #[error("Whois Error: {0}")]
    WhoisError(#[from] Box<dyn Error + Send + Sync>),

    #[error("Tld Extract Error: {0}")]
    TldExtractError(#[from] TldExtractError),

    #[error("Tld Convert Error: {0}")]
    TldConvertError(#[from] TldConvertError),
}

#[instrument(skip(whois))]
pub(crate) async fn whois_command(
    whois: &WhoisClient,
    tld_extractor: &TldExtractor,
    command: WhoIsCommand,
) -> Result<(), WhoisCommandError> {
    let website: Url = command.website.parse().unwrap();

    let whois_info = whois
        .get_info(
            &tld_extractor
                .extract(website.domain().unwrap())?
                .as_root()?,
        )
        .await?;

    println!("Domain: {}\nWhois Data: {:?}", website.as_str(), whois_info);

    Ok(())
}
