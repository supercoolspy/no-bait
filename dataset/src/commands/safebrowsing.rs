use crate::collectors::safebrowsing::{SafebrowsingClient, SafebrowsingError};
use clap::{Args, Subcommand};
use tracing::{Instrument, info_span, instrument};

#[derive(Args, Debug, Clone)]
pub(crate) struct SafebrowsingCommand {
    website: String,
}

#[instrument(skip(gsb))]
pub(crate) async fn safebrowsing_command(
    gsb: SafebrowsingClient,
    command: SafebrowsingCommand,
) -> Result<(), SafebrowsingError> {
    let results = gsb
        .get_url_threat(command.website)
        .instrument(info_span!("gsb_get"))
        .await?;

    if !results.phishing {
        println!("URL is safe")
    } else {
        println!("URL is not safe")
    }

    Ok(())
}
