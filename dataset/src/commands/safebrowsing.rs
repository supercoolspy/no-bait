use crate::collectors::safebrowsing::{SafebrowsingClient, SafebrowsingError};
use clap::Args;
use tracing::{Instrument, info_span, instrument};

#[derive(Args, Debug)]
pub(crate) struct SafebrowsingCommand {
    website: String,
}

#[instrument(skip(gsb))]
pub(crate) async fn safebrowsing_command(
    gsb: SafebrowsingClient,
    command: SafebrowsingCommand,
) -> Result<(), SafebrowsingError> {
    let results = gsb
        .get_url_batch_threat(vec![command.website])
        .instrument(info_span!("gsb_get"))
        .await?;

    if results.is_empty() {
        println!("URL is safe")
    } else {
        println!("URL is not safe")
    }

    Ok(())
}
