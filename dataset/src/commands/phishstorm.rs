use clap::Args;
use log::info;
use reqwest_middleware::ClientWithMiddleware;
use whois_rust::WhoIs;

use crate::collectors::phishstorm::{PhishStormError, download_phishstorm_dataset, get_data_local};

#[derive(Args, Debug)]
pub(crate) struct PhishStormCommand {
    #[arg(short, long, default_value_t = false)]
    local: bool,
    #[arg(short, long, default_value_t = false)]
    no_analysis: bool,
}

pub(crate) async fn phishstorm_command(
    client: &ClientWithMiddleware,
    whois: WhoIs,
    command: PhishStormCommand,
) -> Result<(), PhishStormError> {
    let dataset = if command.local {
        get_data_local().await?
    } else {
        download_phishstorm_dataset(client).await?
    };

    dataset
        .iter()
        .filter(|d| d.label == 1.0)
        .map(|d| &d.domain)
        .for_each(|d| info!("{}", d));

    // TODO: Analyze data

    Ok(())
}
