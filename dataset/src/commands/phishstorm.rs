use clap::Args;
use libsql::Connection;
use log::info;
use reqwest_middleware::ClientWithMiddleware;
use whois_rust::WhoIs;

use crate::collectors::phishstorm::{PhishStormError, download_phishstorm_dataset, get_data_local, PhishStormDataset};
use crate::collectors::{DetectedDomain, ToDetectedDomain};
use crate::database::add_pending_domains;

#[derive(Args, Debug)]
pub(crate) struct PhishStormCommand {
    #[arg(short, long, default_value_t = false)]
    local: bool,
}

pub(crate) async fn phishstorm_command(
    client: &ClientWithMiddleware,
    conn: Connection,
    command: PhishStormCommand,
    no_analysis: bool,
) -> Result<(), PhishStormError> {
    let dataset = if command.local {
        get_data_local().await?
    } else {
        download_phishstorm_dataset(client).await?
    };

    if !no_analysis {
        add_pending_domains(&conn, dataset.to_detected_domains()?).await?;
    }

    Ok(())
}
