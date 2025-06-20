use crate::collectors::ToDetectedDomain;
use crate::collectors::phishstorm::{PhishStormError, download_phishstorm_dataset, get_data_local};
use crate::database::{DBState, add_pending_domains};
use clap::Args;
use reqwest_middleware::ClientWithMiddleware;

#[derive(Args, Debug)]
pub(crate) struct PhishStormCommand {
    #[arg(short, long, default_value_t = false)]
    local: bool,
}

pub(crate) async fn phishstorm_command(
    client: &ClientWithMiddleware,
    db_state: &DBState,
    command: PhishStormCommand,
    no_analysis: bool,
) -> Result<(), PhishStormError> {
    let dataset = if command.local {
        get_data_local().await?
    } else {
        download_phishstorm_dataset(client).await?
    };

    if !no_analysis {
        add_pending_domains(db_state, dataset.to_detected_domains()?).await?;
    }

    Ok(())
}
