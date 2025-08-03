use crate::collectors::legitphish::LegitPhishClient;
use crate::collectors::{CsvCollector, ToDetectedDomain};
use crate::database::{DBState, add_pending_domains};
use crate::processor::wait_until_finished;
use clap::Args;
use reqwest_middleware::ClientWithMiddleware;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tracing::instrument;

#[derive(Args, Debug, Clone)]
pub(crate) struct LegitPhishCommand {
    #[arg(short, long, default_value_t = false)]
    local: bool,
}

#[instrument(skip(client))]
pub(crate) async fn legit_phish_command(
    client: Arc<ClientWithMiddleware>,
    db_state: &DBState,
    shutdown: Arc<AtomicBool>,
    command: LegitPhishCommand,
    no_analysis: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let legit_phish_client = LegitPhishClient::new(client);

    let dataset = if command.local {
        legit_phish_client.get_local().await?
    } else {
        legit_phish_client.download_dataset().await?
    };

    if !no_analysis {
        add_pending_domains(db_state, dataset.to_detected_domains()?).await?;
        wait_until_finished(shutdown, db_state).await?;
    }

    Ok(())
}
