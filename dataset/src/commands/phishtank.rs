use crate::collectors::ToDetectedDomain;
use crate::collectors::phishtank::{PhishTankError, get_data_local, get_latest_data};
use crate::database::{DBState, add_pending_domains};
use crate::processor::wait_until_finished;
use clap::Args;
use reqwest_middleware::ClientWithMiddleware;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tracing::instrument;

#[derive(Args, Debug, Clone)]
pub(crate) struct PhishTankCommand {
    #[arg(short, long, default_value_t = false)]
    local: bool,
}

#[instrument(skip(client))]
pub(crate) async fn phishtank_command(
    client: &ClientWithMiddleware,
    db_state: &DBState,
    shutdown: Arc<AtomicBool>,
    command: PhishTankCommand,
    no_analysis: bool,
) -> Result<(), PhishTankError> {
    let dataset = if command.local {
        get_data_local().await?
    } else {
        get_latest_data(client, env!("CARGO_PKG_NAME").to_owned()).await?
    };

    if !no_analysis {
        add_pending_domains(db_state, dataset.to_detected_domains()?).await?;
        wait_until_finished(shutdown, db_state).await?;
    }

    Ok(())
}
