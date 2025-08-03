use crate::collectors::mendeley_kb::MendeleyKBClient;
use crate::collectors::{CsvCollector, ToDetectedDomain};
use crate::database::{DBState, add_pending_domains};
use crate::processor::wait_until_finished;
use clap::Args;
use reqwest_middleware::ClientWithMiddleware;
use std::error::Error;
use std::sync::Arc;
use tracing::instrument;
use crate::ProcessorInfo;

#[derive(Args, Debug, Clone)]
pub(crate) struct MendeleyKBCommand {
    #[arg(short, long, default_value_t = false)]
    local: bool,
}

#[instrument(skip(client, processor_info))]
pub(crate) async fn mendeley_k_b_command(
    client: Arc<ClientWithMiddleware>,
    db_state: &DBState,
    processor_info: ProcessorInfo,
    command: MendeleyKBCommand,
    no_analysis: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mendeley_k_b_client = MendeleyKBClient::new(client);

    let dataset = if command.local {
        mendeley_k_b_client.get_local().await?
    } else {
        mendeley_k_b_client.download_dataset().await?
    };

    if !no_analysis {
        add_pending_domains(db_state, dataset.to_detected_domains()?).await?;
        wait_until_finished(processor_info, db_state).await?;
    }

    Ok(())
}
