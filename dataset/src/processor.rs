use crate::collectors::rdap::RDAPClient;
use crate::collectors::safebrowsing::SafebrowsingClient;
use crate::collectors::whois::WhoisClient;
use crate::converter::convert_domains;
use crate::database::{
    DBState, DatabaseError, get_amount_pending_db, get_pending_domains, remove_pending_domains,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use tracing::{debug, error, info};

pub(crate) async fn wait_until_finished(db_state: &DBState) -> Result<(), DatabaseError> {
    let pending_memory = db_state.get_pending_count().await;

    if pending_memory > 0 {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Box::pin(wait_until_finished(db_state)).await?;
    };

    let pending_from_db = get_amount_pending_db(db_state.get_connection()).await?;

    if pending_from_db > 0 {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Box::pin(wait_until_finished(db_state)).await?;
    }

    Ok(())
}

pub(super) fn create_processor(
    db_state: Arc<DBState>,
    whois: Arc<WhoisClient>,
    rdap_client: Arc<RDAPClient>,
    gsb_client: Arc<Option<SafebrowsingClient>>,
    mut channel_receiver: Receiver<usize>,
) {
    tokio::spawn(async move {
        loop {
            if let Ok(amount_op) = timeout(Duration::from_secs(10), channel_receiver.recv()).await {
                if amount_op.is_none() {
                    continue;
                }

                let amount = amount_op.unwrap();

                error!("Processing {} domains", amount);
                process_domains(&db_state, &whois, &rdap_client, &gsb_client, amount).await
            } else {
                // Timeout hit, check from db
                let amount = 1000;

                error!("Processing {} domains", amount);
                process_domains(&db_state, &whois, &rdap_client, &gsb_client, amount).await;
            };
        }
    });
}

async fn process_domains(
    db_state: &DBState,
    whois: &WhoisClient,
    rdap_client: &RDAPClient,
    gsb_client: &Option<SafebrowsingClient>,
    amount: usize,
) {
    let pending_res = get_pending_domains(db_state, amount as u64).await;

    if pending_res.is_err() {
        error!(
            "Failed to get {} pending domains: {}",
            amount,
            pending_res.err().unwrap()
        );
        return;
    }

    let pending = pending_res.unwrap();

    if pending.is_empty() {
        debug!("Empty pending domain list, returning");
        return;
    }

    info!("Got {} pending domains", pending.len());

    let rows_to_delete = convert_domains(db_state, whois, rdap_client, &gsb_client, pending).await;

    let remove_res = remove_pending_domains(db_state.get_connection(), rows_to_delete).await;
    if remove_res.is_err() {
        error!(
            "Failed to delete domains from pending table: {}",
            remove_res.err().unwrap()
        );
        return;
    }
}
