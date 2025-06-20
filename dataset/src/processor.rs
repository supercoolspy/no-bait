use crate::converter::convert_domains;
use crate::database::{DBState, get_pending_domains, remove_pending_domains};
use icann_rdap_client::iana::{BootstrapStore, MemoryBootstrapStore};
use log::{debug, error};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use whois_rust::WhoIs;

pub(super) fn create_processor(
    db_state: Arc<DBState>,
    whois: Arc<WhoIs>,
    rdap_client: Arc<icann_rdap_client::http::Client>,
    boostrap: Arc<MemoryBootstrapStore>,
    use_gsb: Arc<bool>,
    mut channel_receiver: Receiver<usize>,
) {
    thread::spawn(|| async move {
        loop {
            if let Ok(amount_op) = timeout(Duration::from_secs(10), channel_receiver.recv()).await {
                if amount_op.is_none() {
                    continue;
                }

                let amount = amount_op.unwrap();

                debug!("Processing {} domains", amount);
                process_domains(&db_state, &whois, &rdap_client, &boostrap, &use_gsb, amount).await
            } else {
                // Timeout hit, check from db
                let amount = 1000;

                debug!("Processing {} domains", amount);
                process_domains(&db_state, &whois, &rdap_client, &boostrap, &use_gsb, amount).await;
            };
        }
    });
}

async fn process_domains(
    db_state: &DBState,
    whois: &WhoIs,
    rdap_client: &icann_rdap_client::http::Client,
    boostrap: &MemoryBootstrapStore,
    use_gsb: &bool,
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

    let rows_to_delete = convert_domains(db_state, whois, rdap_client, boostrap, pending).await;

    let remove_res = remove_pending_domains(db_state.get_connection(), rows_to_delete).await;
    if remove_res.is_err() {
        error!(
            "Failed to delete domains from pending table: {}",
            remove_res.err().unwrap()
        );
        return;
    }
}
