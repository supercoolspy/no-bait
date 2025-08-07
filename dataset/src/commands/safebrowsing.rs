use crate::collectors::safebrowsing::{SafebrowsingClient, SafebrowsingError};
use crate::collectors::{CollectorSpecificInfo, DetectedDomain};
use crate::database::{CollectorColumn, DBState, DatabaseError, row_to_collectors, update_domain};
use clap::Subcommand;
use futures::TryStreamExt;
use libsql::{Row, params};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{Instrument, error, info_span, instrument};
use url::ParseError;

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum SafebrowsingCommand {
    Lookup { website: String },
    AddToAll,
}

#[derive(Error, Debug)]
pub enum SafebrowsingCommandError {
    #[error("Database (Cache) Error: {0}")]
    Database(#[from] DatabaseError),

    #[error("LibSQL Error: {0}")]
    LibSQL(#[from] libsql::Error),

    #[error("Safe browsing error: {0}")]
    Safebrowsing(#[from] SafebrowsingError),

    #[error("Url Parsing error: {0}")]
    UrlParse(#[from] ParseError),
}

#[instrument(skip(gsb))]
pub(crate) async fn safebrowsing_command(
    gsb: SafebrowsingClient,
    db_state: Arc<DBState>,
    command: SafebrowsingCommand,
) -> Result<(), SafebrowsingCommandError> {
    match command {
        SafebrowsingCommand::Lookup { website } => {
            let results = gsb
                .get_url_threat(website)
                .instrument(info_span!("gsb_get"))
                .await?;

            if !results.phishing {
                println!("URL is safe")
            } else {
                println!("URL is not safe")
            }
        }
        SafebrowsingCommand::AddToAll => {
            let rows: Vec<Row> = db_state
                .get_connection()
                .query(
                    "SELECT * FROM domains WHERE collector_info NOT LIKE '%GoogleSafeBrowsing%' LIMIT 500;",
                    params!()
                )
                .await?
                .into_stream()
                .try_collect()
                .await?;

            let mut url_info: HashMap<String, CollectorColumn> = HashMap::with_capacity(rows.len());

            error!("{:?}", rows);
            for row in rows {
                error!("{:?}", row);

                let url = row.get_str(0)?.to_string();

                let collector_info = row_to_collectors(&row)?;

                if collector_info.iter().any(|info| {
                    matches!(
                        &info.collector_specific_info,
                        &CollectorSpecificInfo::GoogleSafeBrowsing { .. }
                    )
                }) {
                    continue;
                }

                url_info.insert(url, collector_info);
            }

            let threats = gsb
                .get_url_batch_threat(url_info.keys().map(|entry| entry.to_string()).collect())
                .await?;

            for (url, info) in threats.into_iter() {
                if url_info.contains_key(&url) {
                    update_domain(
                        db_state.get_connection(),
                        DetectedDomain {
                            url: url.parse()?,
                            collector_info: info,
                        },
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}
