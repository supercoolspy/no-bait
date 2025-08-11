use crate::collectors::safebrowsing::{SafebrowsingClient, SafebrowsingError};
use crate::collectors::{CollectorSpecificInfo, DetectedDomain};
use crate::database::{CollectorColumn, DBState, DatabaseError, row_to_collectors, update_domain};
use clap::Subcommand;
use futures::{StreamExt, TryStreamExt};
use libsql::{Row, params};
use std::collections::HashMap;
use std::str::Utf8Error;
use std::sync::Arc;
use safebrowsing_url::{canonicalize_url, UrlError};
use thiserror::Error;
use tracing::{Instrument, error, info, info_span, instrument};
use url::{ParseError, Url};

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

    #[error("Safebrowsing URL Error: {0}")]
    Url(#[from] UrlError),
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
            let mut amount_query = db_state
                .get_connection()
                .query(
                    "SELECT COUNT(*) FROM domains WHERE collector_info NOT LIKE '%GoogleSafeBrowsing%'",
                    params!()
                )
                .await?;

            if let Ok(Some(amount)) = amount_query.next().await {
                for _ in 1..((amount.get::<u64>(0)? % 500) + 1) {
                    get_gsb_category(&gsb, &db_state).await?
                }
            }


        }
    }

    Ok(())
}

async fn get_gsb_category(
    gsb: &SafebrowsingClient,
    db_state: &DBState
) -> Result<(), SafebrowsingCommandError> {
    let mut row_query = db_state
        .get_connection()
        .query(
            "SELECT * FROM domains WHERE collector_info NOT LIKE '%GoogleSafeBrowsing%' LIMIT 500;",
            params!()
        )
        .await?;

    let mut url_map: HashMap<String, String> = HashMap::with_capacity(500);

    while let Ok(Some(row)) = row_query.next().await {
        let unformatted_url: Url = row.get_str(0)?.parse()?;

        let formatted_url = canonicalize_url(unformatted_url.as_str())?.url;

        let collector_info = row_to_collectors(&row)?;

        if collector_info.iter().any(|info| {
            matches!(
                        &info.collector_specific_info,
                        &CollectorSpecificInfo::GoogleSafeBrowsing { .. }
                    )
        }) {
            continue;
        }

        url_map.insert(formatted_url.clone(), unformatted_url.to_string());
    }

    let threats = gsb
        .get_url_batch_threat(url_map.keys().map(|entry| entry.to_string()).collect())
        .await?;

    for (url, info) in threats.into_iter() {
        if url_map.contains_key(&url) {
            update_domain(
                db_state.get_connection(),
                DetectedDomain {
                    url: url_map
                        .remove(&url)
                        .expect("If in map should be able to get key")
                        .parse()?,
                    collector_info: info,
                },
            )
                .await?;
        }
    }

    Ok(())
}
