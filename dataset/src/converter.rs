use crate::collectors::rdap::{RDAPError, get_rdap_data};
use crate::collectors::whois::{WhoIsError, get_whois_domain};
use crate::database::{
    DBState, DatabaseError, DetectedDomainWithId, Domain, DomainInfo, DomainWithId, add_domain,
    check_exists, update_domain,
};
use futures::StreamExt;
use futures::stream::iter;
use icann_rdap_client::iana::BootstrapStore;
use libsql::Connection;
use log::error;
use rayon::prelude::*;
use thiserror::Error;
use url::Url;
use whois_rust::WhoIs;

type ConvertErrorWithUrl = (Url, ConverterError);

#[derive(Debug, Error)]
pub enum ConverterError {
    #[error("Whois Error: {0}")]
    Whois(#[from] WhoIsError),

    #[error("RDAP Error: {0}")]
    Rdap(#[from] RDAPError),

    #[error("Database Error: {0}")]
    Database(#[from] DatabaseError),
}

async fn check_domains_exist(
    conn: &Connection,
    domains: Vec<DetectedDomainWithId>,
) -> Result<(Vec<DetectedDomainWithId>, Vec<DetectedDomainWithId>), ConverterError> {
    let mut add = Vec::new();
    let mut modify = Vec::new();

    // Convert the pending domains into actual domain entries
    let results = iter(domains)
        .map(|d| async move {
            let exists_res = check_exists(conn, &d.domain.url).await;

            if exists_res.is_err() {
                error!(
                    "Failed to get whether {} exists: {}",
                    d.domain.url,
                    exists_res.err().unwrap()
                );
                return None;
            }

            Some((exists_res.unwrap(), d))
        })
        .buffer_unordered(10) // Process up to 10 concurrently
        .collect::<Vec<_>>()
        .await;

    // Process the results to populate add and modify vectors
    for result in results.into_iter().flatten() {
        // result is already of type (bool, DetectedDomainWithId) after flattening
        let (row, d) = result;
        // May be good in future to use the row, although it could be updated by the time we process it
        if row.is_some() {
            modify.push(d);
        } else {
            add.push(d);
        }
    }

    Ok((add, modify))
}

/// Gets whois/rdap info for a set of domains with id, and returns an Iterator over them
async fn get_info_for_domains(
    domains: Vec<DetectedDomainWithId>,
    whois_client: &WhoIs,
    rdap_client: icann_rdap_client::http::Client,
    store: impl BootstrapStore,
) -> Result<impl Iterator<Item = DomainWithId>, ConverterError> {
    let rdap_client = &rdap_client;
    let store = &store;

    // Add whois/rdap info to domains that aren't already in the database
    let domains_to_add = iter(domains.into_iter())
        .map(|domain| async move {
            let url = domain.domain.url;
            let res = get_whois_domain(whois_client, url.clone()).await;

            // If rdap (and its google tlds) won't have whois info
            if res.is_err() {
                if let Err(WhoIsError::NoWhois) = res {
                    // Get rdap info for domain
                    let rdap = get_rdap_data(rdap_client, store, url.clone())
                        .await
                        .map_err(|e| (url.clone(), ConverterError::from(e)))?;

                    Ok(DomainWithId {
                        domain: Domain {
                            url,
                            whois_info: DomainInfo::RDAPInfo(rdap.to_string()),
                            collectors: vec![domain.domain.collector_info],
                        },
                        row_id: domain.row_id,
                    })
                } else {
                    Err((url.clone(), ConverterError::Whois(res.err().unwrap())))
                }
            } else {
                // We already checked if it was an error
                let whois = res.unwrap();

                Ok::<DomainWithId, (Url, ConverterError)>(DomainWithId {
                    domain: Domain {
                        url,
                        whois_info: DomainInfo::WhoisInfo(whois.whois_data),
                        collectors: vec![domain.domain.collector_info],
                    },
                    row_id: domain.row_id,
                })
            }
        })
        .buffer_unordered(10)
        .filter_map(
            |result: Result<DomainWithId, ConvertErrorWithUrl>| async move {
                match result {
                    Ok(domain) => Some(domain),
                    Err((url, err)) => {
                        error!("Failed to get domain info for domain {}: {}", url, err);
                        None
                    }
                }
            },
        )
        .collect::<Vec<_>>()
        .await;

    Ok(domains_to_add.into_iter())
}

/// Takes in a list of domains, attempts to add them to the database.
/// If the row already exists this modifies the existing row.
/// Returns Vec of Results for the addition to the database with the i64 representing the rowId, if successful
async fn add_domains_to_db(
    conn: &Connection,
    domains: impl Iterator<Item = DomainWithId>,
) -> Vec<Result<i64, ConvertErrorWithUrl>> {
    iter(domains)
        .map(|domain| async move {
            let cloned_url = domain.domain.url.clone();

            let add_res = add_domain(conn, domain.domain.clone()).await;

            if add_res.is_err() {
                let err = add_res.err().unwrap();

                match err {
                    DatabaseError::RowAlreadyExists => {
                        update_domain(
                            conn,
                            domain
                                .domain
                                .try_into()
                                .map_err(|e| (cloned_url.clone(), ConverterError::from(e)))?,
                        )
                        .await
                        .map_err(|e| (cloned_url.clone(), ConverterError::from(e)))?;
                    }
                    _ => return Err((cloned_url, ConverterError::from(err))),
                }
            }

            Ok::<i64, ConvertErrorWithUrl>(domain.row_id)
        })
        .buffer_unordered(10) // Process up to 10 concurrently
        .collect::<Vec<Result<i64, ConvertErrorWithUrl>>>()
        .await
}

/// Processes a batch of domains into the database and returns the rowIds of the domains to delete.
/// If adding a domain to the database fails for any reason, the rowId will not be returned.
/// <u>**Only**</u> rowIds that are returned from this function should be removed from the database.
pub async fn convert_domains_from_memory(
    db_state: DBState,
    whois_client: &WhoIs,
    rdap_client: icann_rdap_client::http::Client,
    store: impl BootstrapStore,
    domains: Vec<DetectedDomainWithId>,
) -> Result<Vec<i64>, ConverterError> {
    let conn = db_state.get_connection();

    let (add, modify) = check_domains_exist(conn, domains).await?;

    // Attempt to add new domains to the db
    let add_domain_results = add_domains_to_db(
        conn,
        get_info_for_domains(add, whois_client, rdap_client, store).await?,
    )
    .await;

    let mut rows_to_delete = add_domain_results
        .into_par_iter()
        .filter_map(|res| {
            if res.is_err() {
                let err = res.err().unwrap();
                error!("Failed to add domain {} to database: {}", err.0, err.1);
                None
            } else {
                res.ok()
            }
        })
        .collect::<Vec<i64>>();

    let mut modified_rows_to_delete = iter(modify.into_iter())
        .map(|domain| async move {
            let url = domain.domain.url.clone();

            let res = update_domain(conn, domain.domain).await;

            if res.is_err() {
                error!("Failed to modify domain {}: {}", url, res.err().unwrap());

                None
            } else {
                Some(domain.row_id)
            }
        })
        .buffer_unordered(10)
        .collect::<Vec<Option<i64>>>()
        .await
        .into_par_iter()
        .flatten()
        .collect::<Vec<i64>>();

    rows_to_delete.append(&mut modified_rows_to_delete);
    drop(modified_rows_to_delete);

    Ok(rows_to_delete)
}
