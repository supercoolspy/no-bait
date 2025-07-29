use std::fmt::Display;
use std::sync::Arc;
use std::error::Error as StdError;
use crate::collectors::rdap::{RDAPClient, RDAPError};
use crate::collectors::safebrowsing::{SafebrowsingClient, SafebrowsingError};
use crate::collectors::sslmate::{SslMateClient, SslMateError};
use crate::collectors::whois::{WhoIsError, WhoisClient};
use crate::collectors::{DomainInfoClient, TldUrl};
use crate::database::{
    add_domain, check_exists, update_domain, DBState, DatabaseError, DetectedDomainWithId, Domain,
    DomainInfo, DomainWithId,
};
use futures::stream::iter;
use futures::StreamExt;
use icann_rdap_client::RdapClientError;
use libsql::Connection;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tldextract::TldExtractor;
use tracing::{debug, error, instrument, trace, warn};
use url::Url;

type ConvertErrorWithUrl = (Url, ConverterError);

#[derive(Debug, Error)]
pub enum ConverterError {
    #[error("Whois Error: {0}")]
    Whois(#[from] WhoIsError),

    #[error("RDAP Error: {0}")]
    Rdap(#[from] RDAPError),

    #[error("Google Safebrowsing Error: {0}")]
    GSB(#[from] SafebrowsingError),

    #[error("Database Error: {0}")]
    Database(#[from] DatabaseError),
}

#[instrument(skip_all, fields(domains_len=domains.len()))]
async fn check_domains_exist(
    conn: &Connection,
    domains: Vec<DetectedDomainWithId>,
) -> (Vec<DetectedDomainWithId>, Vec<DetectedDomainWithId>) {
    let mut add = Vec::new();
    let mut modify = Vec::new();

    // Convert the pending domains into actual domain entries
    let results = iter(domains)
        .map(|d| async move {
            trace!(domain=?d, "Checking if exists");
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
            trace!(domain=?d, "Exists");
            modify.push(d);
        } else {
            trace!(domain=?d, "Doesn't exists");
            add.push(d);
        }
    }

    (add, modify)
}

/// Gets whois/rdap info for a set of domains with id, and returns an Iterator over them
#[instrument(skip_all, fields(domains_len=domains.len()))]
async fn get_info_for_domains(
    domains: Vec<DetectedDomainWithId>,
    domain_info_processor: &Vec<Arc<dyn DomainInfoClient>>,
    tld_extractor: &TldExtractor,
    gsb_client: &Option<SafebrowsingClient>,
) -> impl Iterator<Item = DomainWithId> {
    // Add whois/rdap info to domains that aren't already in the database
    let domains_to_add = iter(domains.into_iter())
        .map(|domain| async move {
            let url = domain.domain.url;

            // Handle TLD extraction without using the ? operator
            let extract_result = tld_extractor.extract(url.as_str());
            if let Err(err) = extract_result {
                error!("TLD extraction error for {}: {}", url, err);
                return Err((url, ConverterError::Database(DatabaseError::NoRow)));
            }

            let tld_extract = extract_result.unwrap();

            // Handle root domain extraction without using the ? operator
            let root_result = tld_extract.as_root();
            if let Err(err) = root_result {
                error!("Root domain extraction error for {}: {}", url, err);
                return Err((url, ConverterError::Database(DatabaseError::NoRow)));
            }

            let root = root_result.unwrap();
            let mut domain_info = DomainInfo::None;

            for (index, next) in domain_info_processor.iter().enumerate() {
                if next.rate_limited() {
                    trace!("Skipping {}, ratelimited", index);
                    continue
                }

                let res = next.get_info(&root).await;

                if let Ok(info) = res {
                    trace!(url=?url, "Got domain info {:?}", info);
                    domain_info = info;
                    break
                }

                let err = res.expect_err("Should be error or breaked");

                error!("Failed to get domain info from collector: {}", err);
            }

            let domain_res = Ok(DomainWithId {
                domain: Domain {
                    url,
                    whois_info: domain_info,
                    cert_info: None,
                    collectors: vec![domain.domain.collector_info],
                },
                row_id: domain.row_id,
            });

            if let Some(gsb_client) = gsb_client {
                if let Ok(mut domain_with_id) = domain_res {
                    let gsb_detection = gsb_client
                        .get_url_batch_threat(domain_with_id.domain.url.to_string())
                        .await
                        .map_err(|e| {
                            (domain_with_id.domain.url.clone(), ConverterError::from(e))
                        })?;

                    domain_with_id.domain.collectors.push(gsb_detection);

                    Ok(domain_with_id)
                } else {
                    domain_res
                }
            } else {
                domain_res
            }
        })
        .buffer_unordered(10)
        .filter_map(
            |result: Result<DomainWithId, ConvertErrorWithUrl>| async move {
                trace!(result=?result, "Checking result of domain");
                match result {
                    Ok(domain) => Some(domain),
                    Err((url, err)) => {
                        error!(url=?url, "Failed to get domain info for domain: {}", err);
                        None
                    }
                }
            },
        )
        .collect::<Vec<_>>()
        .await;

    domains_to_add.into_iter()
}

/// Takes in a list of domains, attempts to add them to the database.
/// If the row already exists this modifies the existing row.
/// Returns Vec of Results for the addition to the database with the i64 representing the rowId, if successful
#[instrument(skip_all)]
async fn add_domains_to_db(
    conn: &Connection,
    domains: impl Iterator<Item = DomainWithId>,
) -> Vec<Result<i64, ConvertErrorWithUrl>> {
    iter(domains)
        .map(|domain| async move {
            trace!(domain=?domain, "Adding domain to db");
            let cloned_url = domain.domain.url.clone();

            let add_res = add_domain(conn, domain.domain.clone()).await;

            if add_res.is_err() {
                let err = add_res.err().unwrap();

                match err {
                    DatabaseError::RowAlreadyExists => {
                        warn!(domain=?domain, "Row already exists even though in new vec");
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

            trace!(row_id = domain.row_id, "Successfully added domain to db");
            Ok::<i64, ConvertErrorWithUrl>(domain.row_id)
        })
        .buffer_unordered(10) // Process up to 10 concurrently
        .collect::<Vec<Result<i64, ConvertErrorWithUrl>>>()
        .await
}

#[instrument(skip_all)]
pub async fn add_certs(
    ssl_mate_client: &SslMateClient,
    tld_extractor: &TldExtractor,
    domains: impl Iterator<Item = DomainWithId>,
) -> impl Iterator<Item = DomainWithId> {
    let rate_limited = &AtomicBool::new(false);

    iter(domains)
        .map(|mut domain_with_id| async move {
            if domain_with_id.domain.cert_info.is_some() || rate_limited.load(Ordering::Relaxed) {
                return domain_with_id
            }

            if let Some(domain) = domain_with_id.domain.url.domain() {
                let extract_res = tld_extractor.extract(domain);

                if let Err(err) = extract_res {
                    error!("Failed to extract domain: {}", err);

                    return domain_with_id;
                }

                let res = ssl_mate_client.get_certs(domain, extract_res.unwrap()).await;

                if let Ok(response) = res {
                    domain_with_id.domain.cert_info = Some(response)
                } else {
                    let err = res.expect_err("Checked if error");

                    if matches!(err, SslMateError::RateLimited) {
                        // Stop requesting certs if we get ratelimited
                        rate_limited.store(true, Ordering::Relaxed)
                    } else {
                        error!(url=?domain_with_id.domain.url, "Failed to get domain info for domain: {}", err);
                    }
                }


            }

            domain_with_id
        })
        .buffer_unordered(10)
        .collect::<Vec<DomainWithId>>()
        .await
        .into_iter()
}

/// Processes a batch of domains into the database and returns the rowIds of the domains to delete.
/// If adding a domain to the database fails for any reason, the rowId will not be returned.
/// <u>**Only**</u> rowIds that are returned from this function should be removed from the database.
#[instrument(skip(domain_info_processor, tld_extractor, gsb_client, ssl_mate_client, domains), fields(domains_len=domains.len()))]
pub async fn convert_domains(
    db_state: &DBState,
    tld_extractor: &TldExtractor,
    domain_info_processor: &Vec<Arc<dyn DomainInfoClient>>,
    ssl_mate_client: &SslMateClient,
    gsb_client: &Option<SafebrowsingClient>,
    domains: Vec<DetectedDomainWithId>,
) -> Vec<i64> {
    let conn = db_state.get_connection();

    let (add, modify) = check_domains_exist(conn, domains).await;
    let add_len = add.len();
    let mod_len = modify.len();
    debug!(
        "Found {} domains to add and {} to modify with a total of {}",
        add_len,
        mod_len,
        add_len + mod_len
    );

    let domains_add = get_info_for_domains(add, domain_info_processor, tld_extractor, gsb_client).await;

    let domains_add = add_certs(ssl_mate_client, tld_extractor, domains_add).await;

    // Attempt to add new domains to the db
    let add_domain_results = add_domains_to_db(conn, domains_add).await;

    debug!("Got to rows to delete");

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
            let res = update_domain(conn, domain.domain).await;

            if res.is_err() {
                error!(
                    row_id = domain.row_id,
                    "Failed to modify domain: {}",
                    res.err().unwrap()
                );

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

    debug!("{} Rows to delete", rows_to_delete.len());

    rows_to_delete
}

#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;
    use crate::collectors::safebrowsing::SafebrowsingClient;
    use crate::collectors::DomainInfoClient;
    use crate::database::{DetectedDomainWithId, DomainWithId};
    use tldextract::TldExtractor;

    pub(crate) async fn get_info_for_domains(
        domains: Vec<DetectedDomainWithId>,
        tld_extractor: &TldExtractor,
        domain_info_processor: &Vec<Arc<dyn DomainInfoClient>>,
        gsb_client: &Option<SafebrowsingClient>,
    ) -> impl Iterator<Item = DomainWithId> {
        super::get_info_for_domains(domains, domain_info_processor, tld_extractor, gsb_client).await
    }
}


