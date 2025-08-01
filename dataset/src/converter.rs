use crate::collectors::rdap::RDAPError;
use crate::collectors::safebrowsing::{SafebrowsingClient, SafebrowsingError};
use crate::collectors::sslmate::{SslMateClient, SslMateError};
use crate::collectors::whois::WhoIsError;
use crate::collectors::{DomainInfoClient, ErrorImportance, TldUrl};
use crate::database::{
    DBState, DatabaseError, DetectedDomainWithId, Domain, DomainInfo, DomainWithId, add_domain,
    check_exists, update_domain,
};
use arc_swap::ArcSwap;
use futures::stream::iter;
use futures::{Stream, StreamExt};
use libsql::Connection;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tldextract::TldExtractor;
use tracing::{debug, error, instrument, trace, warn};

#[derive(Debug, Error)]
pub enum ConverterError {
    #[error("Whois Error: {0}")]
    Whois(#[from] WhoIsError),

    #[error("RDAP Error: {0}")]
    Rdap(#[from] RDAPError),

    #[error("Google Safebrowsing Error: {0}")]
    Gsb(#[from] SafebrowsingError),

    #[error("Database Error: {0}")]
    Database(#[from] DatabaseError),
}

#[instrument(skip_all, fields(domains_len=domains.len()))]
fn check_domains_exist(
    conn: &Connection,
    domains: Vec<DetectedDomainWithId>,
) -> impl Stream<Item = (bool, DetectedDomainWithId)> + '_ {
    // Convert the pending domains into actual domain entries
    iter(domains).filter_map(move |d| async move {
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

        Some((exists_res.unwrap().is_some(), d))
    })
}

/// Gets whois/rdap info for a set of domains with id, and returns an Iterator over them
#[instrument(skip_all)]
async fn get_info_for_domain(
    domain: DetectedDomainWithId,
    domain_info_processor: &ArcSwap<Vec<Arc<dyn DomainInfoClient>>>,
    tld_extractor: &TldExtractor,
    gsb_client: &Option<SafebrowsingClient>,
) -> Result<DomainWithId, ConverterError> {
    let url = domain.domain.url;

    // Handle TLD extraction without using the ? operator
    let extract_result = tld_extractor.extract(url.as_str());
    if let Err(err) = extract_result {
        error!("TLD extraction error for {}: {}", url, err);
        return Err(ConverterError::Database(DatabaseError::NoRow));
    }

    let tld_extract = extract_result.unwrap();

    // Handle root domain extraction without using the ? operator
    let root_result = tld_extract.as_root();
    if let Err(err) = root_result {
        error!("Root domain extraction error for {}: {}", url, err);
        return Err(ConverterError::Database(DatabaseError::NoRow));
    }

    let root = root_result.unwrap();
    let mut domain_info = DomainInfo::None;

    let domain_info_processor_value = domain_info_processor.load_full();

    for (index, next) in domain_info_processor_value.iter().enumerate() {
        let res = next.get_info(&root).await;

        if let Ok(info) = res {
            trace!(url=?url, "Got domain info {:?}", info);
            domain_info = info;
            break;
        }

        let err = res.expect_err("Should be error or breaked");

        match next.error_importance(err.as_ref()) {
            ErrorImportance::Ignore => {}
            ErrorImportance::Log => {
                error!("Failed to get domain info from collector: {}", err);
            }
            ErrorImportance::Stop => {
                let mut new_domain_info_processor_value =
                    domain_info_processor_value.as_ref().clone();
                new_domain_info_processor_value.remove(index);

                drop(domain_info_processor.compare_and_swap(
                    &domain_info_processor_value,
                    Arc::from(new_domain_info_processor_value),
                ));
            }
        }
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
        if gsb_client.rate_limited() {
            return domain_res;
        }

        if let Ok(mut domain_with_id) = domain_res {
            let gsb_detection_res = gsb_client
                .get_url_batch_threat(domain_with_id.domain.url.to_string())
                .await;

            if let Err(err) = gsb_detection_res {
                if matches!(err, SafebrowsingError::RateLimited) {
                    return Ok(domain_with_id);
                }

                return Err(err.into());
            }

            domain_with_id
                .domain
                .collectors
                .push(gsb_detection_res.unwrap());

            Ok(domain_with_id)
        } else {
            domain_res
        }
    } else {
        domain_res
    }
}

/// Takes in a list of domains, attempts to add them to the database.
/// If the row already exists this modifies the existing row.
/// Returns Vec of Results for the addition to the database with the i64 representing the rowId, if successful
#[instrument(skip_all)]
async fn add_domain_to_db(conn: &Connection, domain: DomainWithId) -> Result<i64, ConverterError> {
    trace!(domain=?domain, "Adding domain to db");

    let add_res = add_domain(conn, domain.domain.clone()).await;

    if add_res.is_err() {
        let err = add_res.err().unwrap();

        match err {
            DatabaseError::RowAlreadyExists => {
                warn!(domain=?domain, "Row already exists even though in new vec");
                update_domain(conn, domain.domain.try_into()?).await?;
            }
            _ => return Err(err.into()),
        }
    }

    trace!(row_id = domain.row_id, "Successfully added domain to db");

    Ok(domain.row_id)
}

#[instrument(skip_all)]
pub async fn add_certs(
    ssl_mate_client: &SslMateClient,
    tld_extractor: &TldExtractor,
    mut domain_with_id: DomainWithId,
) -> DomainWithId {
    let rate_limited = &AtomicBool::new(false);

    if domain_with_id.domain.cert_info.is_some() || rate_limited.load(Ordering::Acquire) {
        return domain_with_id;
    }

    if let Some(domain) = domain_with_id.domain.url.domain() {
        let extract_res = tld_extractor.extract(domain);

        if let Err(err) = extract_res {
            error!("Failed to extract domain: {}", err);

            return domain_with_id;
        }

        let res = ssl_mate_client
            .get_certs(domain, extract_res.unwrap())
            .await;

        if let Ok(response) = res {
            domain_with_id.domain.cert_info = Some(response)
        } else {
            let err = res.expect_err("Checked if error");

            if matches!(err, SslMateError::RateLimited) {
                // Stop requesting certs if we get ratelimited
                rate_limited.store(true, Ordering::Release)
            } else {
                error!(url=?domain_with_id.domain.url, "Failed to get domain info for domain: {}", err);
            }
        }
    }

    domain_with_id
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

    let domain_info_processor = &ArcSwap::new(Arc::new(domain_info_processor.to_owned()));

    let rows_to_delete = check_domains_exist(conn, domains)
        .filter_map(|(exists, domain)| async move {
            if !exists {
                let url = domain.domain.url.clone();

                let domain_res =
                    get_info_for_domain(domain, domain_info_processor, tld_extractor, gsb_client)
                        .await;

                if let Some(err) = domain_res.as_ref().err() {
                    error!(url = url.as_str(), "Failed to get info: {}", err);
                    return None;
                }

                let domain = add_certs(ssl_mate_client, tld_extractor, domain_res.unwrap()).await;

                let id_res = add_domain_to_db(conn, domain).await;

                if let Ok(id) = id_res {
                    Some(id)
                } else {
                    let err = id_res.err().unwrap();

                    error!(url = url.as_str(), "Failed to add domain to db: {}", err);

                    None
                }
            } else {
                let res = update_domain(conn, domain.domain).await;

                if let Some(err) = res.err() {
                    error!(row_id = domain.row_id, "Failed to modify domain: {}", err);
                    return None;
                }

                Some(domain.row_id)
            }
        })
        .collect::<Vec<i64>>()
        .await;

    debug!("{} Rows to delete", rows_to_delete.len());

    rows_to_delete
}

#[cfg(test)]
pub mod test_support {
    use crate::collectors::DomainInfoClient;
    use crate::collectors::safebrowsing::SafebrowsingClient;
    use crate::converter::ConverterError;
    use crate::database::{DetectedDomainWithId, DomainWithId};
    use std::sync::Arc;
    use arc_swap::ArcSwap;
    use tldextract::TldExtractor;

    pub(crate) async fn get_info_for_domain(
        domain: DetectedDomainWithId,
        tld_extractor: &TldExtractor,
        domain_info_processor: &Vec<Arc<dyn DomainInfoClient>>,
        gsb_client: &Option<SafebrowsingClient>,
    ) -> Result<DomainWithId, ConverterError> {
        let domain_info_processor = &ArcSwap::new(Arc::new(domain_info_processor.to_owned()));

        super::get_info_for_domain(domain, domain_info_processor, tld_extractor, gsb_client).await
    }
}
