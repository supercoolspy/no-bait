use crate::collectors::rdap::{RDAPError, get_rdap_data};
use crate::collectors::whois::{WhoIsError, WhoIsInfo, get_whois_domain};
use crate::database::{DBState, DetectedDomainWithId, Domain, DomainInfo, DomainWithId};
use futures::StreamExt;
use icann_rdap_client::iana::BootstrapStore;
use rayon::prelude::*;
use thiserror::Error;
use whois_rust::WhoIs;

#[derive(Debug, Error)]
pub enum ConverterError {
    #[error("Whois Error: {0}")]
    Whois(#[from] WhoIsError),

    #[error("RDAP Error: {0}")]
    RDAP(#[from] RDAPError),
}

pub async fn convert_domains_from_memory(
    db_state: DBState,
    whois_client: &WhoIs,
    rdap_client: icann_rdap_client::http::Client,
    store: impl BootstrapStore,
    domains: Vec<DetectedDomainWithId>,
) -> Result<(), ConverterError> {
    let rdap_client = &rdap_client;
    let store = &store;

    let domains: Vec<Result<DomainWithId, ConverterError>> =
        futures::stream::iter(domains.into_iter())
            .map(|domain| async move {
                let url = domain.domain.url;
                let res = get_whois_domain(whois_client, url.clone()).await;

                if res.is_err() {
                    if let Err(WhoIsError::NoWhois) = res {
                        let rdap = get_rdap_data(rdap_client, store, url.clone()).await?;
                        Ok(DomainWithId {
                            domain: Domain {
                                url,
                                whois_info: DomainInfo::RDAPInfo(rdap.to_string()),
                                collectors: vec![domain.domain.collector_info],
                            },
                            row_id: domain.row_id,
                        })
                    } else {
                        Err(ConverterError::Whois(res.err().unwrap()))
                    }
                } else {
                    let whois = res.unwrap();
                    Ok::<DomainWithId, ConverterError>(DomainWithId {
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
            .collect::<Vec<Result<DomainWithId, ConverterError>>>()
            .await;

    // Filter out domains that resulted in errors, keeping only the successful ones
    let successful_domains: Vec<DomainWithId> = domains
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();

    // Continue with just the successful domains
    // You can now use successful_domains for further processing

    Ok(())
}
