use crate::collectors::DomainInfoClient;
use crate::collectors::safebrowsing::SafebrowsingClient;
use crate::collectors::sslmate::SslMateClient;
use crate::converter::convert_domains;
use crate::database::{
    DBState, DatabaseError, get_amount_pending_db, get_pending_domains, remove_pending_domains,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tldextract::TldExtractor;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use tracing::{debug, error, info};

pub(crate) async fn wait_until_finished(
    shutdown: Arc<AtomicBool>,
    db_state: &DBState,
) -> Result<(), DatabaseError> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("Exiting because of Ctrl+C");
            break;
        };

        let pending_memory = db_state.get_pending_count().await;

        if pending_memory > 0 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        let pending_from_db = get_amount_pending_db(db_state.get_connection()).await?;

        if pending_from_db > 0 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        break;
    }

    Ok(())
}

pub(super) fn create_processor(
    db_state: Arc<DBState>,
    tld_extractor: Arc<TldExtractor>,
    domain_info_processor: Arc<Vec<Arc<dyn DomainInfoClient>>>,
    ssl_mate_client: Arc<SslMateClient>,
    gsb_client: Arc<Option<SafebrowsingClient>>,
    shutdown: Arc<AtomicBool>,
    mut channel_receiver: Receiver<usize>,
) {
    tokio::spawn(async move {
        loop {
            if shutdown.load(Ordering::SeqCst) {
                info!("Stopping processor because of Ctrl+C");
                break;
            };

            let max_to_process = db_state.get_max_to_process();

            if let Ok(amount_op) = timeout(Duration::from_secs(10), channel_receiver.recv()).await {
                if amount_op.is_none() {
                    continue;
                }

                let amount = amount_op.unwrap();

                if amount > max_to_process {
                    let remainder = amount % max_to_process;

                    let times_to_process = amount / max_to_process;

                    for _ in 1..=times_to_process {
                        process_domains(
                            &db_state,
                            &tld_extractor,
                            &domain_info_processor,
                            &ssl_mate_client,
                            &gsb_client,
                            max_to_process,
                        )
                        .await;
                    }

                    if remainder != 0 {
                        process_domains(
                            &db_state,
                            &tld_extractor,
                            &domain_info_processor,
                            &ssl_mate_client,
                            &gsb_client,
                            remainder,
                        )
                        .await;
                    }
                } else {
                    process_domains(
                        &db_state,
                        &tld_extractor,
                        &domain_info_processor,
                        &ssl_mate_client,
                        &gsb_client,
                        amount,
                    )
                    .await;
                }
            } else {
                // Timeout hit, check from db

                process_domains(
                    &db_state,
                    &tld_extractor,
                    &domain_info_processor,
                    &ssl_mate_client,
                    &gsb_client,
                    max_to_process,
                )
                .await;
            };
        }
    });
}

async fn process_domains(
    db_state: &DBState,
    tld_extractor: &TldExtractor,
    domain_info_processor: &Vec<Arc<dyn DomainInfoClient>>,
    ssl_mate_client: &SslMateClient,
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

    let rows_to_delete = convert_domains(
        db_state,
        tld_extractor,
        domain_info_processor,
        ssl_mate_client,
        gsb_client,
        pending,
    )
    .await;

    let remove_res = remove_pending_domains(db_state.get_connection(), rows_to_delete).await;
    if remove_res.is_err() {
        error!(
            "Failed to delete domains from pending table: {}",
            remove_res.err().unwrap()
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::collectors::DomainInfoClient;
    use crate::collectors::rdap::RDAPClient;
    use crate::collectors::sslmate::SslMateClient;
    use crate::collectors::whois::WhoisClient;
    use crate::collectors::{
        CollectorSpecificInfo, DetectedDomain, DomainCollectorInfo, ToDetectedDomain, phishstorm,
        phishtank,
    };
    use crate::converter::convert_domains;
    use crate::database::tests::get_test_db_state;
    use crate::database::{DBState, DetectedDomainWithId, DomainInfo, DomainWithId};
    use crate::tests::{TLD_EXTRACTOR, init};
    use crate::{converter, get_reqwest_middleware_client, get_ssl_mate_client};
    use rand::prelude::IteratorRandom;
    use std::future::Future;
    use std::sync::Arc;
    use url::Url;

    async fn process_single_named(domain: &str) {
        let url: Url = domain.parse().expect("Should be able to parse domain");

        let test_domain = DetectedDomain {
            url: url.clone(),
            collector_info: DomainCollectorInfo {
                collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                    category: None,
                },
                phishing: false,
            },
        };

        process_domains(
            vec![test_domain],
            |db_state, domain_info_processors, ssl_mate_client, domains| async move {
                convert_domains(
                    &db_state,
                    &TLD_EXTRACTOR,
                    &domain_info_processors,
                    &ssl_mate_client,
                    &None,
                    domains,
                )
                .await
            },
        )
        .await;
    }

    async fn process_domains_simple(domains: Vec<DetectedDomain>) {
        process_domains(
            domains,
            |db_state, domain_info_processors, ssl_mate_client, domains| async move {
                convert_domains(
                    &db_state,
                    &TLD_EXTRACTOR,
                    &domain_info_processors,
                    &ssl_mate_client,
                    &None,
                    domains,
                )
                .await
            },
        )
        .await;
    }

    async fn process_domains<F, FnOutput, T>(domains: Vec<DetectedDomain>, function: F) -> Vec<T>
    where
        F: Fn(
            Arc<DBState>,
            Vec<Arc<dyn DomainInfoClient>>,
            SslMateClient,
            Vec<DetectedDomainWithId>,
        ) -> FnOutput,
        FnOutput: Future<Output = Vec<T>>,
    {
        init();

        let test_db_state = get_test_db_state().await;
        let db_state = test_db_state.db_state.clone();

        let rdap_client = Arc::new(RDAPClient::new(true, db_state.clone()).await);
        let whois_client = Arc::new(WhoisClient::new(true, db_state.clone()).await);
        // Create domain info processors vector
        let mut domain_info_processors: Vec<Arc<dyn DomainInfoClient>> = Vec::new();
        domain_info_processors.push(whois_client);
        domain_info_processors.push(rdap_client);

        let client = get_reqwest_middleware_client();
        let ssl_mate_client = get_ssl_mate_client(client, true, db_state.clone()).await;

        for domain in &domains {
            let url = domain.url.as_str();

            db_state
                .get_connection()
                .execute("DELETE FROM domains WHERE url=?", [url])
                .await
                .expect("Should be able to remove domain");
        }

        let test_domains: Vec<DetectedDomainWithId> = domains
            .into_iter()
            .map(|d| DetectedDomainWithId {
                domain: d,
                row_id: 0,
            })
            .collect();

        let amount = test_domains.len();

        let row_result = function(
            db_state.clone(),
            domain_info_processors,
            ssl_mate_client,
            test_domains,
        )
        .await;

        assert_eq!(row_result.len(), amount);

        row_result
    }

    #[tokio::test]
    async fn process_single_whois() {
        process_single_named("https://example.com").await
    }

    #[tokio::test]
    async fn process_single_update() {
        process_domains_simple(vec![
            DetectedDomain {
                url: "https://example.com".parse().unwrap(),
                collector_info: DomainCollectorInfo {
                    collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                        category: None,
                    },
                    phishing: false,
                },
            },
            DetectedDomain {
                url: "https://example.com".parse().unwrap(),
                collector_info: DomainCollectorInfo {
                    collector_specific_info: CollectorSpecificInfo::PhishStorm {
                        ranking: 100000000,
                    },
                    phishing: false,
                },
            },
        ])
        .await
    }

    #[tokio::test]
    async fn process_single_rdap() {
        process_single_named("https://google.dev").await
    }

    #[tokio::test]
    async fn process_single_none() {
        let url: Url = "https://nic.co.nr"
            .parse()
            .expect("Should be able to parse domain");

        let test_domain = DetectedDomain {
            url: url.clone(),
            collector_info: DomainCollectorInfo {
                collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                    category: None,
                },
                phishing: false,
            },
        };

        let domains: Vec<DomainWithId> = process_domains(
            vec![test_domain],
            |_db_state, domain_info_processors, _ssl_mate_client, domains| async move {
                vec![
                    converter::test_support::get_info_for_domain(
                        domains.into_iter().take(1).next_back().unwrap(),
                        &TLD_EXTRACTOR,
                        &domain_info_processors,
                        &None,
                    )
                    .await
                    .unwrap(),
                ]
            },
        )
        .await;
        assert!(matches!(
            domains
                .first()
                .expect("Should be able to get first domain")
                .domain
                .whois_info,
            DomainInfo::None
        ));
    }

    #[tokio::test]
    async fn process_single_utf16() {
        process_single_named("https://registro.br").await
    }

    #[tokio::test]
    /// Analyze the data locally, then choose 5 random domains to process
    async fn process_phishstorm_random() {
        init();

        if !tokio::fs::try_exists("./phishstorm.csv").await.unwrap() {
            return;
        }

        let data = phishstorm::get_data_local()
            .await
            .expect("Should be able to get phishstorm data")
            .to_detected_domains()
            .expect("Should be able to convert to detected domains");

        let mut rng = rand::rng();

        let random_domain = data.into_iter().choose_multiple(&mut rng, 5);

        process_domains_simple(random_domain).await
    }

    #[tokio::test]
    /// Analyze the data locally, must be run after get_phishtank_data so that the file exists if in a purely test environment.
    /// Then choose 5 random domains to process.
    async fn process_phishtank_random() {
        init();

        if !tokio::fs::try_exists("./phishtank.json.gz").await.unwrap() {
            return;
        }

        let data = phishtank::get_data_local()
            .await
            .expect("Should be able to get phishtank data")
            .to_detected_domains()
            .expect("Should be able to convert to detected domains");

        let mut rng = rand::rng();

        let random_domains = data.into_iter().choose_multiple(&mut rng, 5);

        process_domains_simple(random_domains).await
    }
}
