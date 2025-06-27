use serde::{Deserialize, Serialize};
use std::net::{AddrParseError, IpAddr};
use thiserror::Error;
use url::{ParseError, Url};

pub(super) mod phishstorm;
pub(super) mod phishtank;
pub(crate) mod rdap;
/// Google safebrowsing
pub(super) mod safebrowsing;
/// Official Whois Data
pub(super) mod whois;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct DomainCollectorInfo {
    pub collector_specific_info: CollectorSpecificInfo,
    pub phishing: bool,
}

/// Domain info specific to the collector
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CollectorSpecificInfo {
    PhishTank { phish_id: i64, ip: Option<IpAddr> },
    PhishStorm { ranking: u32 },
}

/// A domain that has been detected by one of the collectors, but has not been processed yet into the database format
#[derive(Debug, Clone)]
pub struct DetectedDomain {
    pub url: Url,
    pub collector_info: DomainCollectorInfo,
}

#[derive(Debug, Error)] // omit Error if you don’t want Display impls
pub enum DetectedDomainParseError {
    #[error("URL parse error: {0}")]
    Url(#[from] ParseError), // `#[from]` gives automatic `From` impl

    #[error("address parse error: {0}")]
    Addr(#[from] AddrParseError),
}

pub trait ToDetectedDomain {
    fn to_detected_domains(self) -> Result<Vec<DetectedDomain>, DetectedDomainParseError>;
}

#[cfg(test)]
mod tests {
    use crate::collectors::phishtank::get_latest_data;
    use crate::collectors::rdap::{RDAPClient, RDAPError};
    use crate::collectors::{ToDetectedDomain, phishstorm, phishtank};
    use crate::{get_gsb_client, get_reqwest_middleware_client};
    use icann_rdap_common::prelude::RdapResponse;
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;
    use std::sync::Once;
    use url::Url;

    static INIT: Once = Once::new();

    pub fn init_logger() {
        INIT.call_once(|| {
            env_logger::builder()
                .is_test(true) // avoid coloring & timestamps
                .init();
        });
    }

    #[tokio::test]
    #[ignore]
    /// Currently broken since phishtank doesn't offer registration and doesn't work without an api key
    async fn get_phishtank_data() {
        init_logger();

        get_latest_data(
            &ClientBuilder::new(Client::new()).build(),
            "supercoolspy".to_string(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    /// Analyze the data locally, must be run after get_phishtank_data so that the file exists if in a purely test environment
    async fn analyze_phishtank_data() {
        init_logger();

        if !tokio::fs::try_exists("./phishtank.json.gz").await.unwrap() {
            return;
        }

        phishtank::get_data_local()
            .await
            .expect("Should be able to get phishtank data")
            .to_detected_domains()
            .expect("Should be able to convert to detected domains");
    }

    #[tokio::test]
    /// Analyze the data locally, phishstorm.csv must be downloaded
    async fn analyze_phishstorm_data() {
        init_logger();

        if !tokio::fs::try_exists("./phishstorm.csv").await.unwrap() {
            return;
        }

        phishstorm::get_data_local()
            .await
            .expect("Should be able to get phishstorm data")
            .to_detected_domains()
            .expect("Should be able to convert to detected domains");
    }

    #[tokio::test]
    /// Make sure GSB can detect the test urls
    async fn gsb_check() {
        init_logger();

        let client = get_gsb_client(get_reqwest_middleware_client());

        let res = client
            .get_url_batch_threat(vec![
                "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/".to_string(),
                "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/"
                    .to_string(),
            ])
            .await
            .expect("Should be able to get url safety");

        assert_eq!(res.len(), 2)
    }

    #[tokio::test]
    /// Make sure RDAP client fails if the client cannot find a registrar to go to
    async fn rdap_related_fail() {
        init_logger();

        let rdap_client = RDAPClient::new();

        let res = rdap_client
            .get_rdap_data(
                Url::parse("https://example.com").expect("Should be able to parse example url"),
            )
            .await;

        assert!(res.is_err());

        assert!(
            matches!(res.err(), Some(RDAPError::NoRelated)),
            "Error was not No Related field"
        );
    }

    #[tokio::test]
    /// Check if RDAP can resolve a domain
    async fn rdap_get_domain() {
        init_logger();

        let rdap_client = RDAPClient::new();

        // Common for hosting so we want to make sure it resolves
        let res = rdap_client
            .get_rdap_data(
                Url::parse("https://vercel.app").expect("Should be able to parse vercel.app url"),
            )
            .await
            .expect("Should be able to get RDAP info for vercel");

        assert!(
            matches!(res, RdapResponse::Domain(_)),
            "Did not get domain in response"
        );
    }
}
