use crate::database::DomainInfo;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::{AddrParseError, IpAddr};
use thiserror::Error;
use tldextract::TldResult;
use url::{ParseError, Url};

pub(super) mod autowhois;
pub(super) mod legitphish;
pub(super) mod mendeley_kb;
pub(super) mod phishstorm;
pub(super) mod phishtank;
pub(crate) mod rdap;
/// Google safebrowsing
pub(super) mod safebrowsing;
pub(super) mod sslmate;
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
    GoogleSafeBrowsing { category: Option<String> },
    LegitPhish {},
    MendeleyKB {},
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

pub trait TldUrl {
    type Error;
    fn as_root(&self) -> Result<String, Self::Error>;
}

#[derive(Debug, Error)]
pub enum TldConvertError {
    #[error("No Domain")]
    NoDomain,

    #[error("No Suffix")]
    NoSuffix,
}

impl TldUrl for TldResult {
    type Error = TldConvertError;

    fn as_root(&self) -> Result<String, Self::Error> {
        Ok(format!(
            "{}.{}",
            self.domain.as_ref().ok_or(TldConvertError::NoDomain)?,
            self.suffix.as_ref().ok_or(TldConvertError::NoSuffix)?
        ))
    }
}

#[derive(Debug, Clone)]
pub enum ErrorImportance {
    Ignore,
    Log,
    Stop,
}

impl Default for ErrorImportance {
    fn default() -> Self {
        Self::Log
    }
}

#[async_trait]
pub trait DomainInfoClient: Send + Sync {
    async fn get_info(
        &self,
        root: &str,
    ) -> Result<DomainInfo, Box<dyn std::error::Error + Send + Sync>>;

    fn error_importance(
        &self,
        _err: &(dyn std::error::Error + Send + Sync + 'static),
    ) -> ErrorImportance;
}

#[derive(Error, Debug)]
pub(crate) enum CsvError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Zip file parsing error: {0}")]
    ZipParse(#[from] zip::result::ZipError),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
}

pub(crate) trait CsvCollector {
    type Dataset: ToDetectedDomain;

    async fn download_dataset(&self) -> Result<Self::Dataset, CsvError>;

    async fn load_csv(&self, reader: impl Read + Send + Sync) -> Result<Self::Dataset, CsvError>;

    async fn get_local(&self) -> Result<Self::Dataset, CsvError>;
}

#[cfg(test)]
mod tests {
    use crate::collectors::legitphish::LegitPhishClient;
    use crate::collectors::mendeley_kb::MendeleyKBClient;
    use crate::collectors::phishtank::get_latest_data;
    use crate::collectors::rdap::RDAPClient;
    use crate::collectors::{
        CsvCollector, DomainInfoClient, ToDetectedDomain, phishstorm, phishtank,
    };
    use crate::database::tests::get_test_db_state;
    use crate::tests::init;
    use crate::{get_gsb_client, get_reqwest_middleware_client};
    use icann_rdap_common::prelude::RdapResponse;
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;

    #[tokio::test]
    #[ignore]
    /// Currently broken since phishtank doesn't offer registration and doesn't work without an api key
    async fn get_phishtank_data() {
        init();

        get_latest_data(
            &ClientBuilder::new(Client::new()).build(),
            "supercoolspy".to_string(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    /// Analyze the data locally, must be run after get_phishtank_data so that the file exists if in a purely test environment.
    async fn analyze_phishtank_data() {
        init();

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
    /// Analyze the data
    async fn analyze_legit_phish_data() {
        init();

        LegitPhishClient::new(get_reqwest_middleware_client())
            .download_dataset()
            .await
            .expect("Should be able to download LegitPhish dataset")
            .to_detected_domains()
            .expect("Should be able to convert to detected domains");
    }

    #[tokio::test]
    /// Analyze the data
    async fn analyze_mendeley_k_b_data() {
        init();

        MendeleyKBClient::new(get_reqwest_middleware_client())
            .download_dataset()
            .await
            .expect("Should be able to download MendeleyKB dataset")
            .to_detected_domains()
            .expect("Should be able to convert to detected domains");
    }

    #[tokio::test]
    /// Analyze the data locally, phishstorm.csv must be downloaded
    async fn analyze_phishstorm_data() {
        init();

        if !tokio::fs::try_exists("./phishstorm.csv").await.unwrap() {
            return;
        }

        phishstorm::PhishStormClient::new(get_reqwest_middleware_client())
            .get_local()
            .await
            .expect("Should be able to get phishstorm data")
            .to_detected_domains()
            .expect("Should be able to convert to detected domains");
    }

    #[tokio::test]
    /// Make sure GSB can detect the test urls
    async fn gsb_check() {
        init();

        let client = get_gsb_client(
            get_reqwest_middleware_client(),
            true,
            get_test_db_state().await.db_state.clone(),
        )
        .await;

        let res = client
            .get_url_batch_threat(
                "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/"
                    .to_string(),
            )
            .await
            .expect("Should be able to get url safety");

        assert!(res.phishing)
    }

    #[tokio::test]
    /// Check if RDAP can resolve a domain
    async fn rdap_get_domain() {
        init();

        let rdap_client = RDAPClient::new(true, get_test_db_state().await.db_state.clone()).await;

        // Common for hosting so we want to make sure it resolves
        let domain = "vercel.app";
        let res = rdap_client
            .get_info(domain)
            .await
            .expect("Should be able to get RDAP info for vercel");

        assert!(
            matches!(
                res,
                crate::database::DomainInfo::RDAPInfo(RdapResponse::Domain(_))
            ),
            "Did not get domain in response"
        );
    }
}
