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
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;

    #[tokio::test]
    async fn get_phishtank_data() {
        get_latest_data(
            &ClientBuilder::new(Client::new()).build(),
            "supercoolspy".to_string(),
        )
        .await
        .unwrap();
    }
}
