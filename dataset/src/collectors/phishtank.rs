use flate2::bufread::GzDecoder;
use log::{debug, warn};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;
use whois_rust::WhoIs;

use crate::database::Domain;

use super::whois::{WhoIsError, get_whois_domain};

pub type PhishTankDataset = Vec<PhishTankDatasetElement>;

#[derive(Serialize, Deserialize)]
pub struct PhishTankDatasetElement {
    pub(crate) phish_id: i64,
    pub(crate) url: String,
    pub(crate) phish_detail_url: String,
    pub(crate) submission_time: String,
    pub(crate) verified: String,
    pub(crate) verification_time: String,
    pub(crate) online: String,
    pub(crate) details: Vec<Detail>,
    pub(crate) target: String,
}

#[derive(Serialize, Deserialize)]
pub struct Detail {
    pub(crate) ip_address: String,
    pub(crate) cidr_block: String,
    pub(crate) announcing_network: String,
    pub(crate) rir: String,
    pub(crate) country: String,
    pub(crate) detail_time: String,
}

#[derive(Error, Debug)]
pub enum PhishTankError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Ip Address Parse error: {0}")]
    IpAddressParse(#[from] std::net::AddrParseError),

    #[error("Whois Error: {0}")]
    WhoisError(#[from] WhoIsError),
}

pub(super) async fn get_latest_data(
    client: ClientWithMiddleware,
    username: String,
) -> Result<PhishTankDataset, PhishTankError> {
    env_logger::init();
    warn!("phishtank/{}", &username);

    let response = client
        .get("https://data.phishtank.com/data/online-valid.json.gz")
        .header("User-Agent", format!("phishtank/{username}"))
        .send()
        .await?
        .error_for_status()?;
    debug!("Got successful response from PhishTank");

    let bytes = response.bytes().await?;
    debug!("Got data from PhishTank");

    let decoder = GzDecoder::new(Cursor::new(bytes));
    let data: PhishTankDataset = serde_json::from_reader(decoder)?;
    debug!("Successfully turned data into struct");

    Ok(data)
}

pub(super) async fn get_domain_data(
    whois: WhoIs,
    dataset: PhishTankDataset,
) -> Result<Vec<Domain>, PhishTankError> {
    let verified: Vec<&PhishTankDatasetElement> = dataset
        .iter()
        .filter(|datapoint| datapoint.verified == "yes")
        .collect();

    let mut domainData: Vec<Domain> = Vec::new();

    for domain_info in verified {
        let mut domain = Domain::default();

        let ip = domain_info
            .details
            .first()
            .map(|info| &info.ip_address)
            .map(|ip| IpAddr::from_str(ip));

        if let Some(ip_result) = ip {
            if ip_result.is_ok() {
                domain.ip = Some(ip_result?)
            }
        }

        let data = get_whois_domain(&whois, domain.root).await?;
        domain.root = data.domain;
        domain.subdomain = data.subdomain;
        domain.whois_info = data.whois_data;

        domainData.push(domain);
    }

    Ok(domainData)
}
