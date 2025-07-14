use super::whois::WhoIsError;
use crate::collectors::{
    CollectorSpecificInfo, DetectedDomain, DetectedDomainParseError, DomainCollectorInfo,
    ToDetectedDomain,
};
use crate::database::DatabaseError;
use flate2::bufread::GzDecoder;
use rayon::prelude::*;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, error, info_span, instrument, trace};
use url::{ParseError, Url};

pub type PhishTankDataset = Vec<PhishTankDatasetElement>;

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
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

    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Url Parsing error: {0}")]
    UrlParse(#[from] ParseError),

    #[error("Parse error: {0}")]
    ParseError(#[from] DetectedDomainParseError),

    #[error("Database error: {0}")]
    DatabaseError(#[from] DatabaseError),
}

#[instrument(skip(client), err)]
pub(crate) async fn get_latest_data(
    client: &ClientWithMiddleware,
    username: String,
) -> Result<PhishTankDataset, PhishTankError> {
    let response = client
        .get("https://data.phishtank.com/data/online-valid.json.gz")
        .header("User-Agent", format!("phishtank/{username}"))
        .send()
        .await?
        .error_for_status()?;
    debug!("Got successful response from PhishTank");

    let bytes = response.bytes().await?;
    debug!("Got data from PhishTank");

    tokio::fs::write("./phishtank.json.gz", &bytes).await?;

    read_archive_to_data(bytes)
}

#[instrument(err)]
pub(crate) async fn get_data_local() -> Result<PhishTankDataset, PhishTankError> {
    let data = tokio::fs::read("./phishtank.json.gz").await?;
    debug!("Successfully read data locally");
    read_archive_to_data(data.into())
}

#[instrument(skip_all, err)]
fn read_archive_to_data(bytes: bytes::Bytes) -> Result<PhishTankDataset, PhishTankError> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let data: PhishTankDataset = serde_json::from_reader(decoder)?;
    debug!("Successfully turned data into struct");

    Ok(data)
}

impl ToDetectedDomain for PhishTankDataset {
    #[instrument(err)]
    fn to_detected_domains(self) -> Result<Vec<DetectedDomain>, DetectedDomainParseError> {
        self.into_par_iter()
            .filter(|datapoint| datapoint.verified == "yes")
            .map(|domain_info| {
                let parse_span =
                    info_span!("phishtank_to_detected_domains", domain = domain_info.url);
                let _enter = parse_span.enter();

                debug!("Parsing {}", domain_info.url);
                let url = Url::parse(&domain_info.url)?;
                trace!("Parsed URL: {}", url);

                let ip = domain_info
                    .details
                    .first()
                    .map(|info| &info.ip_address)
                    .map(|ip| IpAddr::from_str(ip))
                    .transpose()?;
                trace!("IP Address: {:?}", ip);

                Ok(DetectedDomain {
                    url,
                    collector_info: DomainCollectorInfo {
                        collector_specific_info: CollectorSpecificInfo::PhishTank {
                            phish_id: domain_info.phish_id,
                            ip,
                        },
                        phishing: true,
                    },
                })
            })
            .collect()
    }
}
