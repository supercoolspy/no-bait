use std::io::{Cursor, Read};

use log::{debug, info};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::fs::File;
use thiserror::Error;
use url::Url;
use zip::ZipArchive;

pub(crate) type PhishStormDataset = Vec<PhishStormEntry>;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PhishStormEntry {
    /// Format subdomain.domain/path
    pub(crate) domain: String,
    // 1-10,000,000
    pub(crate) ranking: u32,
    /// value is 1 for phishing and 0 for benign
    pub(crate) label: f32,
}

#[derive(Error, Debug)]
pub(crate) enum PhishStormError {
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

pub(crate) async fn download_phishstorm_dataset(
    client: &ClientWithMiddleware,
) -> Result<PhishStormDataset, PhishStormError> {
    info!("Downloading PhishStorm dataset");
    let res = client
        .get("https://research.aalto.fi/files/16859732/urlset.csv.zip")
        .send()
        .await?
        .error_for_status()?;
    info!("Downloaded PhishStorm dataset");

    let mut archive = ZipArchive::new(Cursor::new(res.bytes().await?))?;
    let mut file = archive.by_name("urlset.csv")?;

    let mut save_file = File::create("./phishstorm.csv")?;

    std::io::copy(&mut file, &mut save_file)?;
    debug!("Saved dataset to storage");

    read_csv_to_data(file)
}

pub(crate) async fn get_data_local() -> Result<PhishStormDataset, PhishStormError> {
    let file = tokio::fs::File::open("./phishstorm.csv").await?;

    read_csv_to_data(file.into_std().await)
}

fn read_csv_to_data(reader: impl Read) -> Result<PhishStormDataset, PhishStormError> {
    let mut data = Vec::new();

    let mut csv_reader = csv::Reader::from_reader(reader);
    for result in csv_reader.deserialize() {
        let record: PhishStormEntry = result?;
        data.push(record);
    }

    Ok(data)
}
