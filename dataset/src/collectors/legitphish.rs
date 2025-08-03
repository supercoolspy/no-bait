use crate::collectors::{
    CollectorSpecificInfo, CsvCollector, CsvError, DetectedDomain, DetectedDomainParseError,
    DomainCollectorInfo, ToDetectedDomain,
};
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelIterator;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;
use tracing::{debug, error, info, info_span, instrument, trace};
use url::Url;

pub(crate) type LegitPhishDataset = Vec<LegitPhishEntry>;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct LegitPhishEntry {
    #[serde(rename = "URL")]
    pub(crate) url: String,
    /// value is 0 for phishing and 1 for benign
    #[serde(rename = "ClassLabel")]
    pub(crate) class_label: u8,
}

/// Client for the LegitPhish Dataset (doi: 10.17632/hx4m73v2sf.2).
/// "Each entry in this subset has been manually verified and is labeled as a phishing URL, making this dataset highly reliable for identifying harmful web content."
pub struct LegitPhishClient {
    client: Arc<ClientWithMiddleware>,
}

impl LegitPhishClient {
    pub fn new(client: Arc<ClientWithMiddleware>) -> Self {
        Self { client }
    }
}

impl CsvCollector for LegitPhishClient {
    type Dataset = LegitPhishDataset;

    #[instrument(skip_all, err)]
    async fn download_dataset(&self) -> Result<Self::Dataset, CsvError> {
        info!("Downloading LegitPhish dataset");
        let data = self.client
            .get("https://data.mendeley.com/public-files/datasets/hx4m73v2sf/files/0ed51e4d-d160-4047-b650-3f0801eea4aa/file_downloaded")
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        info!("Downloaded LegitPhish dataset");

        let mut save_file = File::create("./LegitPhish.csv")?;

        save_file.write_all(&data)?;
        debug!("Saved dataset to storage");

        self.load_csv(save_file).await
    }

    #[instrument(skip_all, err)]
    async fn load_csv(&self, reader: impl Read) -> Result<Self::Dataset, CsvError> {
        let mut data = Vec::new();

        let mut csv_reader = csv::Reader::from_reader(reader);
        for result in csv_reader.deserialize() {
            let record: LegitPhishEntry = result?;
            trace!("Valid record: {}", record.url);
            data.push(record);
        }

        Ok(data)
    }

    #[instrument(skip_all, err)]
    async fn get_local(&self) -> Result<Self::Dataset, CsvError> {
        let file = tokio::fs::File::open("./LegitPhish.csv").await?;
        debug!("Read LegitPhish csv locally");

        self.load_csv(file.into_std().await).await
    }
}

impl ToDetectedDomain for LegitPhishDataset {
    #[instrument(skip(self), err)]
    fn to_detected_domains(self) -> Result<Vec<DetectedDomain>, DetectedDomainParseError> {
        self.into_par_iter()
            .map(|d| {
                let domain = d.url.replace("'", "");
                let parse_span = info_span!("legit_phish_to_detected_domains", domain = domain);
                let _enter = parse_span.enter();

                let url_res = domain.parse::<Url>();
                trace!("URL Result: {:?}", url_res);

                // Due to parallelism it's really hard to tell which domain errored
                if url_res.is_err() {
                    error!("Failed to parse {}", domain);
                    return Err(DetectedDomainParseError::Url(url_res.err().unwrap()));
                }

                Ok(DetectedDomain {
                    url: url_res?,
                    collector_info: DomainCollectorInfo {
                        collector_specific_info: CollectorSpecificInfo::LegitPhish {},
                        phishing: d.class_label == 0,
                    },
                })
            })
            .filter_map(|entry| {
                // Filter out ip addresses
                if entry.as_ref().is_ok_and(|d| d.url.domain().is_none()) {
                    None
                } else {
                    Some(entry)
                }
            })
            .collect()
    }
}
