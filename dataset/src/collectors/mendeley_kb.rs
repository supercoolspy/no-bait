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

pub(crate) type MendeleyKBDataset = Vec<MendeleyKBEntry>;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct MendeleyKBEntry {
    pub(crate) url: String,
    #[serde(rename = "type")]
    pub(crate) entry_type: String,
}

/// Client for the MendeleyKB Dataset (doi: 10.17632/vfszbj9b36.1).
/// Each URL in the dataset is meticulously categorized as either "phishing" or "legitimate."
pub struct MendeleyKBClient {
    client: Arc<ClientWithMiddleware>,
}

impl MendeleyKBClient {
    pub fn new(client: Arc<ClientWithMiddleware>) -> Self {
        Self { client }
    }
}

impl CsvCollector for MendeleyKBClient {
    type Dataset = MendeleyKBDataset;

    #[instrument(skip_all, err)]
    async fn download_dataset(&self) -> Result<Self::Dataset, CsvError> {
        info!("Downloading MendeleyKB dataset");
        let data = self.client
            .get("https://data.mendeley.com/public-files/datasets/vfszbj9b36/files/f0de314f-ea72-4385-9faa-f06593bb0a2d/file_downloaded")
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        info!("Downloaded MendeleyKB dataset");

        let mut save_file = File::create("./MendeleyKB.csv")?;

        save_file.write_all(&data)?;
        debug!("Saved dataset to storage");

        self.load_csv(save_file).await
    }

    #[instrument(skip_all, err)]
    async fn load_csv(&self, reader: impl Read) -> Result<Self::Dataset, CsvError> {
        let mut data = Vec::new();

        let mut csv_reader = csv::Reader::from_reader(reader);
        for result in csv_reader
            .deserialize()
            .enumerate()
            .filter_map(|(line, res)| {
                if line != 385991
                    && line != 389058
                    && line != 389343
                    && line != 391711
                    && line != 392917
                    && line != 393245
                    && line != 399356
                    && line != 398160
                {
                    Some(res)
                } else {
                    None
                }
            })
        {
            let record: MendeleyKBEntry = result?;

            trace!("Valid record: {}", record.url);

            data.push(record);
        }

        Ok(data)
    }

    #[instrument(skip_all, err)]
    async fn get_local(&self) -> Result<Self::Dataset, CsvError> {
        let file = tokio::fs::File::open("./MendeleyKB.csv").await?;
        debug!("Read MendeleyKB csv locally");

        self.load_csv(file.into_std().await).await
    }
}

impl ToDetectedDomain for MendeleyKBDataset {
    #[instrument(skip(self), err)]
    fn to_detected_domains(self) -> Result<Vec<DetectedDomain>, DetectedDomainParseError> {
        self.into_par_iter()
            .map(|d| {
                let domain = d
                    .url
                    .replace("'", "")
                    .replace(" - GET", "")
                    .replace("[.]", ".")
                    .replace(" ", "")
                    .replace(" ", "");
                let parse_span = info_span!("mendeley_k_b_to_detected_domains", domain = domain);
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
                        collector_specific_info: CollectorSpecificInfo::MendeleyKB {},
                        phishing: d.entry_type == "phishing",
                    },
                })
            })
            .filter_map(|entry| {
                // Filter out ip addresses
                // Exclude non-phishing domains for now since dataset is huge
                if entry.as_ref().is_ok_and(|d| d.url.domain().is_none() || d.collector_info.phishing == false) {
                    None
                } else {
                    Some(entry)
                }
            })
            .collect()
    }
}
