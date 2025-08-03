use crate::collectors::{
    CollectorSpecificInfo, CsvCollector, CsvError, DetectedDomain, DetectedDomainParseError,
    DomainCollectorInfo, ToDetectedDomain,
};
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelIterator;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Cursor, Read};
use std::sync::Arc;
use tracing::{debug, error, info, info_span, instrument, trace};
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

pub struct PhishStormClient {
    client: Arc<ClientWithMiddleware>,
}

impl PhishStormClient {
    pub fn new(client: Arc<ClientWithMiddleware>) -> Self {
        Self { client }
    }
}

impl CsvCollector for PhishStormClient {
    type Dataset = PhishStormDataset;

    #[instrument(skip_all, err)]
    async fn download_dataset(&self) -> Result<Self::Dataset, CsvError> {
        info!("Downloading PhishStorm dataset");
        let res = self
            .client
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

        // Drop to avoid issues with async barrier
        drop(file);
        drop(archive);

        self.load_csv(save_file).await
    }

    #[instrument(skip_all, err)]
    async fn load_csv(&self, reader: impl Read + Send + Sync) -> Result<Self::Dataset, CsvError> {
        let mut data = Vec::new();

        let mut csv_reader = csv::Reader::from_reader(reader);
        for result in csv_reader
            .deserialize()
            .enumerate()
            .filter_map(|(line, row)| {
                // 18232-18348 contain invalid data, 19582 (19605 in the csv) contains an invalid domain name
                if !(18231..=18349).contains(&line) && line != 19582 {
                    trace!(row_res=?row, "{} is valid line", line);
                    Some(row)
                } else {
                    trace!(row_res=?row, "{} is invalid line", line);
                    None
                }
            })
        {
            let record: PhishStormEntry = result?;
            trace!("Valid record: {}", record.domain);
            data.push(record);
        }

        Ok(data)
    }

    #[instrument(skip_all, err)]
    async fn get_local(&self) -> Result<Self::Dataset, CsvError> {
        let file = tokio::fs::File::open("./phishstorm.csv").await?;
        debug!("Read phishstorm csv locally");

        self.load_csv(file.into_std().await).await
    }
}

impl ToDetectedDomain for PhishStormDataset {
    #[instrument(skip(self), err)]
    fn to_detected_domains(self) -> Result<Vec<DetectedDomain>, DetectedDomainParseError> {
        self.into_par_iter()
            .map(|d| {
                let domain = d.domain.replace("'", "");
                let parse_span = info_span!("phishstorm_to_detected_domains", domain = domain);
                let _enter = parse_span.enter();

                let url_str = format!("https://{}", domain);
                debug!("Parsing: {}", url_str);
                let url_res = url_str.parse::<Url>();
                trace!("URL Result: {:?}", url_res);

                // Due to parallelism it's really hard to tell which domain errored
                if url_res.is_err() {
                    error!("Failed to parse {}", domain);
                    return Err(DetectedDomainParseError::Url(url_res.err().unwrap()));
                }

                Ok(DetectedDomain {
                    url: url_res?,
                    collector_info: DomainCollectorInfo {
                        collector_specific_info: CollectorSpecificInfo::PhishStorm {
                            ranking: d.ranking,
                        },
                        phishing: d.label == 1.0,
                    },
                })
            })
            .collect()
    }
}
