use std::{
    fmt::format,
    sync::{Arc, LazyLock},
};

use reqwest::Client;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::commands::safebrowsing;

pub(crate) struct SafebrowsingClient {
    api_key: String,
    client: Arc<ClientWithMiddleware>,
}

#[derive(Error, Debug)]
pub enum SafebrowsingError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SafebrowsingRequest {
    pub(crate) client: ClientInfo,
    pub(crate) threat_info: ThreatInfo,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub(crate) client_id: String,
    pub(crate) client_version: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ThreatInfo {
    pub(crate) threat_types: Vec<String>,
    pub(crate) platform_types: Vec<String>,
    pub(crate) threat_entry_types: Vec<String>,
    pub(crate) threat_entries: Vec<ThreatEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ThreatEntry {
    pub(crate) url: String,
}

#[derive(Serialize, Deserialize)]
pub struct SafebrowsingResponse {
    pub(crate) matches: Vec<Match>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub(crate) threat_type: String,
    pub(crate) platform_type: String,
    pub(crate) threat: Threat,
    pub(crate) cache_duration: String,
    pub(crate) threat_entry_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct Threat {
    pub(crate) url: String,
}

static REQUEST: LazyLock<SafebrowsingRequest> = LazyLock::new(|| SafebrowsingRequest {
    client: ClientInfo {
        client_id: env!("CARGO_PKG_NAME").to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    },
    threat_info: ThreatInfo {
        threat_types: vec!["MALWARE".to_string(), "SOCIAL_ENGINEERING".to_string()],
        platform_types: vec!["ANY_PLATFORM".to_string()],
        threat_entry_types: vec!["URL".to_string()],
        threat_entries: vec![],
    },
});

impl SafebrowsingClient {
    pub fn new(client: Arc<ClientWithMiddleware>, api_key: String) -> Self {
        Self { api_key, client }
    }

    /// Returns a list of unsafe urls
    pub async fn get_url_batch_threat(
        &self,
        urls: Vec<String>,
    ) -> Result<Vec<String>, SafebrowsingError> {
        let mut req_data = REQUEST.clone();
        req_data.threat_info.threat_entries = urls
            .iter()
            .map(|url| ThreatEntry {
                url: url.to_string(),
            })
            .collect();

        let res = self
            .client
            .post("https://safebrowsing.googleapis.com/v4/threatMatches:find")
            .query(&[("key", &self.api_key)])
            .json(&req_data)
            .send()
            .await?
            .error_for_status()?;

        let data_res: Result<SafebrowsingResponse, reqwest::Error> = res.json().await;
        if data_res.is_err() {
            // No threats
            return Ok(Vec::new());
        }

        let data = data_res.unwrap();

        Ok(data
            .matches
            .iter()
            .map(|m| m.threat.url.to_string())
            .collect())
    }
}
