use std::sync::{Arc, LazyLock};

use crate::collectors::{CollectorSpecificInfo, DomainCollectorInfo};
use crate::database::{Cache, DBState};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, instrument};

pub(crate) struct SafebrowsingClient {
    api_key: String,
    client: Arc<ClientWithMiddleware>,
    cache: Cache<Option<CollectorSpecificInfo>>,
}

#[derive(Error, Debug)]
pub enum SafebrowsingError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("No Threat Type even though Array has values")]
    NoThreatType,
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
    pub async fn new(
        client: Arc<ClientWithMiddleware>,
        api_key: String,
        memory: bool,
        db_state: Arc<DBState>,
    ) -> Self {
        Self {
            api_key,
            client,
            cache: Cache::new(memory, db_state, "google_safe_browsing".to_string())
                .await
                .expect("Should be able to create cache"),
        }
    }

    /// Returns a list of unsafe urls
    #[instrument(skip(self), err)]
    pub async fn get_url_batch_threat(
        &self,
        url: String,
    ) -> Result<DomainCollectorInfo, SafebrowsingError> {
        let mut req_data = REQUEST.clone();
        req_data.threat_info.threat_entries = vec![ThreatEntry {
            url: url.to_string(),
        }];
        debug!("Mapped urls to threat entries");

        let res = self
            .client
            .post("https://safebrowsing.googleapis.com/v4/threatMatches:find")
            .query(&[("key", &self.api_key)])
            .json(&req_data)
            .send()
            .await?
            .error_for_status()?;
        debug!("Sent request to safe browsing api without error");

        let data_res: Result<SafebrowsingResponse, reqwest::Error> = res.json().await;
        if data_res.is_err() {
            // No threats
            debug!("No threats were found");
            return Ok(DomainCollectorInfo {
                collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                    category: None,
                },
                phishing: false,
            });
        }

        let data = data_res?;
        debug!("Able to get GSB response as json");

        if data.matches.is_empty() {
            Ok(DomainCollectorInfo {
                collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                    category: None,
                },
                phishing: false,
            })
        } else {
            Ok(DomainCollectorInfo {
                collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                    category: data.matches.first().map(|m| m.threat_type.clone()),
                },
                phishing: false,
            })
        }
    }
}
