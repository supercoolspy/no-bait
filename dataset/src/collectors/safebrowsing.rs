use crate::collectors::{CollectorSpecificInfo, DomainCollectorInfo, rate_limited};
use crate::database::{Cache, DBState, DatabaseError};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, instrument};

pub(crate) struct SafebrowsingClient {
    api_key: String,
    client: Arc<ClientWithMiddleware>,
    cache: Cache<DomainCollectorInfo>,
    rate_limited: AtomicU64,
}

#[derive(Error, Debug)]
pub enum SafebrowsingError {
    #[error("Reqwest Middleware error: {0}")]
    ReqwestMiddleware(#[from] reqwest_middleware::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Database (Cache) Error: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("Rate limited")]
    RateLimited,
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
            rate_limited: AtomicU64::new(0),
        }
    }

    /// Returns a list of unsafe urls
    #[instrument(skip(self), err)]
    pub async fn get_url_batch_threat(
        &self,
        url: String,
    ) -> Result<DomainCollectorInfo, SafebrowsingError> {
        if rate_limited(&self.rate_limited) {
            return Err(SafebrowsingError::RateLimited);
        }

        let cache_value = self
            .cache
            .get_from_cache(url.as_str())
            .await
            .unwrap_or_default();

        if let Some(value) = cache_value {
            return Ok(value);
        }

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
            .error_for_status();

        if let Err(reqwest_err) = res {
            if let Some(status) = reqwest_err.status() {
                if status.as_u16() == 429 {
                    let now = SystemTime::now();

                    let unix_time_sec = now
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs();

                    self.rate_limited.store(unix_time_sec, Ordering::Release);

                    return Err(SafebrowsingError::RateLimited);
                }
            }

            return Err(reqwest_err.into());
        }

        debug!("Sent request to safe browsing api without error");

        let data_res: Result<SafebrowsingResponse, reqwest::Error> = res?.json().await;
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

        let info = if data.matches.is_empty() {
            DomainCollectorInfo {
                collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                    category: None,
                },
                phishing: false,
            }
        } else {
            DomainCollectorInfo {
                collector_specific_info: CollectorSpecificInfo::GoogleSafeBrowsing {
                    category: data.matches.first().map(|m| m.threat_type.clone()),
                },
                phishing: true,
            }
        };

        self.cache.add_to_cache(url.clone(), &info).await?;

        Ok(info)
    }
}
