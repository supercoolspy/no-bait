use crate::collectors::sslmate::SslMateResponse;
use crate::collectors::{DetectedDomain, DomainCollectorInfo};
use futures::{FutureExt, StreamExt};
use icann_rdap_common::prelude::RdapResponse;
use libsql::params::IntoValue;
use libsql::{Builder, Connection, Row, params};
use moka::future::Cache as MemoryCache;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::mem::discriminant;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, instrument, trace};
use url::Url;

pub type CollectorColumn = Vec<DomainCollectorInfo>;

#[derive(Debug, Clone)]
pub struct DomainWithId {
    pub domain: Domain,
    pub row_id: i64,
}

#[derive(Debug, Clone)]
pub struct DetectedDomainWithId {
    pub domain: DetectedDomain,
    pub row_id: i64,
}

/// Use when cli arguments could change how data is stored
#[derive(Debug, Clone)]
pub struct DBState {
    conn: Connection,
    db_only: bool,
    /// Pending domains only from this run, None if db_only is true
    pending_domains: Option<Arc<Mutex<Vec<DetectedDomainWithId>>>>,
    /// Channel sender for the amount of pending domains added to the db/in-memory map
    channel_sender: Sender<usize>,
}

impl DBState {
    /// Create a new Database State object.
    /// Should only be called once.
    fn new(conn: Connection, db_only: bool) -> (Self, Receiver<usize>) {
        let (tx, rx): (Sender<usize>, Receiver<usize>) = mpsc::channel(5);

        (
            Self {
                conn,
                db_only,
                pending_domains: if db_only {
                    None
                } else {
                    Some(Arc::new(Mutex::new(Vec::new())))
                },
                channel_sender: tx,
            },
            rx,
        )
    }

    /// Get the raw connection object for the database
    pub fn get_connection(&self) -> &Connection {
        &self.conn
    }

    /// Get min(batch_size, length) pending domains from the in-memory pending domains list
    #[instrument(skip(self))]
    async fn process_pending_batch(&self, batch_size: usize) -> Vec<DetectedDomainWithId> {
        let pending_domains = self.get_pending_domains();
        let mut domains = pending_domains.lock().await;
        let batch_end = batch_size.min(domains.len());
        debug!("Found {} pending domains", batch_end);
        domains.drain(..batch_end).collect()
    }

    /// Get the amount of pending domains in memory
    #[instrument(skip(self), ret)]
    pub async fn get_pending_count(&self) -> usize {
        if self.pending_domains.is_none() {
            return 0;
        }

        self.get_pending_domains().lock().await.len()
    }

    /// Check if in memory pending domains in enabled
    #[instrument(skip_all, ret)]
    pub async fn has_pending_domains(&self) -> bool {
        // Is some check should prevent any
        self.pending_domains.is_some() && !self.get_pending_domains().lock().await.is_empty()
    }

    /// Helper function to get pending domains. This will panic if pending domains is None
    pub fn get_pending_domains(&self) -> &Arc<Mutex<Vec<DetectedDomainWithId>>> {
        self.pending_domains
            .as_ref()
            .expect("Pending domains should exist")
    }
}

/// Domain info from registry/registrar whois/rdap service
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DomainInfo {
    WhoisInfo(String),
    RDAPInfo(RdapResponse),
    None,
}

/// A processed domain that can be added to the training set
#[derive(Debug, Clone)]
pub(crate) struct Domain {
    pub(crate) url: Url,
    pub(crate) whois_info: DomainInfo,
    pub(crate) cert_info: Option<SslMateResponse>,
    pub(crate) collectors: CollectorColumn,
}

impl TryInto<DetectedDomain> for Domain {
    type Error = DatabaseError;

    fn try_into(self) -> Result<DetectedDomain, Self::Error> {
        Ok(DetectedDomain {
            url: self.url,
            collector_info: self
                .collectors
                .first()
                .ok_or(Self::Error::NoCollectorFound)?
                .clone(),
        })
    }
}

pub struct Cache<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> {
    memory_cache: Option<MemoryCache<String, T>>,
    db_state: Arc<DBState>,
    name: String,
}

impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> Cache<T> {
    pub(crate) async fn new(
        memory: bool,
        db_state: Arc<DBState>,
        name: String,
    ) -> Result<Cache<T>, DatabaseError> {
        db_state
            .get_connection()
            .execute(
                &format!("CREATE TABLE IF NOT EXISTS cache_{} (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);", &name),
                params!(),
            )
            .await?;

        let instance = Self {
            memory_cache: if memory {
                let db_state = db_state.clone();
                let name: Arc<str> = Arc::from(name.clone());

                Some(
                    MemoryCache::builder()
                        .async_eviction_listener(move |k: Arc<String>, v: T, cause| {
                            let db_state = db_state.clone();
                            let name = name.clone();

                            async move {
                                if !cause.was_evicted() {
                                    // We don't want to do anything if the program explicitly removed an entry
                                    return;
                                }

                                let res = Self::add_to_cache_db(
                                    &db_state.get_connection(),
                                    &name,
                                    &k,
                                    &v,
                                )
                                .await;

                                if res.is_err() {
                                    error!(
                                        url = k.as_ref(),
                                        "Failed to add evicted entry to database cache: {}",
                                        res.expect_err("Checked if error")
                                    );
                                }
                            }
                            .boxed()
                        })
                        .build(),
                )
            } else {
                None
            },
            db_state,
            name,
        };

        Ok(instance)
    }
}

impl<T: Serialize + DeserializeOwned + Clone + Send + Sync> Cache<T> {
    /// Adds a value to the cache. If using a memory cache, the value is cloned
    pub async fn add_to_cache(&self, key: String, value: &T) -> Result<(), DatabaseError> {
        if self.using_memory_cache() {
            let cache = self.get_memory_cache();

            cache.insert(key, value.clone()).await;
        } else {
            Self::add_to_cache_db(&self.db_state.get_connection(), &self.name, &key, value).await?;
        }

        Ok(())
    }

    async fn add_to_cache_db(
        conn: &Connection,
        name: &str,
        key: &str,
        value: &T,
    ) -> Result<(), DatabaseError> {
        conn.execute(
            &format!("REPLACE INTO cache_{} (key, value) VALUES (?, ?)", name),
            (key, serde_json::to_string(&value)?),
        )
        .await?;

        Ok(())
    }

    /// Gets whether an item exists in the cache
    pub async fn get_from_cache(&self, key: String) -> Result<Option<T>, DatabaseError> {
        if self.using_memory_cache() {
            let memory_res = self.get_memory_cache().get(&key).await;

            if memory_res.is_some() {
                return Ok(memory_res);
            }
        }

        self.get_cache_from_db(key).await
    }

    async fn get_cache_from_db(&self, key: String) -> Result<Option<T>, DatabaseError> {
        let mut res = self
            .db_state
            .get_connection()
            .query(
                &format!("SELECT value from cache_{} WHERE key=?", &self.name),
                [key],
            )
            .await?;

        let row = res.next().await?;

        if row.is_none() {
            return Ok(None);
        }

        let row = row.unwrap();

        Ok(Some(serde_json::from_str(&row.get::<String>(0)?)?))
    }

    fn using_memory_cache(&self) -> bool {
        self.memory_cache.is_some()
    }

    fn get_memory_cache(&self) -> &MemoryCache<String, T> {
        self.memory_cache.as_ref().unwrap()
    }
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("LibSQL Error: {0}")]
    LibSQLError(#[from] libsql::Error),

    #[error("Url Parse Error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Channel Send Error: {0}")]
    ChannelSend(#[from] SendError<usize>),

    #[error("No Row where there should be one")]
    NoRow,

    #[error("Could not convert column to type")]
    ColumnConvert,

    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Row Already Exists")]
    RowAlreadyExists,

    #[error("No Collector Found")]
    NoCollectorFound,

    #[error("Parse error from string")]
    ParseStr,
}

/// Connect to the database and return a DBState object
#[instrument(err)]
pub(super) async fn connect_to_db(
    remote: bool,
    db_only: bool,
) -> libsql::Result<(DBState, Receiver<usize>)> {
    let db = if remote {
        let url = std::env::var("TURSO_DATABASE_URL").expect("TURSO_DATABASE_URL must be set");
        let token = std::env::var("TURSO_AUTH_TOKEN").expect("TURSO_AUTH_TOKEN must be set");
        info!("Using remote database");
        Builder::new_remote(url, token).build().await
    } else {
        info!("Using local database");
        Builder::new_local(Path::new("./phishing.db")).build().await
    }?;

    Ok(DBState::new(db.connect()?, db_only))
}

/// Create the initial database tables for the program to function
pub(crate) async fn init_db(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute(include_str!("../assets/dataset_table.sql"), ())
        .await?;

    Ok(())
}

/// Check whether a url exists in the Domains table and returns the Row object if it does.
/// This prevents an extra call to get the domain info after the fact for pre-exising rows.
#[instrument(skip(conn))]
pub(crate) async fn check_exists(
    conn: &Connection,
    url: &Url,
) -> Result<Option<Row>, DatabaseError> {
    let mut rows = conn
        .query("SELECT * from domains WHERE url = $1", &[url.as_str()])
        .await?;

    Ok(rows.next().await?)
}

/// Create a domain row, will error if the row already exists
#[instrument(skip(conn))]
async fn create_domain_row(conn: &Connection, domain: Domain) -> Result<(), DatabaseError> {
    conn.execute(
        "INSERT INTO domains (url, whois_info, collector_info) VALUES ($1, $2, $3)",
        [
            domain.url.as_str().to_string(),
            serde_json::to_string(&domain.whois_info)?,
            serde_json::to_string(&vec![domain.collectors])?,
        ],
    )
    .await?;

    Ok(())
}

/// Update a domain row, will error if the row doesn't exist
#[instrument(skip(conn, collectors), err)]
async fn update_domain_row(
    conn: &Connection,
    domain: DetectedDomain,
    mut collectors: Vec<DomainCollectorInfo>,
) -> Result<(), DatabaseError> {
    let existing_index = collectors.iter().position(|collector| {
        discriminant(&collector.collector_specific_info)
            == discriminant(&domain.collector_info.collector_specific_info)
    });

    if let Some(existing_index) = existing_index {
        trace!("Found existing version of collector");
        collectors.swap_remove(existing_index);

        collectors.push(domain.collector_info);
    };

    conn.prepare("UPDATE domains SET collector_info=$2 WHERE url = $1")
        .await?
        .execute([serde_json::to_string(&collectors)?])
        .await?;

    Ok(())
}

/// Update a domain, returns DatabaseError::NoRow if the row doesn't exist
#[instrument(skip(conn), err)]
pub(crate) async fn update_domain(
    conn: &Connection,
    domain: DetectedDomain,
) -> Result<(), DatabaseError> {
    let row = check_exists(conn, &domain.url).await?;

    if row.is_some() {
        trace!("Row exists");
        let row = row.unwrap();

        let collectors_str = row.get::<String>(2)?;
        trace!("Collectors value in database: {}", collectors_str);

        let collectors: CollectorColumn = serde_json::from_str(&collectors_str)?;

        update_domain_row(conn, domain, collectors).await
    } else {
        Err(DatabaseError::NoRow)
    }
}

/// Add a domain, returns DatabaseError::RowAlreadyExists if the row already exists
#[instrument(skip(conn), err)]
pub(crate) async fn add_domain(conn: &Connection, domain: Domain) -> Result<(), DatabaseError> {
    let exists = check_exists(conn, &domain.url).await?.is_some();

    if !exists {
        trace!("Domain doesn't exist");
        create_domain_row(conn, domain).await?;

        Ok(())
    } else {
        Err(DatabaseError::RowAlreadyExists)
    }
}

/// Add a pending domain to the pending domains table
#[instrument(err)]
pub(crate) async fn add_pending_domain(
    db_state: &DBState,
    domain: DetectedDomain,
) -> Result<i64, DatabaseError> {
    let conn = db_state.get_connection();

    let mut rows = conn
        .query(
            "INSERT INTO pending_domains (url, collector_data) VALUES ($1, $2) RETURNING rowid",
            [
                domain.url.as_str().into_value()?,
                serde_json::to_string(&domain.collector_info)?.into_value()?,
            ],
        )
        .await?;

    let row_id = if let Some(row) = rows.next().await? {
        trace!("Got row");
        row.get::<i64>(0)?
    } else {
        return Err(DatabaseError::NoRow);
    };

    if !db_state.db_only {
        db_state
            .get_pending_domains()
            .lock()
            .await
            .push(DetectedDomainWithId { domain, row_id });
    }

    db_state.channel_sender.send(1).await?;

    Ok(row_id)
}

/// Add a Vec of pending domains to the pending domains table
#[instrument(skip(domains), fields(domains_len=domains.len()), err)]
pub(crate) async fn add_pending_domains(
    db_state: &DBState,
    domains: Vec<DetectedDomain>,
) -> Result<(), DatabaseError> {
    if domains.is_empty() {
        return Ok(());
    }

    let domains_len = domains.len();

    let conn = db_state.get_connection();
    let tx = conn.transaction().await?;
    let mut domains_with_ids = Vec::with_capacity(domains_len);

    for domain in domains {
        tx.execute(
            "INSERT INTO pending_domains (url, collector_data) VALUES ($1, $2)",
            [
                domain.url.as_str().into_value()?,
                serde_json::to_string(&domain.collector_info)?.into_value()?,
            ],
        )
        .await?;

        let row_id = tx.last_insert_rowid();
        trace!(domain=?domain, "Row Id is {}", row_id);
        domains_with_ids.push(DetectedDomainWithId { domain, row_id });
    }

    tx.commit().await?;

    if !db_state.db_only {
        let mut memory_domains = db_state.get_pending_domains().lock().await;
        memory_domains.reserve(domains_with_ids.len());
        memory_domains.extend(domains_with_ids);
    }

    db_state.channel_sender.send(domains_len).await?;

    Ok(())
}

/// Get at max some amount of pending domains from the pending domains table
#[instrument(skip(conn), err)]
async fn get_pending_from_db(
    conn: &Connection,
    amount: u64,
) -> Result<Vec<DetectedDomainWithId>, DatabaseError> {
    let rows = conn
        .query(
            "SELECT rowid, url, collector_data FROM pending_domains LIMIT $1",
            &[amount],
        )
        .await?;

    let results = rows
        .into_stream()
        .filter_map(|row| async move {
            trace!(row=?row, "Filtering row");

            if row.is_err() {
                error!("Failed to get row: {}", row.err().unwrap());
                return None;
            }

            row.ok()
        })
        .map(|row| {
            let row_id = row.get::<i64>(0)?;
            let url_str = row.get::<String>(1)?;
            let collector_data = row.get::<String>(2)?;
            trace!(
                row_id = row_id,
                url_str = url_str,
                collector_data_str = collector_data,
                "Got data"
            );

            let url = Url::parse(&url_str)?;
            let collector_info: DomainCollectorInfo = serde_json::from_str(&collector_data)?;
            trace!(row_id=row_id, url=?url, collector_info=?collector_info, "Parsed to struct");

            Ok::<DetectedDomainWithId, DatabaseError>(DetectedDomainWithId {
                domain: DetectedDomain {
                    url,
                    collector_info,
                },
                row_id,
            })
        })
        .collect::<Vec<Result<DetectedDomainWithId, DatabaseError>>>()
        .await;

    Ok(results
        .into_iter()
        .filter_map(|domain_res| {
            if domain_res.is_err() {
                let err = domain_res.err().unwrap();

                error!("Failed to get row: {}", err);

                None
            } else {
                domain_res.ok()
            }
        })
        .collect())
}

/// Get pending domains from db, memory, or both depending on settings
#[instrument(skip_all, err)]
pub(crate) async fn get_pending_domains(
    db_state: &DBState,
    amount: u64,
) -> Result<Vec<DetectedDomainWithId>, DatabaseError> {
    if db_state.db_only {
        debug!("Database only, getting from db");
        get_pending_from_db(db_state.get_connection(), amount).await
    } else {
        debug!("Database and Memory, getting from memory first");
        let pending_in_memory = db_state.get_pending_count().await;
        trace!("There are {} domains pending in memory", pending_in_memory);

        if pending_in_memory < amount as usize {
            debug!(
                "There are less domains pending in memory than the amount of domains requested, using db"
            );
            let amount_from_db = amount as usize - pending_in_memory;
            trace!("Getting {} domains from db", amount_from_db);

            let mut pending_domains = db_state.process_pending_batch(amount as usize).await;
            trace!("Got {} domains from memory", pending_domains.len());

            let mut from_db =
                get_pending_from_db(db_state.get_connection(), amount_from_db as u64).await?;
            trace!("Got {} domains from db", from_db.len());

            pending_domains.append(&mut from_db);
            drop(from_db);
            trace!("Got {} total pending domains", pending_domains.len());

            return Ok(pending_domains);
        }

        Ok(db_state.process_pending_batch(amount as usize).await)
    }
}

#[instrument(skip_all, err)]
pub async fn get_amount_pending_db(conn: &Connection) -> Result<u64, DatabaseError> {
    let row = conn
        .query("SELECT COUNT(id) AS cnt FROM pending_domains", params!([]))
        .await?
        .next()
        .await?
        .ok_or(DatabaseError::NoRow)?;

    Ok(row.get(0)?)
}

#[instrument(skip_all, fields(domain_amount=domain_ids.len()), err)]
pub(crate) async fn remove_pending_domains(
    conn: &Connection,
    domain_ids: Vec<i64>,
) -> Result<(), DatabaseError> {
    let tx = conn.transaction().await?;

    for row_id in domain_ids {
        tx.execute("DELETE FROM pending_domains WHERE rowId=$1", &[row_id])
            .await?;

        debug!("Added {} to pending_domains delete transaction", row_id);
    }

    tx.commit().await?;

    Ok(())
}
