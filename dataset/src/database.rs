use crate::collectors::{DetectedDomain, DomainCollectorInfo};
use futures::StreamExt;
use libsql::params::IntoValue;
use libsql::{Builder, Connection, Row};
use log::error;
use serde::{Deserialize, Serialize};
use std::mem::discriminant;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};
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
#[derive(Debug)]
pub struct DBState {
    conn: Connection,
    db_only: bool,
    /// Pending domains only from this run, None if db_only is true
    pending_domains: Option<Arc<Mutex<Vec<DetectedDomainWithId>>>>,
    /// Channel sender for the amount of pending domains added to the db/in-memory map
    channel_sender: Sender<usize>,
    /// Channel receiver for the amount of pending domains added to the db/in-memory map
    channel_receiver: Receiver<usize>,
}

impl DBState {
    /// Create a new Database State object.
    /// Should only be called once.
    fn new(conn: Connection, db_only: bool) -> Self {
        let (tx, rx): (Sender<usize>, Receiver<usize>) = mpsc::channel(5);

        Self {
            conn,
            db_only,
            pending_domains: if db_only {
                None
            } else {
                Some(Arc::new(Mutex::new(Vec::new())))
            },
            channel_sender: tx,
            channel_receiver: rx,
        }
    }

    /// Get the raw connection object for the database
    pub fn get_connection(&self) -> &Connection {
        &self.conn
    }

    /// Get min(batch_size, length) pending domains from the in-memory pending domains list
    async fn process_pending_batch(&self, batch_size: usize) -> Vec<DetectedDomainWithId> {
        let pending_domains = self.get_pending_domains();
        let mut domains = pending_domains.lock().await;
        let batch_end = batch_size.min(domains.len());
        domains.drain(..batch_end).collect()
    }

    /// Get the amount of pending domains in memory
    pub async fn get_pending_count(&self) -> usize {
        if self.pending_domains.is_none() {
            return 0;
        }

        self.get_pending_domains().lock().await.len()
    }

    /// Check if in memory pending domains in enabled
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
    RDAPInfo(String),
}

/// A processed domain that can be added to the training set
#[derive(Debug, Clone)]
pub(crate) struct Domain {
    pub(crate) url: Url,
    pub(crate) whois_info: DomainInfo,
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
}

/// Connect to the database and return a DBState object
pub(super) async fn connect_to_db(remote: bool, db_only: bool) -> libsql::Result<DBState> {
    let db = if remote {
        let url = std::env::var("TURSO_DATABASE_URL").expect("TURSO_DATABASE_URL must be set");
        let token = std::env::var("TURSO_AUTH_TOKEN").expect("TURSO_AUTH_TOKEN must be set");
        Builder::new_remote(url, token).build().await
    } else {
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
pub(crate) async fn update_domain(
    conn: &Connection,
    domain: DetectedDomain,
) -> Result<(), DatabaseError> {
    let row = check_exists(conn, &domain.url).await?;

    if row.is_some() {
        let row = row.unwrap();

        let collectors_str = row.get::<String>(2)?;

        let collectors: CollectorColumn = serde_json::from_str(&collectors_str)?;

        update_domain_row(conn, domain, collectors).await
    } else {
        Err(DatabaseError::NoRow)
    }
}

/// Add a domain, returns DatabaseError::RowAlreadyExists if the row already exists
pub(crate) async fn add_domain(conn: &Connection, domain: Domain) -> Result<(), DatabaseError> {
    let exists = check_exists(conn, &domain.url).await?.is_some();

    if !exists {
        create_domain_row(conn, domain).await?;

        Ok(())
    } else {
        Err(DatabaseError::RowAlreadyExists)
    }
}

/// Add a pending domain to the pending domains table
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

            let url = Url::parse(&url_str)?;
            let collector_info: DomainCollectorInfo = serde_json::from_str(&collector_data)?;

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
pub(crate) async fn get_pending_domains(
    db_state: &mut DBState,
    amount: u64,
) -> Result<Vec<DetectedDomainWithId>, DatabaseError> {
    if db_state.db_only {
        get_pending_from_db(db_state.get_connection(), amount).await
    } else {
        let pending_in_memory = db_state.get_pending_count().await;

        if pending_in_memory < amount as usize {
            let amount_from_db = pending_in_memory - amount as usize;

            let mut pending_domains = db_state.process_pending_batch(amount as usize).await;

            let mut from_db =
                get_pending_from_db(db_state.get_connection(), amount_from_db as u64).await?;

            pending_domains.append(&mut from_db);
            drop(from_db);

            return Ok(pending_domains);
        }

        Ok(db_state.process_pending_batch(amount as usize).await)
    }
}
