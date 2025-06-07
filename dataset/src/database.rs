use crate::collectors::{DetectedDomain, DomainCollectorInfo};
use libsql::params::IntoValue;
use libsql::{Builder, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use url::Url;

pub type CollectorColumn = Vec<DomainCollectorInfo>;

#[derive(Debug, Serialize, Deserialize)]
enum DomainInfo {
    WhoisInfo(String),
    RDAPInfo(String),
}

#[derive(Debug)]
pub(crate) struct Domain {
    pub(crate) url: Url,
    pub(crate) whois_info: DomainInfo,
    pub(crate) collectors: CollectorColumn,
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("LibSQL Error: {0}")]
    LibSQLError(#[from] libsql::Error),

    #[error("No Row where there should be one")]
    NoRow,

    #[error("Could not convert column to type")]
    ColumnConvert,

    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Row Already Exists")]
    RowAlreadyExists,
}

pub(super) async fn connect_to_db(remote: bool) -> libsql::Result<Connection> {
    let db = if remote {
        let url = std::env::var("TURSO_DATABASE_URL").expect("TURSO_DATABASE_URL must be set");
        let token = std::env::var("TURSO_AUTH_TOKEN").expect("TURSO_AUTH_TOKEN must be set");
        Builder::new_remote(url, token).build().await
    } else {
        Builder::new_local(Path::new("./phishing.db")).build().await
    }?;

    db.connect()
}

pub(crate) async fn init_db(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute(include_str!("../assets/dataset_table.sql"), ())
        .await?;

    Ok(())
}

pub(crate) async fn check_exists(conn: &Connection, url: &Url) -> Result<bool, DatabaseError> {
    let rows = conn
        .query("SELECT url from domains WHERE url = $1", &[url.as_str()])
        .await?;

    Ok(rows.column_name(0).is_some())
}

pub(crate) async fn create_domain_row(
    conn: &Connection,
    domain: Domain,
) -> Result<(), DatabaseError> {
    conn.execute(
        "INSERT INTO domains (url, whois_info, collector_info, phishing) VALUES ($1, $2, $3)",
        [
            domain.url.as_str().to_string(),
            serde_json::to_string(&domain.whois_info)?,
            serde_json::to_string(&vec![domain.collectors])?,
        ],
    )
    .await?;

    Ok(())
}

pub(crate) async fn update_domain_row(
    conn: &Connection,
    domain: DetectedDomain,
) -> Result<(), DatabaseError> {
    let mut rows = conn
        .query(
            "SELECT collector_info from domains WHERE url = $1",
            &[domain.url.as_str()],
        )
        .await?;

    let row = rows.next().await?.ok_or(DatabaseError::NoRow)?;

    let column = row.get_value(0)?;

    let collector_info_str = column.as_text().ok_or(DatabaseError::ColumnConvert)?;

    let mut collector_info: CollectorColumn = serde_json::from_str(collector_info_str)?;

    collector_info.push(domain.collector_info);

    conn.prepare("UPDATE domains SET collector_info=$2 WHERE url = $1")
        .await?
        .execute([serde_json::to_string(&collector_info)?])
        .await?;

    Ok(())
}

pub(crate) async fn update_domain(
    conn: &Connection,
    domain: DetectedDomain,
) -> Result<(), DatabaseError> {
    let exists = check_exists(conn, &domain.url).await?;

    if exists {
        update_domain_row(conn, domain).await
    } else {
        Err(DatabaseError::NoRow)
    }
}

pub(crate) async fn add_domain(conn: &Connection, domain: Domain) -> Result<(), DatabaseError> {
    let exists = check_exists(conn, &domain.url).await?;

    if !exists {
        create_domain_row(conn, domain).await?;

        Ok(())
    } else {
        Err(DatabaseError::RowAlreadyExists)
    }
}

pub(crate) async fn add_pending_domain(
    conn: &Connection,
    domain: DetectedDomain,
) -> Result<(), DatabaseError> {
    conn.execute(
        "INSERT INTO pending_domains (url, collector_data) VALUES ($1, $2)",
        [
            domain.url.as_str().into_value()?,
            serde_json::to_string(&domain.collector_info)?.into_value()?,
        ],
    )
    .await?;

    Ok(())
}

pub(crate) async fn add_pending_domains(
    conn: &Connection,
    domains: Vec<DetectedDomain>,
) -> Result<(), DatabaseError> {
    if domains.is_empty() {
        return Ok(());
    }

    let tx = conn.transaction().await?;

    for domain in domains {
        tx.execute(
            "INSERT INTO pending_domains (url, collector_data) VALUES ($1, $2)",
            [
                domain.url.as_str().into_value()?,
                serde_json::to_string(&domain.collector_info)?.into_value()?,
            ],
        )
        .await?;
    }

    tx.commit().await?;

    Ok(())
}
