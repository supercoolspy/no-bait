use std::{net::IpAddr, path::Path};
use std::fmt::Display;
use libsql::{Builder, Connection};
use libsql::params::IntoValue;
use thiserror::Error;
use url::Url;
use crate::collectors::{DetectedDomain, DomainCollectorInfo};

pub type DetectionColumn = Vec<DomainCollectorInfo>;

#[derive(Debug)]
pub(crate) struct Domain {
    pub(crate) url: Url,
    pub(crate) whois_info: String,
    pub(crate) detection: DetectionColumn
}

#[derive(Debug, Error)]
enum DatabaseError {
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
    let rows = conn.query("SELECT url from domains WHERE url = $1", &[url.as_str()]).await?;

    Ok(rows.column_name(0).is_some())
}

pub(crate) async fn create_domain_row(conn: &Connection, domain: Domain) -> Result<(), DatabaseError> {
    conn.execute(
        "INSERT INTO domains (url, whois_info, ip, category) VALUES ($1, $2, $3, $4)",
        [
            domain.url.as_str().to_string(),
            domain.whois_info,
            serde_json::to_string(&domain.detection)?,
        ],
    )
        .await?;

    Ok(())
}

pub(crate) async fn update_domain_row(conn: &Connection, domain: DetectedDomain) -> Result<(), DatabaseError> {
    let mut rows = conn.query("SELECT extra_info from domains WHERE url = $1", &[domain.url.as_str()]).await?;

    let row = rows.next().await?.ok_or(DatabaseError::NoRow)?;

    let column = row.get_value(0)?;
    
    let extra_info_str = column.as_text().ok_or(DatabaseError::ColumnConvert)?;

    let mut extra_info: DetectionColumn = serde_json::from_str(extra_info_str)?;

    extra_info.push(domain.collector_info);
    
    conn.prepare("UPDATE domains SET extra_info=$2 WHERE url = $1").await?
        .execute([serde_json::to_string(&extra_info)?]).await?;

    Ok(())
}

pub(crate) async fn update_domain(conn: &Connection, domain: DetectedDomain) -> Result<(), DatabaseError> {
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
