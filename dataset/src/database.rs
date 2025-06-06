use std::{net::IpAddr, path::Path};
use std::fmt::Display;
use libsql::{Builder, Connection};
use libsql::params::IntoValue;
use url::Url;
use crate::collectors::DomainCollectorInfo;

#[derive(Debug)]
pub(crate) enum DetectionSource {
    PhishStorm,
    PhishTank,
    GSB,
    NotDetected
}

#[allow(clippy::from_over_into)]
impl Into<DetectionSource> for DomainCollectorInfo {
    fn into(self) -> DetectionSource {
        match self {
            DomainCollectorInfo::PhishTank { .. } => DetectionSource::PhishTank,
            DomainCollectorInfo::PhishStorm { .. } => DetectionSource::PhishStorm
        }
    }
}

impl Display for DetectionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            DetectionSource::PhishStorm => "phishstorm",
            DetectionSource::PhishTank => "phishtank",
            DetectionSource::GSB => "googlesafebrowsing",
            // Just in case, but shouldn't be written to array anyway
            DetectionSource::NotDetected => ""
        };

        write!(f, "{}", name)
    }
}

#[derive(Debug)]
pub(crate) struct Domain {
    pub(crate) url: Url,
    pub(crate) whois_info: String,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) detection: DetectionSource
}

// For when we need to change to an actual error
type DatabaseError = libsql::errors::Error;

pub(super) async fn connect_to_db(remote: bool) -> Result<Connection, DatabaseError> {
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
    let category_op = match domain.detection {
        DetectionSource::NotDetected => None,
        _ => Some(domain.detection.to_string())
    };

    let ip_str = domain.ip.map(|ip| ip.to_string());


    conn.execute(
        "INSERT INTO domains (url, whois_info, ip, category) VALUES ($1, $2, $3, $4)",
        [
            domain.url.as_str().into_value()?,
            domain.whois_info.into_value()?,
            ip_str.into_value()?,
            category_op.into_value()?,
        ],
    )
        .await?;

    Ok(())
}

pub(crate) async fn add_domain(conn: &Connection, domain: Domain) -> Result<(), DatabaseError> {
    let exists = check_exists(conn, &domain.url).await?;
    
    if !exists {
        create_domain_row(conn, domain).await?;

        return Ok(());
    }

    
    
    Ok(())
}
