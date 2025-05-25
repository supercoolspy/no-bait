use std::{net::IpAddr, path::Path};

use libsql::{Builder, Connection, params};

#[derive(Default)]
pub(crate) struct Domain {
    pub(crate) root: String,
    pub(crate) subdomain: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) whois_info: String,
    pub(crate) ip: Option<IpAddr>,
}

pub(super) async fn connect_to_db(remote: bool) -> Result<Connection, libsql::errors::Error> {
    let db = if remote {
        let url = std::env::var("TURSO_DATABASE_URL").expect("TURSO_DATABASE_URL must be set");
        let token = std::env::var("TURSO_AUTH_TOKEN").expect("TURSO_AUTH_TOKEN must be set");
        Builder::new_remote(url, token).build().await
    } else {
        Builder::new_local(Path::new("./phishing.db")).build().await
    }?;

    db.connect()
}

pub(crate) async fn init_db(conn: &Connection) -> Result<(), libsql::errors::Error> {
    conn.execute(include_str!("../assets/dataset_table.sql"), ())
        .await?;

    Ok(())
}

pub(crate) async fn add_domain(domain: Domain) {}
