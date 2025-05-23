mod database;

use std::net::IpAddr;
use whois_rust::{WhoIs, WhoIsLookupOptions};

const WHOIS_SERVERS: &str = include_str!("servers.json");

struct Domain {
    root: String,
    subdomain: Option<String>,
    whois_info: String,
    ip: Option<IpAddr>
}

#[tokio::main]
async fn main() {
    let whois = WhoIs::from_string(WHOIS_SERVERS).expect("Should be able to load servers");
}
