mod collectors;
mod commands;
mod database;

use crate::database::init_db;
use clap::{Parser, Subcommand};
use collectors::{safebrowsing::SafebrowsingClient, whois::get_whois_domain};
use commands::{
    phishtank::{PhishTankCommand, phishtank_command},
    safebrowsing::{SafebrowsingCommand, safebrowsing_command},
    whois::{WhoIsCommand, whois_command},
};
use database::connect_to_db;
use dotenv::dotenv;
use log::debug;
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use std::sync::Arc;
use whois_rust::WhoIs;

const WHOIS_SERVERS: &str = include_str!("../assets/servers.json");

#[derive(Parser, Debug)]
#[command(name = "program")]
struct Arguments {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "whois")]
    WhoIs(WhoIsCommand),
    #[command(name = "gsb")]
    GoogleSafeBrowsing(SafebrowsingCommand),
    #[command(name = "phishtank")]
    PhishTank(PhishTankCommand),
}

fn get_whois_client() -> WhoIs {
    let whois = WhoIs::from_string(WHOIS_SERVERS).expect("Should be able to load servers");
    debug!("Loaded Whois server data");

    whois
}

fn get_gsb_client(client: Arc<ClientWithMiddleware>) -> SafebrowsingClient {
    let gsb_api_key = std::env::var("GSB_API_KEY").expect("Should be able to get gsb api key");

    let client = SafebrowsingClient::new(client, gsb_api_key);
    debug!("Created GSB client");

    client
}

#[tokio::main]
async fn main() {
    env_logger::init();

    dotenv().expect("Should be able to load environment variables");
    debug!("Loaded environment variables from dotenv");

    let conn = connect_to_db(false)
        .await
        .expect("Should be able to connect to database");
    debug!("Connected to database");
    init_db(&conn)
        .await
        .expect("Should be able to init database");
    debug!("Init'd database");
    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
    let client = Arc::new(
        ClientBuilder::new(Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build(),
    );

    let args = Arguments::parse();
    match args.command {
        Commands::WhoIs(command) => {
            whois_command(&get_whois_client(), command).await.unwrap();
        }
        Commands::GoogleSafeBrowsing(command) => {
            safebrowsing_command(get_gsb_client(client), command)
                .await
                .unwrap();
        }
        Commands::PhishTank(command) => phishtank_command(&client, get_whois_client(), command)
            .await
            .unwrap(),
    }
}
