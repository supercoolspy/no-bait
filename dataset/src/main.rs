mod collectors;
mod commands;
mod database;
use crate::database::init_db;
use clap::{Parser, Subcommand, arg};
use collectors::{safebrowsing::SafebrowsingClient, whois::get_whois_domain};
use commands::{
    phishstorm::{PhishStormCommand, phishstorm_command},
    phishtank::{PhishTankCommand, phishtank_command},
    safebrowsing::{SafebrowsingCommand, safebrowsing_command},
    whois::{WhoIsCommand, whois_command},
};
use database::connect_to_db;
use dotenv::dotenv;
use log::debug;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use std::sync::Arc;
use whois_rust::WhoIs;

const WHOIS_SERVERS: &str = include_str!("../assets/servers.json");

#[derive(Parser, Debug)]
#[command(name = "program")]
struct Arguments {
    #[arg(short, long, default_value_t = false)]
    no_analysis: bool,

    #[arg(short, long, default_value_t = false)]
    db_only: bool,

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
    #[command(name = "phishstorm")]
    PhishStorm(PhishStormCommand),
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

fn get_reqwest_middleware_client() -> Arc<ClientWithMiddleware> {
    let mut headers = HeaderMap::new();

    let user_agent_value = format!(
        "{name} {version}",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION")
    )
    .to_owned();

    headers.insert(
        "User-Agent",
        HeaderValue::from_str(user_agent_value.as_str()).expect("Should be valid header value"),
    );

    let reqwest_normal_client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .build()
        .expect("Should be able to make regular reqwest client");
    debug!("Created normal reqwest client");

    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
    let client = Arc::new(
        ClientBuilder::new(reqwest_normal_client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build(),
    );
    debug!("Created reqwest client with middleware");

    client
}

#[tokio::main]
async fn main() {
    env_logger::init();

    dotenv().expect("Should be able to load environment variables");
    debug!("Loaded environment variables from dotenv");

    let args = Arguments::parse();

    let db_state = connect_to_db(false, args.db_only)
        .await
        .expect("Should be able to connect to database");
    debug!("Connected to database");
    init_db(db_state.get_connection())
        .await
        .expect("Should be able to init database");
    debug!("Init'd database");

    match args.command {
        Commands::WhoIs(command) => {
            whois_command(&get_whois_client(), command).await.unwrap();
        }
        Commands::GoogleSafeBrowsing(command) => {
            safebrowsing_command(get_gsb_client(get_reqwest_middleware_client()), command)
                .await
                .unwrap();
        }
        Commands::PhishTank(command) => phishtank_command(
            &get_reqwest_middleware_client(),
            db_state,
            command,
            args.no_analysis,
        )
        .await
        .unwrap(),
        Commands::PhishStorm(command) => phishstorm_command(
            &get_reqwest_middleware_client(),
            db_state,
            command,
            args.no_analysis,
        )
        .await
        .unwrap(),
    }
}
