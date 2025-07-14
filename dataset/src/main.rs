mod collectors;
mod commands;
mod converter;
mod database;
mod processor;

use crate::collectors::rdap::RDAPClient;
use crate::collectors::whois::WhoisClient;
use crate::database::{DBState, init_db};
use crate::processor::create_processor;
use clap::{Parser, Subcommand, arg};
use collectors::safebrowsing::SafebrowsingClient;
use commands::{
    phishstorm::{PhishStormCommand, phishstorm_command},
    phishtank::{PhishTankCommand, phishtank_command},
    safebrowsing::{SafebrowsingCommand, safebrowsing_command},
    whois::{WhoIsCommand, whois_command},
};
use database::connect_to_db;
use dotenvy::dotenv;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use std::sync::Arc;
use tracing::debug;
use tracing::level_filters::LevelFilter;

const WHOIS_SERVERS: &str = include_str!("../assets/servers.json");

#[derive(Parser, Debug)]
#[command(name = "program")]
struct Arguments {
    #[arg(short, long, default_value_t = false)]
    no_analysis: bool,

    #[arg(short, long, default_value_t = true)]
    use_gsb: bool,

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

async fn get_gsb_client(
    client: Arc<ClientWithMiddleware>,
    memory: bool,
    db_state: Arc<DBState>,
) -> SafebrowsingClient {
    let gsb_api_key = std::env::var("GSB_API_KEY").expect("Should be able to get gsb api key");

    let client = SafebrowsingClient::new(client, gsb_api_key, memory, db_state).await;
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
    tracing_subscriber::fmt()
        .with_line_number(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_thread_ids(true)
        .init();

    dotenv().expect("Should be able to load environment variables");
    debug!("Loaded environment variables from dotenv");

    let args = Arguments::parse();

    let (db_state, receiver) = connect_to_db(false, args.db_only)
        .await
        .expect("Should be able to connect to database");
    debug!("Connected to database");
    init_db(db_state.get_connection())
        .await
        .expect("Should be able to init database");
    debug!("Init'd database");

    let db_state = Arc::new(db_state);

    let whois = Arc::new(WhoisClient::new(args.db_only, db_state.clone()).await);

    let rdap_client = Arc::new(RDAPClient::new(args.db_only, db_state.clone()).await);

    let client = get_reqwest_middleware_client();

    create_processor(
        db_state.clone(),
        whois.clone(),
        rdap_client,
        if args.use_gsb {
            Arc::new(Some(
                get_gsb_client(client.clone(), args.db_only, db_state.clone()).await,
            ))
        } else {
            Arc::new(None)
        },
        receiver,
    );
    debug!("Created domain processor thread");

    match args.command {
        Commands::WhoIs(command) => {
            whois_command(&whois, command).await.unwrap();
        }
        Commands::GoogleSafeBrowsing(command) => {
            safebrowsing_command(
                get_gsb_client(client.clone(), args.db_only, db_state.clone()).await,
                command,
            )
            .await
            .unwrap();
        }
        Commands::PhishTank(command) => {
            phishtank_command(&client, &db_state, command, args.no_analysis)
                .await
                .unwrap()
        }
        Commands::PhishStorm(command) => {
            phishstorm_command(&client, &db_state, command, args.no_analysis)
                .await
                .unwrap()
        }
    }
}
