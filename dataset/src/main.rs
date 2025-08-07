mod collectors;
mod commands;
mod converter;
mod database;
mod processor;

use crate::collectors::DomainInfoClient;
use crate::collectors::autowhois::AutoWhoisClient;
use crate::collectors::rdap::RDAPClient;
use crate::collectors::sslmate::SslMateClient;
use crate::collectors::whois::WhoisClient;
use crate::commands::legitphish::{LegitPhishCommand, legit_phish_command};
use crate::commands::mendeley_kb::{MendeleyKBCommand, mendeley_k_b_command};
use crate::database::{DBState, init_db};
use crate::processor::{create_processor, wait_until_finished};
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
use std::sync::atomic::{AtomicBool, Ordering};
use tldextract::TldOption;
use tokio::signal;
use tokio::task::JoinHandle;
use tracing::level_filters::LevelFilter;
use tracing::{debug, info};

#[derive(Parser, Debug, Clone)]
#[command(name = "program")]
struct Arguments {
    #[arg(short, long, default_value_t = false)]
    no_analysis: bool,

    #[arg(long, default_value_t = true)]
    use_gsb: bool,

    #[arg(short, long, default_value_t = false)]
    db_only: bool,

    #[arg(long, default_value_t = false)]
    /// Whether to use time to live (true) or time to idle (false) for the cache.
    /// Does nothing if db_only.
    use_time_to_live: bool,

    #[arg(short, long, default_value_t = 600)]
    /// The duration in seconds for a key in the memory cache to expire.
    /// Does nothing if db_only.
    /// 0 means no expiry.
    time_to_expiry: u64,

    #[arg(long, default_value_t = 0)]
    /// Max size for an in memory cache.
    /// Does nothing if db_only.
    /// 0 means no max size.
    max_cache_size: u64,

    #[arg(long, default_value_t = 500)]
    /// The max amount of domains for the processor to handle at once.
    /// If the value is less than the amount of domains to process the amount will be split into chunks and processed individually.
    /// This is useful if you have a large chunk of domains, and want to delete them incrementally.
    max_domains_to_process: usize,

    #[arg(long, default_value_t = 10)]
    /// The max number of domains to process concurrently.
    max_concurrent_domains: usize,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    #[command(name = "whois")]
    WhoIs(WhoIsCommand),
    #[command(subcommand, name = "gsb")]
    GoogleSafeBrowsing(SafebrowsingCommand),
    #[command(name = "phishtank")]
    PhishTank(PhishTankCommand),
    #[command(name = "phishstorm")]
    PhishStorm(PhishStormCommand),
    #[command(name = "legitphish")]
    LegitPhish(LegitPhishCommand),
    #[command(name = "mendeleykb")]
    MendeleyKB(MendeleyKBCommand),
    #[command(name = "auto")]
    Auto,
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

async fn get_ssl_mate_client(
    client: Arc<ClientWithMiddleware>,
    memory: bool,
    db_state: Arc<DBState>,
) -> SslMateClient {
    let ssl_mate_api_key =
        std::env::var("SSLMATE_API_KEY").expect("Should be able to get ssl mate api key");

    let client = SslMateClient::new(client, ssl_mate_api_key, memory, db_state).await;
    debug!("Created SslMate client");

    client
}

async fn get_auto_whois_client(
    client: Arc<ClientWithMiddleware>,
    memory: bool,
    db_state: Arc<DBState>,
) -> AutoWhoisClient {
    let ssl_mate_api_key =
        std::env::var("AUTOWHOIS_API_KEY").expect("Should be able to get ssl mate api key");

    let client = AutoWhoisClient::new(client, ssl_mate_api_key, memory, db_state).await;
    debug!("Created AutoWhois client");

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

#[derive(Debug)]
struct ProcessorInfo {
    shutdown: Arc<AtomicBool>,
    processor_task: JoinHandle<()>,
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

    let (db_state, receiver) = connect_to_db(false, &args)
        .await
        .expect("Should be able to connect to database");
    debug!("Connected to database");
    init_db(db_state.get_connection())
        .await
        .expect("Should be able to init database");
    debug!("Init'd database");

    let db_state = Arc::new(db_state);

    let tld_extractor = Arc::new(TldOption::default().build());

    let whois = Arc::new(WhoisClient::new(args.db_only, db_state.clone()).await);

    let rdap_client = Arc::new(RDAPClient::new(args.db_only, db_state.clone()).await);

    let client = get_reqwest_middleware_client();

    let mut domain_info_processors: Vec<Arc<dyn DomainInfoClient>> = Vec::new();
    domain_info_processors.push(Arc::new(
        get_auto_whois_client(client.clone(), args.db_only, db_state.clone()).await,
    ));
    domain_info_processors.push(rdap_client);
    domain_info_processors.push(whois.clone());

    let shutdown = Arc::new(AtomicBool::new(false));

    {
        let shutdown = shutdown.clone();

        tokio::spawn(async move {
            signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
            info!("Ctrl+C received. Will stop after current domain processing.");
            shutdown.store(true, Ordering::SeqCst);
        });
    }

    let processor = create_processor(
        db_state.clone(),
        tld_extractor.clone(),
        Arc::from(domain_info_processors),
        Arc::new(get_ssl_mate_client(client.clone(), args.db_only, db_state.clone()).await),
        if args.use_gsb {
            Arc::new(Some(
                get_gsb_client(client.clone(), args.db_only, db_state.clone()).await,
            ))
        } else {
            Arc::new(None)
        },
        shutdown.clone(),
        receiver,
    );
    debug!("Created domain processor thread");

    let processor_info = ProcessorInfo {
        shutdown: shutdown.clone(),
        processor_task: processor,
    };

    match args.command {
        Commands::WhoIs(command) => {
            whois_command(&whois, &tld_extractor, command)
                .await
                .unwrap();
        }
        Commands::GoogleSafeBrowsing(command) => {
            safebrowsing_command(
                get_gsb_client(client.clone(), args.db_only, db_state.clone()).await,
                db_state.clone(),
                command,
            )
            .await
            .unwrap();
        }
        Commands::PhishTank(command) => phishtank_command(
            &client,
            &db_state,
            processor_info,
            command,
            args.no_analysis,
        )
        .await
        .unwrap(),
        Commands::PhishStorm(command) => {
            phishstorm_command(client, &db_state, processor_info, command, args.no_analysis)
                .await
                .unwrap()
        }
        Commands::LegitPhish(command) => {
            legit_phish_command(client, &db_state, processor_info, command, args.no_analysis)
                .await
                .unwrap()
        }
        Commands::MendeleyKB(command) => {
            mendeley_k_b_command(client, &db_state, processor_info, command, args.no_analysis)
                .await
                .unwrap()
        }
        Commands::Auto => {
            wait_until_finished(processor_info, &db_state)
                .await
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock, Once};
    use tldextract::{TldExtractor, TldOption};
    use tracing::level_filters::LevelFilter;

    static INIT: Once = Once::new();

    pub(crate) static TLD_EXTRACTOR: LazyLock<Arc<TldExtractor>> =
        LazyLock::new(|| Arc::new(TldOption::default().build()));

    pub fn init() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_line_number(true)
                .with_env_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                )
                .with_test_writer()
                .with_thread_ids(true)
                .init();
        });
    }
}
