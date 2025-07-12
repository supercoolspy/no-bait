use clap::Args;
use tracing::instrument;
use url::Url;
use whois_rust::WhoIs;

use crate::collectors::whois::WhoIsError;
use crate::collectors::whois::WhoisClient;

#[derive(Args, Debug)]
pub(crate) struct WhoIsCommand {
    website: String,
}

#[instrument(skip(whois))]
pub(crate) async fn whois_command(
    whois: &WhoisClient,
    command: WhoIsCommand,
) -> Result<(), WhoIsError> {
    let website: Url = command.website.parse().unwrap();

    let whois_info = whois.get_whois_domain(&website).await?;

    println!("Domain: {}\nWhois Data: {}", website.as_str(), whois_info);

    Ok(())
}
