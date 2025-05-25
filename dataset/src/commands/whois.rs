
use clap::Args;
use whois_rust::WhoIs;

use crate::{collectors::whois::WhoIsError, get_whois_domain};

#[derive(Args, Debug)]
pub(crate) struct WhoIsCommand {
    website: String,
}

pub(crate) async fn whois_command(whois: &WhoIs, command: WhoIsCommand) -> Result<(), WhoIsError> {
    let info = get_whois_domain(whois, command.website).await?;

    println!("Domain: {}\nWhois Data: {}", info.domain, info.whois_data);

    Ok(())
}
