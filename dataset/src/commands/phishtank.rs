use clap::Args;
use reqwest_middleware::ClientWithMiddleware;
use whois_rust::WhoIs;

use crate::collectors::phishtank::{
    PhishTankError, get_data_local, get_latest_data,
};
use crate::collectors::ToDetectedDomain;

#[derive(Args, Debug)]
pub(crate) struct PhishTankCommand {
    #[arg(short, long, default_value_t = false)]
    local: bool,
    #[arg(short, long, default_value_t = false)]
    no_analysis: bool,
}

pub(crate) async fn phishtank_command(
    client: &ClientWithMiddleware,
    whois: WhoIs,
    command: PhishTankCommand,
) -> Result<(), PhishTankError> {
    let dataset = if command.local {
        get_data_local().await?
    } else {
        get_latest_data(client, env!("CARGO_PKG_NAME").to_owned()).await?
    };

    if !command.no_analysis {
        let info = dataset.to_detected_domain()?;
        println!("{:?}", info);
    }

    Ok(())
}
