pub(super) mod phishtank;
/// Google safebrowsing
pub(super) mod safebrowsing;
/// Official Whois Data
pub(super) mod whois;

#[cfg(test)]
mod tests {
    use crate::collectors::phishtank::get_latest_data;
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;

    #[tokio::test]
    async fn get_phishtank_data() {
        get_latest_data(
            &ClientBuilder::new(Client::new()).build(),
            "supercoolspy".to_string(),
        )
        .await
        .unwrap();
    }
}
