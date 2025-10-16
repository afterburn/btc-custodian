use bdk::bitcoin::Network;

pub fn parse_network(s: &str) -> Option<Network> {
    match s.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Some(Network::Bitcoin),
        "testnet" | "testnet3" => Some(Network::Testnet),
        "signet" => Some(Network::Signet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

pub fn get_electrum_url(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "ssl://electrum.blockstream.info:50002",
        _ => "ssl://electrum.blockstream.info:60002",
    }
}
