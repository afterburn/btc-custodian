use crate::error::{ApiError, ApiResult};
use bdk::bitcoin::Network;
use bdk::database::MemoryDatabase;
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::keys::{DerivableKey, ExtendedKey, GeneratableKey};
use bdk::template::Bip84;
use bdk::Wallet;
use std::str::FromStr;
use uuid::Uuid;

pub struct WalletBuilder {
    mnemonic: Option<String>,
    network: Network,
}

impl WalletBuilder {
    pub fn new(_wallet_id: Uuid, network: Network) -> Self {
        Self {
            mnemonic: None,
            network,
        }
    }

    pub fn with_mnemonic(mut self, mnemonic: Option<String>) -> Self {
        self.mnemonic = mnemonic;
        self
    }

    pub fn build(self) -> ApiResult<(Wallet<MemoryDatabase>, String, String)> {
        let mnemonic = self.get_or_generate_mnemonic()?;
        let mnemonic_str = mnemonic.to_string();
        let xkey: ExtendedKey = mnemonic
            .into_extended_key()
            .map_err(|e| ApiError::WalletCreationFailed(e.to_string()))?;

        let xprv = xkey
            .into_xprv(self.network)
            .ok_or_else(|| ApiError::WalletCreationFailed("Failed to derive xprv".to_string()))?;

        let wallet = Wallet::new(
            Bip84(xprv, bdk::KeychainKind::External),
            Some(Bip84(xprv, bdk::KeychainKind::Internal)),
            self.network,
            MemoryDatabase::default(),
        )
        .map_err(|e| ApiError::WalletCreationFailed(e.to_string()))?;

        let descriptor = wallet.get_descriptor_for_keychain(bdk::KeychainKind::External).to_string();

        Ok((wallet, mnemonic_str, descriptor))
    }

    fn get_or_generate_mnemonic(&self) -> ApiResult<Mnemonic> {
        match &self.mnemonic {
            Some(words) => Mnemonic::from_str(words)
                .map_err(|e| ApiError::InvalidMnemonic(e.to_string())),
            None => {
                let generated: bdk::keys::GeneratedKey<_, bdk::miniscript::Segwitv0> = Mnemonic::generate((WordCount::Words12, Language::English))
                    .map_err(|_| ApiError::WalletCreationFailed("Failed to generate mnemonic".to_string()))?;
                Ok(generated.into_key())
            }
        }
    }
}
