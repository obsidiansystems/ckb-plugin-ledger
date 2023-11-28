use std::fmt::Debug;

use bitcoin::util::bip32::{Error as Bip32Error, DerivationPath};
use ckb_types::H160;

use failure::Fail;

use ledger::LedgerError as RawLedgerError;

use super::LedgerId;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "App-agnostic ledger error: {}", _0)]
    RawLedgerError(RawLedgerError),
    #[fail(display = "Ledger with id {:?} not found", _0)]
    LedgerNotFound { id: LedgerId },
    #[fail(display = "Ledger account for lock_arg: {:?} not found", _0)]
    LedgerAccountNotFound(H160),
    #[fail(display = "Search derived address failed: {:?} ", _0)]
    SearchDerivedAddrFailed(H160),
    #[fail(display = "Error in client-side BIP-32 calculations: {}", _0)]
    Bip32Error(Bip32Error),
    #[fail(display = "Error in secp256k1 marshalling: {}", _0)]
    Secp256k1Error(secp256k1::Error),
    #[fail(display = "Error in secp256k1 marshalling: {}", _0)]
    BitcoinSecp256k1Error(bitcoin::secp256k1::Error),
    #[fail(
        display = "Error when parsing ledger response, remaining response too short to parse: expected {} bytes, got data {:?}",
        _0, _1
    )]

    RestOfResponseTooShort { expected: usize, tail: Vec<u8> },
    #[fail(
        display = "Error when parsing ledger response, remaining response left over after parse: {:?}",
        _0
    )]
    TrailingExtraReponse { tail: Vec<u8> },
    #[fail(
        display = "Illegal derivation path the ledger app would not accept: {}",
        _0
    )]
    InvalidDerivationPath { path: DerivationPath },
    #[fail(display = "IO Error while doing Ledger KeyStore operation : {}", _0)]
    KeyStoreIOError(std::io::Error),
    #[fail(display = "Error while doing Json decoding : {}", _0)]
    JsonDecodeError(serde_json::error::Error),
}

impl From<RawLedgerError> for Error {
    fn from(err: RawLedgerError) -> Self {
        Error::RawLedgerError(err)
    }
}

impl From<Bip32Error> for Error {
    fn from(err: Bip32Error) -> Self {
        Error::Bip32Error(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::Secp256k1Error(err)
    }
}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(err: bitcoin::secp256k1::Error) -> Self { Error::BitcoinSecp256k1Error(err) }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Self {
        Error::JsonDecodeError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::KeyStoreIOError(err)
    }
}
