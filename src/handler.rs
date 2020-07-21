use std::str::FromStr;
use ckb_types::{h160, H160};

use ckb_cli_plugin_protocol::{
    JsonrpcError, JsonrpcRequest, JsonrpcResponse, KeyStoreRequest, PluginConfig, PluginRequest,
    PluginResponse, PluginRole,
};
use ckb_sdk::wallet::{
    DerivationPath,
};
use secp256k1::{key::PublicKey};
use ckb_jsonrpc_types::JsonBytes;
use std::convert::TryInto;
use std::io::{self, Write};

use crate::keystore::{
    LedgerKeyStore, LedgerKeyStoreError
};

pub fn handle(keystore: &mut LedgerKeyStore, request: PluginRequest) -> Option<PluginResponse> {
    match request {
        PluginRequest::Quit => None,
        PluginRequest::GetConfig => {
            let config = PluginConfig {
                name: String::from("ledger_plugin"),
                description: String::from("Plugin for Ledger"),
                daemon: true,
                roles: vec![PluginRole::KeyStore {
                    require_password: false,
                }],
            };
            Some(PluginResponse::PluginConfig(config))
        }
        PluginRequest::KeyStore(keystore_request) => {
            match keystore_handler(keystore, keystore_request) {
                Ok(resp) => Some(resp),
                Err(e) => Some(PluginResponse::Error(JsonrpcError {
                    code: 0,
                    message: e.to_string(),
                    data: None,
                }))
        }
        }
        _ => Some(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("Invalid request to keystore"),
            data: None,
        })),
    }
}

fn keystore_handler (keystore: &mut LedgerKeyStore, request: KeyStoreRequest) -> Result <PluginResponse, LedgerKeyStoreError> {
    match request {
        KeyStoreRequest::ListAccount => {
            let accounts = keystore.list_accounts();
            Ok(PluginResponse::H160Vec(accounts))
        }
        KeyStoreRequest::HasAccount(lock_arg) =>
            if let Ok (b) = keystore.has_account(&lock_arg) {
                Ok(PluginResponse::Boolean(b))
            } else {
                Ok(PluginResponse::Boolean(false))
            }
        KeyStoreRequest::CreateAccount(_) => {
            Ok(PluginResponse::Error(JsonrpcError {
                code: 0,
                message: String::from("Create account is not supported for Ledger, try 'ledger import' command instead"),
                data: None,
            }))
        }
        KeyStoreRequest::UpdatePassword { .. } => {
            Ok(PluginResponse::Error(JsonrpcError {
                code: 0,
                message: String::from("Update password is not a valid operation for Ledger"),
                data: None,
            }))
        }
        KeyStoreRequest::Import { .. } => {
            Ok(PluginResponse::Error(JsonrpcError {
                code: 0,
                message: String::from("'account import' is not available for Ledger"),
                data: None,
            }))
        }
        KeyStoreRequest::Export { .. } => {
            Ok(PluginResponse::Error(JsonrpcError {
                code: 0,
                message: String::from("'account export' is not available for Ledger"),
                data: None,
            }))
        }
        KeyStoreRequest::Sign {
            recoverable,
            target,
            ..
        } => {
            eprintln!(
                "SignTaret: {}",
                serde_json::to_string_pretty(&target).unwrap()
            );
            let signature = if recoverable {
                vec![1u8; 65]
            } else {
                vec![2u8; 64]
            };
            Ok(PluginResponse::Bytes(JsonBytes::from_vec(signature)))
        }
        // ExtendedPubkey {
        //     hash160: H160,
        //     path: String,
        //     password: Option<String>,
        // },
        KeyStoreRequest::ExtendedPubkey { hash160, path, password: _ } => {
            let account = keystore.borrow_account(&hash160)?;
            let drv_path = DerivationPath::from_str(&path).unwrap();
            let public_key = account.extended_privkey(drv_path.as_ref())?.public_key()?;
            Ok(PluginResponse::Bytes(JsonBytes::from_vec(public_key.serialize().to_vec())))
        }
        KeyStoreRequest::DerivedKeySet { .. } => Ok(PluginResponse::DerivedKeySet {
            external: vec![
                (
                    "m/44'/309'/0'/0/19".to_owned(),
                    h160!("0x13e41d6F9292555916f17B4882a5477C01270142"),
                ),
                (
                    "m/44'/309'/0'/0/20".to_owned(),
                    h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"),
                ),
            ],
            change: vec![
                (
                    "m/44'/309'/0'/1/19".to_owned(),
                    h160!("0x13e41d6F9292555916f17B4882a5477C01270142"),
                ),
                (
                    "m/44'/309'/0'/1/20".to_owned(),
                    h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"),
                ),
            ],
        }),
        KeyStoreRequest::DerivedKeySetByIndex { .. } => Ok(PluginResponse::DerivedKeySet {
            external: vec![
                (
                    "m/44'/309'/0'/0/19".to_owned(),
                    h160!("0x13e41d6F9292555916f17B4882a5477C01270142"),
                ),
                (
                    "m/44'/309'/0'/0/20".to_owned(),
                    h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"),
                ),
            ],
            change: vec![
                (
                    "m/44'/309'/0'/1/19".to_owned(),
                    h160!("0x13e41d6F9292555916f17B4882a5477C01270142"),
                ),
                (
                    "m/44'/309'/0'/1/20".to_owned(),
                    h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"),
                ),
            ],
        }),
        _ => {
            Ok(PluginResponse::Error(JsonrpcError {
                code: 0,
                message: String::from("Not supported yet"),
                data: None,
            }))
        }
    }
}
