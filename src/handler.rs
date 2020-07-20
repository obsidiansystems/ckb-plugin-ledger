use ckb_types::{h160, H160};

use ckb_cli_plugin_protocol::{
    JsonrpcError, JsonrpcRequest, JsonrpcResponse, KeyStoreRequest, PluginConfig, PluginRequest,
    PluginResponse, PluginRole,
};
use ckb_jsonrpc_types::JsonBytes;
use std::convert::TryInto;
use std::io::{self, Write};

use crate::keystore::{
    LedgerKeyStore,
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
            Some(keystore_handler(keystore, keystore_request))
        }
        _ => Some(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("Invalid request to keystore"),
            data: None,
        })),
    }
}

fn keystore_handler (keystore: &mut LedgerKeyStore, request: KeyStoreRequest) -> PluginResponse {
    match request {
        KeyStoreRequest::ListAccount => {
            let accounts = keystore.list_accounts();
            PluginResponse::H160Vec(accounts)
        }
        KeyStoreRequest::HasAccount(_) => PluginResponse::Boolean(true),
        KeyStoreRequest::CreateAccount(_) => {
            PluginResponse::H160(h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"))
        }
        KeyStoreRequest::UpdatePassword { .. } => PluginResponse::Ok,
        KeyStoreRequest::Import { .. } => {
            PluginResponse::H160(h160!("0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"))
        }
        KeyStoreRequest::Export { .. } => PluginResponse::MasterPrivateKey {
            privkey: JsonBytes::from_vec(vec![3u8; 32]),
            chain_code: JsonBytes::from_vec(vec![4u8; 32]),
        },
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
            PluginResponse::Bytes(JsonBytes::from_vec(signature))
        }
        KeyStoreRequest::ExtendedPubkey { .. } => {
            PluginResponse::Bytes(JsonBytes::from_vec(vec![
                0x02, 0x53, 0x1f, 0xe6, 0x06, 0x81, 0x34, 0x50, 0x3d, 0x27, 0x23, 0x13,
                0x32, 0x27, 0xc8, 0x67, 0xac, 0x8f, 0xa6, 0xc8, 0x3c, 0x53, 0x7e, 0x9a,
                0x44, 0xc3, 0xc5, 0xbd, 0xbd, 0xcb, 0x1f, 0xe3, 0x37,
            ]))
        }
        KeyStoreRequest::DerivedKeySet { .. } => PluginResponse::DerivedKeySet {
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
        },
        KeyStoreRequest::DerivedKeySetByIndex { .. } => PluginResponse::DerivedKeySet {
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
        },
        _ => {
            PluginResponse::Error(JsonrpcError {
                code: 0,
                message: String::from("Not supported yet"),
                data: None,
            })
        }
    }
}
