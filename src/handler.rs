use std::str::FromStr;
use ckb_types::{h160, H160};

use ckb_cli_plugin_protocol::{
    JsonrpcError, JsonrpcRequest, JsonrpcResponse, KeyStoreRequest, PluginConfig, PluginRequest,
    PluginResponse, PluginRole,
};
use ckb_sdk::wallet::{
    DerivationPath, DerivedKeySet
};
use secp256k1::{key::PublicKey};
use ckb_jsonrpc_types::JsonBytes;
use std::convert::TryInto;
use std::io::{self, Write};

use crate::keystore::{
    LedgerKeyStore, LedgerKeyStoreError, target_to_annotated_transaction
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
        // Import {
        //     privkey: [u8; 32],
        //     chain_code: [u8; 32],
        //     password: Option<String>,
        // },
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
        // DerivedKeySet {
        //     hash160: H160,
        //     external_max_len: u32,
        //     change_last: H160,
        //     change_max_len: u32,
        //     password: Option<String>,
        // },
        KeyStoreRequest::DerivedKeySet {
            hash160,
            external_max_len,
            change_last,
            change_max_len,
            password: _
        } => {
            let account = keystore.borrow_account(&hash160)?;
            account.derived_key_set(external_max_len, &change_last, change_max_len).map(|v| derived_key_set_to_response(v))
        }
        // DerivedKeySetByIndex {
        //     hash160: H160,
        //     external_start: u32,
        //     external_length: u32,
        //     change_start: u32,
        //     change_length: u32,
        //     password: Option<String>,
        // },
        KeyStoreRequest::DerivedKeySetByIndex {
            hash160,
            external_start,
            external_length,
            change_start,
            change_length,
            password: _
        } => {
            let account = keystore.borrow_account(&hash160)?;
            let s = account.derived_key_set_by_index(external_start, external_length, change_start, change_length);
            Ok(derived_key_set_to_response(s))
        }
        // Sign {
        //     hash160: H160,
        //     path: String,
        //     message: H256,
        //     target: Box<SignTarget>,
        //     recoverable: bool,
        //     password: Option<String>,
        // },
        KeyStoreRequest::Sign {
            hash160,
            path,
            message: _,
            target,
            recoverable,
            password: _
        } => {
            // eprintln!(
            //     "SignTaret: {}",
            //     serde_json::to_string_pretty(&target).unwrap()
            // );
            let account = keystore.borrow_account(&hash160)?;
            let drv_path = DerivationPath::from_str(&path).unwrap();
            let ledger_cap = account.extended_privkey(drv_path.as_ref())?;
            if recoverable {
                let signature = ledger_cap.begin_sign_recoverable(target_to_annotated_transaction(*target))?;
                Ok(PluginResponse::Bytes(JsonBytes::from_vec(signature)))
            } else {
                Ok(PluginResponse::Error(JsonrpcError {
                    code: 0,
                    message: String::from("Non recoverable signing not supported"),
                    data: None,
                }))
            }
        }
        _ => {
            Ok(PluginResponse::Error(JsonrpcError {
                code: 0,
                message: String::from("Not supported yet"),
                data: None,
            }))
        }
    }
}

fn derived_key_set_to_response (v:DerivedKeySet) -> PluginResponse {
    PluginResponse::DerivedKeySet {
        external: v.external.into_iter().map(|(p, k)| (p.to_string(),k) ).collect(),
        change: v.change.into_iter().map(|(p, k)| (p.to_string(),k) ).collect(),
    }
}
