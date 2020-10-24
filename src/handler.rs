use ckb_types::{bytes::Bytes, H256};
use std::str::FromStr;

use ckb_cli_plugin_protocol::{
    JsonrpcError, KeyStoreRequest, PluginConfig, PluginRequest, PluginResponse, PluginRole,
    SignTarget,
};
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::wallet::{DerivationPath, DerivedKeySet};

use crate::keystore::{to_annotated_transaction, CanDeriveSecp256k1PublicKey, LedgerId, LedgerKeyStore, LedgerKeyStoreError};

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
                })),
            }
        }
        _ => Some(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("Invalid request to keystore"),
            data: None,
        })),
    }
}

fn keystore_handler(
    keystore: &mut LedgerKeyStore,
    request: KeyStoreRequest,
) -> Result<PluginResponse, LedgerKeyStoreError> {
    match request {
        KeyStoreRequest::ListAccount => {
            let ledger_ids = keystore.discovered_devices();
            let lockargs = keystore.list_accounts()?;
            let payload1: Vec<_> = ledger_ids
                .iter()
                .map(|LedgerId(v)| {
                    ckb_jsonrpc_types::JsonBytes::from_bytes(Bytes::from(v.as_bytes().to_vec()))
                })
                .collect();
            let payload2 = lockargs
                .iter()
                .map(|v| {
                    ckb_jsonrpc_types::JsonBytes::from_bytes(Bytes::from(v.as_bytes().to_vec()))
                })
                .collect();
            let payload = [payload1, payload2].concat();
            Ok(PluginResponse::BytesVec(payload))
        }
        KeyStoreRequest::HasAccount(lock_arg) => {
            if let Ok(b) = keystore.has_account(&lock_arg) {
                Ok(PluginResponse::Boolean(b))
            } else {
                Ok(PluginResponse::Boolean(false))
            }
        }
        KeyStoreRequest::CreateAccount(_) => Ok(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from(
                "Create account is not supported for Ledger, try 'ledger import' command instead",
            ),
            data: None,
        })),
        KeyStoreRequest::UpdatePassword { .. } => Ok(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("Update password is not a valid operation for Ledger"),
            data: None,
        })),
        // Import {
        //     privkey: [u8; 32],
        //     chain_code: [u8; 32],
        //     password: Option<String>,
        // },
        KeyStoreRequest::Import { .. } => Ok(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("'account import' is not available for Ledger"),
            data: None,
        })),
        // ImportAccount {
        //     account_id: JsonBytes,
        //     password: Option<String>,
        // },
        KeyStoreRequest::ImportAccount {
            account_id,
            password: _,
        } => {
            let ledger_id: H256 = H256::from_slice(&account_id.into_bytes()).unwrap();
            let h160 = keystore.import_account(LedgerId(ledger_id))?;
            Ok(PluginResponse::H160(h160))
        }
        KeyStoreRequest::Export { .. } => Ok(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("'account export' is not available for Ledger"),
            data: None,
        })),
        // ExtendedPubkey {
        //     hash160: H160,
        //     path: String,
        //     password: Option<String>,
        // },
        KeyStoreRequest::ExtendedPubkey {
            hash160,
            path,
            password: _,
        } => {
            let master = keystore.borrow_account(&hash160)?;
            let drv_path = DerivationPath::from_str(&path).unwrap();
            let public_key = master.as_ledger_cap()
                .child_from_root_path(drv_path.as_ref())?
                .public_key_prompt()?;
            Ok(PluginResponse::Bytes(JsonBytes::from_vec(
                public_key.serialize().to_vec(),
            )))
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
            password: _,
        } => {
            let account = keystore.borrow_account(&hash160)?;
            account
                .derived_key_set(external_max_len, &change_last, change_max_len)
                .map(|v| derived_key_set_to_response(v))
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
            password: _,
        } => {
            let account = keystore.borrow_account(&hash160)?;
            let s = account.derived_key_set_by_index(
                external_start,
                external_length,
                change_start,
                change_length,
            );
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
            password: _,
        } => {
            // eprintln!(
            //     "SignTaret: {}",
            //     serde_json::to_string_pretty(&target).unwrap()
            // );
            let master = keystore.borrow_account(&hash160)?;
            let drv_path = DerivationPath::from_str(&path).unwrap();
            let ledger_cap = master.as_ledger_cap().child_from_root_path(drv_path.as_ref())?;
            let sign_msg = |(msg, display_hex)| -> Result<_, LedgerKeyStoreError> {
                let magic_string = String::from("Nervos Message:");
                let magic_bytes = magic_string.as_bytes();
                let msg_with_magic = [magic_bytes, msg].concat();
                let signature =
                    ledger_cap.sign_message_recoverable(&msg_with_magic, display_hex)?;
                let json_bytes = if recoverable {
                    JsonBytes::from_vec(serialize_signature(&signature).to_vec())
                } else {
                    JsonBytes::from_vec(signature.to_standard().serialize_compact().to_vec())
                };
                Ok(PluginResponse::Bytes(json_bytes))
            };
            match *target {
                SignTarget::Transaction {
                    tx,
                    inputs,
                    change_path,
                } => {
                    let signing_lock_arg = crate::keystore::hash_public_key(&ledger_cap.secp256k1_extended_public_key().public_key);
                    let signature = ledger_cap.begin_sign_recoverable(to_annotated_transaction(
                        tx,
                        inputs,
                        signing_lock_arg,
                        change_path,
                    ))?;
                    Ok(PluginResponse::Bytes(JsonBytes::from_vec(signature)))
                }
                SignTarget::AnyString(string) => sign_msg((&string.as_bytes(), false)),
                SignTarget::AnyData(to_sign) => sign_msg((&to_sign.as_bytes(), true)),
                SignTarget::AnyMessage(h256) => {
                    let signature = ledger_cap.sign_message_hash(&h256.as_bytes())?;
                    let json_bytes = if recoverable {
                        JsonBytes::from_vec(serialize_signature(&signature).to_vec())
                    } else {
                        JsonBytes::from_vec(signature.to_standard().serialize_compact().to_vec())
                    };
                    Ok(PluginResponse::Bytes(json_bytes))
                }
            }
        }
        _ => Ok(PluginResponse::Error(JsonrpcError {
            code: 0,
            message: String::from("Not supported yet"),
            data: None,
        })),
    }
}

fn derived_key_set_to_response(v: DerivedKeySet) -> PluginResponse {
    PluginResponse::DerivedKeySet {
        external: v
            .external
            .into_iter()
            .map(|(p, k)| (p.to_string(), k))
            .collect(),
        change: v
            .change
            .into_iter()
            .map(|(p, k)| (p.to_string(), k))
            .collect(),
    }
}

pub fn serialize_signature(signature: &secp256k1::recovery::RecoverableSignature) -> [u8; 65] {
    let (recov_id, data) = signature.serialize_compact();
    let mut signature_bytes = [0u8; 65];
    signature_bytes[0..64].copy_from_slice(&data[0..64]);
    signature_bytes[64] = recov_id.to_i32() as u8;
    signature_bytes
}
