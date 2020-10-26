use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fs;
use std::io::prelude::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use bitflags;
use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use secp256k1::{key::PublicKey, recovery::RecoverableSignature, recovery::RecoveryId};

use ckb_jsonrpc_types::Transaction;
use ckb_types::{
    bytes::Bytes,
    packed::{self, WitnessArgs},
    H160, H256,
};

use bitcoin_hashes::{hash160, Hash};
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;

use ckb_sdk::constants::SECP_SIGNATURE_SIZE;
use ckb_sdk::wallet::{
    ChainCode, ChildNumber, DerivationPath, DerivedKeySet, ExtendedPubKey, Fingerprint, KeyChain,
};
use serde::{Deserialize, Serialize};

use ledger::LedgerError as RawLedgerError;
use ledger::TransportNativeHID as RawLedgerApp;
use ledger::{with_all_ledgers, with_ledger_matching};
use ledger_apdu::APDUCommand;

pub mod apdu;
mod error;
pub mod parse;

pub use error::Error as LedgerKeyStoreError;

use ckb_types::{
    packed::{AnnotatedTransaction, Bip32, Uint32},
    prelude::*,
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub struct LedgerKeyStore {
    data_dir: PathBuf, // For storing extended public keys, never stores any private key
    imported_accounts: HashMap<H160, LedgerAccount>,
}

const MANDATORY_PREFIX: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 44 },
    ChildNumber::Hardened { index: 309 },
];

pub fn fixed_ledger_account_path() -> DerivationPath { DerivationPath::from(MANDATORY_PREFIX).child(ChildNumber::Hardened { index: 0 }) }

pub fn hash_public_key(public_key: &secp256k1::PublicKey) -> H160 {
    H160::from_slice(&blake2b_256(&public_key.serialize()[..])[0..20]).expect("Generate hash(H160) from pubkey failed")
}

// A `LedgerAccount` that has been imported and saved in the wallet
// Note that `path` is not saved in the JSON and is fixed at m/44'/309'/0'; TODO: Make everything after first 2 components configurable
#[derive(Debug, Clone)]
struct LedgerImportedAccount {
    pub account: LedgerAccount,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
// TODO make contain actual id to distinguish between ledgers
pub struct LedgerId(pub H256);

impl LedgerKeyStore {
    pub fn new(dir: PathBuf) -> Self {
        LedgerKeyStore {
            data_dir: dir.clone(),
            imported_accounts: HashMap::new(),
        }
    }

    pub fn list_accounts(&mut self) -> Result<Vec<H160>, LedgerKeyStoreError> {
        self.refresh_dir()?;
        Ok(self.imported_accounts.keys().cloned().collect())
    }

    pub fn has_account(&mut self, lock_arg: &H160) -> Result<bool, LedgerKeyStoreError> {
        self.refresh_dir()?;
        Ok(self.imported_accounts.contains_key(lock_arg))
    }

    pub fn borrow_account(
        &mut self,
        lock_arg: &H160,
    ) -> Result<&LedgerAccount, LedgerKeyStoreError> {
        self.refresh_dir()?;
        self.imported_accounts
            .get(lock_arg)
            .ok_or_else(|| LedgerKeyStoreError::LedgerAccountNotFound(lock_arg.clone()))
    }

    fn wallet_id_filter(desired_ledger_id: &LedgerId) -> impl Fn(&mut RawLedgerApp) -> bool {
        let desired = desired_ledger_id.clone();
        return move |ledger| {
            match LedgerKeyStore::query_ledger_id(ledger) {
                Ok(current_ledger_id) => current_ledger_id == desired,

                // This usually happens when a ledger is on a home screen.
                Err(LedgerKeyStoreError::RawLedgerError(RawLedgerError::APDU(_))) => false,
                Err(err) => {
                    debug!("Ignoring the following error: {}", err);
                    false
                }
            }
        };
    }

    fn query_ledger_id(device: &mut RawLedgerApp) -> Result<LedgerId, LedgerKeyStoreError> {
        let command = apdu::get_wallet_id();
        // This timeout hack prevents a ledger on the homescreen in screensaver mode from blocking
        // for 2.8 hours before failing
        let response = device
            .exchange(&command, Some(2_000))
            .map_err(LedgerKeyStoreError::from);
        debug!("Nervos CKB Ledger app wallet id: {:02x?}", response);
        return response.and_then(|response| {
            let mut resp = &response.data[..];
            // TODO: The ledger app gives us 64 bytes but we only use 32
            // bytes. We should either limit how many the ledger app
            // gives, or take all 64 bytes here.
            let raw_wallet_id = parse::split_off_at(&mut resp, 32)?;
            let _ = parse::split_off_at(&mut resp, 32)?;
            parse::assert_nothing_left(resp)?;
            return Ok(LedgerId(H256::from_slice(raw_wallet_id).unwrap()));
        });
    }

    fn refresh_dir(&mut self) -> Result<(), LedgerKeyStoreError> {
        for entry in fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let mut file = fs::File::open(&path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let account_or_err = ledger_imported_account_from_json(&contents);
                debug!("{:?}", account_or_err);
                let account = account_or_err?.account;
                self.imported_accounts
                    .entry(account.lock_arg())
                    .or_insert(account);
            }
        }
        Ok(())
    }

    pub fn discovered_devices<'a>(&'a mut self) -> Vec<LedgerId> {
        let mut discovered_ids = Vec::new();
        let res = with_all_ledgers(&mut |mut ledger| {
            // Note: Choosing to ignore the error here
            if let Ok(ledger_id) = LedgerKeyStore::query_ledger_id(&mut ledger) {
                if !self
                    .imported_accounts
                    .values()
                    .any(|lmc| ledger_id == lmc.ledger_id)
                {
                    discovered_ids.push(ledger_id);
                }
            }
            return Ok(());
        });
        return res.map_or(Vec::new(), |_| discovered_ids);
    }

    pub fn import_account<'a>(
        &'a mut self,
        account_id: LedgerId,
    ) -> Result<H160, LedgerKeyStoreError> {
        let get_ledger_with_id = LedgerKeyStore::wallet_id_filter(&account_id);
        let res = with_ledger_matching(get_ledger_with_id, &mut |ledger_app| {
            let bip_account_index = 0;
            let command = apdu::do_account_import(bip_account_index);
            let response = ledger_app.exchange(&command, None)?;
            debug!(
                "Nervos CBK Ledger app extended pub key raw public key {:02x?}",
                &response
            );
            let mut resp = &response.data[..];
            let len1 = parse::split_first(&mut resp)? as usize;
            let raw_public_key = parse::split_off_at(&mut resp, len1)?;
            let len2 = parse::split_first(&mut resp)? as usize;
            let chain_code = parse::split_off_at(&mut resp, len2)?;
            parse::assert_nothing_left(resp)?;
            let public_key = PublicKey::from_slice(&raw_public_key)?;
            let chain_code = ChainCode(chain_code.try_into().expect("chain_code is not 32 bytes"));
            let path = fixed_ledger_account_path();
            let ext_pub_key_root = ExtendedPubKey {
                depth: path.as_ref().len() as u8,
                parent_fingerprint: {
                    let mut engine = hash160::Hash::engine();
                    engine
                        .write_all(b"`parent_fingerprint` currently unused by Nervos.")
                        .expect("write must ok");
                    Fingerprint::from(&hash160::Hash::from_engine(engine)[0..4])
                },
                child_number: ChildNumber::Hardened { index: 0 },
                public_key,
                chain_code,
            };
            let LedgerId(ledger_id) = &account_id;
            let filepath = self.data_dir.join(ledger_id.to_string());
            let account = LedgerAccount {
                ledger_id: account_id.clone(),
                ext_pub_key_root,
                path,
            };
            let lock_arg = account.lock_arg();
            let json_value = ledger_imported_account_to_json(&LedgerImportedAccount { account: account.clone() })?;
            self.imported_accounts
                .insert(lock_arg.clone(), account );
            fs::File::create(&filepath)
                .and_then(|mut file| file.write_all(json_value.to_string().as_bytes()))
                .map_err(|err| LedgerKeyStoreError::KeyStoreIOError(err))?;
            return Ok(lock_arg);
        });
        match res {
            // Convert this particular error
            Err(LedgerKeyStoreError::RawLedgerError(RawLedgerError::DeviceNotFound)) => {
                Err(LedgerKeyStoreError::LedgerNotFound {
                    id: account_id.clone(),
                })
            }
            _ => res,
        }
    }
}

pub trait CanDeriveSecp256k1PublicKey {
    fn secp256k1_extended_public_key(&self) -> ExtendedPubKey;
    fn derive_secp256k1_public_key(&self, child: ChildNumber) -> Result<ExtendedPubKey, LedgerKeyStoreError> {
        self.secp256k1_extended_public_key().derive_secp256k1_public_key(child)
    }
    fn derive_secp256k1_public_key_by_path(&self, path: &DerivationPath) -> Result<ExtendedPubKey, LedgerKeyStoreError> {
        path.into_iter().fold(Ok(self.secp256k1_extended_public_key()), |pubkey, &child| pubkey?.derive_secp256k1_public_key(child))
    }
}

impl CanDeriveSecp256k1PublicKey for ExtendedPubKey {
    fn secp256k1_extended_public_key(&self) -> ExtendedPubKey { self.clone() }
    fn derive_secp256k1_public_key(&self, child: ChildNumber) -> Result<ExtendedPubKey, LedgerKeyStoreError> {
        self.ckd_pub(&SECP256K1, child).map_err(LedgerKeyStoreError::Bip32Error)
    }
}

pub fn key_chain_to_child_number(key_chain: KeyChain) -> ChildNumber {
    match key_chain {
        KeyChain::External => ChildNumber::Normal { index: 0 },
        KeyChain::Change => ChildNumber::Normal { index: 1},
    }
}

const WRITE_ERR_MSG: &'static str = "IO error not possible when writing to Vec last I checked";

fn derivation_path_to_bytes(path_opt: Option<DerivationPath>) -> Vec<u8> {
    let drv_path = path_opt.unwrap_or(fixed_ledger_account_path());
    let mut bip_path = Vec::new();
    bip_path
        .write_u8(drv_path.as_ref().len() as u8)
        .expect(WRITE_ERR_MSG);
    for &child_num in drv_path.as_ref().iter() {
        bip_path
            .write_u32::<BigEndian>(From::from(child_num))
            .expect(WRITE_ERR_MSG);
    }
    bip_path
}

#[derive(Debug, Clone)]
pub struct LedgerAccount {
    pub ledger_id: LedgerId,
    pub ext_pub_key_root: ExtendedPubKey,
    pub path: DerivationPath,
}

impl CanDeriveSecp256k1PublicKey for LedgerAccount {
    fn secp256k1_extended_public_key(&self) -> ExtendedPubKey { self.ext_pub_key_root }
}

impl LedgerAccount {
    pub fn lock_arg(&self) -> H160 {
        hash_public_key(&self.ext_pub_key_root.public_key)
    }

    pub fn bip44_extended_public_key(
        &self,
        chain: KeyChain,
        index: ChildNumber,
    ) -> Result<ExtendedPubKey, LedgerKeyStoreError> {
        let chain_child_num = key_chain_to_child_number(chain);
        self.derive_secp256k1_public_key(chain_child_num)?.derive_secp256k1_public_key(index)
    }

    pub fn derived_key_set_by_index(
        &self,
        external_start: u32,
        external_length: u32,
        change_start: u32,
        change_length: u32,
    ) -> DerivedKeySet {
        let get_pairs = |chain, start, length| {
            (0..length)
                .map(|i| {
                    let path = fixed_ledger_account_path()
                        .child(key_chain_to_child_number(chain))
                        .child(ChildNumber::Normal { index: i + start });
                    let extended_pubkey = self.bip44_extended_public_key(chain, ChildNumber::from(i + start)).unwrap();
                    (path, hash_public_key(&extended_pubkey.public_key))
                })
                .into_iter()
                .collect::<Vec<_>>()
        };
        DerivedKeySet {
            external: get_pairs(KeyChain::External, external_start, external_length),
            change: get_pairs(KeyChain::Change, change_start, change_length),
        }
    }

    pub fn derived_key_set(
        &self,
        external_max_len: u32,
        change_last: &H160,
        change_max_len: u32,
    ) -> Result<DerivedKeySet, LedgerKeyStoreError> {
        let mut external_key_set = Vec::new();
        for i in 0..external_max_len {
            let chain = key_chain_to_child_number(KeyChain::External);
            let index = ChildNumber::Normal { index: i };
            let path = fixed_ledger_account_path().child(chain).child(index);
            let hash = hash_public_key(&self.derive_secp256k1_public_key(chain)?.derive_secp256k1_public_key(index)?.public_key);
            external_key_set.push((path, hash));
        }

        let mut change_key_set = Vec::new();
        for i in 0..change_max_len {
            let chain = key_chain_to_child_number(KeyChain::Change);
            let index = ChildNumber::Normal { index: i };
            let path = fixed_ledger_account_path().child(chain).child(index);
            let hash = hash_public_key(&self.derive_secp256k1_public_key(chain)?.derive_secp256k1_public_key(index)?.public_key);
            change_key_set.push((path, hash.clone()));
            if change_last == &hash {
                return Ok(DerivedKeySet {
                    external: external_key_set,
                    change: change_key_set,
                });
            }
        }
        Err(LedgerKeyStoreError::SearchDerivedAddrFailed(
            change_last.clone(),
        ))
    }

    pub fn child(&self, child: ChildNumber) -> Result<LedgerAccount, LedgerKeyStoreError> {
        let extended_pubkey = self.derive_secp256k1_public_key(child)?;
        Ok(LedgerAccount {
            ledger_id: self.ledger_id.clone(),
            ext_pub_key_root: extended_pubkey,
            path: self.path.child(child),
        })
    }

    pub fn child_from_root_path(&self, path: &[ChildNumber]) -> Result<LedgerAccount, LedgerKeyStoreError> {
        if self.root_path_is_child(path) {
            path
                .iter()
                .skip(self.path.as_ref().len())
                .fold(Ok(self.clone()), |account, &child| account?.child(child))
        } else {
            Err(LedgerKeyStoreError::InvalidDerivationPath {
                path: path.as_ref().iter().cloned().collect(),
            })
        }
    }

    pub fn root_path_is_child(&self, path: &[ChildNumber]) -> bool {
        path.iter()
            .map(Some)
            .chain(std::iter::repeat(None))
            .zip(self.path.as_ref().iter())
            .all(|(x, y)| x == Some(y))
    }

    pub fn public_key_prompt(&self) -> Result<secp256k1::PublicKey, LedgerKeyStoreError> {
        let get_ledger_with_id = LedgerKeyStore::wallet_id_filter(&self.ledger_id);
        return with_ledger_matching(get_ledger_with_id, &mut |ledger_app| {
            let mut data = Vec::new();
            data.write_u8(self.path.as_ref().len() as u8)
                .expect(WRITE_ERR_MSG);
            for &child_num in self.path.as_ref().iter() {
                data.write_u32::<BigEndian>(From::from(child_num))
                    .expect(WRITE_ERR_MSG);
            }
            let command = apdu::extend_public_key(data);
            let response = ledger_app.exchange(&command, None)?;
            debug!(
                "Nervos CBK Ledger app extended pub key raw public key {:02x?} for path {:?}",
                &response, &self.path
            );
            let mut resp = &response.data[..];
            let len = parse::split_first(&mut resp)? as usize;
            let raw_public_key = parse::split_off_at(&mut resp, len)?;
            Ok(PublicKey::from_slice(&raw_public_key)?)
        });
    }

    pub fn begin_sign_recoverable(
        &self,
        tx: AnnotatedTransaction,
    ) -> Result<Vec<u8>, LedgerKeyStoreError> {
        // Need to fill in missing “path” from signer.
        let mut raw_path = Vec::<Uint32>::new();
        for &child_num in self.path.as_ref().iter() {
            let raw_child_num: u32 = child_num.into();
            let raw_path_bytes = raw_child_num.to_le_bytes();
            raw_path.push(
                Uint32::new_builder()
                    .nth0(raw_path_bytes[0].into())
                    .nth1(raw_path_bytes[1].into())
                    .nth2(raw_path_bytes[2].into())
                    .nth3(raw_path_bytes[3].into())
                    .build(),
            )
        }

        let sign_path = Bip32::new_builder().set(raw_path).build();
        let change_path = if tx.change_path().len() == 0 {
            sign_path.clone()
        } else {
            tx.change_path()
        };

        let raw_message = tx
            .as_builder()
            .sign_path(sign_path)
            .change_path(change_path)
            .build();

        debug!(
            "Modified Nervos CKB Ledger app message of {:02x?} with length {:?}",
            raw_message.as_slice(),
            raw_message.as_slice().len()
        );

        let get_ledger_with_id = LedgerKeyStore::wallet_id_filter(&self.ledger_id);
        return with_ledger_matching(get_ledger_with_id, &mut |ledger_app| {
            let chunk = |mut message: &[u8]| -> Result<_, LedgerKeyStoreError> {
                assert!(message.len() > 0, "initial message must be non-empty");
                let mut base = SignP1::FIRST;
                loop {
                    let length = ::std::cmp::min(message.len(), MAX_APDU_SIZE);
                    let chunk = parse::split_off_at(&mut message, length)?;
                    let rest_length = message.len();
                    let response = ledger_app.exchange(
                        &APDUCommand {
                            cla: 0x80,
                            ins: 0x03,
                            p1: (if rest_length > 0 {
                                base
                            } else {
                                base | SignP1::LAST_MARKER
                            })
                            .bits,
                            p2: 0,
                            data: chunk.to_vec(),
                        },
                        None,
                    )?;
                    if rest_length == 0 {
                        return Ok(response);
                    }
                    base = SignP1::NEXT;
                }
            };

            let response = chunk(raw_message.as_slice().as_ref())?;

            debug!(
                "Received Nervos CKB Ledger result of {:02x?} with length {:?}",
                response.data,
                response.data.len()
            );

            Ok(response.data)
        });
    }

    pub fn sign_message_recoverable(
        &self,
        message: &[u8],
        display_hex: bool,
    ) -> Result<RecoverableSignature, LedgerKeyStoreError> {
        let get_ledger_with_id = LedgerKeyStore::wallet_id_filter(&self.ledger_id);
        return with_ledger_matching(get_ledger_with_id, &mut |ledger_app| {
            let message_vec: Vec<u8> = message.iter().cloned().collect();
            let chunk = |mut message: &[u8]| -> Result<_, LedgerKeyStoreError> {
                assert!(message.len() > 0, "initial message must be non-empty");

                let display_byte = vec![display_hex as u8];
                let bip_path = derivation_path_to_bytes(Some(self.path.clone()));
                let init_packet = [&display_byte[..], &bip_path[..]].concat();
                let init_apdu = apdu::sign_message(SignP1::FIRST.bits, init_packet);
                let _ = ledger_app.exchange(&init_apdu, None);

                let mut base = SignP1::NEXT;
                loop {
                    let length = ::std::cmp::min(message.len(), MAX_APDU_SIZE);
                    let chunk = parse::split_off_at(&mut message, length)?;
                    let rest_length = message.len();
                    let p1 = (if rest_length > 0 {
                        base
                    } else {
                        base | SignP1::LAST_MARKER
                    })
                    .bits;
                    let command = apdu::sign_message(p1, chunk.to_vec());
                    let response = ledger_app.exchange(&command, None)?;
                    if rest_length == 0 {
                        return Ok(response);
                    }
                    base = SignP1::NEXT;
                }
            };
            let response = chunk(message_vec.as_slice().as_ref())?;
            let raw_signature = response.data.clone();
            let mut resp = &raw_signature[..];
            let data = parse::split_off_at(&mut resp, 64)?;
            let recovery_id = RecoveryId::from_i32(parse::split_first(&mut resp)? as i32)?;
            parse::assert_nothing_left(resp)?;
            let rec_sig = RecoverableSignature::from_compact(data, recovery_id)?;
            return Ok(rec_sig);
        });
    }

    pub fn sign_message_hash(
        &self,
        message: &[u8],
    ) -> Result<RecoverableSignature, LedgerKeyStoreError> {
        assert!(message.len() > 0, "initial message must be non-empty");
        let get_ledger_with_id = LedgerKeyStore::wallet_id_filter(&self.ledger_id);
        return with_ledger_matching(get_ledger_with_id, &mut |ledger_app| {
            let init_packet = derivation_path_to_bytes(Some(self.path.clone()));
            let init_apdu = apdu::sign_message_hash(SignP1::FIRST.bits, init_packet);
            let _ = ledger_app.exchange(&init_apdu, None);
            let mut message_clone = message.clone();
            let length = ::std::cmp::min(message.len(), MAX_APDU_SIZE);
            let chunk = parse::split_off_at(&mut message_clone, length)?;
            let p1 = SignP1::LAST_MARKER.bits;
            let command = apdu::sign_message_hash(p1, chunk.to_vec());
            let response = ledger_app.exchange(&command, None)?;
            let raw_signature = response.data.clone();
            let mut resp = &raw_signature[..];
            let data = parse::split_off_at(&mut resp, 64)?;
            let recovery_id = RecoveryId::from_i32(parse::split_first(&mut resp)? as i32)?;
            parse::assert_nothing_left(resp)?;
            let rec_sig = RecoverableSignature::from_compact(data, recovery_id)?;
            return Ok(rec_sig);
        });
    }
}

const MAX_APDU_SIZE: usize = 230;

bitflags::bitflags! {
    struct SignP1: u8 {
        // for the path
        const FIRST = 0b_0000_0000;
        // for the tx
        const NEXT  = 0b_0000_0001;
        //const HASH_ONLY_NEXT  = 0b_000_0010 | Self::NEXT.bits; // You only need it once
        const CHANGE_PATH = 0b_0001_0000;
        const IS_CONTEXT = 0b_0010_0000;
        const NO_FALLBACK = 0b_0100_0000;
        const LAST_MARKER = 0b_1000_0000;
        const MASK = Self::LAST_MARKER.bits | Self::NO_FALLBACK.bits | Self::IS_CONTEXT.bits;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerAccountJson {
    ledger_id: H256,
    lock_arg: H160,
    extended_public_key_root: LedgerAccountExtendedPubKeyJson,
    // TODO: `path` missing because it's not configurable
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerAccountExtendedPubKeyJson {
    address: String,
    chain_code: [u8; 32],
}

fn ledger_imported_account_to_json(
    inp: &LedgerImportedAccount,
) -> Result<serde_json::Value, serde_json::error::Error> {
    let LedgerId(ledger_id) = inp.account.ledger_id.clone();
    let lock_arg = inp.account.lock_arg();
    let extended_public_key_root = LedgerAccountExtendedPubKeyJson {
        address: inp.account.ext_pub_key_root.public_key.to_string(),
        chain_code: (|ChainCode(bytes)| bytes)(inp.account.ext_pub_key_root.chain_code),
    };
    serde_json::to_value(LedgerAccountJson {
        ledger_id,
        lock_arg,
        extended_public_key_root,
    })
}

fn ledger_imported_account_from_json(
    inp: &String,
) -> Result<LedgerImportedAccount, LedgerKeyStoreError> {
    let parsed_acc: LedgerAccountJson = serde_json::from_str(inp)?;
    let path = fixed_ledger_account_path();
    let ext_pub_key_root = {
        let public_key = PublicKey::from_str(&parsed_acc.extended_public_key_root.address)?;
        let chain_code = ChainCode(parsed_acc.extended_public_key_root.chain_code);
        ExtendedPubKey {
            depth: path.as_ref().len() as u8,
            parent_fingerprint: {
                let mut engine = hash160::Hash::engine();
                engine
                    .write_all(b"`parent_fingerprint` currently unused by Nervos.")
                    .expect("write must ok");
                Fingerprint::from(&hash160::Hash::from_engine(engine)[0..4])
            },
            child_number: ChildNumber::Hardened { index: 0 },
            public_key,
            chain_code,
        }
    };

    let account = LedgerAccount {
        ledger_id: LedgerId(parsed_acc.ledger_id),
        ext_pub_key_root,
        path,
    };

    let account_lock_arg = account.lock_arg();
    if account_lock_arg != parsed_acc.lock_arg {
        panic!(format!("Imported account's lock arg ({}) doesn't match the lock arg of the public key ({})", parsed_acc.lock_arg, account_lock_arg));
    }

    Ok(LedgerImportedAccount { account })
}


pub fn to_annotated_transaction(
    tx: Transaction,
    input_txs: Vec<Transaction>,
    signing_lock_arg: H160,
    change_path: String,
) -> AnnotatedTransaction {
    let input_count_bytes = tx.inputs.len().to_le_bytes();
    let num_inputs = tx.inputs.len();
    let annotated_inputs = input_txs
        .iter()
        .zip(tx.inputs.iter())
        .map(|(transaction, input)|
            packed::AnnotatedCellInput::new_builder()
                .input(From::from(input.clone()))
                .source(packed::Transaction::from(transaction.clone()).raw())
                .build()
        ).collect::<Vec<_>>();

    let cell_deps = tx
        .cell_deps
        .iter()
        .cloned()
        .map(From::from)
        .collect::<Vec<_>>();
    let header_deps = tx.header_deps.iter().map(Pack::pack).collect::<Vec<_>>();
    let outputs = tx
        .outputs
        .iter()
        .cloned()
        .map(From::from)
        .collect::<Vec<_>>();
    let outputs_data = tx
        .outputs_data
        .iter()
        .cloned()
        .map(From::from)
        .collect::<Vec<_>>();
    let raw_tx = packed::AnnotatedRawTransaction::new_builder()
        .version(tx.version.pack())
        .cell_deps(packed::CellDepVec::new_builder().set(cell_deps).build())
        .header_deps(packed::Byte32Vec::new_builder().set(header_deps).build())
        .inputs(
            packed::AnnotatedCellInputVec::new_builder()
                .set(annotated_inputs)
                .build(),
        )
        .outputs(packed::CellOutputVec::new_builder().set(outputs).build())
        .outputs_data(packed::BytesVec::new_builder().set(outputs_data).build())
        .build();

    let input_count = packed::Uint32::new_builder()
        .nth0(input_count_bytes[0].into())
        .nth1(input_count_bytes[1].into())
        .nth2(input_count_bytes[2].into())
        .nth3(input_count_bytes[3].into())
        .build();

    // Ignore the root change path, which is the default value sent when change is not specified
    let raw_change_path = if change_path == "m" { Vec::<packed::Uint32>::new() } else {
        DerivationPath::from_str(&change_path)
            .unwrap()
            .as_ref()
            .iter()
            .map(|&child_num| {
                let raw_child_num: u32 = child_num.into();
                let raw_change_path_bytes = raw_child_num.to_le_bytes();
                packed::Uint32::new_builder()
                    .nth0(raw_change_path_bytes[0].into())
                    .nth1(raw_change_path_bytes[1].into())
                    .nth2(raw_change_path_bytes[2].into())
                    .nth3(raw_change_path_bytes[3].into())
                    .build()
            })
            .collect::<Vec<packed::Uint32>>()
        };

    let witnesses_vec = if tx.witnesses.is_empty() {
        eprintln!("witnesses_vec is empty!!");
        let init_witness = WitnessArgs::default()
            .as_builder()
            .lock(Some(Bytes::from(vec![0u8; SECP_SIGNATURE_SIZE])).pack())
            .build();
        vec![init_witness.as_bytes().pack()]
    } else {
        let signing_lock_arg_json_bytes = match signing_lock_arg {
            H160(arr) => ckb_jsonrpc_types::JsonBytes::from_vec(arr.to_vec()),
        };
        tx.witnesses
            .iter()
            .cloned()
            .zip(tx.inputs.iter())
            .zip(input_txs.iter())
            .filter_map(|((witness, input), input_tx)|
                if input_tx.outputs[input.previous_output.index.value() as u32 as usize].lock.args == signing_lock_arg_json_bytes
                { Some(witness) }
                else
                { None })
            .chain(tx.witnesses.iter().skip(num_inputs).cloned())
            .map(From::from)
            .collect::<Vec<_>>()
    };

    packed::AnnotatedTransaction::new_builder()
        .change_path(packed::Bip32::new_builder().set(raw_change_path).build())
        .input_count(input_count)
        .raw(raw_tx)
        .witnesses(witnesses_vec.pack())
        .build()
}
