use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::Debug;
use std::fs;
use std::io::prelude::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use bitflags;
use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use secp256k1::{key::PublicKey, recovery::RecoverableSignature, recovery::RecoveryId};

use ckb_types::{
    bytes::Bytes,
    packed::{self, WitnessArgs},
    H160, H256,
};
use ckb_jsonrpc_types::{
    Transaction
};

use bitcoin_hashes::{hash160, Hash};
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;

use ckb_sdk::constants::{SECP_SIGNATURE_SIZE};
use ckb_sdk::wallet::{
    ChildNumber, DerivationPath, DerivedKeySet, ExtendedPubKey, Fingerprint, KeyChain, ChainCode
};
use serde::{Deserialize, Serialize};

use ledger::get_all_ledgers;
use ledger::TransportNativeHID as RawLedgerApp;
use ledger::LedgerError as RawLedgerError;
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
    discovered_devices: HashMap<LedgerId, Arc<RawLedgerApp>>,
    imported_accounts: HashMap<H160, LedgerMasterCap>,
    paths: HashSet<String>, // All the HID_Paths of every device we have a mutex for
}

#[derive(Debug, Clone)]
struct LedgerImportedAccount {
    ledger_id: LedgerId,
    lock_arg: H160,
    ext_pub_key_root: ExtendedPubKey,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
// TODO make contain actual id to distinguish between ledgers
pub struct LedgerId(pub H256);

impl LedgerKeyStore {
    pub fn new(dir: PathBuf) -> Self {
        LedgerKeyStore {
            data_dir: dir.clone(),
            discovered_devices: HashMap::new(),
            imported_accounts: HashMap::new(),
            paths: HashSet::new(),
        }
    }

    pub fn list_accounts(&mut self) -> Vec <H160> {
        if let Ok(()) = self.refresh_dir() {
            self.imported_accounts.keys().cloned().collect()
        } else {
            Vec::<_>::new()
        }
    }

    pub fn has_account(&mut self, lock_arg: &H160) -> Result<bool, LedgerKeyStoreError> {
        self.refresh_dir()?;
        Ok(self.imported_accounts.contains_key(lock_arg))
    }

    pub fn borrow_account(
        &mut self,
        lock_arg: &H160,
    ) -> Result<&LedgerMasterCap, LedgerKeyStoreError> {
        self.refresh_dir()?;
        self.refresh()?;
        self.imported_accounts
            .get(lock_arg)
            .ok_or_else(|| LedgerKeyStoreError::LedgerAccountNotFound(lock_arg.clone()))
    }

    fn clear_discovered_devices(&mut self) -> () {
        let mut paths_to_remove = Vec::new();
        for i in self.discovered_devices.values() {
            paths_to_remove.push(i.hid_path());
        }
        for i in paths_to_remove {
            let _ = self.paths.remove(&i);
        }
        self.discovered_devices.clear();
    }

    fn add_to_discovered(&mut self, ledger_id: LedgerId, device: RawLedgerApp) {
        self.paths.insert(device.hid_path());
        self.discovered_devices.insert(ledger_id, Arc::new(device));
    }

    fn reset_devices(&mut self) -> Result<(), LedgerKeyStoreError> {
        // TODO: Make sure that this drops all of the ledgers, and make sure
        // that dropping the ledgers results in their handles getting closed
        self.discovered_devices.clear();
        self.imported_accounts = HashMap::new();
        self.paths = HashSet::new();
        return self.refresh();
    }

    fn match_device_to_account(&mut self, ledger_id: LedgerId, device: RawLedgerApp) -> () {
        let maybe_cap = self
            .imported_accounts
            .values()
            .find(|cap| cap.account.ledger_id.clone() == ledger_id);
        match maybe_cap {
            Some(cap) => {
                // Does the existing account already have a handle to a ledger?
                if let Some(old_device) = cap.ledger_app.as_ref() {
                    if old_device.hid_path() == device.hid_path() {
                        // Two devices with the same HID_PATH and the same wallet-id
                        // This is bad because we have now written to both of them.
                        // ledger-rs has problems when this occurs (the next exchange that
                        // occur return the message from the previous exchange), so we wipe both from
                        // our system, and start over.
                        let _ = self.reset_devices();
                    } else {
                        // A ledger has been taken out and put back in again
                        // Update the account with the new HID_Device handle
                        let account = cap.account.clone();
                        let existing_path = old_device.hid_path().clone();
                        let new_path = device.hid_path().clone();
                        self.paths.remove(&existing_path);
                        self.imported_accounts.remove(&account.lock_arg);

                        self.paths.insert(new_path);
                        self.imported_accounts.insert(
                            account.lock_arg.clone(),
                            LedgerMasterCap {
                                account: account,
                                ledger_app: Some(Arc::new(device)),
                            },
                        );
                    }
                } else {
                    let account = cap.account.clone();
                    self.paths.insert(device.hid_path());
                    self.imported_accounts.insert(
                        account.lock_arg.clone(),
                        LedgerMasterCap {
                            account: account,
                            ledger_app: Some(Arc::new(device)),
                        },
                    );
                }
            }
            None => {
                self.add_to_discovered(ledger_id.clone(), device);
            }
        };
    }
    fn refresh(&mut self) -> Result<(), LedgerKeyStoreError> {
        self.clear_discovered_devices();

        // We need to check for imported accounts first
        self.refresh_dir()?;
        let paths_to_ignore = self.paths.iter().cloned().collect();
        if let Ok(devices) = get_all_ledgers(paths_to_ignore) {
            for device in devices {

                let command = apdu::get_wallet_id();
                // This timeout hack prevents a ledger on the homescreen in screensaver mode from blocking
                // for 2.8 hours before failing
                let response = device.exchange(&command, Some(2_000));
                debug!("Nervos CKB Ledger app wallet id: {:02x?}", response);

                match response {
                    // This happens when a ledger is on a home screen. Instead of causing an
                    // error, we just ignore this ledger
                    Err(RawLedgerError::APDU(_)) => { } //ignore this error

                    Err(err) => { return Err(LedgerKeyStoreError::RawLedgerError(err)) }
                    Ok(response) => {
                        let mut resp = &response.data[..];
                        // TODO: The ledger app gives us 64 bytes but we only use 32
                        // bytes. We should either limit how many the ledger app
                        // gives, or take all 64 bytes here.
                        let raw_wallet_id = parse::split_off_at(&mut resp, 32)?;
                        let _ = parse::split_off_at(&mut resp, 32)?;
                        parse::assert_nothing_left(resp)?;

                        let ledger_id = LedgerId(H256::from_slice(raw_wallet_id).unwrap());
                        // Check if this id matches any of the imported accounts
                        self.match_device_to_account(ledger_id, device);
                    }
                }
            }
        }
        Ok(())
    }

    fn refresh_dir(&mut self) -> Result<(), LedgerKeyStoreError> {
        for entry in fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let mut file = fs::File::open(&path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let account = ledger_imported_account_from_json(&contents)?;
                self.imported_accounts
                    .entry(account.lock_arg.clone())
                    .or_insert(LedgerMasterCap {
                        account,
                        ledger_app: None,
                    });
            }
        }
        Ok(())
    }

    pub fn discovered_devices<'a>(
        &'a mut self,
    ) -> Vec<LedgerId> {
        if let Ok(_) = self.refresh() {
            self.discovered_devices.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn import_account<'a, 'b>(
        &'a mut self,
        account_id: &'b LedgerId,
    ) -> Result<H160, LedgerKeyStoreError> {
        self.refresh()?;
        let ledger_app = self.discovered_devices.remove(account_id).ok_or_else(|| {
            LedgerKeyStoreError::LedgerNotFound {
                id: account_id.clone(),
            }
        })?;
        let ledger_path = ledger_app.hid_path();
        self.paths.remove(&ledger_path);
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
        let path = DerivationPath::from_str("m/44'/309'/0'").unwrap();
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
        let LedgerId(ledger_id) = account_id;
        let filepath = self.data_dir.join(ledger_id.to_string());
        let lock_arg = hash_public_key(&public_key);
        let account = LedgerImportedAccount {
            ledger_id: account_id.clone(),
            lock_arg: lock_arg.clone(),
            ext_pub_key_root,
        };
        let json_value = ledger_imported_account_to_json(&account)?;
        self.imported_accounts.insert(
            lock_arg.clone(),
            LedgerMasterCap {
                account,
                ledger_app: Some(ledger_app),
            },
        );
        self.paths.insert(ledger_path);
        fs::File::create(&filepath)
            .and_then(|mut file| file.write_all(json_value.to_string().as_bytes()))
            .map_err(|err| LedgerKeyStoreError::KeyStoreIOError(err))?;
        Ok(lock_arg)
    }

}

/// A ledger device with the Nervos app.
#[derive(Clone)]
pub struct LedgerMasterCap {
    account: LedgerImportedAccount,
    // TODO no Arc once we have "generic associated types" and can just borrow the device.
    ledger_app: Option<Arc<RawLedgerApp>>,
}

impl LedgerMasterCap {
    pub fn derive_extended_public_key(
        &self,
        chain: KeyChain,
        index: ChildNumber,
    ) -> ExtendedPubKey {
        let epk = match chain {
            KeyChain::External => self
                .account
                .ext_pub_key_root
                .ckd_pub(&SECP256K1, ChildNumber::Normal { index: 0 })
                .unwrap(),
            KeyChain::Change => self
                .account
                .ext_pub_key_root
                .ckd_pub(&SECP256K1, ChildNumber::Normal { index: 1 })
                .unwrap(),
        };
        epk.ckd_pub(&SECP256K1, index).unwrap()
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
                    let path_string = format!("m/44'/309'/0'/{}/{}", chain as u8, i + start);
                    let path = DerivationPath::from_str(path_string.as_str()).unwrap();
                    let extended_pubkey =
                        self.derive_extended_public_key(chain, ChildNumber::from(i + start));
                    let pubkey = extended_pubkey.public_key;
                    let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
                        .expect("Generate hash(H160) from pubkey failed");
                    (path, hash)
                })
                .into_iter()
                .collect::<Vec<_>>()
        };
        DerivedKeySet {
            external: get_pairs(KeyChain::External, external_start, external_length),
            change: get_pairs(KeyChain::Change, change_start, change_length),
        }
    }

    fn derivation_path_to_bytes(path_opt: Option<DerivationPath>) -> Vec<u8> {
        let drv_path = path_opt.unwrap_or(DerivationPath::from_str("m/44'/309'/0'").unwrap());
        let mut bip_path = Vec::new();
        bip_path
            .write_u8(drv_path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in drv_path.as_ref().iter() {
            bip_path
                .write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }
        return bip_path;
    }


    pub fn extended_privkey(&self, path: &[ChildNumber]) -> Result<LedgerCap, LedgerKeyStoreError> {
        if !is_valid_derivation_path(path.as_ref()) {
            return Err(LedgerKeyStoreError::InvalidDerivationPath {
                path: path.as_ref().iter().cloned().collect(),
            });
        }

        Ok(LedgerCap {
            master: self.clone(),
            path: From::from(path.as_ref()),
        })
    }

    pub fn derived_key_set(
        &self,
        external_max_len: u32,
        change_last: &H160,
        change_max_len: u32,
    ) -> Result<DerivedKeySet, LedgerKeyStoreError> {
        let mut external_key_set = Vec::new();
        for i in 0..external_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::External as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let epk = self
                .account
                .ext_pub_key_root
                .ckd_pub(&SECP256K1, ChildNumber::Normal { index: 0 })
                .unwrap();
            let extended_pubkey = epk
                .ckd_pub(&SECP256K1, ChildNumber::Normal { index: i })
                .unwrap();
            let pubkey = extended_pubkey.public_key;
            let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
                .expect("Generate hash(H160) from pubkey failed");
            external_key_set.push((path, hash));
        }

        let mut change_key_set = Vec::new();
        for i in 0..change_max_len {
            let path_string = format!("m/44'/309'/0'/{}/{}", KeyChain::Change as u8, i);
            let path = DerivationPath::from_str(path_string.as_str()).unwrap();
            let epk = self
                .account
                .ext_pub_key_root
                .ckd_pub(&SECP256K1, ChildNumber::Normal { index: 1 })
                .unwrap();
            let extended_pubkey = epk
                .ckd_pub(&SECP256K1, ChildNumber::Normal { index: i })
                .unwrap();
            let pubkey = extended_pubkey.public_key;
            let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
                .expect("Generate hash(H160) from pubkey failed");
            change_key_set.push((path, hash.clone()));
            if change_last == &hash {
                return Ok(DerivedKeySet {
                    external: external_key_set,
                    change: change_key_set,
                });
            }
        }
        Err(LedgerKeyStoreError::SearchDerivedAddrFailed(change_last.clone()))
    }
}

const WRITE_ERR_MSG: &'static str = "IO error not possible when writing to Vec last I checked";

/// A ledger device with the Nervos app constrained to a specific derivation path.
#[derive(Clone)]
pub struct LedgerCap {
    master: LedgerMasterCap,
    pub path: DerivationPath,
}

impl LedgerCap {
    pub fn public_key_prompt(&self) -> Result<secp256k1::PublicKey, LedgerKeyStoreError> {
        let mut data = Vec::new();
        data.write_u8(self.path.as_ref().len() as u8)
            .expect(WRITE_ERR_MSG);
        for &child_num in self.path.as_ref().iter() {
            data.write_u32::<BigEndian>(From::from(child_num))
                .expect(WRITE_ERR_MSG);
        }
        let command = apdu::extend_public_key(data);
        let ledger_app =
            self.master
                .ledger_app
                .as_ref()
                .ok_or(LedgerKeyStoreError::LedgerNotFound {
                    id: self.master.account.ledger_id.clone(),
                })?;
        let response = ledger_app.exchange(&command, None)?;
        debug!(
            "Nervos CBK Ledger app extended pub key raw public key {:02x?} for path {:?}",
            &response, &self.path
        );
        let mut resp = &response.data[..];
        let len = parse::split_first(&mut resp)? as usize;
        let raw_public_key = parse::split_off_at(&mut resp, len)?;
        Ok(PublicKey::from_slice(&raw_public_key)?)
    }

    pub fn begin_sign_recoverable(&self, tx: AnnotatedTransaction)
                              -> Result<Vec<u8>, LedgerKeyStoreError> {

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

        let chunk = |mut message: &[u8]| -> Result<_, LedgerKeyStoreError> {
            assert!(message.len() > 0, "initial message must be non-empty");
            let mut base = SignP1::FIRST;
            loop {
                let length = ::std::cmp::min(message.len(), MAX_APDU_SIZE);
                let chunk = parse::split_off_at(&mut message, length)?;
                let rest_length = message.len();
                let ledger_app = self.master.ledger_app.as_ref().ok_or(
                    LedgerKeyStoreError::LedgerNotFound {
                        id: self.master.account.ledger_id.clone(),
                    },
                )?;
                let response = ledger_app.exchange(&APDUCommand {
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
                }, None)?;
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
    }

    pub fn sign_message_recoverable(
        &self,
        message: &[u8],
        display_hex: bool,
    ) -> Result<RecoverableSignature, LedgerKeyStoreError> {
        let message_vec: Vec<u8> = message.iter().cloned().collect();
        let chunk = |mut message: &[u8]| -> Result<_, LedgerKeyStoreError> {
            assert!(message.len() > 0, "initial message must be non-empty");

            let display_byte = vec![display_hex as u8];
            let bip_path = LedgerMasterCap::derivation_path_to_bytes(Some(self.path.clone()));
            let init_packet = [&display_byte[..], &bip_path[..]].concat();
            let ledger_app = self.master
                    .ledger_app
                    .as_ref()
                    .ok_or(LedgerKeyStoreError::LedgerNotFound {
                        id: self.master.account.ledger_id.clone(),
                    })?;

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
    }

    pub fn sign_message_hash(
        &self,
        message: &[u8],
    ) -> Result<RecoverableSignature, LedgerKeyStoreError> {
        assert!(message.len() > 0, "initial message must be non-empty");
        let init_packet = LedgerMasterCap::derivation_path_to_bytes(Some(self.path.clone()));
        let init_apdu = apdu::sign_message_hash(SignP1::FIRST.bits, init_packet);
        let ledger_app = self.master
            .ledger_app
            .as_ref()
            .ok_or(LedgerKeyStoreError::LedgerNotFound {
                id: self.master.account.ledger_id.clone(),
            })?;
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerAccountExtendedPubKeyJson {
    address: String,
    chain_code: [u8; 32],
}

fn ledger_imported_account_to_json(
    inp: &LedgerImportedAccount,
) -> Result<serde_json::Value, serde_json::error::Error> {
    let LedgerId(ledger_id) = inp.ledger_id.clone();
    let lock_arg = inp.lock_arg.clone();
    let extended_public_key_root = LedgerAccountExtendedPubKeyJson {
        address: inp.ext_pub_key_root.public_key.to_string(),
        chain_code: (|ChainCode(bytes)| bytes)(inp.ext_pub_key_root.chain_code),
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
    let acc: LedgerAccountJson = serde_json::from_str(inp)?;
    let ext_pub_key_root = {
        let path = DerivationPath::from_str("m/44'/309'/0'").unwrap();
        let public_key = PublicKey::from_str(&acc.extended_public_key_root.address)?;
        let chain_code = ChainCode(acc.extended_public_key_root.chain_code);
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

    Ok(LedgerImportedAccount {
        ledger_id: LedgerId(acc.ledger_id),
        lock_arg: acc.lock_arg,
        ext_pub_key_root,
    })
}

fn hash_public_key(public_key: &secp256k1::PublicKey) -> H160 {
    H160::from_slice(&blake2b_256(&public_key.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed")
}

const MANDATORY_PREFIX: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 44 },
    ChildNumber::Hardened { index: 309 },
];

fn is_valid_derivation_path(path: &[ChildNumber]) -> bool {
    path.iter()
        .map(Some)
        .chain(std::iter::repeat(None))
        .zip(MANDATORY_PREFIX.iter())
        .all(|(x, y)| x == Some(y))
}

pub fn to_annotated_transaction (tx: Transaction, inputs: Vec<Transaction>, change_path: String)
                                 -> AnnotatedTransaction {
    let mut annotated_inputs = Vec::new();
    let input_count_bytes = tx.inputs.len().to_le_bytes();
    for (transaction, input) in inputs.into_iter().zip(tx.inputs.into_iter())
    {
        annotated_inputs.push(
            packed::AnnotatedCellInput::new_builder()
                .input(From::from(input))
                .source(packed::Transaction::from(transaction.clone()).raw())
                .build(),
        );
    }

    let cell_deps = tx.cell_deps.iter().cloned().map(From::from).collect::<Vec<_>>();
    let header_deps = tx.header_deps.iter().map(Pack::pack).collect::<Vec<_>>();
    let outputs = tx.outputs.iter().cloned().map(From::from).collect::<Vec<_>>();
    let outputs_data = tx.outputs_data.iter().cloned().map(From::from).collect::<Vec<_>>();
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

    let mut raw_change_path = Vec::<packed::Uint32>::new();

    // Ignore the root change path, which is the default value sent when change is not specified
    if change_path != "m" {
        for &child_num in DerivationPath::from_str(&change_path).unwrap().as_ref().iter() {
            let raw_child_num: u32 = child_num.into();
            let raw_change_path_bytes = raw_child_num.to_le_bytes();
            raw_change_path.push(
                packed::Uint32::new_builder()
                    .nth0(raw_change_path_bytes[0].into())
                    .nth1(raw_change_path_bytes[1].into())
                    .nth2(raw_change_path_bytes[2].into())
                    .nth3(raw_change_path_bytes[3].into())
                    .build(),
            )
        }
    };

    let witnesses_vec = if tx.witnesses.is_empty() {
        eprintln!("witnesses_vec is empty!!");
        let init_witness = WitnessArgs::default()
            .as_builder()
            .lock(Some(Bytes::from(vec![0u8; SECP_SIGNATURE_SIZE])).pack())
            .build();
        vec![init_witness.as_bytes().pack()]
    } else {
        tx.witnesses.iter().cloned().map(From::from).collect::<Vec<_>>()
    };

    packed::AnnotatedTransaction::new_builder()
        .change_path(packed::Bip32::new_builder().set(raw_change_path).build())
        .input_count(input_count)
        .raw(raw_tx)
        .witnesses(witnesses_vec.pack())
        .build()
}
