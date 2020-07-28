use ckb_cli_plugin_protocol::{
    JsonrpcRequest, JsonrpcResponse,
};
use std::convert::TryInto;
use std::fs;
use std::io::{self, Write};

use crate::handler::handle;
use crate::keystore::{
    LedgerKeyStore,
};

mod handler;
mod keystore;

fn main() {
    env_logger::init();
    let mut keystore = get_ledger_key_store().unwrap();
    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => {
                break;
            }
            Ok(_n) => {
                let jsonrpc_request: JsonrpcRequest = serde_json::from_str(&line).unwrap();
                let (id, request) = jsonrpc_request.try_into().unwrap();
                if let Some(response) = handle(&mut keystore, request) {
                    let jsonrpc_response = JsonrpcResponse::from((id, response));
                    let response_string =
                        format!("{}\n", serde_json::to_string(&jsonrpc_response).unwrap());
                    io::stdout().write_all(response_string.as_bytes()).unwrap();
                    io::stdout().flush().unwrap();
                }
            }
            Err(_err) => {}
        }
    }
}

fn get_ledger_key_store() -> Result<LedgerKeyStore, String> {
    let mut keystore_dir = dirs::home_dir().unwrap();
    keystore_dir.push(".ckb-cli");
    keystore_dir.push("ledger-keystore");
    fs::create_dir_all(&keystore_dir).map_err(|err| err.to_string())?;
    Ok(LedgerKeyStore::new(keystore_dir))
}
