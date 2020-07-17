use ckb_cli_plugin_protocol::{
    JsonrpcRequest, JsonrpcResponse,
};
use std::convert::TryInto;
use std::io::{self, Write};

use crate::handler::handle;

mod handler;

fn main() {
    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => {
                break;
            }
            Ok(_n) => {
                let jsonrpc_request: JsonrpcRequest = serde_json::from_str(&line).unwrap();
                let (id, request) = jsonrpc_request.try_into().unwrap();
                if let Some(response) = handle(request) {
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
