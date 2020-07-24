# CKB-CLI Ledger Plugin

## Installation

### Build by nix

```
nix-build
...
/nix/store/x2vvbbvxq1wz4fqfp2ymb497jg3dh5vp-ckb-plugin-ledger
```

Note the path mentioned after the nix-build succeeds and use it in the `plugin install` command of in `ckb-cli`.


```
CKB> plugin install --binary-path /nix/store/x2vvbbvxq1wz4fqfp2ymb497jg3dh5vp-ckb-plugin-ledger/bin/ckb-plugin-ledger
CKB> plugin list
- description: "It's a keystore for demo"
  is_active: true
  name: demo_keystore
```

### Using `cargo`

Useful for incremental compilation.
Do `nix-shell --run cargo build` to create the build incrementally.
And use the path of created binary to install the plugin in `ckb-cli`

## Debugging

- Print to `stderr` using `eprintln`
  This will always gets printed on the terminal, so its useful only during development work.

- Use the `error!`, `warn!`, `info!`, `debug!` or `trace!` macros from `log` package

  The logging of these messages can be controlled in the runtime via environment variable `RUST_LOG`.

  - To enable plugin's internal debug messages
  
  ```
  RUST_LOG=ckb_plugin_ledger::=debug ./debug/ckb-cli
  ```

  - To enable `ckb-cli` JSON RPC debug messages

  ```
  RUST_LOG=ckb_cli::plugin=debug ./debug/ckb-cli
  ```
  
  - The above two can be combined like this
  
  ```
  RUST_LOG=ckb_cli::plugin=debug,ckb_plugin_ledger::=debug ./debug/ckb-cli
  ```
