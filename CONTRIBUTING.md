# Contributing

## Setup development environment

Do `nix-shell --run cargo build` to create the build incrementally.

The default path is `target` dir in the root of repo.
But it can be overriden by `cargo build --target-dir <plugin-build-path>`

Use the path of created binary to install the plugin in `ckb-cli`

```
CKB> plugin install --binary-path <plugin-build-path>/debug/ckb-plugin-ledger
```

**Note: It is necessary to do `plugin uninstall --name ledger_plugin`, and install it again everytime the build is modified**

It is also necessary to do `account list` once the plugin in installed again, otherwise the `ckb-cli` will give weird errors whenever the plugin `lock-arg` is used.

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

## Clearing Keystore Data ##

Ledger account information is stored locally in `~/.ckb-cli/ledger-keystore/`.
If it is required to remove the imported account data, you can do so by running `rm -rf ~/.ckb-cli/ledger-keystore/` to remove all accounts or a file for a particular account like `rm ~/.ckb-cli/ledger-keystore/9c6e60f3e812ef5c859bbc900f427bffe63294c5490f93e4e50beb688c0798bf`.
