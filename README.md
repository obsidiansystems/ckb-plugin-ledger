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
