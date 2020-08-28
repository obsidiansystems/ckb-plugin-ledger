# Ledger Plugin for CKB-CLI

This plugin provides support of [Nervos Ledger app](https://github.com/obsidiansystems/ledger-app-nervos) for [`ckb-cli`](https://github.com/nervosnetwork/ckb-cli/)

To use this plugin it needs to be built from the source, and then installed in the `ckb-cli`

## Building the plugin

### Using nix-build

You can build from source if you have Nix installed.
<!-- Add nix installation instruction/command? -->

``` sh
$ git clone https://github.com/obsidiansystems/ckb-plugin-ledger.git
$ cd ckb-plugin-ledger
$ git checkout master
$ nix-build
```

Once the `nix-build` command finishes it will print a path like this
<!-- , and create a file named `result` which should not be deleted -->

```
/nix/store/x2vvbbvxq1wz4fqfp2ymb497jg3dh5vp-ckb-plugin-ledger
```

Append `/bin/ckb-plugin-ledger` to this path, and use it in the `plugin install` command of in `ckb-cli`.

### Using cargo

It is also possible to build the plugin without `nix` by using `cargo` command.

``` sh
$ git clone https://github.com/obsidiansystems/ckb-plugin-ledger.git
$ cd ckb-plugin-ledger
$ git checkout master
$ cargo build
```

Use the output path of this command in the `plugin install` command
```
$ echo "$PWD/target/debug/ckb-plugin-ledger"
```

## Installing the plugin in ckb-cli

Make sure you have the latest `ckb-cli` installed.

Use the path obtained after building the plugin in the `--binary-path` argument

```
CKB> plugin install --binary-path /nix/store/x2vvbbvxq1wz4fqfp2ymb497jg3dh5vp-ckb-plugin-ledger/bin/ckb-plugin-ledger
CKB> plugin list
daemon: true
description: Plugin for Ledger
name: ledger_plugin
```
It may be the case that you wish to reinstall an updated version of a plugin that has already been installed. To do this, you
must first uninstall the older version of the plugin before installing the new one:
```
CKB> plugin uninstall --name ledger_plugin
Plugin ledger_plugin uninstalled!
CKB> plugin list
[]
```

## Importing Ledger account

Use the `account list` command to see connected Ledger devices. Be sure to have the Nervos application open on the device, otherwise it will not be detected:

```
CKB> account list
- "#": 0
  account-id: 0x9c6e60f3e812ef5c859bbc900f427bffe63294c5490f93e4e50beb688c0798bf
  source: "[plugin]: ledger_plugin"
```

The `account-id` shown is the public key hash for the path m/44'/309', which is the root Nervos path. the `account-id` will be
used for ```<account-id>``` argument in the `account import-from-plugin` command as described below.

Use the `account import-from-plugin --account-id <account-id>` command to import the account to the `ckb-cli`.
You will receive a confirmation prompt on the device which should say `Import Account`.
Confirm this to import the account. This operation will provide the extended public key of path `m/44'/309'/0'` to the `ckb-cli`.

```
CKB> account import-from-plugin --account-id 0x9c6e60f3e812ef5c859bbc900f427bffe63294c5490f93e4e50beb688c0798bf
address:
  mainnet: ckb1qyqg64fqws0sdgrz2s7da2dzrlpq6plw9xcqhuexcr
  testnet: ckt1qyqg64fqws0sdgrz2s7da2dzrlpq6plw9xcq2e8e5l
lock_arg: 0x8d5520741f06a062543cdea9a21fc20d07ee29b0
```

## Listing Ledger Accounts ###

If you have already imported the Ledger account, then `account list` command will instead give the account details.
They will be shown even if the device is not connected.

``` sh
CKB> account list
- "#": 0
  address:
    mainnet: ckb1qyqg64fqws0sdgrz2s7da2dzrlpq6plw9xcqhuexcr
    testnet: ckt1qyqg64fqws0sdgrz2s7da2dzrlpq6plw9xcq2e8e5l
  has_ckb_root: false
  lock_arg: 0x8d5520741f06a062543cdea9a21fc20d07ee29b0
  lock_hash: 0xe8e5dbae54d1ae5257ea55c1fbc210ef5521e0707b0d59bfb17e9f344ef96b7f
  source: "[plugin]: ledger_plugin"
```
