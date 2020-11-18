# Revision history for `ckb-plugin-ledger`

## v0.2.1 - 2020-11-18

### Release Notes

This release primarily fixes bugs and improves overall code quality.

- Source reformatted with new Cargo fmt settings, standardized for Nervos.
- Only relevant transaction witnesses are now sent to the Ledger device, based
  on information from the keystore, fixing issues that might be caused by
  improper grouping of witnesses in the process of creating a transaction.
  
This release has been tested with:
- Nervos Ledger App: [v0.5.1 - 61435fe19c722a0445ac3743cc42b84139842c33](https://github.com/obsidiansystems/ledger-app-nervos/releases/tag/v0.5.1)
- CKB-CLI: [babc52ae593474f7fddb80f7c229374203310d6a](https://github.com/nervosnetwork/ckb-cli/tree/ledger-support)

## v0.2.0 - 2020-09-30

### Release Notes
- Improve support with multiple ledgers, and mid-operation unplugged ledgers.
- When listing accounts, return errors to `ckb-cli` rather than an empty lists of accounts.

This release has been tested with:
- Nervos Ledger App: [v0.5.0 - 88026362a0bbf096ae911f33be5149415a2a7c77](https://github.com/obsidiansystems/ledger-app-nervos/releases/tag/v0.5.0)
- CKB-CLI: [b460c998d6681a89a47b3af203ecc5f12d7b2507](https://github.com/obsidiansystems/ckb-cli/commit/b460c998d6681a89a47b3af203ecc5f12d7b2507)

## v0.1.0 - 2020-08-07

* Initial release
