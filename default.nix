{ pkgsFun ? import (import ./nix/nixpkgs/thunk.nix)

, rustOverlay ? import "${import ./nix/nixpkgs-mozilla/thunk.nix}/rust-overlay.nix"

# Rust manifest hash must be updated when rust-toolchain file changes.
, rustPackages ? pkgs.rustChannelOf {
    date = "2020-05-04";
    rustToolchain = ./rust-toolchain;
    sha256 = "07mp7n4n3cmm37mv152frv7p9q58ahjw5k8gcq48vfczrgm5qgiy";
  }

, pkgs ? pkgsFun {
    overlays = [
      rustOverlay
    ];
  }

, gitignoreNix ? import ./nix/gitignore.nix/thunk.nix

}:

let
  rustPlatform = pkgs.makeRustPlatform {
    inherit (rustPackages) cargo;
    rustc = rustPackages.rust;
  };
  inherit (import gitignoreNix { inherit (pkgs) lib; }) gitignoreSource;
in rustPlatform.buildRustPackage {
  name = "ckb-plugin-ledger";
  src = gitignoreSource ./.;
  nativeBuildInputs = [ pkgs.pkgconfig ];
  buildInputs = [ rustPackages.rust-std pkgs.openssl pkgs.libudev ];
  verifyCargoDeps = true;

  # Cargo hash must be updated when Cargo.lock file changes.
  # cargoSha256 = pkgs.lib.fakeSha256;
  cargoSha256 = "0cma5wyxdvzv34nlha8gwd6wqdg2y7nra7d8cfy72c7zrk073knv";
}
