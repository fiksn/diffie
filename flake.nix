{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    fenix.url = "github:nix-community/fenix";
    crane.url = "github:ipetkov/crane";
  };

  outputs = inputs@{ nixpkgs, flake-parts, fenix, crane, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];

      perSystem = { system, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ fenix.overlays.default ];
          };

          rustToolchain = fenix.packages.${system}.stable.toolchain;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;
          linuxInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.acl
          ];
          darwinInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];

          crossTarget = "x86_64-unknown-linux-gnu";
          crossPkgs = pkgs.pkgsCross.gnu64;
          crossToolchain = fenix.packages.${system}.combine [
            fenix.packages.${system}.stable.cargo
            fenix.packages.${system}.stable.rustc
            fenix.packages.${system}.targets.${crossTarget}.stable.rust-std
          ];
          crossCraneLib = (crane.mkLib pkgs).overrideToolchain crossToolchain;
        in
        {
          packages.default = craneLib.buildPackage {
            inherit src;
            cargoExtraArgs = "--locked";
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [
              pkgs.openssl
            ] ++ linuxInputs ++ darwinInputs;
            doCheck = true;
          };

          packages.faclaudit-linux-amd64 = crossCraneLib.buildPackage {
            inherit src;
            cargoExtraArgs = "--locked --bin faclaudit";
            CARGO_BUILD_TARGET = crossTarget;

            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER" =
              "${crossPkgs.stdenv.cc}/bin/${crossPkgs.stdenv.cc.targetPrefix}cc";
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS =
              "-L ${crossPkgs.acl}/lib";

            nativeBuildInputs = [ crossPkgs.stdenv.cc ];
            buildInputs = [ crossPkgs.acl ];

            doCheck = false;
          };

          devShells.default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.pkg-config
              pkgs.openssl
              pkgs.git
            ] ++ linuxInputs ++ darwinInputs;

            RUST_BACKTRACE = "1";
          };
        };
    };
}
