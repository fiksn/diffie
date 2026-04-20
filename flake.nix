{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    fenix.url = "github:nix-community/fenix";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, fenix, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ fenix.overlays.default ];
        };

        rustToolchain = fenix.packages.${system}.stable.toolchain;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        src = craneLib.cleanCargoSource ./.;

        # ── Cross-compilation: Linux x86_64 ──────────────────────────────────
        crossTarget = "x86_64-unknown-linux-gnu";

        # Package set cross-compiled for x86_64-linux (runs on current host)
        crossPkgs = pkgs.pkgsCross.gnu64;

        # Rust toolchain that can emit x86_64-linux code
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
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];
          doCheck = true;
        };

        # nix build .#faclaudit-linux-amd64
        packages.faclaudit-linux-amd64 = crossCraneLib.buildPackage {
          inherit src;
          cargoExtraArgs = "--locked --bin faclaudit";
          CARGO_BUILD_TARGET = crossTarget;

          # Cross-linker: gcc that runs on host but targets x86_64-linux
          "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER" =
            "${crossPkgs.stdenv.cc}/bin/${crossPkgs.stdenv.cc.targetPrefix}cc";

          # libacl search path for the target
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS =
            "-L ${crossPkgs.acl}/lib";

          # cross-compiler on PATH (needed by cc-rs / build scripts)
          nativeBuildInputs = [ crossPkgs.stdenv.cc ];

          # libacl compiled for x86_64-linux
          buildInputs = [ crossPkgs.acl ];

          doCheck = false; # can't run Linux binaries on the build host
        };

        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.pkg-config
            pkgs.openssl
            pkgs.git
            pkgs.acl
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];

          RUST_BACKTRACE = "1";
        };
      });
}
