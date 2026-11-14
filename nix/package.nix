{
  lib,
  stdenv,
  craneLib,
  rust-bin,
  fetchurl,
  zstd,
  pkg-config,
  libmnl,
  libnftnl,
}:

let
  manifest = lib.importTOML ../Cargo.toml;

  # Aya builds the eBPF objects with `-Z build-std=core`, which needs a nightly
  # toolchain with rust-src. Pinned to match the CI nightly; bump together with
  # bpf-linker when the LLVM major version changes.
  toolchain = rust-bin.nightly."2026-10-17".minimal.override {
    extensions = [ "rust-src" ];
  };

  bpf-linker = stdenv.mkDerivation rec {
    pname = "bpf-linker";
    version = "0.11.0";
    src = fetchurl {
      url = "https://github.com/aya-rs/bpf-linker/releases/download/v${version}/bpf-linker-x86_64-unknown-linux-musl.tar.zst";
      sha256 = "10f62ba9ab7e544d538370552660efcb4f1a19153d5752bbf0f6b51f3bada450";
    };
    nativeBuildInputs = [ zstd ];
    sourceRoot = ".";
    unpackCmd = "zstd -dc $curSrc | tar -x";
    installPhase = "install -Dm755 bpf-linker $out/bin/bpf-linker";
    meta.platforms = [ "x86_64-linux" ];
  };

  craneLib' = craneLib.overrideToolchain toolchain;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../build.rs
      ../src
      ../config
      ../cidrwall-common
      ../cidrwall-ebpf
    ];
  };

  commonArgs = {
    inherit src;
    pname = manifest.package.name;
    inherit (manifest.package) version;
    strictDeps = true;

    # The workspace lock plus the standard library lock, so build-std=core works offline.
    cargoVendorDir = craneLib'.vendorMultipleCargoDeps {
      inherit (craneLib'.findCargoFiles src) cargoConfigs;
      cargoLockList = [
        ../Cargo.lock
        "${toolchain}/lib/rustlib/src/rust/library/Cargo.lock"
      ];
    };

    nativeBuildInputs = [
      pkg-config
      bpf-linker
    ];
    buildInputs = [
      libmnl
      libnftnl
    ];
  };
in
craneLib'.buildPackage (
  commonArgs
  // {
    # Dependency-only builds stub out build.rs, which would drop the embedded eBPF objects.
    cargoArtifacts = null;
    cargoExtraArgs = "--locked --package cidrwall";

    passthru = { inherit toolchain bpf-linker; };

    postInstall = ''
      install -Dm644 config/cidrwall.toml $out/share/cidrwall/cidrwall.toml
    '';

    meta = {
      inherit (manifest.package) description;
      license = with lib.licenses; [
        mit
        asl20
      ];
      mainProgram = "cidrwall";
      platforms = [ "x86_64-linux" ];
    };
  }
)
