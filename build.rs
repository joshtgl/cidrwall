use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

// Nightly used to build the eBPF objects, shared with the CI workflows,
// Dockerfiles and nix/package.nix. Bump together with bpf-linker.
const EBPF_TOOLCHAIN: &str = include_str!("ebpf-toolchain").trim_ascii();
// Overrides EBPF_TOOLCHAIN, e.g. so CI can build older published versions with
// the toolchain it has installed.
const EBPF_TOOLCHAIN_ENV: &str = "CIDRWALL_EBPF_TOOLCHAIN";

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-env-changed={EBPF_TOOLCHAIN_ENV}");
    let xdp = std::env::var_os("CARGO_FEATURE_XDP").is_some();
    let tc = std::env::var_os("CARGO_FEATURE_TC").is_some();
    if !xdp && !tc {
        return Ok(());
    }
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("read Cargo workspace metadata")?;
    let package = packages
        .into_iter()
        .find(|package| package.name.as_str() == "cidrwall-ebpf")
        .ok_or_else(|| anyhow!("cidrwall-ebpf package not found"))?;
    let root_dir = package
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("cidrwall-ebpf manifest has no parent"))?;
    let toolchain = std::env::var(EBPF_TOOLCHAIN_ENV).unwrap_or_else(|_| EBPF_TOOLCHAIN.to_owned());
    std::env::set_current_dir(root_dir)
        .with_context(|| format!("enter cidrwall-ebpf source directory {root_dir}"))?;
    let mut features = Vec::new();
    if xdp {
        features.push("xdp-program");
    }
    if tc {
        features.push("tc-program");
    }
    aya_build::build_ebpf(
        [aya_build::Package {
            name: package.name.as_str(),
            root_dir: root_dir.as_str(),
            features: &features,
            ..Default::default()
        }],
        Toolchain::Custom(&toolchain),
    )
}
