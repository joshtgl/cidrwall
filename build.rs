use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
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
        Toolchain::Nightly,
    )
}
