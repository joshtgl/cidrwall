use crate::zones::{ResolvedRule, Zones};
use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[arg(
        long,
        env = "CIDRWALL_CONFIG",
        default_value = "/etc/cidrwall/cidrwall.toml"
    )]
    pub config: PathBuf,
    #[arg(long, env = "CIDRWALL_ZONES")]
    pub zones: Option<PathBuf>,
    #[arg(long, env = "CIDRWALL_INBOUND")]
    pub inbound: Option<PathBuf>,
    #[arg(long, env = "CIDRWALL_OUTBOUND")]
    pub outbound: Option<PathBuf>,
    #[arg(long, env = "CIDRWALL_TABLE")]
    pub table: Option<String>,
    #[arg(long, env = "CIDRWALL_PRIORITY")]
    pub priority: Option<i32>,
    #[arg(long, env = "CIDRWALL_DEBOUNCE_MS")]
    pub debounce_ms: Option<u64>,
    #[arg(long, env = "CIDRWALL_RECONCILE_SECS")]
    pub reconcile_secs: Option<u64>,
    #[arg(long, env = "CIDRWALL_ALLOW_FLOWTABLE_BYPASS")]
    pub allow_flowtable_bypass: Option<bool>,
    #[arg(long, env = "CIDRWALL_POPULATE_BATCH_ELEMENTS")]
    pub populate_batch_elements: Option<u32>,
    #[arg(long, help = "Validate configuration and print the resolved rules")]
    pub check: bool,
    #[arg(
        long,
        value_enum,
        conflicts_with = "check",
        help = "Remove owned kernel state and exit"
    )]
    pub cleanup: Option<CleanupTarget>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum CleanupTarget {
    Xdp,
    Tc,
    Nftables,
    All,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub files: Files,
    #[serde(default)]
    pub zones: Option<Zones>,
    #[serde(default)]
    pub nftables: Nftables,
    #[serde(default)]
    pub xdp: Xdp,
    #[serde(default)]
    pub tc: Tc,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub rules: Rules,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    #[serde(default)]
    pub zones: Option<PathBuf>,
    #[serde(default)]
    pub inbound: Option<PathBuf>,
    #[serde(default)]
    pub outbound: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Nftables {
    pub table: String,
    pub priority: i32,
    pub allow_flowtable_bypass: bool,
    pub batch_page_bytes: u32,
    pub populate_batch_elements: u32,
    pub cleanup_on_exit: bool,
}
impl Default for Nftables {
    fn default() -> Self {
        Self {
            table: "cidrwall".into(),
            priority: -5,
            allow_flowtable_bypass: false,
            batch_page_bytes: 128 * 1024,
            populate_batch_elements: 2_000,
            cleanup_on_exit: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Xdp {
    pub mode: XdpMode,
    pub pin_path: PathBuf,
    pub ipv4_max_entries: u32,
    pub ipv6_max_entries: u32,
    pub populate_batch_elements: u32,
    pub allow_nftables_overlap: bool,
    pub cleanup_on_exit: bool,
    pub rules: Vec<XdpRule>,
}

impl Default for Xdp {
    fn default() -> Self {
        Self {
            mode: XdpMode::Auto,
            pin_path: "/sys/fs/bpf/cidrwall".into(),
            ipv4_max_entries: 5_000_000,
            ipv6_max_entries: 5_000_000,
            populate_batch_elements: 2_000,
            allow_nftables_overlap: false,
            cleanup_on_exit: false,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    #[default]
    Auto,
    Native,
    Generic,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpRule {
    pub blocklist: Direction,
    pub ingress_zones: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tc {
    pub pin_path: PathBuf,
    pub ipv4_max_entries: u32,
    pub ipv6_max_entries: u32,
    pub populate_batch_elements: u32,
    pub attach_order: TcAttachOrder,
    pub allow_nftables_overlap: bool,
    pub allow_hardware_flowtable_bypass: bool,
    pub cleanup_on_exit: bool,
    pub rules: Vec<TcRule>,
}

impl Default for Tc {
    fn default() -> Self {
        Self {
            pin_path: "/sys/fs/bpf/cidrwall-tc".into(),
            ipv4_max_entries: 5_000_000,
            ipv6_max_entries: 5_000_000,
            populate_batch_elements: 2_000,
            attach_order: TcAttachOrder::First,
            allow_nftables_overlap: false,
            allow_hardware_flowtable_bypass: false,
            cleanup_on_exit: false,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TcAttachOrder {
    #[default]
    First,
    Last,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcRule {
    pub blocklist: Direction,
    pub egress_zones: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Runtime {
    pub debounce_ms: u64,
    pub reconcile_secs: u64,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            debounce_ms: 500,
            reconcile_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub input: Vec<RuleMapping>,
    pub forward: Vec<RuleMapping>,
    pub output: Vec<RuleMapping>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMapping {
    pub blocklist: Direction,
    #[serde(default)]
    pub ingress_zones: Vec<String>,
    #[serde(default)]
    pub egress_zones: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Config {
    pub fn load(cli: &Cli) -> Result<Self> {
        let text = std::fs::read_to_string(&cli.config)
            .with_context(|| format!("read {}", cli.config.display()))?;
        let mut value: Self =
            toml::from_str(&text).with_context(|| format!("parse {}", cli.config.display()))?;
        if let Some(v) = &cli.zones {
            value.files.zones = Some(v.clone());
            value.zones = None;
        }
        if let Some(v) = &cli.inbound {
            value.files.inbound = Some(v.clone());
        }
        if let Some(v) = &cli.outbound {
            value.files.outbound = Some(v.clone());
        }
        if let Some(v) = &cli.table {
            value.nftables.table = v.clone();
        }
        if let Some(v) = cli.priority {
            value.nftables.priority = v;
        }
        if let Some(v) = cli.debounce_ms {
            value.runtime.debounce_ms = v;
        }
        if let Some(v) = cli.reconcile_secs {
            value.runtime.reconcile_secs = v;
        }
        if let Some(v) = cli.allow_flowtable_bypass {
            value.nftables.allow_flowtable_bypass = v;
        }
        if let Some(v) = cli.populate_batch_elements {
            value.nftables.populate_batch_elements = v;
        }
        value.validate(cli.cleanup.is_some())?;
        Ok(value)
    }

    pub fn validate(&self, cleanup: bool) -> Result<()> {
        if self.nftables.table.is_empty()
            || self
                .nftables
                .table
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        {
            bail!("invalid nftables table name")
        }
        if self.runtime.debounce_ms == 0 || self.runtime.reconcile_secs == 0 {
            bail!("debounce and reconciliation intervals must be non-zero")
        }
        if self.nftables.batch_page_bytes < 64 * 1024 {
            bail!("batch_page_bytes must be at least 65536")
        }
        if self.nftables.populate_batch_elements == 0 {
            bail!("populate_batch_elements must be non-zero")
        }
        if self.xdp.ipv4_max_entries == 0
            || self.xdp.ipv6_max_entries == 0
            || self.xdp.populate_batch_elements == 0
        {
            bail!("XDP map capacities and population size must be non-zero")
        }
        if self.xdp.pin_path.as_os_str().is_empty() || !self.xdp.pin_path.is_absolute() {
            bail!("xdp.pin_path must be an absolute path")
        }
        if self.tc.ipv4_max_entries == 0
            || self.tc.ipv6_max_entries == 0
            || self.tc.populate_batch_elements == 0
        {
            bail!("TC map capacities and population size must be non-zero")
        }
        if self.tc.pin_path.as_os_str().is_empty() || !self.tc.pin_path.is_absolute() {
            bail!("tc.pin_path must be an absolute path")
        }
        if self.tc.pin_path == self.xdp.pin_path {
            bail!("tc.pin_path and xdp.pin_path must be different")
        }
        if cleanup {
            return Ok(());
        }
        if self.rules.input.is_empty()
            && self.rules.forward.is_empty()
            && self.rules.output.is_empty()
            && self.xdp.rules.is_empty()
            && self.tc.rules.is_empty()
        {
            bail!("at least one rule mapping is required")
        }
        for rule in &self.xdp.rules {
            if rule.blocklist != Direction::Inbound {
                bail!("XDP rules only support the inbound blocklist")
            }
            if rule.ingress_zones.is_empty() {
                bail!("XDP rules require at least one ingress zone")
            }
        }
        for rule in &self.tc.rules {
            if rule.blocklist != Direction::Outbound {
                bail!("TC rules only support the outbound blocklist")
            }
            if rule.egress_zones.is_empty() {
                bail!("TC rules require at least one egress zone")
            }
        }
        for direction in [Direction::Inbound, Direction::Outbound] {
            if self.uses(direction) && self.blocklist_path(direction).is_none() {
                bail!(
                    "[files].{} is required because a rule references the {} blocklist",
                    direction.name(),
                    direction.name()
                )
            }
        }
        match (&self.files.zones, &self.zones) {
            (None, None) => bail!("zones must be defined in [zones] or [files].zones"),
            (Some(_), Some(_)) => {
                bail!("zones must be defined in only one of [zones] or [files].zones")
            }
            _ => {}
        }
        let zones = self.load_zones()?;
        let xdp_interfaces = self.resolve_xdp_interfaces(&zones)?;
        if !self.xdp.allow_nftables_overlap && !xdp_interfaces.is_empty() {
            for rule in self.resolve_rules(&zones)? {
                if rule.blocklist != Direction::Inbound
                    || !matches!(
                        rule.chain,
                        crate::zones::Chain::Input | crate::zones::Chain::Forward
                    )
                {
                    continue;
                }
                if rule.ingress.is_empty()
                    || rule
                        .ingress
                        .iter()
                        .any(|name| xdp_interfaces.contains(name))
                {
                    bail!(
                        "XDP and nftables inbound rules overlap on a resolved ingress interface; set xdp.allow_nftables_overlap = true to allow this"
                    )
                }
            }
        }
        let tc_interfaces = self.resolve_tc_interfaces(&zones)?;
        if !self.tc.rules.is_empty() && tc_interfaces.is_empty() {
            bail!("TC rules must resolve to at least one egress interface")
        }
        if !self.tc.allow_nftables_overlap && !tc_interfaces.is_empty() {
            for rule in self.resolve_rules(&zones)? {
                if rule.blocklist != Direction::Outbound
                    || !matches!(
                        rule.chain,
                        crate::zones::Chain::Output | crate::zones::Chain::Forward
                    )
                {
                    continue;
                }
                if rule.egress.is_empty()
                    || rule.egress.iter().any(|name| tc_interfaces.contains(name))
                {
                    bail!(
                        "TC and nftables outbound rules overlap on a resolved egress interface; set tc.allow_nftables_overlap = true to allow this"
                    )
                }
            }
        }
        Ok(())
    }

    pub fn debounce(&self) -> Duration {
        Duration::from_millis(self.runtime.debounce_ms)
    }

    pub fn blocklist_path(&self, direction: Direction) -> Option<&Path> {
        match direction {
            Direction::Inbound => self.files.inbound.as_deref(),
            Direction::Outbound => self.files.outbound.as_deref(),
        }
    }

    pub fn uses(&self, direction: Direction) -> bool {
        self.rules
            .input
            .iter()
            .chain(&self.rules.forward)
            .chain(&self.rules.output)
            .any(|rule| rule.blocklist == direction)
            || self
                .xdp
                .rules
                .iter()
                .any(|rule| rule.blocklist == direction)
            || self.tc.rules.iter().any(|rule| rule.blocklist == direction)
    }

    pub fn uses_nftables(&self, direction: Direction) -> bool {
        self.rules
            .input
            .iter()
            .chain(&self.rules.forward)
            .chain(&self.rules.output)
            .any(|rule| rule.blocklist == direction)
    }

    pub fn resolve_xdp_interfaces(
        &self,
        zones: &Zones,
    ) -> Result<std::collections::BTreeSet<String>> {
        let mut interfaces = std::collections::BTreeSet::new();
        for rule in &self.xdp.rules {
            interfaces.extend(zones.interfaces(&rule.ingress_zones)?);
        }
        Ok(interfaces)
    }

    pub fn resolve_tc_interfaces(
        &self,
        zones: &Zones,
    ) -> Result<std::collections::BTreeSet<String>> {
        let mut interfaces = std::collections::BTreeSet::new();
        for rule in &self.tc.rules {
            interfaces.extend(zones.interfaces(&rule.egress_zones)?);
        }
        Ok(interfaces)
    }
    pub fn reconcile(&self) -> Duration {
        Duration::from_secs(self.runtime.reconcile_secs)
    }

    pub fn resolve_rules(&self, zones: &Zones) -> Result<Vec<ResolvedRule>> {
        zones.resolve(&self.rules)
    }

    pub fn load_zones(&self) -> Result<Zones> {
        match (&self.files.zones, &self.zones) {
            (Some(path), None) => Zones::load(path),
            (None, Some(zones)) => Ok(zones.clone()),
            (None, None) => bail!("zones must be defined in [zones] or [files].zones"),
            (Some(_), Some(_)) => {
                bail!("zones must be defined in only one of [zones] or [files].zones")
            }
        }
    }
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

pub fn open_blocklist(path: &Path) -> Result<std::io::BufReader<std::fs::File>> {
    Ok(std::io::BufReader::new(
        std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE_CONFIG: &str = r#"
[files]
inbound = "/data/inbound.txt"
outbound = "/data/outbound.txt"

[zones]
WAN = ["eth0"]
LOCAL = { interfaces = [], local = true }

[[rules.input]]
blocklist = "inbound"
ingress_zones = ["WAN"]
"#;

    #[test]
    fn accepts_inline_zones_without_a_zones_file() {
        let config: Config = toml::from_str(INLINE_CONFIG).unwrap();
        config.validate(false).unwrap();

        let rules = config.resolve_rules(&config.load_zones().unwrap()).unwrap();
        assert_eq!(rules[0].ingress, ["eth0"]);
    }

    #[test]
    fn accepts_an_omitted_unused_blocklist() {
        let text = INLINE_CONFIG.replace("outbound = \"/data/outbound.txt\"\n", "");
        let config: Config = toml::from_str(&text).unwrap();

        config.validate(false).unwrap();
        assert!(config.blocklist_path(Direction::Inbound).is_some());
        assert!(config.blocklist_path(Direction::Outbound).is_none());
    }

    #[test]
    fn rejects_an_omitted_referenced_blocklist() {
        let text = INLINE_CONFIG.replace("inbound = \"/data/inbound.txt\"\n", "");
        let config: Config = toml::from_str(&text).unwrap();

        let error = config.validate(false).unwrap_err().to_string();
        assert!(error.contains("[files].inbound is required"));
    }

    #[test]
    fn rejects_inline_and_file_zones_together() {
        let text = INLINE_CONFIG.replacen("[files]", "[files]\nzones = \"/data/zones.json\"", 1);
        let config: Config = toml::from_str(&text).unwrap();

        assert!(
            config
                .validate(false)
                .unwrap_err()
                .to_string()
                .contains("only one")
        );
    }

    #[test]
    fn explicit_zones_path_overrides_inline_zones() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("cidrwall.toml");
        let zones_path = root.path().join("zones.json");
        std::fs::write(&config_path, INLINE_CONFIG).unwrap();
        std::fs::write(&zones_path, r#"{"WAN":["wan0"]}"#).unwrap();
        let cli = Cli {
            config: config_path,
            zones: Some(zones_path),
            inbound: None,
            outbound: None,
            table: None,
            priority: None,
            debounce_ms: None,
            reconcile_secs: None,
            allow_flowtable_bypass: None,
            populate_batch_elements: None,
            check: false,
            cleanup: None,
        };

        let config = Config::load(&cli).unwrap();
        let rules = config.resolve_rules(&config.load_zones().unwrap()).unwrap();
        assert_eq!(rules[0].ingress, ["wan0"]);
    }

    #[test]
    fn accepts_xdp_ingress_with_nftables_output() {
        let text = r#"
[files]
inbound = "/data/inbound.txt"
outbound = "/data/outbound.txt"
[zones]
WAN = ["eth0"]
[[xdp.rules]]
blocklist = "inbound"
ingress_zones = ["WAN"]
[[rules.output]]
blocklist = "outbound"
egress_zones = ["WAN"]
"#;
        let config: Config = toml::from_str(text).unwrap();
        config.validate(false).unwrap();
        assert_eq!(
            config
                .resolve_xdp_interfaces(&config.load_zones().unwrap())
                .unwrap(),
            ["eth0".to_owned()].into_iter().collect()
        );
    }

    #[test]
    fn rejects_xdp_outbound_rules() {
        let text = INLINE_CONFIG
            .replace("[[rules.input]]", "[[xdp.rules]]")
            .replace("blocklist = \"inbound\"", "blocklist = \"outbound\"");
        let config: Config = toml::from_str(&text).unwrap();
        assert!(
            config
                .validate(false)
                .unwrap_err()
                .to_string()
                .contains("only support the inbound")
        );
    }

    #[test]
    fn rejects_accidental_xdp_nftables_overlap() {
        let text = INLINE_CONFIG.replace(
            "[[rules.input]]",
            "[[xdp.rules]]\nblocklist = \"inbound\"\ningress_zones = [\"WAN\"]\n\n[[rules.input]]",
        );
        let config: Config = toml::from_str(&text).unwrap();
        assert!(
            config
                .validate(false)
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );

        let allowed = text.replace("[zones]", "[xdp]\nallow_nftables_overlap = true\n\n[zones]");
        let config: Config = toml::from_str(&allowed).unwrap();
        config.validate(false).unwrap();
    }

    #[test]
    fn accepts_tc_outbound_rules_and_deduplicates_interfaces() {
        let text = r#"
[files]
outbound = "/data/outbound.txt"
[zones]
WAN = ["eth0", "eth1"]
BACKUP = ["eth1"]
[tc]
attach_order = "last"
[[tc.rules]]
blocklist = "outbound"
egress_zones = ["WAN", "BACKUP"]
"#;
        let config: Config = toml::from_str(text).unwrap();
        config.validate(false).unwrap();
        assert_eq!(config.tc.attach_order, TcAttachOrder::Last);
        assert_eq!(
            config
                .resolve_tc_interfaces(&config.load_zones().unwrap())
                .unwrap(),
            ["eth0".to_owned(), "eth1".to_owned()].into_iter().collect()
        );
    }

    #[test]
    fn rejects_tc_inbound_and_empty_egress_rules() {
        let inbound = INLINE_CONFIG
            .replace("[[rules.input]]", "[[tc.rules]]")
            .replace("ingress_zones", "egress_zones");
        let config: Config = toml::from_str(&inbound).unwrap();
        assert!(
            config
                .validate(false)
                .unwrap_err()
                .to_string()
                .contains("only support the outbound")
        );

        let empty = r#"
[files]
outbound = "/data/outbound.txt"
[zones]
WAN = ["eth0"]
[tc]
[[tc.rules]]
blocklist = "outbound"
egress_zones = []
"#;
        let config: Config = toml::from_str(empty).unwrap();
        assert!(
            config
                .validate(false)
                .unwrap_err()
                .to_string()
                .contains("at least one egress zone")
        );
    }

    #[test]
    fn rejects_accidental_tc_nftables_overlap() {
        let text = r#"
[files]
outbound = "/data/outbound.txt"
[zones]
WAN = ["eth0"]
[tc]
[[tc.rules]]
blocklist = "outbound"
egress_zones = ["WAN"]
[[rules.output]]
blocklist = "outbound"
egress_zones = ["WAN"]
"#;
        let config: Config = toml::from_str(text).unwrap();
        assert!(
            config
                .validate(false)
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );

        let allowed = text.replace("[tc]", "[tc]\nallow_nftables_overlap = true");
        let config: Config = toml::from_str(&allowed).unwrap();
        config.validate(false).unwrap();
    }

    #[test]
    fn rejects_shared_xdp_and_tc_pin_paths() {
        let text = INLINE_CONFIG.replace(
            "[zones]",
            "[tc]\npin_path = \"/sys/fs/bpf/cidrwall\"\n\n[zones]",
        );
        let config: Config = toml::from_str(&text).unwrap();
        assert!(
            config
                .validate(false)
                .unwrap_err()
                .to_string()
                .contains("must be different")
        );
    }
}
