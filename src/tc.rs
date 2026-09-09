use crate::{
    blocklist::{self, AddressPrefix},
    config::{Config, Direction, Tc as TcConfig, TcAttachOrder, open_blocklist},
};
use anyhow::{Context, Result, bail};
use aya::{
    Ebpf, EbpfLoader,
    maps::{
        Array, MapData,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        links::{FdLink, PinnedLink},
        tc::TcAttachOptions,
    },
};
use cidrwall_common::{Control, LAYOUT_VERSION, SLOT_COUNT};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fs,
    path::{Path, PathBuf},
};

const CONTROL: &str = "CONTROL";
const IPV4_A: &str = "IPV4_A";
const IPV4_B: &str = "IPV4_B";
const IPV6_A: &str = "IPV6_A";
const IPV6_B: &str = "IPV6_B";
const MAP_NAMES: [&str; 5] = [CONTROL, IPV4_A, IPV4_B, IPV6_A, IPV6_B];
const PROGRAM: &str = "cidrwall_tc";
const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cidrwall-tc"));

type V4Trie = LpmTrie<MapData, [u8; 4], u8>;
type V6Trie = LpmTrie<MapData, [u8; 16], u8>;

pub struct TcManager {
    config: TcConfig,
    interface_names: BTreeSet<String>,
    interfaces: BTreeMap<u32, String>,
    _ebpf: Ebpf,
    control: Array<MapData, Control>,
    ipv4_a: V4Trie,
    ipv4_b: V4Trie,
    ipv6_a: V6Trie,
    ipv6_b: V6Trie,
    links: BTreeMap<u32, PinnedLink>,
}

impl TcManager {
    pub fn new(config: &Config, interface_names: BTreeSet<String>) -> Result<Self> {
        let tc = config.tc.clone();
        fs::create_dir_all(&tc.pin_path)
            .with_context(|| format!("create TC pin directory {}", tc.pin_path.display()))?;
        fs::create_dir_all(link_dir(&tc))
            .with_context(|| format!("create TC link directory {}", link_dir(&tc).display()))?;

        let interfaces = resolve_interfaces(&interface_names)?;
        let mut loader = EbpfLoader::new();
        loader
            .default_map_pin_directory(&tc.pin_path)
            .map_max_entries(IPV4_A, tc.ipv4_max_entries)
            .map_max_entries(IPV4_B, tc.ipv4_max_entries)
            .map_max_entries(IPV6_A, tc.ipv6_max_entries)
            .map_max_entries(IPV6_B, tc.ipv6_max_entries);
        let mut ebpf = loader.load(OBJECT).context("load cidrwall TC object")?;

        let mut control: Array<_, Control> = ebpf
            .take_map(CONTROL)
            .context("TC object has no CONTROL map")?
            .try_into()?;
        let current = control.get(&0, 0)?;
        if current.layout_version == 0 {
            control.set(
                0,
                Control {
                    layout_version: LAYOUT_VERSION,
                    active_slot: 0,
                },
                0,
            )?;
        } else if current.layout_version != LAYOUT_VERSION || current.active_slot >= SLOT_COUNT {
            bail!(
                "{} contains an incompatible TC map layout (version={}, active_slot={})",
                tc.pin_path.display(),
                current.layout_version,
                current.active_slot
            );
        }

        let ipv4_a = take_v4(&mut ebpf, IPV4_A)?;
        let ipv4_b = take_v4(&mut ebpf, IPV4_B)?;
        let ipv6_a = take_v6(&mut ebpf, IPV6_A)?;
        let ipv6_b = take_v6(&mut ebpf, IPV6_B)?;

        let program: &mut SchedClassifier = ebpf
            .program_mut(PROGRAM)
            .context("TC object has no cidrwall_tc program")?
            .try_into()?;
        program.load().context("load cidrwall TCX program")?;

        Ok(Self {
            config: tc,
            interface_names,
            interfaces,
            _ebpf: ebpf,
            control,
            ipv4_a,
            ipv4_b,
            ipv6_a,
            ipv6_b,
            links: BTreeMap::new(),
        })
    }

    pub fn activate(&mut self) -> Result<()> {
        self.replace_startup_links()
    }

    pub fn reload(&mut self, config: &Config, reason: &str) -> Result<()> {
        let active = self.control.get(&0, 0)?.active_slot;
        let inactive = 1 - active;
        self.clear_slot(inactive)?;
        let path = config
            .blocklist_path(Direction::Outbound)
            .context("outbound blocklist is not configured for TC")?;
        let reader = open_blocklist(path)?;
        let mut ipv4 = 0u64;
        let mut ipv6 = 0u64;
        let result = blocklist::stream_chunks(
            reader,
            self.config.populate_batch_elements as usize,
            |chunk| {
                for interval in chunk {
                    for prefix in blocklist::interval_prefixes(*interval) {
                        match prefix {
                            AddressPrefix::V4 {
                                address,
                                prefix_len,
                            } => {
                                if ipv4 >= u64::from(self.config.ipv4_max_entries) {
                                    bail!(
                                        "TC IPv4 map capacity exceeded ({})",
                                        self.config.ipv4_max_entries
                                    );
                                }
                                self.v4_mut(inactive).insert(
                                    &Key::new(u32::from(prefix_len), address.octets()),
                                    1,
                                    0,
                                )?;
                                ipv4 += 1;
                            }
                            AddressPrefix::V6 {
                                address,
                                prefix_len,
                            } => {
                                if ipv6 >= u64::from(self.config.ipv6_max_entries) {
                                    bail!(
                                        "TC IPv6 map capacity exceeded ({})",
                                        self.config.ipv6_max_entries
                                    );
                                }
                                self.v6_mut(inactive).insert(
                                    &Key::new(u32::from(prefix_len), address.octets()),
                                    1,
                                    0,
                                )?;
                                ipv6 += 1;
                            }
                        }
                    }
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            if let Err(clear) = self.clear_slot(inactive) {
                log::error!("failed to clear rejected TC staging slot: {clear:#}");
            }
            return Err(error).with_context(|| format!("stage TC blocklist {}", path.display()));
        }

        self.control.set(
            0,
            Control {
                layout_version: LAYOUT_VERSION,
                active_slot: inactive,
            },
            0,
        )?;
        if let Err(error) = self.clear_slot(active) {
            log::error!("obsolete TC slot cleanup deferred: {error:#}");
        }
        log::info!(
            "activated TC blocklist: reason={reason} path={} ipv4_prefixes={ipv4} ipv6_prefixes={ipv6} slot={inactive}",
            path.display()
        );
        Ok(())
    }

    pub fn reconcile(&mut self) -> Result<()> {
        let state = self.control.get(&0, 0)?;
        if state.layout_version != LAYOUT_VERSION || state.active_slot >= SLOT_COUNT {
            bail!("TC control map has an incompatible layout");
        }
        let current = resolve_interfaces(&self.interface_names)?;
        let obsolete: Vec<_> = self
            .links
            .keys()
            .filter(|ifindex| !current.contains_key(ifindex))
            .copied()
            .collect();
        for ifindex in obsolete {
            if let Some(link) = self.links.remove(&ifindex) {
                drop(link.unpin().context("unpin obsolete TCX link")?);
            }
        }
        self.interfaces = current;
        self.attach_missing_links()
    }

    pub fn cleanup(mut self) -> Result<()> {
        let pin_path = self.config.pin_path.clone();
        for (_, link) in std::mem::take(&mut self.links) {
            drop(link.unpin().context("unpin TCX link")?);
        }
        drop(self);
        remove_map_pins(&pin_path)
    }

    pub fn cleanup_pinned(config: &TcConfig) -> Result<()> {
        validate_pinned_layout(config)?;
        if link_dir(config).exists() {
            for entry in fs::read_dir(link_dir(config))? {
                let path = entry?.path();
                if path.is_file() {
                    drop(PinnedLink::from_pin(&path)?.unpin()?);
                }
            }
        }
        remove_map_pins(&config.pin_path)
    }

    fn replace_startup_links(&mut self) -> Result<()> {
        let desired: BTreeSet<_> = self.interfaces.keys().copied().collect();
        for entry in fs::read_dir(link_dir(&self.config))? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Ok(ifindex) = name.parse::<u32>() else {
                continue;
            };
            if !desired.contains(&ifindex) {
                drop(PinnedLink::from_pin(&path)?.unpin()?);
            }
        }

        for (ifindex, name) in self.interfaces.clone() {
            let path = link_path(&self.config, ifindex);
            let old = path
                .exists()
                .then(|| PinnedLink::from_pin(&path))
                .transpose()?;
            let new = self.attach_new(&name, ifindex)?;
            if let Some(old) = old {
                let old_fd = old.unpin().context("unpin replaced TCX link")?;
                match new.pin(&path) {
                    Ok(pinned) => {
                        self.links.insert(ifindex, pinned);
                        drop(old_fd);
                    }
                    Err(error) => {
                        let _ = old_fd.pin(&path);
                        return Err(error.into());
                    }
                }
            } else {
                self.links.insert(ifindex, new.pin(&path)?);
            }
            log::info!("attached TCX: interface={name} ifindex={ifindex}");
        }
        Ok(())
    }

    fn attach_missing_links(&mut self) -> Result<()> {
        let missing: Vec<_> = self
            .interfaces
            .iter()
            .filter(|(ifindex, _)| !self.links.contains_key(ifindex))
            .map(|(ifindex, name)| (*ifindex, name.clone()))
            .collect();
        let mut attached = Vec::new();
        for (ifindex, name) in missing {
            match self.attach_new(&name, ifindex) {
                Ok(link) => {
                    let pinned = link.pin(link_path(&self.config, ifindex))?;
                    self.links.insert(ifindex, pinned);
                    attached.push(ifindex);
                    log::info!("attached TCX: interface={name} ifindex={ifindex}");
                }
                Err(error) => {
                    for ifindex in attached {
                        if let Some(link) = self.links.remove(&ifindex)
                            && let Err(cleanup) = link.unpin()
                        {
                            log::error!("failed to roll back TCX link {ifindex}: {cleanup}");
                        }
                    }
                    return Err(error)
                        .with_context(|| format!("attach TCX to {name} (ifindex {ifindex})"));
                }
            }
        }
        Ok(())
    }

    fn attach_new(&mut self, name: &str, ifindex: u32) -> Result<FdLink> {
        let order = match self.config.attach_order {
            TcAttachOrder::First => LinkOrder::first(),
            TcAttachOrder::Last => LinkOrder::last(),
        };
        let program: &mut SchedClassifier = self
            ._ebpf
            .program_mut(PROGRAM)
            .context("TC object has no cidrwall_tc program")?
            .try_into()?;
        let id = program
            .attach_with_options(
                name,
                TcAttachType::Egress,
                TcAttachOptions::TcxOrder(order),
            )
            .with_context(|| {
                format!(
                    "attach TCX egress program to {name} (ifindex {ifindex}); TC requires Linux 6.6 or newer"
                )
            })?;
        let link = program.take_link(id)?;
        link.try_into()
            .map_err(|_| anyhow::anyhow!("kernel did not create a pinnable TCX link"))
    }

    fn clear_slot(&mut self, slot: u32) -> Result<()> {
        let v4_keys: Vec<_> = self.v4_mut(slot).keys().collect::<Result<_, _>>()?;
        for key in v4_keys {
            self.v4_mut(slot).remove(&key)?;
        }
        let v6_keys: Vec<_> = self.v6_mut(slot).keys().collect::<Result<_, _>>()?;
        for key in v6_keys {
            self.v6_mut(slot).remove(&key)?;
        }
        Ok(())
    }

    fn v4_mut(&mut self, slot: u32) -> &mut V4Trie {
        if slot == 0 {
            &mut self.ipv4_a
        } else {
            &mut self.ipv4_b
        }
    }

    fn v6_mut(&mut self, slot: u32) -> &mut V6Trie {
        if slot == 0 {
            &mut self.ipv6_a
        } else {
            &mut self.ipv6_b
        }
    }
}

fn take_v4(ebpf: &mut Ebpf, name: &str) -> Result<V4Trie> {
    Ok(ebpf
        .take_map(name)
        .with_context(|| format!("TC object has no {name} map"))?
        .try_into()?)
}

fn take_v6(ebpf: &mut Ebpf, name: &str) -> Result<V6Trie> {
    Ok(ebpf
        .take_map(name)
        .with_context(|| format!("TC object has no {name} map"))?
        .try_into()?)
}

fn resolve_interfaces(names: &BTreeSet<String>) -> Result<BTreeMap<u32, String>> {
    let mut interfaces = BTreeMap::new();
    for name in names {
        if name.contains('/') || name == "." || name == ".." {
            bail!("invalid interface name {name:?}");
        }
        let path = Path::new("/sys/class/net").join(name).join("ifindex");
        let ifindex: u32 = fs::read_to_string(&path)
            .with_context(|| format!("TC interface {name:?} does not exist"))?
            .trim()
            .parse()
            .with_context(|| format!("read interface index from {}", path.display()))?;
        if interfaces.insert(ifindex, name.clone()).is_some() {
            bail!("multiple TC interfaces resolved to ifindex {ifindex}");
        }
    }
    Ok(interfaces)
}

fn validate_pinned_layout(config: &TcConfig) -> Result<()> {
    let path = config.pin_path.join(CONTROL);
    if !path.exists() {
        bail!(
            "no cidrwall TC state exists at {}",
            config.pin_path.display()
        );
    }
    let map = MapData::from_pin(&path)?;
    let control = Array::<_, Control>::try_from(aya::maps::Map::Array(map))?;
    let state = control.get(&0, 0)?;
    if state.layout_version != LAYOUT_VERSION || state.active_slot >= SLOT_COUNT {
        bail!(
            "refusing to clean an incompatible TC layout at {}",
            config.pin_path.display()
        );
    }
    Ok(())
}

fn remove_map_pins(pin_path: &Path) -> Result<()> {
    for name in MAP_NAMES {
        let path = pin_path.join(name);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("remove TC map pin {}", path.display()))?;
        }
    }
    let links = pin_path.join("links");
    if links.exists() {
        fs::remove_dir(&links)
            .with_context(|| format!("remove TC link directory {}", links.display()))?;
    }
    if pin_path.exists() {
        fs::remove_dir(pin_path)
            .with_context(|| format!("remove TC pin directory {}", pin_path.display()))?;
    }
    Ok(())
}

fn link_dir(config: &TcConfig) -> PathBuf {
    config.pin_path.join("links")
}

fn link_path(config: &TcConfig, ifindex: u32) -> PathBuf {
    link_dir(config).join(ifindex.to_string())
}
