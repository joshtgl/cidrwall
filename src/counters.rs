//! Per-interface packet counters shared by the XDP and TCX programs.
//!
//! The daemon owns the keys: it creates an entry when it attaches to an interface and removes
//! entries for interfaces it no longer manages. The programs only look entries up and fall back
//! to `COUNTERS_UNKNOWN`, so packets are never lost from the totals.

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::{Map, MapData, MapError, PerCpuArray, PerCpuHashMap, PerCpuValues},
    util::nr_cpus,
};
use cidrwall_common::{Counter, Counters};
use std::{collections::BTreeSet, path::Path};

pub const COUNTERS: &str = "COUNTERS";
pub const COUNTERS_UNKNOWN: &str = "COUNTERS_UNKNOWN";

const BPF_NOEXIST: u64 = 1;
const E2BIG: i32 = 7;
const EEXIST: i32 = 17;

pub struct CounterMaps {
    label: &'static str,
    counters: PerCpuHashMap<MapData, u32, Counters>,
}

impl CounterMaps {
    pub fn take(ebpf: &mut Ebpf, label: &'static str) -> Result<Self> {
        let counters = ebpf
            .take_map(COUNTERS)
            .with_context(|| format!("{label} object has no {COUNTERS} map"))?
            .try_into()?;
        Ok(Self { label, counters })
    }

    /// Make the map hold exactly one entry per managed interface. Counting is best-effort, so
    /// failures are logged rather than allowed to block attachment.
    pub fn sync(&mut self, ifindexes: &BTreeSet<u32>) {
        if let Err(error) = self.retain(ifindexes) {
            log::warn!("failed to remove stale {} counters: {error:#}", self.label);
        }
        for ifindex in ifindexes {
            if let Err(error) = self.track(*ifindex) {
                log::warn!("{error:#}");
            }
        }
    }

    /// Create a zeroed entry for `ifindex`, keeping counts already pinned for it.
    fn track(&mut self, ifindex: u32) -> Result<()> {
        let cpus = nr_cpus().map_err(|(_, error)| error)?.get() as usize;
        let zeroed = PerCpuValues::try_from(vec![Counters::default(); cpus])?;
        match self.counters.insert(&ifindex, zeroed, BPF_NOEXIST) {
            Ok(()) => Ok(()),
            Err(error) if errno(&error) == Some(EEXIST) => Ok(()),
            Err(error) if errno(&error) == Some(E2BIG) => {
                log::warn!(
                    "{} counter map is full; ifindex {ifindex} will be counted as unknown",
                    self.label
                );
                Ok(())
            }
            Err(error) => Err(error)
                .with_context(|| format!("create {} counters for ifindex {ifindex}", self.label)),
        }
    }

    /// Remove entries for interfaces outside `keep`, so a reused ifindex starts from zero.
    fn retain(&mut self, keep: &BTreeSet<u32>) -> Result<()> {
        let stale: Vec<_> = self
            .counters
            .keys()
            .filter(|key| !matches!(key, Ok(ifindex) if keep.contains(ifindex)))
            .collect::<Result<_, _>>()?;
        for ifindex in stale {
            self.counters
                .remove(&ifindex)
                .with_context(|| format!("remove {} counters for ifindex {ifindex}", self.label))?;
        }
        Ok(())
    }
}

/// Per-interface totals summed across CPUs; `None` is the unknown-interface bucket.
pub fn read_pinned(pin_path: &Path) -> Result<Vec<(Option<u32>, Counters)>> {
    let map = MapData::from_pin(pin_path.join(COUNTERS))?;
    let counters = PerCpuHashMap::<_, u32, Counters>::try_from(Map::PerCpuHashMap(map))?;
    let map = MapData::from_pin(pin_path.join(COUNTERS_UNKNOWN))?;
    let unknown = PerCpuArray::<_, Counters>::try_from(Map::PerCpuArray(map))?;
    let mut totals = Vec::new();
    for entry in counters.iter() {
        let (ifindex, values) = entry?;
        totals.push((Some(ifindex), sum(&values)));
    }
    totals.push((None, sum(&unknown.get(&0, 0)?)));
    Ok(totals)
}

fn sum(values: &PerCpuValues<Counters>) -> Counters {
    let mut total = Counters::default();
    for cpu in values.iter() {
        for (total, value) in total.slots.iter_mut().zip(cpu.slots) {
            *total = Counter {
                packets: total.packets.wrapping_add(value.packets),
                bytes: total.bytes.wrapping_add(value.bytes),
            };
        }
    }
    total
}

fn errno(error: &MapError) -> Option<i32> {
    match error {
        MapError::SyscallError(error) => error.io_error.raw_os_error(),
        _ => None,
    }
}
