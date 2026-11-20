//! Optional JSON status file.
//!
//! The same state as `/metrics`, for local readers such as health checks and status tools that
//! would rather not parse Prometheus text, and without a listener. A background thread rewrites
//! it atomically every `status.interval_secs`, so a reader can tell a stuck daemon by `updated`.

use crate::{
    config::Config,
    metrics::{Engine, Metrics, Sample, sample, unix_now},
};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{fs, path::Path, thread, time::Duration};

/// Bumped when a field changes meaning or goes away; new fields keep the version.
const VERSION: u32 = 1;

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Status {
    version: u32,
    /// Unix seconds of this snapshot.
    updated: u64,
    /// One entry per enforcement path: a backend applying a blocklist in a direction.
    enforcement: Vec<Enforcement>,
    reconcile_failures: u64,
    /// Backends whose packet counters could not be read for this snapshot.
    counter_errors: Vec<&'static str>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Enforcement {
    backend: &'static str,
    direction: &'static str,
    interfaces: Vec<String>,
    ipv4_prefixes: u64,
    ipv6_prefixes: u64,
    source_cidrs: u64,
    /// Active A/B map slot (XDP and TC only).
    active_slot: Option<u32>,
    /// Unix seconds of the last successful apply.
    last_success: Option<u64>,
    /// The most recent apply succeeded; false before the first one.
    last_apply_ok: bool,
    /// Rejected reloads; the previous generation stayed active.
    apply_failures: u64,
    dropped: Counter,
    /// nftables counts drops only.
    passed: Option<Counter>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
struct Counter {
    packets: u64,
    bytes: u64,
}

/// Start the writer thread when `status.file` is set.
pub fn spawn(config: &Config, metrics: &Metrics) -> Result<()> {
    let Some(path) = config.status.file.clone() else {
        return Ok(());
    };
    let interval = Duration::from_secs(config.status.interval_secs);
    let config = config.clone();
    let metrics = metrics.clone();
    thread::Builder::new()
        .name("status".into())
        .spawn(move || {
            log::info!("status file enabled: path={}", path.display());
            let mut last_error = None;
            loop {
                let status = build(&sample(&config, &metrics), unix_now());
                match write(&path, &status) {
                    Ok(()) => last_error = None,
                    Err(error) => {
                        let message = format!("{error:#}");
                        if last_error.as_ref() != Some(&message) {
                            log::warn!("status file write failed: {message}");
                            last_error = Some(message);
                        }
                    }
                }
                thread::sleep(interval);
            }
        })
        .context("spawn status file thread")?;
    Ok(())
}

fn build(sample: &Sample, now: u64) -> Status {
    let state = &sample.state;
    let enforcement = state
        .applies
        .iter()
        .map(|(&(engine, direction), apply)| {
            let mut dropped = Counter::default();
            let mut passed = (engine != Engine::Nftables).then(Counter::default);
            for packet in sample
                .packets
                .iter()
                .filter(|p| p.engine == engine && p.direction == direction)
            {
                let counter = if packet.verdict == "drop" {
                    Some(&mut dropped)
                } else {
                    passed.as_mut()
                };
                if let Some(counter) = counter {
                    counter.packets = counter.packets.saturating_add(packet.packets);
                    counter.bytes = counter.bytes.saturating_add(packet.bytes);
                }
            }
            let interfaces = if engine == Engine::Nftables {
                state
                    .nft_interfaces
                    .get(&direction)
                    .map(|names| names.iter().cloned().collect())
                    .unwrap_or_default()
            } else {
                state
                    .interfaces
                    .get(&engine)
                    .map(|names| names.values().cloned().collect())
                    .unwrap_or_default()
            };
            Enforcement {
                backend: engine.name(),
                direction: direction.name(),
                interfaces,
                ipv4_prefixes: apply.ipv4_entries,
                ipv6_prefixes: apply.ipv6_entries,
                source_cidrs: apply.source_cidrs,
                active_slot: apply.active_slot,
                last_success: apply.last_success_unix,
                last_apply_ok: apply.last_ok,
                apply_failures: apply.failures,
                dropped,
                passed,
            }
        })
        .collect();
    Status {
        version: VERSION,
        updated: now,
        enforcement,
        reconcile_failures: state.reconcile_failures,
        counter_errors: sample.failed.iter().map(|e| e.name()).collect(),
    }
}

/// Write through a temporary file in the same directory, so readers never see a partial file.
fn write(path: &Path, status: &Status) -> Result<()> {
    let json = serde_json::to_vec_pretty(status).context("serialize status")?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    fs::write(&temporary, json).with_context(|| format!("write {}", path.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Direction;
    use crate::metrics::PacketSample;
    use std::collections::BTreeMap;

    /// Interface names by index, as the eBPF managers record them.
    fn names(pairs: &[(u32, &str)]) -> BTreeMap<u32, String> {
        pairs.iter().map(|(i, n)| (*i, (*n).to_string())).collect()
    }

    fn packet(
        engine: Engine,
        direction: Direction,
        interface: &str,
        verdict: &'static str,
        n: u64,
    ) -> PacketSample {
        PacketSample {
            engine,
            direction,
            interface: interface.into(),
            family: "ipv4",
            verdict,
            packets: n,
            bytes: n * 100,
        }
    }

    #[test]
    fn sums_counters_per_enforcement_path() {
        let metrics = Metrics::default();
        metrics.configure(Engine::Xdp, Direction::Inbound);
        metrics.set_interfaces(Engine::Xdp, names(&[(2, "wan0"), (3, "wan1")]));
        metrics.applied(Engine::Xdp, Direction::Inbound, 10, 2, 11, Some(1));
        metrics.configure(Engine::Nftables, Direction::Outbound);
        metrics.set_nft_interfaces(Direction::Outbound, ["wan0".to_string()].into());
        metrics.apply_failed(Engine::Nftables, Direction::Outbound);
        metrics.reconcile_failed();
        let sample = Sample {
            state: crate::metrics::state(&metrics),
            packets: vec![
                packet(Engine::Xdp, Direction::Inbound, "wan0", "drop", 5),
                packet(Engine::Xdp, Direction::Inbound, "wan1", "drop", 2),
                packet(Engine::Xdp, Direction::Inbound, "wan0", "pass", 40),
                packet(Engine::Nftables, Direction::Outbound, "", "drop", 3),
            ],
            failed: vec![Engine::Tc],
        };

        let status = build(&sample, 1_000);
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["updated"], 1_000);
        assert_eq!(json["reconcileFailures"], 1);
        assert_eq!(json["counterErrors"], serde_json::json!(["tc"]));
        let nft = &json["enforcement"][0];
        assert_eq!(nft["backend"], "nftables");
        assert_eq!(nft["direction"], "outbound");
        assert_eq!(nft["interfaces"], serde_json::json!(["wan0"]));
        assert_eq!(nft["lastApplyOk"], false);
        assert_eq!(nft["lastSuccess"], serde_json::Value::Null);
        assert_eq!(nft["applyFailures"], 1);
        assert_eq!(
            nft["dropped"],
            serde_json::json!({"packets": 3, "bytes": 300})
        );
        assert_eq!(nft["passed"], serde_json::Value::Null);
        let xdp = &json["enforcement"][1];
        assert_eq!(xdp["backend"], "xdp");
        assert_eq!(xdp["interfaces"], serde_json::json!(["wan0", "wan1"]));
        assert_eq!(xdp["ipv4Prefixes"], 10);
        assert_eq!(xdp["ipv6Prefixes"], 2);
        assert_eq!(xdp["sourceCidrs"], 11);
        assert_eq!(xdp["activeSlot"], 1);
        assert_eq!(xdp["lastApplyOk"], true);
        assert_eq!(
            xdp["dropped"],
            serde_json::json!({"packets": 7, "bytes": 700})
        );
        assert_eq!(
            xdp["passed"],
            serde_json::json!({"packets": 40, "bytes": 4000})
        );
    }

    #[test]
    fn replaces_the_file_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        let sample = Sample {
            state: crate::metrics::state(&Metrics::default()),
            packets: Vec::new(),
            failed: Vec::new(),
        };
        write(&path, &build(&sample, 1)).unwrap();
        write(&path, &build(&sample, 2)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(json["updated"], 2);
        assert_eq!(json["enforcement"], serde_json::json!([]));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
