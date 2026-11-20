//! Optional Prometheus `/metrics` listener.
//!
//! The daemon records apply outcomes into shared state; packet counters are read from the kernel
//! when a scrape arrives, so the endpoint never serves stale values and needs no timer.

use crate::config::{Config, Direction};
use anyhow::{Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Budget for reading a whole request, and separately for writing the whole response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const BIND_RETRY_INITIAL: Duration = Duration::from_secs(1);
const BIND_RETRY_MAX: Duration = Duration::from_secs(60);
const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);
const MAX_REQUEST_BYTES: u64 = 8192;
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Outcome of one successful eBPF blocklist apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyStats {
    pub ipv4_prefixes: u64,
    pub ipv6_prefixes: u64,
    pub source_cidrs: u64,
    pub slot: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Engine {
    Nftables,
    Xdp,
    Tc,
}

impl Engine {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Xdp => "xdp",
            Self::Tc => "tc",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ApplyState {
    pub(crate) active_slot: Option<u32>,
    pub(crate) ipv4_entries: u64,
    pub(crate) ipv6_entries: u64,
    pub(crate) source_cidrs: u64,
    pub(crate) last_success_unix: Option<u64>,
    pub(crate) failures: u64,
    pub(crate) last_ok: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct State {
    pub(crate) applies: BTreeMap<(Engine, Direction), ApplyState>,
    pub(crate) interfaces: BTreeMap<Engine, BTreeMap<u32, String>>,
    /// Interfaces the nftables rules match, which have no per-interface counters.
    pub(crate) nft_interfaces: BTreeMap<Direction, BTreeSet<String>>,
    pub(crate) reconcile_failures: u64,
    scrape_errors: BTreeMap<Engine, u64>,
}

/// Cheap handle to the daemon's metric state; clones share the same state.
#[derive(Clone, Default)]
pub struct Metrics(Arc<Mutex<State>>);

impl Metrics {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register an enforcement path so it reports `last_apply_ok 0` before its first apply.
    pub fn configure(&self, engine: Engine, direction: Direction) {
        self.lock().applies.entry((engine, direction)).or_default();
    }

    pub fn applied(
        &self,
        engine: Engine,
        direction: Direction,
        ipv4_entries: u64,
        ipv6_entries: u64,
        source_cidrs: u64,
        active_slot: Option<u32>,
    ) {
        let mut state = self.lock();
        let entry = state.applies.entry((engine, direction)).or_default();
        entry.active_slot = active_slot;
        entry.ipv4_entries = ipv4_entries;
        entry.ipv6_entries = ipv6_entries;
        entry.source_cidrs = source_cidrs;
        entry.last_success_unix = Some(unix_now());
        entry.last_ok = true;
    }

    pub fn apply_failed(&self, engine: Engine, direction: Direction) {
        let mut state = self.lock();
        let entry = state.applies.entry((engine, direction)).or_default();
        entry.failures += 1;
        entry.last_ok = false;
    }

    pub fn reconcile_failed(&self) {
        self.lock().reconcile_failures += 1;
    }

    pub fn set_interfaces(&self, engine: Engine, interfaces: BTreeMap<u32, String>) {
        self.lock().interfaces.insert(engine, interfaces);
    }

    pub fn set_nft_interfaces(&self, direction: Direction, interfaces: BTreeSet<String>) {
        self.lock().nft_interfaces.insert(direction, interfaces);
    }
}

/// Packet and byte totals for one label set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PacketSample {
    pub(crate) engine: Engine,
    pub(crate) direction: Direction,
    pub(crate) interface: String,
    pub(crate) family: &'static str,
    pub(crate) verdict: &'static str,
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
}

/// The daemon's recorded state with the kernel counters read alongside it.
pub(crate) struct Sample {
    pub(crate) state: State,
    pub(crate) packets: Vec<PacketSample>,
    /// Engines whose counters could not be read this time.
    pub(crate) failed: Vec<Engine>,
}

/// Bind the listener and serve scrapes on a background thread.
/// Start one listener thread per address. Binding happens on that thread and is retried with
/// backoff, so an address that is not yet available never blocks or fails blocklist enforcement.
pub fn spawn(addresses: &[SocketAddr], config: &Config, metrics: &Metrics) -> Result<()> {
    for &address in addresses {
        let config = config.clone();
        let metrics = metrics.clone();
        thread::Builder::new()
            .name("metrics".into())
            .spawn(move || listen(address, &config, &metrics, BIND_RETRY_INITIAL))
            .with_context(|| format!("spawn metrics listener thread for {address}"))?;
    }
    Ok(())
}

fn listen(address: SocketAddr, config: &Config, metrics: &Metrics, retry: Duration) {
    let listener = bind_with_retry(address, retry);
    log::info!("metrics listener started: address={address} path=/metrics");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve(stream, config, metrics) {
                    log::debug!("metrics request failed: address={address}: {error}");
                }
            }
            Err(error) => {
                log::warn!("metrics listener accept failed: address={address}: {error}");
                // Errors such as EMFILE persist briefly; avoid spinning on them.
                thread::sleep(ACCEPT_ERROR_DELAY);
            }
        }
    }
}

/// Bind `address`, doubling the delay between attempts up to `BIND_RETRY_MAX`. A failure is
/// logged as a warning when first seen or when the error changes; repeats are logged at debug.
fn bind_with_retry(address: SocketAddr, initial: Duration) -> TcpListener {
    let mut delay = initial;
    let mut last_error = None;
    loop {
        match TcpListener::bind(address) {
            Ok(listener) => return listener,
            Err(error) => {
                let message = error.to_string();
                if last_error.as_ref() == Some(&message) {
                    log::debug!(
                        "metrics listener bind failed: address={address} retry_in={delay:?}: {error}"
                    );
                } else {
                    log::warn!(
                        "metrics listener bind failed; retrying in the background: address={address} retry_in={delay:?}: {error}"
                    );
                    last_error = Some(message);
                }
                thread::sleep(delay);
                delay = delay.saturating_mul(2).min(BIND_RETRY_MAX);
            }
        }
    }
}

/// Socket I/O bounded by one deadline across every call, so a client trickling bytes cannot hold
/// a listener thread longer than the deadline.
struct Deadline<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl<'a> Deadline<'a> {
    fn new(stream: &'a TcpStream, budget: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + budget,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "metrics request deadline exceeded",
            ));
        }
        Ok(remaining)
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        let mut stream = self.stream;
        stream.read(buffer)
    }
}

impl Write for Deadline<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        let mut stream = self.stream;
        stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stream = self.stream;
        stream.flush()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Metrics,
    NotFound,
    MethodNotAllowed,
    BadRequest,
}

fn route(request_line: &str) -> Route {
    let mut parts = request_line.split_ascii_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Route::BadRequest;
    };
    if !version.starts_with("HTTP/") {
        return Route::BadRequest;
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    match (method, path) {
        ("GET", "/metrics") => Route::Metrics,
        (_, "/metrics") => Route::MethodNotAllowed,
        _ => Route::NotFound,
    }
}

fn serve(stream: TcpStream, config: &Config, metrics: &Metrics) -> io::Result<()> {
    let mut reader =
        BufReader::new(Deadline::new(&stream, REQUEST_TIMEOUT).take(MAX_REQUEST_BYTES));
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    // Drain headers so closing the socket does not reset the connection before the reply lands.
    let mut header = String::new();
    while reader.read_line(&mut header)? > 0 && !matches!(header.as_str(), "\r\n" | "\n") {
        header.clear();
    }
    let (status, content_type, body) = match route(&request_line) {
        Route::Metrics => ("200 OK", CONTENT_TYPE, collect(config, metrics)),
        Route::NotFound => ("404 Not Found", "text/plain", "not found\n".into()),
        Route::MethodNotAllowed => (
            "405 Method Not Allowed",
            "text/plain",
            "method not allowed\n".into(),
        ),
        Route::BadRequest => ("400 Bad Request", "text/plain", "bad request\n".into()),
    };
    let mut stream = Deadline::new(&stream, REQUEST_TIMEOUT);
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Read kernel counters, then render them with the daemon's recorded state.
fn collect(config: &Config, metrics: &Metrics) -> String {
    let sample = sample(config, metrics);
    render(&sample.state, &sample.packets)
}

/// Read kernel counters and take a copy of the daemon's recorded state.
pub(crate) fn sample(config: &Config, metrics: &Metrics) -> Sample {
    #[cfg(any(feature = "xdp", feature = "tc"))]
    let interfaces = metrics.lock().interfaces.clone();
    let mut samples = Vec::new();
    let mut failed = Vec::new();
    #[cfg(feature = "xdp")]
    if !config.xdp.rules.is_empty() {
        match ebpf_samples(
            Engine::Xdp,
            Direction::Inbound,
            &config.xdp.pin_path,
            &interfaces,
        ) {
            Ok(values) => samples.extend(values),
            Err(error) => {
                log::debug!("XDP counters unavailable: {error:#}");
                failed.push(Engine::Xdp);
            }
        }
    }
    #[cfg(feature = "tc")]
    if !config.tc.rules.is_empty() {
        match ebpf_samples(
            Engine::Tc,
            Direction::Outbound,
            &config.tc.pin_path,
            &interfaces,
        ) {
            Ok(values) => samples.extend(values),
            Err(error) => {
                log::debug!("TC counters unavailable: {error:#}");
                failed.push(Engine::Tc);
            }
        }
    }
    if [Direction::Inbound, Direction::Outbound]
        .into_iter()
        .any(|direction| config.uses_nftables(direction))
    {
        match crate::netlink::drop_counters(config) {
            Ok(values) => samples.extend(values.into_iter().map(|value| PacketSample {
                engine: Engine::Nftables,
                direction: value.direction,
                interface: String::new(),
                family: value.family,
                verdict: "drop",
                packets: value.packets,
                bytes: value.bytes,
            })),
            Err(error) => {
                log::debug!("nftables counters unavailable: {error}");
                failed.push(Engine::Nftables);
            }
        }
    }
    let state = {
        let mut state = metrics.lock();
        for engine in &failed {
            *state.scrape_errors.entry(*engine).or_default() += 1;
        }
        state.clone()
    };
    Sample {
        state,
        packets: samples,
        failed,
    }
}

#[cfg(any(feature = "xdp", feature = "tc"))]
fn ebpf_samples(
    engine: Engine,
    direction: Direction,
    pin_path: &std::path::Path,
    interfaces: &BTreeMap<Engine, BTreeMap<u32, String>>,
) -> Result<Vec<PacketSample>> {
    use cidrwall_common::{Family, counter_index};
    let names = interfaces.get(&engine);
    let mut samples = Vec::new();
    for (ifindex, counters) in crate::counters::read_pinned(pin_path)? {
        let interface = match ifindex {
            None => String::new(),
            Some(ifindex) => names
                .and_then(|names| names.get(&ifindex))
                .cloned()
                .unwrap_or_else(|| ifindex.to_string()),
        };
        for family in Family::ALL {
            for (verdict, dropped) in [("pass", false), ("drop", true)] {
                let Some(&counter) = counters.slots.get(counter_index(family, dropped)) else {
                    continue;
                };
                samples.push(PacketSample {
                    engine,
                    direction,
                    interface: interface.clone(),
                    family: family.name(),
                    verdict,
                    packets: counter.packets,
                    bytes: counter.bytes,
                });
            }
        }
    }
    Ok(samples)
}

fn render(state: &State, samples: &[PacketSample]) -> String {
    let mut out = String::new();
    let packet_labels = |sample: &PacketSample| {
        format!(
            "backend=\"{}\",direction=\"{}\",interface=\"{}\",family=\"{}\",verdict=\"{}\"",
            sample.engine.name(),
            sample.direction.name(),
            escape(&sample.interface),
            sample.family,
            sample.verdict
        )
    };
    header(
        &mut out,
        "cidrwall_packets_total",
        "counter",
        "Packets evaluated against a blocklist; nftables counts drops only.",
    );
    for sample in samples {
        sample_line(
            &mut out,
            "cidrwall_packets_total",
            &packet_labels(sample),
            sample.packets,
        );
    }
    header(
        &mut out,
        "cidrwall_bytes_total",
        "counter",
        "Bytes evaluated against a blocklist; nftables counts drops only.",
    );
    for sample in samples {
        sample_line(
            &mut out,
            "cidrwall_bytes_total",
            &packet_labels(sample),
            sample.bytes,
        );
    }

    let apply_labels = |engine: Engine, direction: Direction| {
        format!(
            "backend=\"{}\",direction=\"{}\"",
            engine.name(),
            direction.name()
        )
    };
    header(
        &mut out,
        "cidrwall_loaded_entries",
        "gauge",
        "Kernel entries in the active blocklist: nftables interval elements or eBPF LPM prefixes.",
    );
    for ((engine, direction), apply) in &state.applies {
        for (family, value) in [("ipv4", apply.ipv4_entries), ("ipv6", apply.ipv6_entries)] {
            let labels = format!("{},family=\"{family}\"", apply_labels(*engine, *direction));
            sample_line(&mut out, "cidrwall_loaded_entries", &labels, value);
        }
    }
    header(
        &mut out,
        "cidrwall_source_cidrs",
        "gauge",
        "CIDRs read from the blocklist file for the active generation.",
    );
    for ((engine, direction), apply) in &state.applies {
        sample_line(
            &mut out,
            "cidrwall_source_cidrs",
            &apply_labels(*engine, *direction),
            apply.source_cidrs,
        );
    }
    header(
        &mut out,
        "cidrwall_active_slot",
        "gauge",
        "Active A/B map slot of an eBPF blocklist.",
    );
    for ((engine, direction), apply) in &state.applies {
        if let Some(slot) = apply.active_slot {
            sample_line(
                &mut out,
                "cidrwall_active_slot",
                &apply_labels(*engine, *direction),
                slot,
            );
        }
    }
    header(
        &mut out,
        "cidrwall_last_apply_success_timestamp_seconds",
        "gauge",
        "Unix time of the last successful blocklist apply.",
    );
    for ((engine, direction), apply) in &state.applies {
        if let Some(timestamp) = apply.last_success_unix {
            sample_line(
                &mut out,
                "cidrwall_last_apply_success_timestamp_seconds",
                &apply_labels(*engine, *direction),
                timestamp,
            );
        }
    }
    header(
        &mut out,
        "cidrwall_last_apply_ok",
        "gauge",
        "Whether the most recent blocklist apply succeeded.",
    );
    for ((engine, direction), apply) in &state.applies {
        sample_line(
            &mut out,
            "cidrwall_last_apply_ok",
            &apply_labels(*engine, *direction),
            u8::from(apply.last_ok),
        );
    }
    header(
        &mut out,
        "cidrwall_apply_failures_total",
        "counter",
        "Blocklist applies rejected while the previous generation stayed active.",
    );
    for ((engine, direction), apply) in &state.applies {
        sample_line(
            &mut out,
            "cidrwall_apply_failures_total",
            &apply_labels(*engine, *direction),
            apply.failures,
        );
    }
    header(
        &mut out,
        "cidrwall_reconcile_failures_total",
        "counter",
        "Periodic reconciliations that reported an error.",
    );
    sample_line(
        &mut out,
        "cidrwall_reconcile_failures_total",
        "",
        state.reconcile_failures,
    );
    header(
        &mut out,
        "cidrwall_scrape_errors_total",
        "counter",
        "Scrapes that could not read a backend's kernel counters.",
    );
    for (engine, errors) in &state.scrape_errors {
        let labels = format!("source=\"{}\"", engine.name());
        sample_line(&mut out, "cidrwall_scrape_errors_total", &labels, errors);
    }
    header(
        &mut out,
        "cidrwall_build_info",
        "gauge",
        "cidrwall build information.",
    );
    let labels = format!("version=\"{}\"", env!("CARGO_PKG_VERSION"));
    sample_line(&mut out, "cidrwall_build_info", &labels, 1);
    out
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

fn sample_line(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let _ = writeln!(out, "{name}{{{labels}}} {value}");
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// A copy of the recorded state, without reading counters.
#[cfg(test)]
pub(crate) fn state(metrics: &Metrics) -> State {
    metrics.lock().clone()
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_config() -> Config {
        toml::from_str(
            r#"
[zones]
WAN = ["eth0"]
[[rules.input]]
blocklist = "inbound"
ingress_zones = ["WAN"]
"#,
        )
        .unwrap()
    }

    fn get(address: SocketAddr, path: &str) -> io::Result<String> {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(stream, "GET {path} HTTP/1.1\r\nHost: test\r\n\r\n")?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    #[test]
    fn listener_binds_once_the_address_is_released() {
        let blocker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = blocker.local_addr().unwrap();
        let config = test_config();
        let metrics = Metrics::default();
        thread::spawn(move || listen(address, &config, &metrics, Duration::from_millis(20)));

        // The listener keeps retrying while the port is taken; the blocker answers nothing.
        thread::sleep(Duration::from_millis(100));
        drop(blocker);

        let deadline = Instant::now() + Duration::from_secs(5);
        let response = loop {
            match get(address, "/missing") {
                Ok(response) => break response,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("listener never bound {address}: {error}"),
            }
        };
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
    }

    #[test]
    fn deadline_bounds_a_trickling_request() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            for _ in 0..50 {
                if stream.write_all(b"G").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let (stream, _) = listener.accept().unwrap();
        let started = Instant::now();
        let mut reader = BufReader::new(Deadline::new(&stream, Duration::from_millis(200)));
        let error = reader.read_line(&mut String::new()).unwrap_err();
        // A socket timeout surfaces as WouldBlock; an expired deadline before a read as TimedOut.
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_millis(600));
        drop(stream);
        client.join().unwrap();
    }

    #[test]
    fn routes_only_get_metrics() {
        assert_eq!(route("GET /metrics HTTP/1.1\r\n"), Route::Metrics);
        assert_eq!(route("GET /metrics?x=1 HTTP/1.0\r\n"), Route::Metrics);
        assert_eq!(route("POST /metrics HTTP/1.1\r\n"), Route::MethodNotAllowed);
        assert_eq!(route("GET / HTTP/1.1\r\n"), Route::NotFound);
        assert_eq!(route("GET /metrics\r\n"), Route::BadRequest);
        assert_eq!(route("GET /metrics FTP/1.1\r\n"), Route::BadRequest);
        assert_eq!(route(""), Route::BadRequest);
        assert_eq!(route("\u{0}\u{1}garbage"), Route::BadRequest);
    }

    #[test]
    fn escapes_label_values() {
        assert_eq!(escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape("a\nb"), r"a\nb");
    }

    #[test]
    fn renders_state_and_samples() {
        let metrics = Metrics::default();
        metrics.configure(Engine::Nftables, Direction::Outbound);
        metrics.applied(Engine::Xdp, Direction::Inbound, 10, 2, 9, Some(1));
        metrics.apply_failed(Engine::Xdp, Direction::Inbound);
        metrics.reconcile_failed();
        let mut state = metrics.lock().clone();
        state
            .applies
            .get_mut(&(Engine::Xdp, Direction::Inbound))
            .unwrap()
            .last_success_unix = Some(1_700_000_000);
        state.scrape_errors.insert(Engine::Tc, 3);
        let samples = [PacketSample {
            engine: Engine::Xdp,
            direction: Direction::Inbound,
            interface: "eth0".into(),
            family: "ipv4",
            verdict: "drop",
            packets: 5,
            bytes: 300,
        }];
        let text = render(&state, &samples);
        let lines: Vec<_> = text.lines().filter(|line| !line.starts_with('#')).collect();
        assert_eq!(
            lines,
            [
                r#"cidrwall_packets_total{backend="xdp",direction="inbound",interface="eth0",family="ipv4",verdict="drop"} 5"#,
                r#"cidrwall_bytes_total{backend="xdp",direction="inbound",interface="eth0",family="ipv4",verdict="drop"} 300"#,
                r#"cidrwall_loaded_entries{backend="nftables",direction="outbound",family="ipv4"} 0"#,
                r#"cidrwall_loaded_entries{backend="nftables",direction="outbound",family="ipv6"} 0"#,
                r#"cidrwall_loaded_entries{backend="xdp",direction="inbound",family="ipv4"} 10"#,
                r#"cidrwall_loaded_entries{backend="xdp",direction="inbound",family="ipv6"} 2"#,
                r#"cidrwall_source_cidrs{backend="nftables",direction="outbound"} 0"#,
                r#"cidrwall_source_cidrs{backend="xdp",direction="inbound"} 9"#,
                r#"cidrwall_active_slot{backend="xdp",direction="inbound"} 1"#,
                r#"cidrwall_last_apply_success_timestamp_seconds{backend="xdp",direction="inbound"} 1700000000"#,
                r#"cidrwall_last_apply_ok{backend="nftables",direction="outbound"} 0"#,
                r#"cidrwall_last_apply_ok{backend="xdp",direction="inbound"} 0"#,
                r#"cidrwall_apply_failures_total{backend="nftables",direction="outbound"} 0"#,
                r#"cidrwall_apply_failures_total{backend="xdp",direction="inbound"} 1"#,
                "cidrwall_reconcile_failures_total 1",
                r#"cidrwall_scrape_errors_total{source="tc"} 3"#,
                &format!(
                    r#"cidrwall_build_info{{version="{}"}} 1"#,
                    env!("CARGO_PKG_VERSION")
                ),
            ]
        );
        assert!(text.contains("# TYPE cidrwall_packets_total counter\n"));
    }
}
