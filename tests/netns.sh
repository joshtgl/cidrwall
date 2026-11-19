#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "tests/netns.sh must run as root" >&2
    exit 77
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${CIDRWALL_BIN:-$ROOT/target/debug/cidrwall}
if [ "${CIDRWALL_MOUNT_NS:-0}" != "1" ]; then
    exec unshare --mount --propagation private env CIDRWALL_MOUNT_NS=1 "$0"
fi
TMP=$(mktemp -d /tmp/cidrwall-netns.XXXXXX)
mkdir "$TMP/bpffs"
mount -t bpf bpf "$TMP/bpffs"
ROUTER="cidrwall-router-$$"
WAN="cidrwall-wan-$$"
LAN="cidrwall-lan-$$"
PID=""
fail() {
    echo "namespace test failed: $*" >&2
    exit 1
}
wait_for_log() {
    log_file=$1
    pattern=$2
    description=$3
    tries=0
    until grep -q "$pattern" "$log_file"; do
        if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
            cat "$log_file" >&2
            fail "$description daemon exited before becoming ready"
        fi
        tries=$((tries + 1))
        if [ "$tries" -gt 100 ]; then
            cat "$log_file" >&2
            fail "timed out waiting for $description"
        fi
        sleep 0.1
    done
}
METRICS="127.0.0.1:9737"
# Print the value of one exact series from the router's metrics endpoint.
metric() {
    ip netns exec "$ROUTER" curl -sf "http://$METRICS/metrics" |
        awk -v series="$1" 'index($0, series " ") == 1 { print $2 }'
}
expect_metric_positive() {
    value=$(metric "$1")
    if [ -z "$value" ] || [ "$value" -le 0 ]; then
        ip netns exec "$ROUTER" curl -sf "http://$METRICS/metrics" >&2 || true
        fail "$2 (series $1 = '$value')"
    fi
}
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        for log_file in "$TMP"/*log; do
            if [ -f "$log_file" ]; then
                echo "--- $log_file ---" >&2
                sed -n '1,240p' "$log_file" >&2
            fi
        done
    fi
    if [ -n "$PID" ]; then kill -TERM "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
    ip netns del "$ROUTER" 2>/dev/null || true
    ip netns del "$WAN" 2>/dev/null || true
    ip netns del "$LAN" 2>/dev/null || true
    umount "$TMP/bpffs" 2>/dev/null || true
    rm -rf -- "$TMP"
}
trap cleanup EXIT INT TERM

cd "$ROOT"
if [ -z "${CIDRWALL_BIN:-}" ]; then
    # Under sudo, building as root would leave root-owned files in target/; require a fresh build.
    if [ -z "${SUDO_USER:-}" ] && command -v cargo >/dev/null 2>&1; then
        cargo build --locked
    elif [ ! -x "$BIN" ] ||
        [ -n "$(find Cargo.toml Cargo.lock build.rs src cidrwall-common cidrwall-ebpf -newer "$BIN" -print 2>/dev/null | head -n 1)" ]; then
        echo "$BIN is missing or older than the sources; run cargo build first" >&2
        exit 1
    fi
fi
ip netns add "$ROUTER"
ip netns add "$WAN"
ip netns add "$LAN"
ip link add nb-wan type veth peer name wan0
ip link add nb-lan type veth peer name lan0
ip link set wan0 netns "$ROUTER"
ip link set nb-wan netns "$WAN"
ip link set lan0 netns "$ROUTER"
ip link set nb-lan netns "$LAN"

ip -n "$ROUTER" addr add 192.0.2.1/24 dev wan0
ip -n "$ROUTER" addr add 198.51.100.1/24 dev wan0
ip -n "$ROUTER" addr add 10.0.0.1/24 dev lan0
ip -n "$ROUTER" addr add 2001:db8:100::1/64 dev wan0 nodad
ip -n "$ROUTER" addr add 2001:db8:200::1/64 dev wan0 nodad
ip -n "$ROUTER" addr add fd00::1/64 dev lan0 nodad
ip -n "$WAN" addr add 192.0.2.2/24 dev nb-wan
ip -n "$WAN" addr add 198.51.100.2/24 dev nb-wan
ip -n "$WAN" addr add 2001:db8:100::2/64 dev nb-wan nodad
ip -n "$WAN" addr add 2001:db8:200::2/64 dev nb-wan nodad
ip -n "$LAN" addr add 10.0.0.2/24 dev nb-lan
ip -n "$LAN" addr add fd00::2/64 dev nb-lan nodad
for spec in "$ROUTER lo" "$ROUTER wan0" "$ROUTER lan0" "$WAN nb-wan" "$LAN nb-lan"; do
    set -- $spec
    ip -n "$1" link set "$2" up
done
ip netns exec "$ROUTER" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$ROUTER" sysctl -q -w net.ipv6.conf.all.forwarding=1
ip -n "$WAN" route add 10.0.0.0/24 via 192.0.2.1
ip -n "$WAN" -6 route add fd00::/64 via 2001:db8:100::1
ip -n "$LAN" route add 192.0.2.0/24 via 10.0.0.1
ip -n "$LAN" route add 198.51.100.0/24 via 10.0.0.1
ip -n "$LAN" -6 route add 2001:db8:100::/64 via fd00::1
ip -n "$LAN" -6 route add 2001:db8:200::/64 via fd00::1

# Prove the namespace topology before installing any filtering rules.
ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null
ip netns exec "$WAN" ping -c 1 -W 1 10.0.0.2 >/dev/null
ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null
ip netns exec "$LAN" ping -c 1 -W 1 198.51.100.2 >/dev/null
ip netns exec "$ROUTER" ping -c 1 -W 1 2001:db8:200::2 >/dev/null
ip netns exec "$LAN" ping -c 1 -W 1 2001:db8:200::2 >/dev/null

cat >"$TMP/zones.json" <<'EOF'
{"WAN":["wan0"],"LAN":["lan0"]}
EOF
cat >"$TMP/inbound.txt" <<'EOF'
# generated
192.0.2.2/32
2001:db8:1::/48
EOF
cat >"$TMP/outbound.txt" <<'EOF'
# generated
198.51.100.2/32
2001:db8:2::/48
EOF
cat >"$TMP/cidrwall.toml" <<EOF
[files]
zones = "$TMP/zones.json"
inbound = "$TMP/inbound.txt"
outbound = "$TMP/outbound.txt"
[nftables]
allow_flowtable_bypass = false
populate_batch_elements = 2
[metrics]
listen = "$METRICS"
[[rules.input]]
blocklist = "inbound"
ingress_zones = ["WAN"]
[[rules.forward]]
blocklist = "inbound"
ingress_zones = ["WAN"]
egress_zones = ["LAN"]
[[rules.output]]
blocklist = "outbound"
egress_zones = ["WAN"]
[[rules.forward]]
blocklist = "outbound"
ingress_zones = ["LAN"]
egress_zones = ["WAN"]
EOF

ip netns exec "$ROUTER" "$BIN" --config "$TMP/cidrwall.toml" >"$TMP/log" 2>&1 &
PID=$!
wait_for_log "$TMP/log" 'activated blocklist generations: reason=startup' 'initial nftables startup'
ip netns exec "$ROUTER" nft list table inet cidrwall >"$TMP/ruleset"

# Input inbound: source 192.0.2.2 arriving on WAN.
if ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
    fail "nftables input rule did not block inbound traffic"
fi
# Forward inbound: source 192.0.2.2 from WAN to LAN.
if ip netns exec "$WAN" ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1; then
    fail "nftables forward rule did not block inbound traffic"
fi
# Output outbound: destination 198.51.100.2 leaving WAN.
if ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "nftables output rule did not block outbound traffic"
fi
# Forward outbound: LAN to destination 198.51.100.2 on WAN.
if ip netns exec "$LAN" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "nftables forward rule did not block outbound traffic"
fi
expect_metric_positive 'cidrwall_packets_total{backend="nftables",direction="inbound",interface="",family="ipv4",verdict="drop"}' \
    "nftables inbound drops were not counted"
expect_metric_positive 'cidrwall_packets_total{backend="nftables",direction="outbound",interface="",family="ipv4",verdict="drop"}' \
    "nftables outbound drops were not counted"
expect_metric_positive 'cidrwall_last_apply_success_timestamp_seconds{backend="nftables",direction="inbound"}' \
    "nftables startup apply was not recorded"
ip netns exec "$ROUTER" nft list counters table inet cidrwall | grep -q 'counter inbound_ipv4_drops' ||
    fail "named nftables drop counter is missing"
drops_before_reload=$(metric 'cidrwall_packets_total{backend="nftables",direction="inbound",interface="",family="ipv4",verdict="drop"}')

# An invalid atomic replacement must retain the active inbound set.
printf '%s\n' '192.0.2.2/32' '192.0.2.4/32' 'not-a-cidr' >"$TMP/.inbound.tmp"
mv "$TMP/.inbound.tmp" "$TMP/inbound.txt"
sleep 1
if ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
    fail "invalid reload replaced the active inbound nftables generation"
fi
expect_metric_positive 'cidrwall_apply_failures_total{backend="nftables",direction="inbound"}' \
    "rejected nftables reload was not counted"
[ "$(metric 'cidrwall_last_apply_ok{backend="nftables",direction="inbound"}')" = 0 ] ||
    fail "rejected nftables reload still reports last_apply_ok=1"

# A valid rename reloads inbound independently; outbound must remain blocked.
printf '%s\n' '203.0.113.0/24' >"$TMP/.inbound.tmp"
mv "$TMP/.inbound.tmp" "$TMP/inbound.txt"
tries=0
until ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 30 ]; then cat "$TMP/log" >&2; fail "valid inbound nftables reload did not activate"; fi
    sleep 0.1
done
# Named counters must survive the dispatch-chain flush that activates a new generation.
drops_after_reload=$(metric 'cidrwall_packets_total{backend="nftables",direction="inbound",interface="",family="ipv4",verdict="drop"}')
[ "$drops_after_reload" -ge "$drops_before_reload" ] ||
    fail "nftables drop counter reset on reload ($drops_before_reload -> $drops_after_reload)"
if ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "inbound reload replaced the active outbound nftables generation"
fi

kill -TERM "$PID"
wait "$PID"
PID=""
ip netns exec "$ROUTER" nft list table inet cidrwall >/dev/null

# An unreferenced outbound blocklist may be omitted and creates no outbound generation sets.
ip netns exec "$ROUTER" nft delete table inet cidrwall
printf '%s\n' '192.0.2.2/32' >"$TMP/inbound.txt"
cat >"$TMP/inbound-only.toml" <<EOF
[files]
zones = "$TMP/zones.json"
inbound = "$TMP/inbound.txt"
[nftables]
allow_flowtable_bypass = false
populate_batch_elements = 2
[[rules.input]]
blocklist = "inbound"
ingress_zones = ["WAN"]
EOF
ip netns exec "$ROUTER" "$BIN" --config "$TMP/inbound-only.toml" >"$TMP/inbound-only-log" 2>&1 &
PID=$!
wait_for_log "$TMP/inbound-only-log" 'activated blocklist generations: reason=startup' 'inbound-only nftables startup'
if ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
    fail "inbound-only nftables rule did not block traffic"
fi
ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null
if ip netns exec "$ROUTER" nft list table inet cidrwall | grep -q 'set out_.*_g'; then
    echo "inbound-only configuration created outbound generation sets" >&2
    exit 1
fi
kill -TERM "$PID"
wait "$PID"
PID=""

# A pre-generation table is incompatible and must remain untouched.
ip netns exec "$ROUTER" nft delete table inet cidrwall
ip netns exec "$ROUTER" nft add table inet cidrwall
ip netns exec "$ROUTER" nft 'add set inet cidrwall inbound_v4 { type ipv4_addr; flags interval; }'
if ip netns exec "$ROUTER" "$BIN" --config "$TMP/cidrwall.toml" >"$TMP/legacy-log" 2>&1; then
    echo "daemon accepted a pre-generation table" >&2
    exit 1
fi
grep -q 'unsupported pre-generation layout' "$TMP/legacy-log"
ip netns exec "$ROUTER" nft list set inet cidrwall inbound_v4 >/dev/null
ip netns exec "$ROUTER" nft delete table inet cidrwall

# XDP ingress and nftables output can be enabled together and reload independently.
printf '%s\n' '192.0.2.2/32' >"$TMP/inbound.txt"
cat >"$TMP/xdp.toml" <<EOF
[files]
zones = "$TMP/zones.json"
inbound = "$TMP/inbound.txt"
outbound = "$TMP/outbound.txt"
[nftables]
populate_batch_elements = 2
[xdp]
mode = "generic"
pin_path = "$TMP/bpffs/cidrwall"
ipv4_max_entries = 1024
ipv6_max_entries = 1024
populate_batch_elements = 2
cleanup_on_exit = true
[metrics]
listen = "$METRICS"
[[xdp.rules]]
blocklist = "inbound"
ingress_zones = ["WAN"]
[[rules.output]]
blocklist = "outbound"
egress_zones = ["WAN"]
EOF
ip netns exec "$ROUTER" "$BIN" --config "$TMP/xdp.toml" >"$TMP/xdp-log" 2>&1 &
PID=$!
wait_for_log "$TMP/xdp-log" 'activated XDP blocklist: reason=startup' 'XDP startup'
ifindex=$(ip -n "$ROUTER" -o link show wan0 | cut -d: -f1 | tr -d ' ')
if [ ! -e "$TMP/bpffs/cidrwall/links/$ifindex" ]; then
    cat "$TMP/xdp-log" >&2
    fail "XDP link was not pinned for wan0"
fi
if ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
    fail "XDP did not block inbound traffic"
fi
expect_metric_positive 'cidrwall_packets_total{backend="xdp",direction="inbound",interface="wan0",family="ipv4",verdict="drop"}' \
    "XDP drops were not counted for wan0"
metric 'cidrwall_active_slot{backend="xdp",direction="inbound"}' | grep -q . ||
    fail "XDP active slot was not reported"
if ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "nftables did not block outbound traffic in hybrid mode"
fi
printf '%s\n' '203.0.113.0/24' >"$TMP/.inbound.tmp"
mv "$TMP/.inbound.tmp" "$TMP/inbound.txt"
tries=0
until ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 30 ]; then cat "$TMP/xdp-log" >&2; fail "valid XDP reload did not activate"; fi
    sleep 0.1
done
if ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "XDP reload replaced the active outbound nftables generation"
fi
kill -TERM "$PID"
wait "$PID"
PID=""
if [ -e "$TMP/bpffs/cidrwall" ]; then
    echo "XDP cleanup_on_exit left pinned state behind" >&2
    exit 1
fi
ip netns exec "$ROUTER" nft list table inet cidrwall >/dev/null
ip netns exec "$ROUTER" nft delete table inet cidrwall

# A restart swaps the running XDP program on the pinned link in place, keeping enforcement and counts.
printf '%s\n' '192.0.2.2/32' >"$TMP/inbound.txt"
sed 's/^cleanup_on_exit = true$/cleanup_on_exit = false/' "$TMP/xdp.toml" >"$TMP/xdp-keep.toml"
ip netns exec "$ROUTER" "$BIN" --config "$TMP/xdp-keep.toml" >"$TMP/xdp-keep-log" 2>&1 &
PID=$!
wait_for_log "$TMP/xdp-keep-log" 'activated XDP blocklist: reason=startup' 'XDP keep startup'
ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1 || true
xdp_drops_before_restart=$(metric 'cidrwall_packets_total{backend="xdp",direction="inbound",interface="wan0",family="ipv4",verdict="drop"}')
kill -TERM "$PID"
wait "$PID"
PID=""
ip netns exec "$ROUTER" "$BIN" --config "$TMP/xdp-keep.toml" >"$TMP/xdp-restart-log" 2>&1 &
PID=$!
wait_for_log "$TMP/xdp-restart-log" 'activated XDP blocklist: reason=startup' 'XDP restart'
replaced=$(sed -n 's/.*replaced XDP program: interface=wan0 .* program=\([0-9]*\)->\([0-9]*\).*/\1 \2/p' "$TMP/xdp-restart-log")
set -- $replaced
[ "$#" -eq 2 ] && [ "$1" != "$2" ] || {
    cat "$TMP/xdp-restart-log" >&2
    fail "XDP restart did not replace the program on the existing link"
}
if ip netns exec "$WAN" ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1; then
    fail "XDP enforcement was lost during restart"
fi
xdp_drops_after_restart=$(metric 'cidrwall_packets_total{backend="xdp",direction="inbound",interface="wan0",family="ipv4",verdict="drop"}')
[ -n "$xdp_drops_after_restart" ] && [ "$xdp_drops_after_restart" -gt "$xdp_drops_before_restart" ] ||
    fail "pinned XDP counters did not survive restart ($xdp_drops_before_restart -> $xdp_drops_after_restart)"
kill -TERM "$PID"
wait "$PID"
PID=""
ip netns exec "$ROUTER" "$BIN" --config "$TMP/xdp-keep.toml" --cleanup xdp
[ ! -e "$TMP/bpffs/cidrwall" ] || fail "XDP cleanup left pinned state behind"
ip netns exec "$ROUTER" nft delete table inet cidrwall

# TCX egress blocks both local and forwarded traffic and permits software flowtables.
ip netns exec "$ROUTER" nft add table inet tcflow
ip netns exec "$ROUTER" nft 'add flowtable inet tcflow fast { hook ingress priority 0; devices = { wan0 }; }'
printf '%s\n' '198.51.100.2/32' '2001:db8:200::2/128' >"$TMP/outbound.txt"
cat >"$TMP/tc.toml" <<EOF
[files]
zones = "$TMP/zones.json"
outbound = "$TMP/outbound.txt"
[tc]
pin_path = "$TMP/bpffs/cidrwall-tc"
ipv4_max_entries = 1024
ipv6_max_entries = 1024
populate_batch_elements = 2
cleanup_on_exit = false
[metrics]
listen = "$METRICS"
[[tc.rules]]
blocklist = "outbound"
egress_zones = ["WAN"]
EOF
ip netns exec "$ROUTER" "$BIN" --config "$TMP/tc.toml" >"$TMP/tc-log" 2>&1 &
PID=$!
wait_for_log "$TMP/tc-log" 'activated TC blocklist: reason=startup' 'TC startup'
ifindex=$(ip -n "$ROUTER" -o link show wan0 | cut -d: -f1 | tr -d ' ')
if [ ! -e "$TMP/bpffs/cidrwall-tc/links/$ifindex" ]; then
    fail "TCX link was not pinned for wan0"
fi
if ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "TCX did not block local outbound traffic"
fi
if ip netns exec "$LAN" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "TCX did not block forwarded outbound traffic"
fi
if ip netns exec "$ROUTER" ping -c 1 -W 1 2001:db8:200::2 >/dev/null 2>&1; then
    fail "TCX did not block local IPv6 outbound traffic"
fi
if ip netns exec "$LAN" ping -c 1 -W 1 2001:db8:200::2 >/dev/null 2>&1; then
    fail "TCX did not block forwarded IPv6 outbound traffic"
fi
ip netns exec "$ROUTER" ping -c 1 -W 1 192.0.2.2 >/dev/null
expect_metric_positive 'cidrwall_packets_total{backend="tc",direction="outbound",interface="wan0",family="ipv4",verdict="drop"}' \
    "TC IPv4 drops were not counted for wan0"
expect_metric_positive 'cidrwall_packets_total{backend="tc",direction="outbound",interface="wan0",family="ipv6",verdict="drop"}' \
    "TC IPv6 drops were not counted for wan0"
expect_metric_positive 'cidrwall_packets_total{backend="tc",direction="outbound",interface="wan0",family="ipv4",verdict="pass"}' \
    "TC passes were not counted for wan0"

# A rejected TC reload retains the active slot.
printf '%s\n' '198.51.100.2/32' '2001:db8:200::2/128' 'not-a-cidr' >"$TMP/.outbound.tmp"
mv "$TMP/.outbound.tmp" "$TMP/outbound.txt"
sleep 1
if ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
    fail "invalid reload replaced the active TC generation"
fi

# A valid TC reload changes the destination atomically.
printf '%s\n' '192.0.2.2/32' '2001:db8:100::2/128' >"$TMP/.outbound.tmp"
mv "$TMP/.outbound.tmp" "$TMP/outbound.txt"
tries=0
until ip netns exec "$ROUTER" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 30 ]; then cat "$TMP/tc-log" >&2; fail "valid TC reload did not activate"; fi
    sleep 0.1
done
if ip netns exec "$ROUTER" ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; then
    fail "valid TC reload did not block the replacement destination"
fi
if ip netns exec "$ROUTER" ping -c 1 -W 1 2001:db8:100::2 >/dev/null 2>&1; then
    fail "valid TC reload did not block the replacement IPv6 destination"
fi

# Pinned TCX state survives daemon shutdown and is adopted on restart.
tc_drops_before_restart=$(metric 'cidrwall_packets_total{backend="tc",direction="outbound",interface="wan0",family="ipv4",verdict="drop"}')
kill -TERM "$PID"
wait "$PID"
PID=""
if ip netns exec "$ROUTER" ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; then
    fail "TCX enforcement did not survive daemon shutdown"
fi
ip netns exec "$ROUTER" "$BIN" --config "$TMP/tc.toml" >"$TMP/tc-restart-log" 2>&1 &
PID=$!
wait_for_log "$TMP/tc-restart-log" 'attached TCX:' 'TC restart'
if ip netns exec "$ROUTER" ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1; then
    fail "TCX enforcement was lost during restart"
fi
tc_drops_after_restart=$(metric 'cidrwall_packets_total{backend="tc",direction="outbound",interface="wan0",family="ipv4",verdict="drop"}')
[ -n "$tc_drops_after_restart" ] && [ "$tc_drops_after_restart" -gt "$tc_drops_before_restart" ] ||
    fail "pinned TC counters did not survive restart ($tc_drops_before_restart -> $tc_drops_after_restart)"
kill -TERM "$PID"
wait "$PID"
PID=""
ip netns exec "$ROUTER" "$BIN" --config "$TMP/tc.toml" --cleanup tc
if [ -e "$TMP/bpffs/cidrwall-tc" ]; then
    fail "TC cleanup left pinned state behind"
fi
ip netns exec "$ROUTER" ping -c 1 -W 1 192.0.2.2 >/dev/null
ip netns exec "$ROUTER" nft delete table inet tcflow

# Hardware flowtable declarations fail TC startup unless explicitly allowed.
ip netns exec "$ROUTER" nft add table inet tchardware
if ip netns exec "$ROUTER" nft 'add flowtable inet tchardware fast { hook ingress priority 0; devices = { wan0 }; flags offload; }' 2>/dev/null; then
    if ip netns exec "$ROUTER" "$BIN" --config "$TMP/tc.toml" >"$TMP/tc-hardware-log" 2>&1; then
        fail "TC accepted a hardware-offloaded flowtable without an override"
    fi
    grep -q 'hardware-offloaded flowtable uses TC-protected interface' "$TMP/tc-hardware-log"
    sed 's/cleanup_on_exit = false/cleanup_on_exit = true\nallow_hardware_flowtable_bypass = true/' "$TMP/tc.toml" >"$TMP/tc-hardware-allowed.toml"
    ip netns exec "$ROUTER" "$BIN" --config "$TMP/tc-hardware-allowed.toml" >"$TMP/tc-hardware-allowed-log" 2>&1 &
    PID=$!
    wait_for_log "$TMP/tc-hardware-allowed-log" 'attached TCX:' 'hardware-flowtable override startup'
    kill -TERM "$PID"
    wait "$PID"
    PID=""
else
    echo "hardware flowtable integration check skipped: veth does not support offload"
fi
ip netns exec "$ROUTER" nft delete table inet tchardware

# A protected flowtable must make startup fail closed.
ip netns exec "$ROUTER" nft add table inet flowtest
ip netns exec "$ROUTER" nft 'add flowtable inet flowtest fast { hook ingress priority 0; devices = { wan0 }; }'
if ip netns exec "$ROUTER" "$BIN" --config "$TMP/cidrwall.toml" >"$TMP/flowtable-log" 2>&1; then
    echo "daemon accepted a flowtable on protected wan0" >&2
    exit 1
fi
grep -q 'flowtable offload uses protected interface' "$TMP/flowtable-log"
echo "native nftables, XDP, and TCX enforcement verified"
