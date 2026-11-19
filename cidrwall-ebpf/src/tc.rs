#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{__sk_buff, TC_ACT_SHOT, TC_ACT_UNSPEC},
    macros::{classifier, map},
    maps::{Array, LpmTrie, PerCpuArray, PerCpuHashMap},
    programs::TcContext,
};
use cidrwall_common::{Control, Counters, Family, MAX_COUNTER_INTERFACES, counter_index};

#[map]
static CONTROL: Array<Control> = Array::pinned(1, 0);
#[map]
static IPV4_A: LpmTrie<[u8; 4], u8> = LpmTrie::pinned(5_000_000, 0);
#[map]
static IPV4_B: LpmTrie<[u8; 4], u8> = LpmTrie::pinned(5_000_000, 0);
#[map]
static IPV6_A: LpmTrie<[u8; 16], u8> = LpmTrie::pinned(5_000_000, 0);
#[map]
static IPV6_B: LpmTrie<[u8; 16], u8> = LpmTrie::pinned(5_000_000, 0);
#[map]
static COUNTERS: PerCpuHashMap<u32, Counters> = PerCpuHashMap::pinned(MAX_COUNTER_INTERFACES, 0);
#[map]
static COUNTERS_UNKNOWN: PerCpuArray<Counters> = PerCpuArray::pinned(1, 0);

// Private: the `classifier` wrapper inherits this visibility, and a public safe function taking
// the kernel's raw `__sk_buff` pointer trips `clippy::not_unsafe_ptr_arg_deref`.
#[classifier]
fn cidrwall_tc(ctx: TcContext) -> i32 {
    let (family, blocked) = classify(&ctx).unwrap_or((Family::Other, false));
    record(ifindex(&ctx), family, blocked, u64::from(ctx.len()));
    if blocked { TC_ACT_SHOT } else { TC_ACT_UNSPEC }
}

fn ifindex(ctx: &TcContext) -> u32 {
    // SAFETY: the kernel passes classifiers a valid `__sk_buff` that outlives the program run.
    unsafe { (*(ctx.as_ptr() as *const __sk_buff)).ifindex }
}

/// Entries are created by the daemon at attach time; this program only looks them up.
fn record(ifindex: u32, family: Family, blocked: bool, bytes: u64) {
    let Some(counters) = COUNTERS
        .get_ptr_mut(&ifindex)
        .or_else(|| COUNTERS_UNKNOWN.get_ptr_mut(0))
    else {
        return;
    };
    if let Some(counter) = unsafe { (*counters).slots.get_mut(counter_index(family, blocked)) } {
        counter.packets += 1;
        counter.bytes += bytes;
    }
}

fn classify(ctx: &TcContext) -> Result<(Family, bool), ()> {
    let mut offset = 14usize;
    let mut ether_type = read_be_u16(ctx, 12)?;
    for _ in 0..2 {
        if ether_type != 0x8100 && ether_type != 0x88a8 {
            break;
        }
        ether_type = read_be_u16(ctx, offset + 2)?;
        offset += 4;
    }
    let slot = CONTROL.get(0).map_or(0, |value| value.active_slot);
    match ether_type {
        0x0800 => {
            let version_ihl = read_array::<1>(ctx, offset)?[0];
            if version_ihl >> 4 != 4 || version_ihl & 0x0f < 5 {
                return Ok((Family::Other, false));
            }
            let address = read_array::<4>(ctx, offset + 16)?;
            let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
            let hit = if slot == 0 {
                IPV4_A.get(&key)
            } else {
                IPV4_B.get(&key)
            };
            Ok((Family::Ipv4, hit.is_some()))
        }
        0x86dd => {
            if read_array::<1>(ctx, offset)?[0] >> 4 != 6 {
                return Ok((Family::Other, false));
            }
            let address = read_array::<16>(ctx, offset + 24)?;
            let key = aya_ebpf::maps::lpm_trie::Key::new(128, address);
            let hit = if slot == 0 {
                IPV6_A.get(&key)
            } else {
                IPV6_B.get(&key)
            };
            Ok((Family::Ipv6, hit.is_some()))
        }
        _ => Ok((Family::Other, false)),
    }
}

fn read_be_u16(ctx: &TcContext, offset: usize) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(read_array::<2>(ctx, offset)?))
}

fn read_array<const N: usize>(ctx: &TcContext, offset: usize) -> Result<[u8; N], ()> {
    ctx.load::<[u8; N]>(offset).map_err(|_| ())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
