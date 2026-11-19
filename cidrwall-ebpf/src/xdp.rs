#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LpmTrie, PerCpuArray, PerCpuHashMap},
    programs::XdpContext,
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

#[xdp]
pub fn cidrwall(ctx: XdpContext) -> u32 {
    let (family, blocked) = classify(&ctx).unwrap_or((Family::Other, false));
    record(
        ctx.ingress_ifindex() as u32,
        family,
        blocked,
        (ctx.data_end() - ctx.data()) as u64,
    );
    if blocked {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }
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

fn classify(ctx: &XdpContext) -> Result<(Family, bool), ()> {
    let data = ctx.data();
    let end = ctx.data_end();
    if data + 14 > end {
        return Ok((Family::Other, false));
    }
    let mut offset = 14usize;
    let mut ether_type = read_be_u16(data, end, 12)?;
    for _ in 0..2 {
        if ether_type != 0x8100 && ether_type != 0x88a8 {
            break;
        }
        ether_type = read_be_u16(data, end, offset + 2)?;
        offset += 4;
    }
    let slot = CONTROL.get(0).map_or(0, |value| value.active_slot);
    match ether_type {
        0x0800 => {
            if data + offset + 20 > end {
                return Ok((Family::Other, false));
            }
            let version_ihl = read_u8(data, end, offset)?;
            if version_ihl >> 4 != 4 || version_ihl & 0x0f < 5 {
                return Ok((Family::Other, false));
            }
            let address = read_array::<4>(data, end, offset + 12)?;
            let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
            let hit = if slot == 0 {
                IPV4_A.get(&key)
            } else {
                IPV4_B.get(&key)
            };
            Ok((Family::Ipv4, hit.is_some()))
        }
        0x86dd => {
            if data + offset + 40 > end || read_u8(data, end, offset)? >> 4 != 6 {
                return Ok((Family::Other, false));
            }
            let address = read_array::<16>(data, end, offset + 8)?;
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

fn read_u8(data: usize, end: usize, offset: usize) -> Result<u8, ()> {
    if data + offset + 1 > end {
        return Err(());
    }
    Ok(unsafe { *((data + offset) as *const u8) })
}

fn read_be_u16(data: usize, end: usize, offset: usize) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(read_array::<2>(data, end, offset)?))
}

fn read_array<const N: usize>(data: usize, end: usize, offset: usize) -> Result<[u8; N], ()> {
    if data + offset + N > end {
        return Err(());
    }
    let mut value = [0; N];
    let mut index = 0;
    while let Some(byte) = value.get_mut(index) {
        *byte = unsafe { *((data + offset + index) as *const u8) };
        index += 1;
    }
    Ok(value)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
