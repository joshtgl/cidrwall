#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_SHOT, TC_ACT_UNSPEC},
    macros::{classifier, map},
    maps::{Array, LpmTrie},
    programs::TcContext,
};
use cidrwall_common::Control;

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

#[classifier]
pub fn cidrwall_tc(ctx: TcContext) -> i32 {
    try_cidrwall(&ctx).unwrap_or(TC_ACT_UNSPEC)
}

fn try_cidrwall(ctx: &TcContext) -> Result<i32, ()> {
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
    let blocked = match ether_type {
        0x0800 => {
            let version_ihl = read_array::<1>(ctx, offset)?[0];
            if version_ihl >> 4 != 4 || version_ihl & 0x0f < 5 {
                return Ok(TC_ACT_UNSPEC);
            }
            let address = read_array::<4>(ctx, offset + 16)?;
            let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
            if slot == 0 {
                IPV4_A.get(&key)
            } else {
                IPV4_B.get(&key)
            }
            .is_some()
        }
        0x86dd => {
            if read_array::<1>(ctx, offset)?[0] >> 4 != 6 {
                return Ok(TC_ACT_UNSPEC);
            }
            let address = read_array::<16>(ctx, offset + 24)?;
            let key = aya_ebpf::maps::lpm_trie::Key::new(128, address);
            if slot == 0 {
                IPV6_A.get(&key)
            } else {
                IPV6_B.get(&key)
            }
            .is_some()
        }
        _ => false,
    };
    Ok(if blocked { TC_ACT_SHOT } else { TC_ACT_UNSPEC })
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
