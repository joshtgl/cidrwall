#![no_std]

pub const LAYOUT_VERSION: u32 = 1;
pub const SLOT_COUNT: u32 = 2;

/// Upper bound on interfaces with their own counter entry; further interfaces count as unknown.
pub const MAX_COUNTER_INTERFACES: u32 = 256;
pub const COUNTER_SLOTS: usize = 6;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Control {
    pub layout_version: u32,
    pub active_slot: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Ipv4 = 0,
    Ipv6 = 1,
    Other = 2,
}

impl Family {
    pub const ALL: [Self; 3] = [Self::Ipv4, Self::Ipv6, Self::Other];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Other => "other",
        }
    }
}

/// Position of a family/verdict pair inside [`Counters::slots`].
pub const fn counter_index(family: Family, dropped: bool) -> usize {
    family as usize * 2 + dropped as usize
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub slots: [Counter; COUNTER_SLOTS],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Control {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Counters {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_indexes_are_dense_and_distinct() {
        let mut seen = [false; COUNTER_SLOTS];
        for family in Family::ALL {
            for dropped in [false, true] {
                let index = counter_index(family, dropped);
                assert!(!seen[index]);
                seen[index] = true;
            }
        }
        assert!(seen.iter().all(|value| *value));
    }
}
