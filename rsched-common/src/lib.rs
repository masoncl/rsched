#![no_std]

#[cfg(feature = "user")]
extern crate aya;

pub const MAX_SLOTS: usize = 64;
pub const TASK_COMM_LEN: usize = 16;
pub const MAX_CPUS: usize = 1024;
pub const MAX_GENERIC_EVENTS: usize = 8;
pub const LINEAR_THRESHOLD: u64 = 500;
pub const LINEAR_STEP: u64 = 10;
pub const LINEAR_SLOTS: u32 = 50;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Hist {
    pub slots: [u32; MAX_SLOTS],
}

impl Default for Hist {
    fn default() -> Self {
        Self {
            slots: [0; MAX_SLOTS],
        }
    }
}

impl Hist {
    pub const fn zero() -> Self {
        Self {
            slots: [0; MAX_SLOTS],
        }
    }

    pub fn merge_from(&mut self, other: &Self) {
        let mut i = 0;
        while i < MAX_SLOTS {
            self.slots[i] += other.slots[i];
            i += 1;
        }
    }

    pub fn total_count(&self) -> u64 {
        let mut sum = 0u64;
        let mut i = 0;
        while i < MAX_SLOTS {
            sum += self.slots[i] as u64;
            i += 1;
        }
        sum
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HistData {
    pub hist: Hist,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

impl HistData {
    pub const fn zero() -> Self {
        Self {
            hist: Hist::zero(),
            comm: [0; TASK_COMM_LEN],
            cgroup_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TimesliceStats {
    pub voluntary: Hist,
    pub involuntary: Hist,
    pub involuntary_count: u64,
}

impl TimesliceStats {
    pub const fn zero() -> Self {
        Self {
            voluntary: Hist::zero(),
            involuntary: Hist::zero(),
            involuntary_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TimesliceData {
    pub stats: TimesliceStats,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

impl TimesliceData {
    pub const fn zero() -> Self {
        Self {
            stats: TimesliceStats::zero(),
            comm: [0; TASK_COMM_LEN],
            cgroup_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct NrRunningData {
    pub hist: Hist,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

impl NrRunningData {
    pub const fn zero() -> Self {
        Self {
            hist: Hist::zero(),
            comm: [0; TASK_COMM_LEN],
            cgroup_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MigrationData {
    pub count: u64,
    pub cross_ccx_count: u64,
    pub cross_numa_count: u64,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

impl MigrationData {
    pub const fn zero() -> Self {
        Self {
            count: 0,
            cross_ccx_count: 0,
            cross_numa_count: 0,
            comm: [0; TASK_COMM_LEN],
            cgroup_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct WakingData {
    pub hist: Hist,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

impl WakingData {
    pub const fn zero() -> Self {
        Self {
            hist: Hist::zero(),
            comm: [0; TASK_COMM_LEN],
            cgroup_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CpuPerfData {
    pub user_cycles_hist: Hist,
    pub kernel_cycles_hist: Hist,
    pub total_user_cycles: u64,
    pub total_kernel_cycles: u64,
    pub total_user_instructions: u64,
    pub total_kernel_instructions: u64,
    pub sample_count: u64,
}

impl CpuPerfData {
    pub const fn zero() -> Self {
        Self {
            user_cycles_hist: Hist::zero(),
            kernel_cycles_hist: Hist::zero(),
            total_user_cycles: 0,
            total_kernel_cycles: 0,
            total_user_instructions: 0,
            total_kernel_instructions: 0,
            sample_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CpuPerfDataFull {
    pub data: CpuPerfData,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

impl CpuPerfDataFull {
    pub const fn zero() -> Self {
        Self {
            data: CpuPerfData::zero(),
            comm: [0; TASK_COMM_LEN],
            cgroup_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CpuPerfCtx {
    pub last_user_cycles: u64,
    pub last_kernel_cycles: u64,
    pub last_user_instructions: u64,
    pub last_kernel_instructions: u64,
    pub running_pid: u32,
}

impl CpuPerfCtx {
    pub const fn zero() -> Self {
        Self {
            last_user_cycles: 0,
            last_kernel_cycles: 0,
            last_user_instructions: 0,
            last_kernel_instructions: 0,
            running_pid: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenericPerfData {
    pub counters: [u64; MAX_GENERIC_EVENTS],
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

impl GenericPerfData {
    pub const fn zero() -> Self {
        Self {
            counters: [0; MAX_GENERIC_EVENTS],
            comm: [0; TASK_COMM_LEN],
            cgroup_id: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenericPerfCtx {
    pub last_values: [u64; MAX_GENERIC_EVENTS],
    pub running_pid: u32,
}

impl GenericPerfCtx {
    pub const fn zero() -> Self {
        Self {
            last_values: [0; MAX_GENERIC_EVENTS],
            running_pid: 0,
        }
    }
}

/// Calculate histogram slot for a given delay in nanoseconds
#[inline(always)]
pub fn hist_slot(delay_ns: u64) -> u32 {
    let delay_us = delay_ns / 1000;
    if delay_us < LINEAR_THRESHOLD {
        let slot = (delay_us / LINEAR_STEP) as u32;
        if slot < LINEAR_SLOTS {
            slot
        } else {
            LINEAR_SLOTS - 1
        }
    } else if delay_us < 512 {
        LINEAR_SLOTS
    } else {
        let log2_val = log2_u64(delay_us);
        let slot = LINEAR_SLOTS + (log2_val - 8);
        if slot < MAX_SLOTS as u32 {
            slot
        } else {
            MAX_SLOTS as u32 - 1
        }
    }
}

#[inline(always)]
pub fn log2_u64(v: u64) -> u32 {
    let hi = (v >> 32) as u32;
    if hi != 0 {
        log2_u32(hi as u64) + 32
    } else {
        log2_u32(v)
    }
}

#[inline(always)]
pub fn log2_u32(v: u64) -> u32 {
    let mut r: u32;
    let mut v = v;
    r = ((v > 0xFFFF_FFFF) as u32) << 5;
    v >>= r;
    let mut shift = ((v > 0xFFFF) as u32) << 4;
    v >>= shift;
    r |= shift;
    shift = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    r |= shift;
    shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    r |= shift;
    shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    r |= shift;
    r |= (v >> 1) as u32;
    r
}

#[inline(always)]
pub fn log2_slot(v: u64) -> u32 {
    let slot = log2_u64(v);
    if slot < MAX_SLOTS as u32 {
        slot
    } else {
        MAX_SLOTS as u32 - 1
    }
}

// aya::Pod implementations for userspace map access
#[cfg(feature = "user")]
mod pod_impls {
    use super::*;
    unsafe impl aya::Pod for Hist {}
    unsafe impl aya::Pod for HistData {}
    unsafe impl aya::Pod for TimesliceStats {}
    unsafe impl aya::Pod for TimesliceData {}
    unsafe impl aya::Pod for NrRunningData {}
    unsafe impl aya::Pod for MigrationData {}
    unsafe impl aya::Pod for WakingData {}
    unsafe impl aya::Pod for CpuPerfData {}
    unsafe impl aya::Pod for CpuPerfDataFull {}
    unsafe impl aya::Pod for GenericPerfData {}
}
