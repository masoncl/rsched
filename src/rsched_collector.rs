// SPDX-License-Identifier: GPL-2.0
use crate::cpu_metrics::CpuPerfData;
use anyhow::Result;
use libbpf_rs::{Map, MapCore, MapFlags};
use plain::Plain;
use std::collections::HashMap;

pub const MAX_SLOTS: usize = 64;
pub const MIG_HIST_SLOTS: usize = 1025;
pub const TASK_COMM_LEN: usize = 16;

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
    pub fn merge_from(&mut self, other: &Self) {
        for i in 0..MAX_SLOTS {
            self.slots[i] += other.slots[i];
        }
    }

    pub fn total_count(&self) -> u64 {
        self.slots.iter().map(|&c| c as u64).sum()
    }
}

#[derive(Clone)]
pub struct MigHist {
    pub slots: [u32; MIG_HIST_SLOTS],
}

impl Default for MigHist {
    fn default() -> Self {
        Self {
            slots: [0; MIG_HIST_SLOTS],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HistData {
    pub hist: Hist,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct TimesliceStats {
    pub voluntary: Hist,
    pub involuntary: Hist,
    pub involuntary_count: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TimesliceData {
    pub stats: TimesliceStats,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

#[derive(Copy, Clone, Default)]
pub struct MigrationCounts {
    pub total: u64,
    pub cross_ccx: u64,
    pub cross_numa: u64,
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

impl WithComm for MigrationData {
    type Data = MigrationCounts;

    fn extract_data(&self) -> Self::Data {
        MigrationCounts {
            total: self.count,
            cross_ccx: self.cross_ccx_count,
            cross_numa: self.cross_numa_count,
        }
    }

    fn extract_comm(&self) -> String {
        self.comm.comm_str()
    }

    fn extract_cgroup_id(&self) -> u64 {
        self.cgroup_id
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CpuPerfDataFull {
    pub data: CpuPerfData,
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

pub const MAX_GENERIC_EVENTS: usize = 8;
pub type GenericPerfResult = HashMap<u32, ([u64; MAX_GENERIC_EVENTS], String, u64)>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenericPerfData {
    pub counters: [u64; MAX_GENERIC_EVENTS],
    pub comm: [u8; TASK_COMM_LEN],
    pub cgroup_id: u64,
}

unsafe impl Plain for GenericPerfData {}

impl WithComm for GenericPerfData {
    type Data = [u64; MAX_GENERIC_EVENTS];

    fn extract_data(&self) -> Self::Data {
        self.counters
    }

    fn extract_comm(&self) -> String {
        self.comm.comm_str()
    }

    fn extract_cgroup_id(&self) -> u64 {
        self.cgroup_id
    }
}

// Helper trait for comm extraction
trait CommExtractor {
    fn comm_str(&self) -> String;
}

impl CommExtractor for [u8; TASK_COMM_LEN] {
    fn comm_str(&self) -> String {
        let end = self.iter().position(|&c| c == 0).unwrap_or(TASK_COMM_LEN);
        String::from_utf8_lossy(&self[..end]).trim().to_string()
    }
}

// Trait for extracting data with comm and cgroup_id
trait WithComm {
    type Data;
    fn extract_data(&self) -> Self::Data;
    fn extract_comm(&self) -> String;
    fn extract_cgroup_id(&self) -> u64;
}

impl WithComm for HistData {
    type Data = Hist;

    fn extract_data(&self) -> Self::Data {
        self.hist
    }

    fn extract_comm(&self) -> String {
        self.comm.comm_str()
    }

    fn extract_cgroup_id(&self) -> u64 {
        self.cgroup_id
    }
}

impl WithComm for TimesliceData {
    type Data = TimesliceStats;

    fn extract_data(&self) -> Self::Data {
        self.stats
    }

    fn extract_comm(&self) -> String {
        self.comm.comm_str()
    }

    fn extract_cgroup_id(&self) -> u64 {
        self.cgroup_id
    }
}

impl WithComm for CpuPerfDataFull {
    type Data = CpuPerfData;

    fn extract_data(&self) -> Self::Data {
        self.data
    }

    fn extract_comm(&self) -> String {
        self.comm.comm_str()
    }

    fn extract_cgroup_id(&self) -> u64 {
        self.cgroup_id
    }
}

unsafe impl Plain for Hist {}
unsafe impl Plain for HistData {}
unsafe impl Plain for TimesliceStats {}
unsafe impl Plain for TimesliceData {}
unsafe impl Plain for MigrationData {}
unsafe impl Plain for CpuPerfDataFull {}

pub struct RschedCollector<'a> {
    hists_map: &'a Map<'a>,
    cpu_hists_map: &'a Map<'a>,
    cpu_idle_hists_map: &'a Map<'a>,
    timeslice_hists_map: &'a Map<'a>,
    nr_running_hists_map: &'a Map<'a>,
    waking_delay_map: &'a Map<'a>,
    sleep_hists_map: &'a Map<'a>,
    migration_counts_map: &'a Map<'a>,
    cpu_perf_map: &'a Map<'a>,
    generic_perf_map: &'a Map<'a>,
}

impl<'a> RschedCollector<'a> {
    pub fn new(maps: &'a crate::RschedMaps) -> Self {
        Self {
            hists_map: &maps.hists,
            cpu_hists_map: &maps.cpu_hists,
            cpu_idle_hists_map: &maps.cpu_idle_hists,
            timeslice_hists_map: &maps.timeslice_hists,
            nr_running_hists_map: &maps.nr_running_hists,
            waking_delay_map: &maps.waking_delay,
            sleep_hists_map: &maps.sleep_hists,
            migration_counts_map: &maps.migration_counts,
            cpu_perf_map: &maps.cpu_perf_stats,
            generic_perf_map: &maps.generic_perf_stats,
        }
    }

    // Generic collection function for data with comm and cgroup_id
    fn collect_with_comm<T, D>(&self, map: &Map) -> Result<HashMap<u32, (D, String, u64)>>
    where
        T: Plain + WithComm<Data = D>,
    {
        let mut results = HashMap::new();
        let keys: Vec<Vec<u8>> = map.keys().collect();

        for key in keys {
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap());
            let value = map.lookup(&key, MapFlags::ANY)?;

            if let Some(value) = value {
                let data = plain::from_bytes::<T>(&value).expect("Invalid data format");
                results.insert(
                    pid,
                    (
                        data.extract_data(),
                        data.extract_comm(),
                        data.extract_cgroup_id(),
                    ),
                );
            }

            let _ = map.delete(&key);
        }
        Ok(results)
    }

    // Generic collection function for plain data (no comm)
    fn collect_plain<T: Plain + Clone>(&self, map: &Map) -> Result<HashMap<u32, T>> {
        let mut results = HashMap::new();
        let keys: Vec<Vec<u8>> = map.keys().collect();

        for key in keys {
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap());
            let value = map.lookup(&key, MapFlags::ANY)?;

            if let Some(value) = value {
                let data = plain::from_bytes::<T>(&value).expect("Invalid data format");
                results.insert(pid, data.clone());
            }

            let _ = map.delete(&key);
        }
        Ok(results)
    }

    pub fn collect_histograms(&mut self) -> Result<HashMap<u32, (Hist, String, u64)>> {
        self.collect_with_comm::<HistData, Hist>(self.hists_map)
    }

    pub fn collect_cpu_histograms(&mut self) -> Result<HashMap<u32, Hist>> {
        self.collect_plain::<Hist>(self.cpu_hists_map)
    }

    pub fn collect_cpu_idle_histograms(&mut self) -> Result<HashMap<u32, Hist>> {
        self.collect_plain::<Hist>(self.cpu_idle_hists_map)
    }

    pub fn collect_nr_running_hists(&mut self) -> Result<HashMap<u32, (Hist, String, u64)>> {
        self.collect_with_comm::<HistData, Hist>(self.nr_running_hists_map)
    }

    pub fn collect_waking_delays(&mut self) -> Result<HashMap<u32, (Hist, String, u64)>> {
        self.collect_with_comm::<HistData, Hist>(self.waking_delay_map)
    }

    pub fn collect_sleep_durations(&mut self) -> Result<HashMap<u32, (Hist, String, u64)>> {
        self.collect_with_comm::<HistData, Hist>(self.sleep_hists_map)
    }

    pub fn collect_timeslice_stats(
        &mut self,
    ) -> Result<HashMap<u32, (TimesliceStats, String, u64)>> {
        self.collect_with_comm::<TimesliceData, TimesliceStats>(self.timeslice_hists_map)
    }

    pub fn collect_migration_counts(
        &mut self,
    ) -> Result<HashMap<u32, (MigrationCounts, String, u64)>> {
        self.collect_with_comm::<MigrationData, MigrationCounts>(self.migration_counts_map)
    }

    pub fn collect_cpu_perf(&mut self) -> Result<HashMap<u32, (CpuPerfData, String, u64)>> {
        self.collect_with_comm::<CpuPerfDataFull, CpuPerfData>(self.cpu_perf_map)
    }

    pub fn collect_generic_perf(&mut self) -> Result<GenericPerfResult> {
        self.collect_with_comm::<GenericPerfData, [u64; MAX_GENERIC_EVENTS]>(self.generic_perf_map)
    }
}
