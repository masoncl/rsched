// SPDX-License-Identifier: GPL-2.0
use crate::cpu_metrics::CpuPerfData;
use anyhow::Result;
use aya::maps::HashMap as AyaHashMap;
use rsched_common::*;
use std::borrow::BorrowMut;
use std::collections::HashMap;

pub const MIG_HIST_SLOTS: usize = 1025;

// Re-export common types so the rest of the codebase can keep using them
pub use rsched_common::{
    CpuPerfDataFull, GenericPerfData, Hist, HistData, MigrationData, TimesliceData, TimesliceStats,
    MAX_GENERIC_EVENTS, MAX_SLOTS, TASK_COMM_LEN,
};

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

#[derive(Copy, Clone, Default)]
pub struct MigrationCounts {
    pub total: u64,
    pub cross_ccx: u64,
    pub cross_numa: u64,
}

pub type GenericPerfResult = HashMap<u32, ([u64; MAX_GENERIC_EVENTS], String, u64)>;

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

pub struct RschedCollector;

impl RschedCollector {
    pub fn new() -> Self {
        Self
    }

    fn collect_with_comm_map<M, T, D>(
        map: &mut AyaHashMap<M, u32, T>,
    ) -> Result<HashMap<u32, (D, String, u64)>>
    where
        M: BorrowMut<aya::maps::MapData>,
        T: aya::Pod + WithComm<Data = D>,
    {
        let mut results = HashMap::new();
        let keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();
        for pid in keys {
            if let Ok(data) = map.get(&pid, 0) {
                results.insert(
                    pid,
                    (
                        data.extract_data(),
                        data.extract_comm(),
                        data.extract_cgroup_id(),
                    ),
                );
            }
            let _ = map.remove(&pid);
        }
        Ok(results)
    }

    fn collect_plain_map<M, T>(map: &mut AyaHashMap<M, u32, T>) -> Result<HashMap<u32, T>>
    where
        M: BorrowMut<aya::maps::MapData>,
        T: aya::Pod + Clone,
    {
        let mut results = HashMap::new();
        let keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();
        for key in keys {
            if let Ok(data) = map.get(&key, 0) {
                results.insert(key, data);
            }
            let _ = map.remove(&key);
        }
        Ok(results)
    }

    pub fn collect_histograms<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, HistData>,
    ) -> Result<HashMap<u32, (Hist, String, u64)>> {
        Self::collect_with_comm_map(map)
    }

    pub fn collect_cpu_histograms<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, Hist>,
    ) -> Result<HashMap<u32, Hist>> {
        Self::collect_plain_map(map)
    }

    pub fn collect_cpu_idle_histograms<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, Hist>,
    ) -> Result<HashMap<u32, Hist>> {
        Self::collect_plain_map(map)
    }

    pub fn collect_nr_running_hists<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, NrRunningData>,
    ) -> Result<HashMap<u32, (Hist, String, u64)>> {
        let mut results = HashMap::new();
        let keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();
        for pid in keys {
            if let Ok(data) = map.get(&pid, 0) {
                results.insert(pid, (data.hist, data.comm.comm_str(), data.cgroup_id));
            }
            let _ = map.remove(&pid);
        }
        Ok(results)
    }

    pub fn collect_waking_delays<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, WakingData>,
    ) -> Result<HashMap<u32, (Hist, String, u64)>> {
        let mut results = HashMap::new();
        let keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();
        for pid in keys {
            if let Ok(data) = map.get(&pid, 0) {
                results.insert(pid, (data.hist, data.comm.comm_str(), data.cgroup_id));
            }
            let _ = map.remove(&pid);
        }
        Ok(results)
    }

    pub fn collect_sleep_durations<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, HistData>,
    ) -> Result<HashMap<u32, (Hist, String, u64)>> {
        Self::collect_with_comm_map(map)
    }

    pub fn collect_timeslice_stats<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, TimesliceData>,
    ) -> Result<HashMap<u32, (TimesliceStats, String, u64)>> {
        Self::collect_with_comm_map(map)
    }

    pub fn collect_migration_counts<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, MigrationData>,
    ) -> Result<HashMap<u32, (MigrationCounts, String, u64)>> {
        Self::collect_with_comm_map(map)
    }

    pub fn collect_cpu_perf<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, CpuPerfDataFull>,
    ) -> Result<HashMap<u32, (CpuPerfData, String, u64)>> {
        Self::collect_with_comm_map(map)
    }

    pub fn collect_generic_perf<M: BorrowMut<aya::maps::MapData>>(
        map: &mut AyaHashMap<M, u32, GenericPerfData>,
    ) -> Result<GenericPerfResult> {
        Self::collect_with_comm_map(map)
    }
}
