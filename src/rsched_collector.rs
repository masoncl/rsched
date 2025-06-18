// SPDX-License-Identifier: GPL-2.0
use crate::cpu_metrics::CpuPerfData;
use anyhow::Result;
use libbpf_rs::{Map, MapCore, MapFlags};
use plain::Plain;
use std::collections::HashMap;

pub const MAX_SLOTS: usize = 64;
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HistData {
    pub hist: Hist,
    pub comm: [u8; TASK_COMM_LEN],
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
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CpuPerfDataFull {
    pub data: CpuPerfData,
    pub comm: [u8; TASK_COMM_LEN],
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

// Trait for extracting data with comm
trait WithComm {
    type Data;
    fn extract_data(&self) -> Self::Data;
    fn extract_comm(&self) -> String;
}

impl WithComm for HistData {
    type Data = Hist;

    fn extract_data(&self) -> Self::Data {
        self.hist
    }

    fn extract_comm(&self) -> String {
        self.comm.comm_str()
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
}

impl WithComm for CpuPerfDataFull {
    type Data = CpuPerfData;

    fn extract_data(&self) -> Self::Data {
        self.data
    }

    fn extract_comm(&self) -> String {
        self.comm.comm_str()
    }
}

unsafe impl Plain for Hist {}
unsafe impl Plain for HistData {}
unsafe impl Plain for TimesliceStats {}
unsafe impl Plain for TimesliceData {}
unsafe impl Plain for CpuPerfDataFull {}

pub struct RschedCollector<'a> {
    hists_map: &'a Map<'a>,
    cpu_hists_map: &'a Map<'a>,
    timeslice_hists_map: &'a Map<'a>,
    nr_running_hists_map: &'a Map<'a>,
    waking_delay_map: &'a Map<'a>,
    cpu_perf_map: &'a Map<'a>,
}

impl<'a> RschedCollector<'a> {
    pub fn new(maps: &'a crate::RschedMaps) -> Self {
        Self {
            hists_map: &maps.hists,
            cpu_hists_map: &maps.cpu_hists,
            timeslice_hists_map: &maps.timeslice_hists,
            nr_running_hists_map: &maps.nr_running_hists,
            waking_delay_map: &maps.waking_delay,
            cpu_perf_map: &maps.cpu_perf_stats,
        }
    }

    // Generic collection function for data with comm
    fn collect_with_comm<T, D>(&self, map: &Map) -> Result<HashMap<u32, (D, String)>>
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
                results.insert(pid, (data.extract_data(), data.extract_comm()));
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

    pub fn collect_histograms(&mut self) -> Result<HashMap<u32, (Hist, String)>> {
        self.collect_with_comm::<HistData, Hist>(self.hists_map)
    }

    pub fn collect_cpu_histograms(&mut self) -> Result<HashMap<u32, Hist>> {
        self.collect_plain::<Hist>(self.cpu_hists_map)
    }

    pub fn collect_nr_running_hists(&mut self) -> Result<HashMap<u32, (Hist, String)>> {
        self.collect_with_comm::<HistData, Hist>(self.nr_running_hists_map)
    }

    pub fn collect_waking_delays(&mut self) -> Result<HashMap<u32, (Hist, String)>> {
        self.collect_with_comm::<HistData, Hist>(self.waking_delay_map)
    }

    pub fn collect_timeslice_stats(&mut self) -> Result<HashMap<u32, (TimesliceStats, String)>> {
        self.collect_with_comm::<TimesliceData, TimesliceStats>(self.timeslice_hists_map)
    }

    pub fn collect_cpu_perf(&mut self) -> Result<HashMap<u32, (CpuPerfData, String)>> {
        self.collect_with_comm::<CpuPerfDataFull, CpuPerfData>(self.cpu_perf_map)
    }
}
