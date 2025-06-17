// SPDX-License-Identifier: GPL-2.0
use anyhow::Result;
use libbpf_rs::{Map, MapFlags};
use plain::Plain;
use std::collections::HashMap;

pub const MAX_SLOTS: usize = 64;

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
#[derive(Default, Copy, Clone)]
pub struct TimesliceStats {
    pub voluntary: Hist,
    pub involuntary: Hist,
    pub involuntary_count: u64,
}

unsafe impl Plain for Hist {}
unsafe impl Plain for TimesliceStats {}

pub struct RschedCollector<'a> {
    hists_map: &'a Map,
    cpu_hists_map: &'a Map,
    timeslice_hists_map: &'a Map,
    nr_running_hists_map: &'a Map,
    waking_delay_map: &'a Map,
}

impl<'a> RschedCollector<'a> {
    pub fn new(maps: &'a crate::RschedMaps) -> Self {
        Self {
            hists_map: maps.hists(),
            cpu_hists_map: maps.cpu_hists(),
            timeslice_hists_map: maps.timeslice_hists(),
            nr_running_hists_map: maps.nr_running_hists(),
            waking_delay_map: maps.waking_delay(),
        }
    }

    pub fn collect_histograms(&mut self) -> Result<HashMap<u32, Hist>> {
        return self.collect(self.hists_map);
    }

    pub fn collect_cpu_histograms(&mut self) -> Result<HashMap<u32, Hist>> {
        return self.collect(self.cpu_hists_map);
    }

    pub fn collect_nr_running_hists(&mut self) -> Result<HashMap<u32, Hist>> {
        return self.collect(self.nr_running_hists_map);
    }

    pub fn collect_waking_delays(&mut self) -> Result<HashMap<u32, Hist>> {
        return self.collect(self.waking_delay_map);
    }

    fn collect(&mut self, mapper: &Map) -> Result<HashMap<u32, Hist>> {
        let mut results = HashMap::new();

        // Collect all keys first to avoid borrowing issues
        let keys: Vec<Vec<u8>> = mapper.keys().collect();

        for key in keys {
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap());
            let value = mapper.lookup(&key, MapFlags::ANY)?;

            if let Some(value) = value {
                let hist = plain::from_bytes::<Hist>(&value).expect("Invalid histogram format");
                results.insert(pid, *hist);
            }

            // Delete the entry after reading
            let _ = mapper.delete(&key);
        }
        Ok(results)
    }

    pub fn collect_timeslice_stats(&mut self) -> Result<HashMap<u32, TimesliceStats>> {
        let mut results = HashMap::new();

        // Collect all keys first to avoid borrowing issues
        let keys: Vec<Vec<u8>> = self.timeslice_hists_map.keys().collect();

        for key in keys {
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap());
            let value = self.timeslice_hists_map.lookup(&key, MapFlags::ANY)?;

            if let Some(value) = value {
                let stats = plain::from_bytes::<TimesliceStats>(&value)
                    .expect("Invalid timeslice stats format");
                results.insert(pid, *stats);
            }

            // Delete the entry after reading
            let _ = self.timeslice_hists_map.delete(&key);
        }
        Ok(results)
    }
}
