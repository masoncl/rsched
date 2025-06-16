use crate::rsched_collector::{Hist, TimesliceStats, MAX_SLOTS};
use crate::schedstat::SchedstatData;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

// Add these constants to match BPF
const LINEAR_STEP: u64 = 10;
const LINEAR_SLOTS: usize = 50;

#[derive(Copy, Clone)]
pub enum OutputMode {
    Grouped,
    Detailed,
    Collapsed,
}

pub struct FilterOptions {
    pub comm_regex: Option<Regex>,
    pub pid_filter: Option<u32>,
    pub min_latency_us: u64,
    pub trace_sched_waking: bool,
}

pub struct RschedStats {
    pid_stats: HashMap<u32, RschedPidStats>,
    cpu_stats: HashMap<u32, Hist>,
    timeslice_stats: HashMap<u32, TimesliceStatsData>,
    nr_running_stats: HashMap<u32, NrRunningData>,
    waking_delay_stats: HashMap<u32, WakingDelayData>,
    schedstat_data: Option<SchedstatData>,
}

struct RschedPidStats {
    hist: Hist,
    comm: String,
}

struct TimesliceStatsData {
    stats: TimesliceStats,
    comm: String,
}

struct NrRunningData {
    hist: Hist,
    comm: String,
}

struct WakingDelayData {
    hist: Hist,
    comm: String,
}

// Represents either a single process or a collapsed group of processes
struct ProcessEntry {
    comm: String,
    hist: Hist,
    timeslice_stats: TimesliceStats,
    nr_running_hist: Hist,
    waking_delay_hist: Hist,
    pids: Vec<u32>,
}

// Latency groups for grouped output
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum LatencyGroup {
    VeryLow,  // < 10 us
    Low,      // 10-100 us
    Medium,   // 100-1000 us (1ms)
    High,     // 1-10 ms
    VeryHigh, // > 10 ms
}

impl LatencyGroup {
    fn from_percentile(p90: u64) -> Self {
        // Classify based on p90
        if p90 < 10 {
            LatencyGroup::VeryLow
        } else if p90 < 100 {
            LatencyGroup::Low
        } else if p90 < 1000 {
            LatencyGroup::Medium
        } else if p90 < 10000 {
            LatencyGroup::High
        } else {
            LatencyGroup::VeryHigh
        }
    }

    fn description(&self) -> &'static str {
        match self {
            LatencyGroup::VeryLow => "Very Low (<10μs)",
            LatencyGroup::Low => "Low (10-100μs)",
            LatencyGroup::Medium => "Medium (100μs-1ms)",
            LatencyGroup::High => "High (1-10ms)",
            LatencyGroup::VeryHigh => "Very High (>10ms)",
        }
    }
}

impl RschedStats {
    pub fn new() -> Self {
        Self {
            pid_stats: HashMap::new(),
            cpu_stats: HashMap::new(),
            timeslice_stats: HashMap::new(),
            nr_running_stats: HashMap::new(),
            waking_delay_stats: HashMap::new(),
            schedstat_data: None,
        }
    }

    pub fn update(&mut self, histograms: HashMap<u32, Hist>) {
        for (pid, hist) in histograms {
            let comm = Self::get_comm(pid);

            let stats = self.pid_stats.entry(pid).or_insert(RschedPidStats {
                hist: Hist::default(),
                comm,
            });

            // Merge histograms
            for i in 0..MAX_SLOTS {
                stats.hist.slots[i] += hist.slots[i];
            }
        }
    }

    pub fn update_cpu(&mut self, cpu_histograms: HashMap<u32, Hist>) {
        for (cpu, hist) in cpu_histograms {
            let stats = self.cpu_stats.entry(cpu).or_insert(Hist::default());

            // Merge histograms
            for i in 0..MAX_SLOTS {
                stats.slots[i] += hist.slots[i];
            }
        }
    }
    pub fn update_schedstat(&mut self, schedstat_data: SchedstatData) {
        self.schedstat_data = Some(schedstat_data);
    }

    pub fn update_timeslices(&mut self, timeslice_data: HashMap<u32, TimesliceStats>) {
        for (pid, new_stats) in timeslice_data {
            let comm = Self::get_comm(pid);

            let stats = self
                .timeslice_stats
                .entry(pid)
                .or_insert(TimesliceStatsData {
                    stats: TimesliceStats::default(),
                    comm,
                });

            // Merge timeslice histograms
            for i in 0..MAX_SLOTS {
                stats.stats.voluntary.slots[i] += new_stats.voluntary.slots[i];
                stats.stats.involuntary.slots[i] += new_stats.involuntary.slots[i];
            }
            stats.stats.involuntary_count += new_stats.involuntary_count;
        }
    }

    pub fn update_nr_running(&mut self, nr_running_data: HashMap<u32, Hist>) {
        for (pid, hist) in nr_running_data {
            let comm = Self::get_comm(pid);

            let stats = self.nr_running_stats.entry(pid).or_insert(NrRunningData {
                hist: Hist::default(),
                comm,
            });

            // Merge histograms
            for i in 0..MAX_SLOTS {
                stats.hist.slots[i] += hist.slots[i];
            }
        }
    }

    pub fn update_waking_delays(&mut self, waking_delays: HashMap<u32, Hist>) {
        for (pid, hist) in waking_delays {
            let comm = Self::get_comm(pid);

            let stats = self
                .waking_delay_stats
                .entry(pid)
                .or_insert(WakingDelayData {
                    hist: Hist::default(),
                    comm,
                });

            // Merge histograms
            for i in 0..MAX_SLOTS {
                stats.hist.slots[i] += hist.slots[i];
            }
        }
    }

    pub fn print_schedstat(&self, schedstat_data: &SchedstatData) {
        // Print schedstat metrics in 3 columns
        println!("\n=== System-wide Schedstat Metrics (deltas) ===");

        // Collect all metrics into a sorted vector
        let mut metrics: Vec<(&String, &u64)> = schedstat_data.domain_totals.iter().collect();
        metrics.sort_by(|a, b| a.0.cmp(b.0));

        // Print in 3 columns
        let metrics_per_col = (metrics.len() + 2) / 3;

        for row in 0..metrics_per_col {
            for col in 0..3 {
                let idx = col * metrics_per_col + row;
                if idx < metrics.len() {
                    let (name, value) = metrics[idx];
                    print!("{:<30} {:>9} ", name, value);
                    if col < 2 {
                        print!("| ");
                    }
                }
            }
            println!();
        }

        // Also print CPU field totals
        if !schedstat_data.cpu_totals.is_empty() {
            println!("\n=== CPU Field Totals (deltas) ===");
            let cpu_fields = vec![
                "yld_count",
                "sched_count",
                "sched_goidle",
                "ttwu_count",
                "ttwu_local",
                "rq_cpu_time",
                "rq_run_delay usec",
                "rq_pcount",
            ];

            for (i, field) in cpu_fields.iter().enumerate() {
                if i < schedstat_data.cpu_totals.len() {
                    let mut val = schedstat_data.cpu_totals[i];
                    if *field == "rq_run_delay usec" {
                        val = val / schedstat_data.cpu_totals[i + 1];
                    }
                    print!("{:<17} {:>12} ", field, val);
                    if (i + 1) % 3 == 0 {
                        println!();
                    } else {
                        print!("| ");
                    }
                }
            }
            if cpu_fields.len() % 3 != 0 {
                println!();
            }
        }

        println!();
    }

    pub fn print_summary(&self, mode: OutputMode, filters: &FilterOptions) -> Result<()> {
        // Clear screen for better readability
        print!("\x1B[2J\x1B[1;1H");

        let detailed = matches!(mode, OutputMode::Detailed);
        let collapsed = matches!(mode, OutputMode::Collapsed);

        // Build process entries based on collapse mode
        let process_entries = self.build_process_entries(filters, collapsed);

        if process_entries.is_empty() {
            println!("No processes match the specified filters.\n");
        } else {
            self.print_process_stats(&process_entries, detailed, collapsed)?;
            println!();

            if filters.trace_sched_waking {
                self.print_waking_delay_stats(&process_entries, detailed, collapsed)?;
                println!();
            }

            self.print_timeslice_stats(&process_entries, detailed, collapsed)?;
            println!();
            self.print_nr_running_stats(&process_entries, detailed, collapsed)?;
        }
        if let Some(data) = &self.schedstat_data {
            self.print_schedstat(data);
        }

        // Print CPU stats
        self.print_cpu_stats(filters, detailed)?;

        Ok(())
    }

    fn print_waking_delay_stats(
        &self,
        entries: &[ProcessEntry],
        detailed: bool,
        collapsed: bool,
    ) -> Result<()> {
        let title = if collapsed {
            "Collapsed Waking Delay Statistics"
        } else {
            "Per-Process Waking Delay Statistics"
        };

        println!("=== {} (microseconds) ===", title);
        println!("(Time from sched_waking to sched_switch)\n");

        if detailed {
            // Detailed mode: show all entries
            let entry_refs: Vec<&ProcessEntry> = entries.iter().collect();
            self.print_waking_delay_table(&entry_refs, collapsed);
        } else {
            // Grouped mode: show top entries by p90 waking delay
            println!("Processes by waking delay:\n");

            // Sort by p90 waking delay
            let mut sorted_entries: Vec<&ProcessEntry> = entries.iter().collect();
            sorted_entries.sort_by(|a, b| {
                let a_p90 = self.calculate_percentile(&a.waking_delay_hist, 90);
                let b_p90 = self.calculate_percentile(&b.waking_delay_hist, 90);
                b_p90.cmp(&a_p90)
            });

            let show_count = sorted_entries.len().min(10);
            let table_entries: Vec<&ProcessEntry> =
                sorted_entries.iter().take(show_count).copied().collect();

            self.print_waking_delay_table(&table_entries, collapsed);

            if sorted_entries.len() > show_count {
                println!("  ... and {} more\n", sorted_entries.len() - show_count);
            }
        }

        Ok(())
    }

    fn print_waking_delay_table(&self, entries: &[&ProcessEntry], collapsed: bool) {
        // Calculate the maximum command name length
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12}",
                "COMMAND",
                "PROCS",
                "p50",
                "p90",
                "p95",
                "COUNT",
                width = max_comm_len
            );
        } else {
            println!(
                "  {:<8} {:<width$} {:<10} {:<10} {:<10} {:<12}",
                "PID",
                "COMMAND",
                "p50",
                "p90",
                "p95",
                "COUNT",
                width = max_comm_len
            );
        }

        for entry in entries {
            let total_count = self.get_total_count(&entry.waking_delay_hist);
            if total_count == 0 {
                continue;
            }

            let p50 = self.calculate_percentile(&entry.waking_delay_hist, 50);
            let p90 = self.calculate_percentile(&entry.waking_delay_hist, 90);
            let p95 = self.calculate_percentile(&entry.waking_delay_hist, 95);

            if collapsed {
                println!(
                    "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12}",
                    &entry.comm,
                    entry.pids.len(),
                    p50,
                    p90,
                    p95,
                    total_count,
                    width = max_comm_len
                );
            } else {
                println!(
                    "  {:<8} {:<width$} {:<10} {:<10} {:<10} {:<12}",
                    entry.pids[0],
                    &entry.comm,
                    p50,
                    p90,
                    p95,
                    total_count,
                    width = max_comm_len
                );
            }
        }
    }

    fn print_nr_running_stats(
        &self,
        entries: &[ProcessEntry],
        detailed: bool,
        collapsed: bool,
    ) -> Result<()> {
        let title = if collapsed {
            "Collapsed Runqueue Depth Statistics"
        } else {
            "Per-Process Runqueue Depth Statistics"
        };

        println!("=== {} (nr_running at wakeup) ===\n", title);

        if detailed {
            // Detailed mode: show all entries
            let entry_refs: Vec<&ProcessEntry> = entries.iter().collect();
            self.print_nr_running_table(&entry_refs, collapsed);
        } else {
            // Grouped mode: show top entries by p90 nr_running
            println!("Processes by runqueue depth at wakeup:\n");

            // Sort by p90 nr_running
            let mut sorted_entries: Vec<&ProcessEntry> = entries.iter().collect();
            sorted_entries.sort_by(|a, b| {
                let a_p90 = self.calculate_nr_running_percentile(&a.nr_running_hist, 90);
                let b_p90 = self.calculate_nr_running_percentile(&b.nr_running_hist, 90);
                b_p90.cmp(&a_p90)
            });

            let show_count = sorted_entries.len().min(10);
            let table_entries: Vec<&ProcessEntry> =
                sorted_entries.iter().take(show_count).copied().collect();

            self.print_nr_running_table(&table_entries, collapsed);

            if sorted_entries.len() > show_count {
                println!("  ... and {} more\n", sorted_entries.len() - show_count);
            }
        }

        Ok(())
    }

    fn print_nr_running_table(&self, entries: &[&ProcessEntry], collapsed: bool) {
        // Calculate the maximum command name length
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12}",
                "COMMAND",
                "PROCS",
                "p50",
                "p90",
                "p95",
                "COUNT",
                width = max_comm_len
            );
        } else {
            println!(
                "  {:<8} {:<width$} {:<10} {:<10} {:<10} {:<12}",
                "PID",
                "COMMAND",
                "p50",
                "p90",
                "p95",
                "COUNT",
                width = max_comm_len
            );
        }

        for entry in entries {
            let total_count = self.get_total_count(&entry.nr_running_hist);
            if total_count == 0 {
                continue;
            }

            let p50 = self.calculate_nr_running_percentile(&entry.nr_running_hist, 50);
            let p90 = self.calculate_nr_running_percentile(&entry.nr_running_hist, 90);
            let p95 = self.calculate_nr_running_percentile(&entry.nr_running_hist, 95);

            if collapsed {
                println!(
                    "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12}",
                    &entry.comm,
                    entry.pids.len(),
                    p50,
                    p90,
                    p95,
                    total_count,
                    width = max_comm_len
                );
            } else {
                println!(
                    "  {:<8} {:<width$} {:<10} {:<10} {:<10} {:<12}",
                    entry.pids[0],
                    &entry.comm,
                    p50,
                    p90,
                    p95,
                    total_count,
                    width = max_comm_len
                );
            }
        }
    }
    // Update calculate_nr_running_percentile to use all 64 slots
    fn calculate_nr_running_percentile(&self, hist: &Hist, percentile: u8) -> u32 {
        let total_count = self.get_total_count(hist);
        if total_count == 0 {
            return 0;
        }

        let target_count = (total_count * percentile as u64) / 100;
        let mut cumulative_count = 0u64;

        for (slot, &count) in hist.slots.iter().enumerate() {
            cumulative_count += count as u64;

            if cumulative_count >= target_count {
                // For nr_running, slots directly represent task counts
                // With 64 slots, we can represent 0-63 tasks directly
                return slot as u32;
            }
        }

        // If we get here, return the max slot value
        63
    }

    fn calculate_percentile(&self, hist: &Hist, percentile: u8) -> u64 {
        let total_count = self.get_total_count(hist);
        if total_count == 0 {
            return 0;
        }

        let target_count = (total_count * percentile as u64) / 100;
        let mut cumulative_count = 0u64;

        for (slot, &count) in hist.slots.iter().enumerate() {
            let prev_cumulative = cumulative_count;
            cumulative_count += count as u64;

            if cumulative_count >= target_count {
                // Calculate position within this bucket for interpolation
                let count_in_bucket = count as u64;
                let position_in_bucket = target_count - prev_cumulative;
                let fraction = if count_in_bucket > 0 {
                    position_in_bucket as f64 / count_in_bucket as f64
                } else {
                    0.5
                };

                // Determine the range for this slot
                let (lower_bound, upper_bound) = self.get_slot_range(slot);

                // Interpolate within the range
                // Add 1 because both bounds are inclusive
                let range = upper_bound - lower_bound + 1;
                return lower_bound + (fraction * range as f64) as u64;
            }
        }

        // If we get here, return a large value
        1u64 << 27 // ~134 seconds
    }

    // Helper function to get the microsecond range for a histogram slot
    fn get_slot_range(&self, slot: usize) -> (u64, u64) {
        if slot < LINEAR_SLOTS {
            // Linear buckets: each slot covers LINEAR_STEP microseconds
            let lower = slot as u64 * LINEAR_STEP;
            let upper = lower + LINEAR_STEP - 1;
            (lower, upper)
        } else if slot == LINEAR_SLOTS {
            // Special transition slot for 500-511μs
            (500, 511)
        } else {
            // Log2 buckets: slot 51 starts at 512μs (2^9)
            // slot 52 = 1024μs (2^10), slot 53 = 2048μs (2^11), etc.
            let log2_val = (slot - LINEAR_SLOTS - 1) + 9;
            let lower = 1u64 << log2_val;
            let upper = (1u64 << (log2_val + 1)) - 1;
            (lower, upper)
        }
    }

    fn build_process_entries(&self, filters: &FilterOptions, collapse: bool) -> Vec<ProcessEntry> {
        if collapse {
            // Collapse by command name
            let mut comm_map: HashMap<String, ProcessEntry> = HashMap::new();

            // Process scheduling latency data
            for (pid, stats) in &self.pid_stats {
                if !self.should_include_process(pid, &stats.comm, filters) {
                    continue;
                }

                let total_count = self.get_total_count(&stats.hist);
                if total_count == 0 {
                    continue;
                }

                let entry = comm_map.entry(stats.comm.clone()).or_insert(ProcessEntry {
                    comm: stats.comm.clone(),
                    hist: Hist::default(),
                    timeslice_stats: TimesliceStats::default(),
                    nr_running_hist: Hist::default(),
                    waking_delay_hist: Hist::default(),
                    pids: Vec::new(),
                });

                // Merge histogram
                for i in 0..MAX_SLOTS {
                    entry.hist.slots[i] += stats.hist.slots[i];
                }
                entry.pids.push(*pid);
            }

            // Add timeslice data
            for (_pid, ts_data) in &self.timeslice_stats {
                if let Some(entry) = comm_map.get_mut(&ts_data.comm) {
                    // Merge timeslice stats
                    for i in 0..MAX_SLOTS {
                        entry.timeslice_stats.voluntary.slots[i] +=
                            ts_data.stats.voluntary.slots[i];
                        entry.timeslice_stats.involuntary.slots[i] +=
                            ts_data.stats.involuntary.slots[i];
                    }
                    entry.timeslice_stats.involuntary_count += ts_data.stats.involuntary_count;
                }
            }

            // Add nr_running data
            for (_pid, nr_data) in &self.nr_running_stats {
                if let Some(entry) = comm_map.get_mut(&nr_data.comm) {
                    // Merge nr_running histogram
                    for i in 0..MAX_SLOTS {
                        entry.nr_running_hist.slots[i] += nr_data.hist.slots[i];
                    }
                }
            }

            // Add waking delay data
            for (_pid, wd_data) in &self.waking_delay_stats {
                if let Some(entry) = comm_map.get_mut(&wd_data.comm) {
                    // Merge waking delay histogram
                    for i in 0..MAX_SLOTS {
                        entry.waking_delay_hist.slots[i] += wd_data.hist.slots[i];
                    }
                }
            }

            comm_map.into_values().collect()
        } else {
            // Individual processes
            self.pid_stats
                .iter()
                .filter(|(pid, stats)| {
                    self.should_include_process(pid, &stats.comm, filters)
                        && self.get_total_count(&stats.hist) > 0
                })
                .map(|(pid, stats)| {
                    let ts_stats = self
                        .timeslice_stats
                        .get(pid)
                        .map(|ts| ts.stats.clone())
                        .unwrap_or_default();

                    let nr_hist = self
                        .nr_running_stats
                        .get(pid)
                        .map(|nr| nr.hist.clone())
                        .unwrap_or_default();

                    let waking_delay_hist = self
                        .waking_delay_stats
                        .get(pid)
                        .map(|wd| wd.hist.clone())
                        .unwrap_or_default();

                    ProcessEntry {
                        comm: stats.comm.clone(),
                        hist: stats.hist.clone(),
                        timeslice_stats: ts_stats,
                        nr_running_hist: nr_hist,
                        waking_delay_hist,
                        pids: vec![*pid],
                    }
                })
                .collect()
        }
    }

    fn print_timeslice_stats(
        &self,
        entries: &[ProcessEntry],
        detailed: bool,
        collapsed: bool,
    ) -> Result<()> {
        let title = if collapsed {
            "Collapsed Time Slice Statistics"
        } else {
            "Per-Process Time Slice Statistics"
        };

        println!("=== {} (microseconds) ===\n", title);

        if detailed {
            // Detailed mode: show all entries
            let entry_refs: Vec<&ProcessEntry> = entries.iter().collect();
            self.print_timeslice_table(&entry_refs, collapsed);
        } else {
            // Grouped mode: group by involuntary switch rate
            println!("Time slice statistics grouped by preemption rate:\n");

            // Sort by involuntary context switch rate
            let mut sorted_entries: Vec<&ProcessEntry> = entries.iter().collect();
            sorted_entries.sort_by(|a, b| {
                let a_rate = if a.timeslice_stats.involuntary_count > 0 {
                    a.timeslice_stats.involuntary_count as f64
                        / (self.get_total_count(&a.timeslice_stats.voluntary)
                            + self.get_total_count(&a.timeslice_stats.involuntary))
                            as f64
                } else {
                    0.0
                };

                let b_rate = if b.timeslice_stats.involuntary_count > 0 {
                    b.timeslice_stats.involuntary_count as f64
                        / (self.get_total_count(&b.timeslice_stats.voluntary)
                            + self.get_total_count(&b.timeslice_stats.involuntary))
                            as f64
                } else {
                    0.0
                };

                b_rate.partial_cmp(&a_rate).unwrap()
            });

            let show_count = sorted_entries.len().min(10);
            let table_entries: Vec<&ProcessEntry> =
                sorted_entries.iter().take(show_count).copied().collect();

            self.print_timeslice_table(&table_entries, collapsed);

            if sorted_entries.len() > show_count {
                println!("  ... and {} more\n", sorted_entries.len() - show_count);
            }
        }

        Ok(())
    }

    fn print_timeslice_table(&self, entries: &[&ProcessEntry], collapsed: bool) {
        // Calculate the maximum command name length
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<12} {:<20} {:<20} {:<12}",
                "COMMAND",
                "PROCS",
                "INVOL_COUNT",
                "VOLUNTARY(p50/p90)",
                "PREEMPTED(p50/p90)",
                "PREEMPT%",
                width = max_comm_len
            );
        } else {
            println!(
                "  {:<8} {:<width$} {:<12} {:<20} {:<20} {:<12}",
                "PID",
                "COMMAND",
                "INVOL_COUNT",
                "VOLUNTARY(p50/p90)",
                "PREEMPTED(p50/p90)",
                "PREEMPT%",
                width = max_comm_len
            );
        }

        for entry in entries {
            let vol_count = self.get_total_count(&entry.timeslice_stats.voluntary);
            let invol_count = self.get_total_count(&entry.timeslice_stats.involuntary);
            let total = vol_count + invol_count;

            let vol_p50 = self.calculate_percentile(&entry.timeslice_stats.voluntary, 50);
            let vol_p90 = self.calculate_percentile(&entry.timeslice_stats.voluntary, 90);
            let invol_p50 = self.calculate_percentile(&entry.timeslice_stats.involuntary, 50);
            let invol_p90 = self.calculate_percentile(&entry.timeslice_stats.involuntary, 90);

            let preempt_pct = if total > 0 {
                (entry.timeslice_stats.involuntary_count as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let vol_str = if vol_count > 0 {
                format!("{}/{}", vol_p50, vol_p90)
            } else {
                "-".to_string()
            };

            let invol_str = if invol_count > 0 {
                format!("{}/{}", invol_p50, invol_p90)
            } else {
                "-".to_string()
            };

            if collapsed {
                println!(
                    "  {:<width$} {:<8} {:<12} {:<20} {:<20} {:<12.1}%",
                    &entry.comm,
                    entry.pids.len(),
                    entry.timeslice_stats.involuntary_count,
                    vol_str,
                    invol_str,
                    preempt_pct,
                    width = max_comm_len
                );
            } else {
                println!(
                    "  {:<8} {:<width$} {:<12} {:<20} {:<20} {:<12.1}%",
                    entry.pids[0],
                    &entry.comm,
                    entry.timeslice_stats.involuntary_count,
                    vol_str,
                    invol_str,
                    preempt_pct,
                    width = max_comm_len
                );
            }
        }
    }

    fn print_process_stats(
        &self,
        entries: &[ProcessEntry],
        detailed: bool,
        collapsed: bool,
    ) -> Result<()> {
        let title = if collapsed {
            "Collapsed Scheduling Delays by Command"
        } else {
            "Per-Process Scheduling Delays"
        };

        println!("=== {} (microseconds) ===\n", title);

        if detailed {
            // Detailed mode: show all entries
            let entry_refs: Vec<&ProcessEntry> = entries.iter().collect();
            self.print_process_table(&entry_refs, collapsed);
        } else {
            // Grouped mode: group by latency ranges
            let mut latency_groups: HashMap<LatencyGroup, Vec<&ProcessEntry>> = HashMap::new();

            for entry in entries {
                let p90 = self.calculate_percentile(&entry.hist, 90);
                let group = LatencyGroup::from_percentile(p90);
                latency_groups
                    .entry(group)
                    .or_insert_with(Vec::new)
                    .push(entry);
            }

            let mut groups: Vec<_> = latency_groups.iter().collect();
            groups.sort_by_key(|(group, _)| *group);

            for (group, group_entries) in groups {
                println!("{} ({} entries):", group.description(), group_entries.len());

                // Sort by p90 descending
                let mut sorted_entries = group_entries.clone();
                sorted_entries.sort_by(|a, b| {
                    let p90_a = self.calculate_percentile(&a.hist, 90);
                    let p90_b = self.calculate_percentile(&b.hist, 90);
                    p90_b.cmp(&p90_a)
                });

                // Show top 10 by p90
                let show_count = sorted_entries.len().min(10);
                let table_entries: Vec<&ProcessEntry> =
                    sorted_entries.iter().take(show_count).copied().collect();

                self.print_process_table(&table_entries, collapsed);

                if sorted_entries.len() > show_count {
                    println!("  ... and {} more\n", sorted_entries.len() - show_count);
                } else {
                    println!();
                }
            }
        }

        Ok(())
    }

    fn print_process_table(&self, entries: &[&ProcessEntry], collapsed: bool) {
        // Calculate the maximum command name length
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        // Use the collapsed parameter to determine format, not the data
        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12} {:<20}",
                "COMMAND",
                "PROCS",
                "p50",
                "p90",
                "p95",
                "COUNT",
                "PIDs",
                width = max_comm_len
            );
        } else {
            println!(
                "  {:<8} {:<width$} {:<10} {:<10} {:<10} {:<12}",
                "PID",
                "COMMAND",
                "p50",
                "p90",
                "p95",
                "COUNT",
                width = max_comm_len
            );
        }

        for entry in entries {
            let total_count = self.get_total_count(&entry.hist);
            let p50 = self.calculate_percentile(&entry.hist, 50);
            let p90 = self.calculate_percentile(&entry.hist, 90);
            let p95 = self.calculate_percentile(&entry.hist, 95);

            if collapsed {
                let pid_str = self.format_pid_list(&entry.pids);
                println!(
                    "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12} {:<20}",
                    &entry.comm,
                    entry.pids.len(),
                    p50,
                    p90,
                    p95,
                    total_count,
                    pid_str,
                    width = max_comm_len
                );
            } else {
                println!(
                    "  {:<8} {:<width$} {:<10} {:<10} {:<10} {:<12}",
                    entry.pids[0],
                    &entry.comm,
                    p50,
                    p90,
                    p95,
                    total_count,
                    width = max_comm_len
                );
            }
        }
    }

    fn print_cpu_stats(&self, filters: &FilterOptions, detailed: bool) -> Result<()> {
        let filtered_cpus: Vec<(u32, &Hist)> = self
            .cpu_stats
            .iter()
            .filter(|(_, hist)| {
                let total_count = self.get_total_count(hist);
                if total_count == 0 {
                    return false;
                }
                // Apply latency filter if specified
                if filters.min_latency_us > 0 {
                    let p50 = self.calculate_percentile(hist, 50);
                    p50 >= filters.min_latency_us
                } else {
                    true
                }
            })
            .map(|(cpu, hist)| (*cpu, hist))
            .collect();

        if filtered_cpus.is_empty() {
            println!("\nNo CPUs match the specified filters.");
            return Ok(());
        }

        println!("\n=== Per-CPU Scheduling Delays (microseconds) ===\n");

        if detailed {
            // Detailed mode: show all CPUs
            println!(
                "{:<8} {:<10} {:<10} {:<10} {:<12}",
                "CPU", "p50", "p90", "p95", "COUNT"
            );

            let mut sorted_cpus = filtered_cpus;
            sorted_cpus.sort_by_key(|(cpu, _)| *cpu);

            for (cpu, hist) in sorted_cpus {
                let total_count = self.get_total_count(hist);
                let p50 = self.calculate_percentile(hist, 50);
                let p90 = self.calculate_percentile(hist, 90);
                let p95 = self.calculate_percentile(hist, 95);

                println!(
                    "{:<8} {:<10} {:<10} {:<10} {:<12}",
                    cpu, p50, p90, p95, total_count
                );
            }
        } else {
            // Grouped mode: group CPUs by latency
            let mut cpu_groups: HashMap<LatencyGroup, Vec<u32>> = HashMap::new();

            for (cpu, hist) in filtered_cpus {
                let p90 = self.calculate_percentile(hist, 90);
                let group = LatencyGroup::from_percentile(p90);
                cpu_groups.entry(group).or_insert_with(Vec::new).push(cpu);
            }

            let mut groups: Vec<_> = cpu_groups.iter().collect();
            groups.sort_by_key(|(group, _)| *group);

            for (group, cpus) in groups {
                let mut sorted_cpus = cpus.clone();
                sorted_cpus.sort();

                println!(
                    "{}: CPUs {}",
                    group.description(),
                    format_cpu_list(&sorted_cpus)
                );

                // Show aggregate stats for this CPU group
                let mut total_hist = Hist::default();
                for cpu in &sorted_cpus {
                    if let Some(hist) = self.cpu_stats.get(cpu) {
                        for i in 0..MAX_SLOTS {
                            total_hist.slots[i] += hist.slots[i];
                        }
                    }
                }

                let total_count = self.get_total_count(&total_hist);
                let p50 = self.calculate_percentile(&total_hist, 50);
                let p90 = self.calculate_percentile(&total_hist, 90);
                let p95 = self.calculate_percentile(&total_hist, 95);

                println!(
                    "  Aggregate: p50={:<6} p90={:<6} p95={:<6} count={}\n",
                    p50, p90, p95, total_count
                );
            }
        }

        Ok(())
    }

    fn should_include_process(&self, pid: &u32, comm: &str, filters: &FilterOptions) -> bool {
        // Check PID filter
        if let Some(filter_pid) = filters.pid_filter {
            if *pid != filter_pid {
                return false;
            }
        }

        // Check comm regex filter
        if let Some(ref regex) = filters.comm_regex {
            if !regex.is_match(comm) {
                return false;
            }
        }

        // Check latency threshold - use p50 as representative
        if filters.min_latency_us > 0 {
            if let Some(stats) = self.pid_stats.get(pid) {
                let p50 = self.calculate_percentile(&stats.hist, 50);
                if p50 < filters.min_latency_us {
                    return false;
                }
            }
        }

        true
    }

    fn format_pid_list(&self, pids: &[u32]) -> String {
        let mut sorted_pids = pids.to_vec();
        sorted_pids.sort();

        if sorted_pids.len() <= 3 {
            sorted_pids
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        } else {
            format!(
                "{},...(+{})",
                sorted_pids
                    .iter()
                    .take(3)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                sorted_pids.len() - 3
            )
        }
    }

    fn get_comm(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_else(|_| "<unknown>".to_string())
            .trim()
            .to_string()
    }

    fn get_total_count(&self, hist: &Hist) -> u64 {
        hist.slots.iter().map(|&count| count as u64).sum()
    }
}

// Helper function to format CPU lists nicely
fn format_cpu_list(cpus: &[u32]) -> String {
    if cpus.is_empty() {
        return String::new();
    }

    let mut ranges = Vec::new();
    let mut start = cpus[0];
    let mut end = cpus[0];

    for &cpu in &cpus[1..] {
        if cpu == end + 1 {
            end = cpu;
        } else {
            if start == end {
                ranges.push(format!("{}", start));
            } else {
                ranges.push(format!("{}-{}", start, end));
            }
            start = cpu;
            end = cpu;
        }
    }

    if start == end {
        ranges.push(format!("{}", start));
    } else {
        ranges.push(format!("{}-{}", start, end));
    }

    ranges.join(",")
}
