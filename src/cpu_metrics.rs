// SPDX-License-Identifier: GPL-2.0
use crate::rsched_collector::Hist;
use crate::rsched_stats::{FilterOptions, OutputMode};
use std::collections::HashMap;

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct CpuPerfData {
    pub user_cycles_hist: Hist,
    pub kernel_cycles_hist: Hist,
    pub total_user_cycles: u64,
    pub total_kernel_cycles: u64,
    pub total_user_instructions: u64,
    pub total_kernel_instructions: u64,
    pub sample_count: u64,
}

unsafe impl plain::Plain for CpuPerfData {}

pub struct CpuMetrics {
    pid_metrics: HashMap<u32, PidCpuMetrics>,
    /// Per-PID log2 histograms of per-second event rates, one Hist per event.
    generic_pid_hists: HashMap<u32, GenericPidHists>,
    /// Previous tick's raw counters for delta computation.
    last_generic_counters: HashMap<u32, Vec<u64>>,
    generic_event_names: Vec<String>,
    last_update_time: std::time::Instant,
}

struct GenericPidHists {
    hists: Vec<Hist>,
    comm: String,
    cgroup_id: u64,
}

#[derive(Clone)]
struct GenericProcessEntry {
    comm: String,
    hists: Vec<Hist>,
    pids: Vec<u32>,
}

struct PidCpuMetrics {
    total_user_cycles: u64,
    total_kernel_cycles: u64,
    total_user_instructions: u64,
    total_kernel_instructions: u64,
    comm: String,
    cgroup_id: u64,
}

// Represents either a single process or a collapsed group of processes
#[derive(Clone)]
struct CpuProcessEntry {
    comm: String,
    total_user_cycles: u64,
    total_kernel_cycles: u64,
    total_user_instructions: u64,
    total_kernel_instructions: u64,
    pids: Vec<u32>,
}

// Performance groups based on cycles per second
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PerfGroup {
    VeryLow,  // < 1M cycles/sec
    Low,      // 1-100M cycles/sec
    Medium,   // 100M-1G cycles/sec
    High,     // 1-10G cycles/sec
    VeryHigh, // > 10G cycles/sec
}

impl PerfGroup {
    fn from_cycles_per_sec(cycles_per_sec: f64) -> Self {
        let mcycles = cycles_per_sec / 1_000_000.0;
        if mcycles < 1.0 {
            PerfGroup::VeryLow
        } else if mcycles < 100.0 {
            PerfGroup::Low
        } else if mcycles < 1000.0 {
            PerfGroup::Medium
        } else if mcycles < 10000.0 {
            PerfGroup::High
        } else {
            PerfGroup::VeryHigh
        }
    }

    fn description(&self) -> &'static str {
        match self {
            PerfGroup::VeryLow => "Very Low (<1M cycles/sec)",
            PerfGroup::Low => "Low (1-100M cycles/sec)",
            PerfGroup::Medium => "Medium (100M-1G cycles/sec)",
            PerfGroup::High => "High (1-10G cycles/sec)",
            PerfGroup::VeryHigh => "Very High (>10G cycles/sec)",
        }
    }
}

impl CpuMetrics {
    pub fn new(generic_event_names: Vec<String>) -> Self {
        Self {
            pid_metrics: HashMap::new(),
            generic_pid_hists: HashMap::new(),
            last_generic_counters: HashMap::new(),
            generic_event_names,
            last_update_time: std::time::Instant::now(),
        }
    }

    pub fn update(&mut self, cpu_data: HashMap<u32, (CpuPerfData, String, u64)>) {
        for (pid, (data, comm, cgroup_id)) in cpu_data {
            let metrics = self.pid_metrics.entry(pid).or_insert(PidCpuMetrics {
                total_user_cycles: 0,
                total_kernel_cycles: 0,
                total_user_instructions: 0,
                total_kernel_instructions: 0,
                comm: comm.clone(),
                cgroup_id,
            });

            if metrics.comm != comm {
                metrics.comm = comm;
            }
            metrics.cgroup_id = cgroup_id;

            metrics.total_user_cycles += data.total_user_cycles;
            metrics.total_kernel_cycles += data.total_kernel_cycles;
            metrics.total_user_instructions += data.total_user_instructions;
            metrics.total_kernel_instructions += data.total_kernel_instructions;
        }
    }

    /// Called every 1-second tick. Computes per-PID deltas from the previous
    /// tick's counters and records each delta as a sample in a log2 histogram.
    pub fn record_generic_tick(
        &mut self,
        data: HashMap<
            u32,
            (
                [u64; crate::rsched_collector::MAX_GENERIC_EVENTS],
                String,
                u64,
            ),
        >,
    ) {
        let num_events = self.generic_event_names.len();

        for (pid, (counters, comm, cgroup_id)) in data {
            // Look up or create histogram entry
            let hists = self
                .generic_pid_hists
                .entry(pid)
                .or_insert_with(|| GenericPidHists {
                    hists: vec![Hist::default(); num_events],
                    comm: comm.clone(),
                    cgroup_id,
                });
            hists.comm.clone_from(&comm);
            hists.cgroup_id = cgroup_id;

            // Compute deltas from previous tick
            if let Some(prev) = self.last_generic_counters.get(&pid) {
                for i in 0..num_events {
                    let delta = counters[i].saturating_sub(prev[i]);
                    if delta > 0 {
                        let slot = log2_slot(delta);
                        if slot < crate::rsched_collector::MAX_SLOTS {
                            hists.hists[i].slots[slot] += 1;
                        }
                    }
                }
            }

            // Store current counters for next tick
            self.last_generic_counters
                .insert(pid, counters[..num_events].to_vec());
        }
    }

    pub fn print_summary(&mut self, output_mode: OutputMode, filters: &FilterOptions) {
        let now = std::time::Instant::now();
        let elapsed_secs = now.duration_since(self.last_update_time).as_secs_f64();
        self.last_update_time = now;

        if elapsed_secs == 0.0 {
            return;
        }

        let collapsed = matches!(output_mode, OutputMode::Collapsed);
        let detailed = matches!(output_mode, OutputMode::Detailed);

        // IPC section (only when pid_metrics has data)
        if !self.pid_metrics.is_empty() {
            let process_entries = self.build_process_entries(filters, collapsed, detailed);

            println!("\n=== CPU Performance Metrics ===");

            if process_entries.is_empty() {
                println!("No processes match the specified filters for CPU metrics.\n");
            } else {
                Self::print_global_metrics(&process_entries, elapsed_secs);

                if detailed {
                    Self::print_detailed_metrics(&process_entries, collapsed, elapsed_secs);
                } else {
                    Self::print_grouped_metrics(&process_entries, collapsed, elapsed_secs);
                }
            }
        }

        // Generic event sections (independent of IPC)
        if !self.generic_event_names.is_empty() {
            self.print_generic_event_metrics(output_mode, filters, elapsed_secs);
        }

        // Clear incremental data for next interval
        self.pid_metrics.clear();
        self.generic_pid_hists.clear();
        self.last_generic_counters.clear();
    }

    fn build_process_entries(
        &self,
        filters: &FilterOptions,
        collapsed: bool,
        detailed: bool,
    ) -> Vec<CpuProcessEntry> {
        // In detailed mode, always show individual processes (implies -C/no-collapse)
        if collapsed && !detailed {
            // Collapse by command name
            let mut comm_map: HashMap<String, CpuProcessEntry> = HashMap::new();

            for (pid, metrics) in &self.pid_metrics {
                if !Self::should_include_process(pid, &metrics.comm, metrics.cgroup_id, filters) {
                    continue;
                }

                let entry = comm_map
                    .entry(metrics.comm.clone())
                    .or_insert(CpuProcessEntry {
                        comm: metrics.comm.clone(),
                        total_user_cycles: 0,
                        total_kernel_cycles: 0,
                        total_user_instructions: 0,
                        total_kernel_instructions: 0,
                        pids: Vec::new(),
                    });

                entry.total_user_cycles += metrics.total_user_cycles;
                entry.total_kernel_cycles += metrics.total_kernel_cycles;
                entry.total_user_instructions += metrics.total_user_instructions;
                entry.total_kernel_instructions += metrics.total_kernel_instructions;
                entry.pids.push(*pid);
            }

            comm_map.into_values().collect()
        } else {
            // Individual processes
            self.pid_metrics
                .iter()
                .filter(|(pid, metrics)| {
                    Self::should_include_process(pid, &metrics.comm, metrics.cgroup_id, filters)
                })
                .filter(|(_, metrics)| {
                    metrics.total_user_cycles > 0 || metrics.total_kernel_cycles > 0
                })
                .map(|(pid, metrics)| CpuProcessEntry {
                    comm: metrics.comm.clone(),
                    total_user_cycles: metrics.total_user_cycles,
                    total_kernel_cycles: metrics.total_kernel_cycles,
                    total_user_instructions: metrics.total_user_instructions,
                    total_kernel_instructions: metrics.total_kernel_instructions,
                    pids: vec![*pid],
                })
                .collect()
        }
    }

    fn print_global_metrics(entries: &[CpuProcessEntry], elapsed_secs: f64) {
        let mut global_user_cycles = 0u64;
        let mut global_kernel_cycles = 0u64;
        let mut global_user_instructions = 0u64;
        let mut global_kernel_instructions = 0u64;

        for entry in entries {
            global_user_cycles += entry.total_user_cycles;
            global_kernel_cycles += entry.total_kernel_cycles;
            global_user_instructions += entry.total_user_instructions;
            global_kernel_instructions += entry.total_kernel_instructions;
        }

        let global_user_ipc = if global_user_cycles > 0 {
            global_user_instructions as f64 / global_user_cycles as f64
        } else {
            0.0
        };

        let global_kernel_ipc = if global_kernel_cycles > 0 {
            global_kernel_instructions as f64 / global_kernel_cycles as f64
        } else {
            0.0
        };

        println!(
            "Global: User {} cycles/sec (IPC: {:.2}), Kernel {} cycles/sec (IPC: {:.2})",
            format_rate(global_user_cycles as f64 / elapsed_secs),
            global_user_ipc,
            format_rate(global_kernel_cycles as f64 / elapsed_secs),
            global_kernel_ipc
        );
    }

    fn print_detailed_metrics(entries: &[CpuProcessEntry], collapsed: bool, elapsed_secs: f64) {
        println!(
            "\nDetailed CPU Performance by Process ({} processes):\n",
            entries.len()
        );

        // Sort by total cycles/sec
        let mut sorted_entries = entries.to_vec();
        sorted_entries.sort_by(|a, b| {
            let a_total = a.total_user_cycles + a.total_kernel_cycles;
            let b_total = b.total_user_cycles + b.total_kernel_cycles;
            b_total.cmp(&a_total)
        });

        let entry_refs: Vec<&CpuProcessEntry> = sorted_entries.iter().collect();
        Self::print_process_table(&entry_refs, collapsed, elapsed_secs);
    }

    fn print_process_table(entries: &[&CpuProcessEntry], collapsed: bool, elapsed_secs: f64) {
        // Calculate max command length
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<14} {:<14} {:<8} {:<8} {:<15}",
                "COMMAND",
                "PROCS",
                "USER CYC/s",
                "KERN CYC/s",
                "U-IPC",
                "K-IPC",
                "PIDs",
                width = max_comm_len
            );
        } else {
            println!(
                "  {:<8} {:<width$} {:<14} {:<14} {:<8} {:<8}",
                "PID",
                "COMMAND",
                "USER CYC/s",
                "KERN CYC/s",
                "U-IPC",
                "K-IPC",
                width = max_comm_len
            );
        }

        for entry in entries {
            let user_cycles_per_sec = entry.total_user_cycles as f64 / elapsed_secs;
            let kernel_cycles_per_sec = entry.total_kernel_cycles as f64 / elapsed_secs;

            let user_ipc = if entry.total_user_cycles > 0 {
                entry.total_user_instructions as f64 / entry.total_user_cycles as f64
            } else {
                0.0
            };

            let kernel_ipc = if entry.total_kernel_cycles > 0 {
                entry.total_kernel_instructions as f64 / entry.total_kernel_cycles as f64
            } else {
                0.0
            };

            if collapsed {
                let pid_str = Self::format_pid_list(&entry.pids);
                println!(
                    "  {:<width$} {:<8} {:<14} {:<14} {:<8.2} {:<8.2} {:<15}",
                    &entry.comm,
                    entry.pids.len(),
                    format_rate(user_cycles_per_sec),
                    format_rate(kernel_cycles_per_sec),
                    user_ipc,
                    kernel_ipc,
                    pid_str,
                    width = max_comm_len
                );
            } else {
                println!(
                    "  {:<8} {:<width$} {:<14} {:<14} {:<8.2} {:<8.2}",
                    entry.pids[0],
                    &entry.comm,
                    format_rate(user_cycles_per_sec),
                    format_rate(kernel_cycles_per_sec),
                    user_ipc,
                    kernel_ipc,
                    width = max_comm_len
                );
            }
        }
    }

    fn print_grouped_metrics(entries: &[CpuProcessEntry], collapsed: bool, elapsed_secs: f64) {
        println!("\nCPU Performance by Usage Group:\n");

        let mut perf_groups: HashMap<PerfGroup, Vec<&CpuProcessEntry>> = HashMap::new();

        for entry in entries {
            let total_cycles_per_sec =
                (entry.total_user_cycles + entry.total_kernel_cycles) as f64 / elapsed_secs;
            let group = PerfGroup::from_cycles_per_sec(total_cycles_per_sec);
            perf_groups.entry(group).or_default().push(entry);
        }

        let mut groups: Vec<_> = perf_groups.iter().collect();
        groups.sort_by_key(|(group, _)| *group);

        for (group, group_entries) in groups.iter().rev() {
            println!("{} ({} entries):", group.description(), group_entries.len());

            // Sort within group by total cycles/sec
            let mut sorted_entries: Vec<&CpuProcessEntry> = group_entries.to_vec();
            sorted_entries.sort_by(|a, b| {
                let a_total = a.total_user_cycles + a.total_kernel_cycles;
                let b_total = b.total_user_cycles + b.total_kernel_cycles;
                b_total.cmp(&a_total)
            });

            // Show top 10
            let show_count = sorted_entries.len().min(10);
            let table_entries: Vec<&CpuProcessEntry> =
                sorted_entries.iter().take(show_count).copied().collect();

            Self::print_process_table(&table_entries, collapsed, elapsed_secs);

            if sorted_entries.len() > show_count {
                println!("  ... and {} more\n", sorted_entries.len() - show_count);
            } else {
                println!();
            }
        }
    }

    fn print_generic_event_metrics(
        &self,
        output_mode: OutputMode,
        filters: &FilterOptions,
        _elapsed_secs: f64,
    ) {
        let collapsed = matches!(output_mode, OutputMode::Collapsed);
        let detailed = matches!(output_mode, OutputMode::Detailed);
        let num_events = self.generic_event_names.len();

        for event_idx in 0..num_events {
            let event_name = &self.generic_event_names[event_idx];
            println!("\n=== {} (per second) ===", event_name);

            let entries = self.build_generic_entries(filters, collapsed, event_idx);

            let entries_with_data: Vec<&GenericProcessEntry> = entries
                .iter()
                .filter(|e| e.hists[0].total_count() > 0)
                .collect();

            if entries_with_data.is_empty() {
                println!("No data.\n");
                continue;
            }

            if detailed {
                let mut sorted = entries_with_data;
                sorted.sort_by(|a, b| {
                    let a_p90 = log2_percentile(&a.hists[0], 90);
                    let b_p90 = log2_percentile(&b.hists[0], 90);
                    b_p90.cmp(&a_p90)
                });

                Self::print_generic_table(&sorted, collapsed);
            } else {
                let mut sorted = entries_with_data;
                sorted.sort_by(|a, b| {
                    let a_p90 = log2_percentile(&a.hists[0], 90);
                    let b_p90 = log2_percentile(&b.hists[0], 90);
                    b_p90.cmp(&a_p90)
                });

                let show_count = sorted.len().min(20);
                let table_entries: Vec<&GenericProcessEntry> =
                    sorted.iter().take(show_count).copied().collect();

                Self::print_generic_table(&table_entries, collapsed);

                if sorted.len() > show_count {
                    println!("  ... and {} more\n", sorted.len() - show_count);
                }
            }
        }
    }

    fn print_generic_table(entries: &[&GenericProcessEntry], collapsed: bool) {
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<12} {:<12} {:<12} {:<10}",
                "COMMAND",
                "PROCS",
                "p50/s",
                "p90/s",
                "p99/s",
                "SAMPLES",
                width = max_comm_len
            );
        } else {
            println!(
                "  {:<8} {:<width$} {:<12} {:<12} {:<12} {:<10}",
                "PID",
                "COMMAND",
                "p50/s",
                "p90/s",
                "p99/s",
                "SAMPLES",
                width = max_comm_len
            );
        }

        for entry in entries {
            let hist = &entry.hists[0];
            let total = hist.total_count();
            if total == 0 {
                continue;
            }

            let p50 = log2_percentile(hist, 50);
            let p90 = log2_percentile(hist, 90);
            let p99 = log2_percentile(hist, 99);

            if collapsed {
                println!(
                    "  {:<width$} {:<8} {:<12} {:<12} {:<12} {:<10}",
                    &entry.comm,
                    entry.pids.len(),
                    format_rate(p50 as f64),
                    format_rate(p90 as f64),
                    format_rate(p99 as f64),
                    total,
                    width = max_comm_len
                );
            } else {
                println!(
                    "  {:<8} {:<width$} {:<12} {:<12} {:<12} {:<10}",
                    entry.pids[0],
                    &entry.comm,
                    format_rate(p50 as f64),
                    format_rate(p90 as f64),
                    format_rate(p99 as f64),
                    total,
                    width = max_comm_len
                );
            }
        }
        println!();
    }

    fn build_generic_entries(
        &self,
        filters: &FilterOptions,
        collapsed: bool,
        event_idx: usize,
    ) -> Vec<GenericProcessEntry> {
        if collapsed {
            let mut comm_map: HashMap<String, GenericProcessEntry> = HashMap::new();

            for (pid, ph) in &self.generic_pid_hists {
                if !Self::should_include_process(pid, &ph.comm, ph.cgroup_id, filters) {
                    continue;
                }
                if event_idx >= ph.hists.len() {
                    continue;
                }

                let entry = comm_map
                    .entry(ph.comm.clone())
                    .or_insert(GenericProcessEntry {
                        comm: ph.comm.clone(),
                        hists: vec![Hist::default()],
                        pids: Vec::new(),
                    });

                entry.hists[0].merge_from(&ph.hists[event_idx]);
                entry.pids.push(*pid);
            }

            comm_map.into_values().collect()
        } else {
            self.generic_pid_hists
                .iter()
                .filter(|(pid, ph)| {
                    Self::should_include_process(pid, &ph.comm, ph.cgroup_id, filters)
                })
                .filter(|(_, ph)| {
                    event_idx < ph.hists.len() && ph.hists[event_idx].total_count() > 0
                })
                .map(|(pid, ph)| GenericProcessEntry {
                    comm: ph.comm.clone(),
                    hists: vec![ph.hists[event_idx]],
                    pids: vec![*pid],
                })
                .collect()
        }
    }

    fn should_include_process(
        pid: &u32,
        comm: &str,
        cgroup_id: u64,
        filters: &FilterOptions,
    ) -> bool {
        if let Some(filter_pid) = filters.pid_filter {
            if *pid != filter_pid {
                return false;
            }
        }

        // Check if this process matches a global comm pattern (bypasses cgroup filter)
        let global_comm_match = if let Some(ref regexes) = filters.global_comm_regexes {
            regexes.iter().any(|regex| regex.is_match(comm))
        } else {
            false
        };

        if !global_comm_match {
            // Normal filtering: comm AND cgroup
            if let Some(ref regexes) = filters.comm_regexes {
                if !regexes.iter().any(|regex| regex.is_match(comm)) {
                    return false;
                }
            }

            if let Some(ref cgroup_set) = filters.cgroup_filter {
                if !cgroup_set.contains(&cgroup_id) {
                    return false;
                }
            }
        }

        true
    }

    fn format_pid_list(pids: &[u32]) -> String {
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
}

/// Compute log2 slot index for a value (mirrors BPF log2_slot).
fn log2_slot(v: u64) -> usize {
    if v == 0 {
        return 0;
    }
    let slot = 63 - v.leading_zeros() as usize;
    if slot < crate::rsched_collector::MAX_SLOTS {
        slot
    } else {
        crate::rsched_collector::MAX_SLOTS - 1
    }
}

/// Compute a percentile from a log2-indexed histogram.
/// Returns the value at the bucket boundary (2^slot).
fn log2_percentile(hist: &Hist, percentile: u8) -> u64 {
    let total = hist.total_count();
    if total == 0 {
        return 0;
    }

    let target = (total * percentile as u64) / 100;
    let mut cumulative = 0u64;

    for (slot, &count) in hist.slots.iter().enumerate() {
        cumulative += count as u64;
        if cumulative >= target {
            return 1u64 << slot;
        }
    }

    0
}

fn format_rate(value: f64) -> String {
    if value >= 1_000_000_000_000.0 {
        format!("{:.1}T", value / 1_000_000_000_000.0)
    } else if value >= 1_000_000_000.0 {
        format!("{:.1}G", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.1}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}K", value / 1_000.0)
    } else {
        format!("{:.0}", value)
    }
}
