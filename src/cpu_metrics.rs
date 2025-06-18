// SPDX-License-Identifier: GPL-2.0
use crate::rsched_collector::{Hist, MAX_SLOTS};
use regex::Regex;
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
    last_update_time: std::time::Instant,
}

struct PidCpuMetrics {
    user_cycles_hist: Hist,
    kernel_cycles_hist: Hist,
    total_user_cycles: u64,
    total_kernel_cycles: u64,
    total_user_instructions: u64,
    total_kernel_instructions: u64,
    sample_count: u64,
    comm: String,
}

// Represents either a single process or a collapsed group of processes
#[derive(Clone)]
struct CpuProcessEntry {
    comm: String,
    user_cycles_hist: Hist,
    kernel_cycles_hist: Hist,
    total_user_cycles: u64,
    total_kernel_cycles: u64,
    total_user_instructions: u64,
    total_kernel_instructions: u64,
    sample_count: u64,
    pids: Vec<u32>,
}

// Performance groups based on cycles per second
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PerfGroup {
    VeryLow,  // < 10M cycles/sec
    Low,      // 10-100M cycles/sec
    Medium,   // 100-1000M cycles/sec
    High,     // 1-10G cycles/sec
    VeryHigh, // > 10G cycles/sec
}

impl PerfGroup {
    fn from_mcycles_per_sec(mcycles: f64) -> Self {
        if mcycles < 10.0 {
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
            PerfGroup::VeryLow => "Very Low (<10M cycles p95)",
            PerfGroup::Low => "Low (10-100M cycles p95)",
            PerfGroup::Medium => "Medium (100M-1G cycles p95)",
            PerfGroup::High => "High (1-10G cycles p95)",
            PerfGroup::VeryHigh => "Very High (>10G cycles p95)",
        }
    }
}

pub struct CpuFilterOptions {
    pub comm_regex: Option<Regex>,
    pub pid_filter: Option<u32>,
    pub detailed: bool,
    pub collapsed: bool,
}

impl CpuMetrics {
    pub fn new() -> Self {
        Self {
            pid_metrics: HashMap::new(),
            last_update_time: std::time::Instant::now(),
        }
    }

    // Calculate percentile from a histogram (reusing logic from rsched_stats)
    fn calculate_percentile(&self, hist: &Hist, percentile: u8) -> u64 {
        let total_count = hist.slots.iter().map(|&count| count as u64).sum::<u64>();
        if total_count == 0 {
            return 0;
        }

        let target_count = (total_count * percentile as u64) / 100;
        let mut cumulative_count = 0u64;

        for (slot, &count) in hist.slots.iter().enumerate() {
            let prev_cumulative = cumulative_count;
            cumulative_count += count as u64;

            if cumulative_count >= target_count {
                // For CPU metrics, we're using pure log2 histograms
                // Each slot represents values from 2^slot to 2^(slot+1)-1
                if slot == 0 {
                    return 1; // Special case for slot 0
                }

                // Calculate position within this bucket for interpolation
                let count_in_bucket = count as u64;
                let position_in_bucket = target_count - prev_cumulative;
                let fraction = if count_in_bucket > 0 {
                    position_in_bucket as f64 / count_in_bucket as f64
                } else {
                    0.5
                };

                let lower_bound = 1u64 << slot;
                let upper_bound = (1u64 << (slot + 1)) - 1;
                let range = upper_bound - lower_bound + 1;
                return lower_bound + (fraction * range as f64) as u64;
            }
        }

        // If we get here, return max value
        1u64 << 63
    }

    pub fn update(&mut self, cpu_data: HashMap<u32, CpuPerfData>) {
        for (pid, data) in cpu_data {
            let comm = Self::get_comm(pid);

            let metrics = self.pid_metrics.entry(pid).or_insert(PidCpuMetrics {
                user_cycles_hist: Hist::default(),
                kernel_cycles_hist: Hist::default(),
                total_user_cycles: 0,
                total_kernel_cycles: 0,
                total_user_instructions: 0,
                total_kernel_instructions: 0,
                sample_count: 0,
                comm,
            });

            // Merge histograms
            for i in 0..MAX_SLOTS {
                metrics.user_cycles_hist.slots[i] += data.user_cycles_hist.slots[i];
                metrics.kernel_cycles_hist.slots[i] += data.kernel_cycles_hist.slots[i];
            }

            metrics.total_user_cycles += data.total_user_cycles;
            metrics.total_kernel_cycles += data.total_kernel_cycles;
            metrics.total_user_instructions += data.total_user_instructions;
            metrics.total_kernel_instructions += data.total_kernel_instructions;
            metrics.sample_count += data.sample_count;
        }
    }

    pub fn print_summary(&mut self, filters: &CpuFilterOptions) {
        let now = std::time::Instant::now();
        let elapsed_secs = now.duration_since(self.last_update_time).as_secs_f64();
        self.last_update_time = now;

        if elapsed_secs == 0.0 {
            return;
        }

        // Build process entries based on collapse mode
        let process_entries = self.build_process_entries(filters, elapsed_secs);

        if process_entries.is_empty() {
            println!("\n=== CPU Performance Metrics ===");
            println!("No processes match the specified filters for CPU metrics.\n");
            return;
        }

        println!("\n=== CPU Performance Metrics ===");

        // Calculate and print global metrics
        self.print_global_metrics(&process_entries, elapsed_secs);

        // Print process-level metrics
        if filters.detailed {
            self.print_detailed_metrics(&process_entries, filters.collapsed, elapsed_secs);
        } else {
            self.print_grouped_metrics(&process_entries, filters.collapsed, elapsed_secs);
        }

        // Clear incremental data for next interval
        self.pid_metrics.clear();
    }

    fn build_process_entries(
        &self,
        filters: &CpuFilterOptions,
        _elapsed_secs: f64,
    ) -> Vec<CpuProcessEntry> {
        if filters.collapsed {
            // Collapse by command name
            let mut comm_map: HashMap<String, CpuProcessEntry> = HashMap::new();

            for (pid, metrics) in &self.pid_metrics {
                if !self.should_include_process(pid, &metrics.comm, filters) {
                    continue;
                }

                if metrics.sample_count == 0 {
                    continue;
                }

                let entry = comm_map
                    .entry(metrics.comm.clone())
                    .or_insert(CpuProcessEntry {
                        comm: metrics.comm.clone(),
                        user_cycles_hist: Hist::default(),
                        kernel_cycles_hist: Hist::default(),
                        total_user_cycles: 0,
                        total_kernel_cycles: 0,
                        total_user_instructions: 0,
                        total_kernel_instructions: 0,
                        sample_count: 0,
                        pids: Vec::new(),
                    });

                // Merge histograms
                for i in 0..MAX_SLOTS {
                    entry.user_cycles_hist.slots[i] += metrics.user_cycles_hist.slots[i];
                    entry.kernel_cycles_hist.slots[i] += metrics.kernel_cycles_hist.slots[i];
                }

                entry.total_user_cycles += metrics.total_user_cycles;
                entry.total_kernel_cycles += metrics.total_kernel_cycles;
                entry.total_user_instructions += metrics.total_user_instructions;
                entry.total_kernel_instructions += metrics.total_kernel_instructions;
                entry.sample_count += metrics.sample_count;
                entry.pids.push(*pid);
            }

            comm_map.into_values().collect()
        } else {
            // Individual processes
            self.pid_metrics
                .iter()
                .filter(|(pid, metrics)| {
                    self.should_include_process(pid, &metrics.comm, filters)
                        && metrics.sample_count > 0
                })
                .map(|(pid, metrics)| CpuProcessEntry {
                    comm: metrics.comm.clone(),
                    user_cycles_hist: metrics.user_cycles_hist.clone(),
                    kernel_cycles_hist: metrics.kernel_cycles_hist.clone(),
                    total_user_cycles: metrics.total_user_cycles,
                    total_kernel_cycles: metrics.total_kernel_cycles,
                    total_user_instructions: metrics.total_user_instructions,
                    total_kernel_instructions: metrics.total_kernel_instructions,
                    sample_count: metrics.sample_count,
                    pids: vec![*pid],
                })
                .collect()
        }
    }

    fn print_global_metrics(&self, entries: &[CpuProcessEntry], elapsed_secs: f64) {
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

        let global_user_mcycles_per_sec = (global_user_cycles as f64 / elapsed_secs) / 1_000_000.0;
        let global_kernel_mcycles_per_sec =
            (global_kernel_cycles as f64 / elapsed_secs) / 1_000_000.0;

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
            "Global: User {:.1}M cycles/sec (IPC: {:.2}), Kernel {:.1}M cycles/sec (IPC: {:.2})",
            global_user_mcycles_per_sec,
            global_user_ipc,
            global_kernel_mcycles_per_sec,
            global_kernel_ipc
        );
    }

    fn print_detailed_metrics(
        &self,
        entries: &[CpuProcessEntry],
        collapsed: bool,
        elapsed_secs: f64,
    ) {
        println!("\nDetailed CPU Performance by Process (cycles are per timeslice):\n");

        // Sort by total cycles
        let mut sorted_entries = entries.to_vec();
        sorted_entries.sort_by(|a, b| {
            let a_total = a.total_user_cycles + a.total_kernel_cycles;
            let b_total = b.total_user_cycles + b.total_kernel_cycles;
            b_total.cmp(&a_total)
        });

        let entry_refs: Vec<&CpuProcessEntry> = sorted_entries.iter().collect();
        self.print_process_table(&entry_refs, collapsed, elapsed_secs);
    }

    fn print_process_table(
        &self,
        entries: &[&CpuProcessEntry],
        collapsed: bool,
        _elapsed_secs: f64,
    ) {
        // Calculate max command length
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<20} {:<20} {:<8} {:<8} {:<15}",
                "COMMAND",
                "PROCS",
                "USER CYC(p50/p95)",
                "KERN CYC(p50/p95)",
                "U-IPC",
                "K-IPC",
                "PIDs",
                width = max_comm_len
            );
        } else {
            println!(
                "  {:<8} {:<width$} {:<20} {:<20} {:<8} {:<8}",
                "PID",
                "COMMAND",
                "USER CYC(p50/p95)",
                "KERN CYC(p50/p95)",
                "U-IPC",
                "K-IPC",
                width = max_comm_len
            );
        }

        for entry in entries {
            // Calculate percentiles for cycles
            let user_p50 = self.calculate_percentile(&entry.user_cycles_hist, 50);
            let user_p95 = self.calculate_percentile(&entry.user_cycles_hist, 95);
            let kernel_p50 = self.calculate_percentile(&entry.kernel_cycles_hist, 50);
            let kernel_p95 = self.calculate_percentile(&entry.kernel_cycles_hist, 95);

            // Format as K/M/G for readability
            let format_cycles = |cycles: u64| -> String {
                if cycles >= 1_000_000_000 {
                    format!("{:.1}G", cycles as f64 / 1_000_000_000.0)
                } else if cycles >= 1_000_000 {
                    format!("{:.1}M", cycles as f64 / 1_000_000.0)
                } else if cycles >= 1_000 {
                    format!("{:.1}K", cycles as f64 / 1_000.0)
                } else {
                    format!("{}", cycles)
                }
            };

            let user_cycles_str =
                format!("{}/{}", format_cycles(user_p50), format_cycles(user_p95));
            let kernel_cycles_str = format!(
                "{}/{}",
                format_cycles(kernel_p50),
                format_cycles(kernel_p95)
            );

            // IPC calculations remain the same (ratio doesn't change with averaging)
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
                let pid_str = self.format_pid_list(&entry.pids);
                println!(
                    "  {:<width$} {:<8} {:<20} {:<20} {:<8.2} {:<8.2} {:<15}",
                    &entry.comm,
                    entry.pids.len(),
                    user_cycles_str,
                    kernel_cycles_str,
                    user_ipc,
                    kernel_ipc,
                    pid_str,
                    width = max_comm_len
                );
            } else {
                println!(
                    "  {:<8} {:<width$} {:<20} {:<20} {:<8.2} {:<8.2}",
                    entry.pids[0],
                    &entry.comm,
                    user_cycles_str,
                    kernel_cycles_str,
                    user_ipc,
                    kernel_ipc,
                    width = max_comm_len
                );
            }
        }
    }

    fn print_grouped_metrics(
        &self,
        entries: &[CpuProcessEntry],
        collapsed: bool,
        elapsed_secs: f64,
    ) {
        println!("\nCPU Performance by Usage Group (cycles are per timeslice):\n");

        let mut perf_groups: HashMap<PerfGroup, Vec<&CpuProcessEntry>> = HashMap::new();

        for entry in entries {
            // Use p95 of total cycles (user + kernel) for grouping
            let user_p95 = self.calculate_percentile(&entry.user_cycles_hist, 95);
            let kernel_p95 = self.calculate_percentile(&entry.kernel_cycles_hist, 95);
            let total_p95_mcycles = (user_p95 + kernel_p95) as f64 / 1_000_000.0;

            let group = PerfGroup::from_mcycles_per_sec(total_p95_mcycles);
            perf_groups
                .entry(group)
                .or_insert_with(Vec::new)
                .push(entry);
        }

        let mut groups: Vec<_> = perf_groups.iter().collect();
        groups.sort_by_key(|(group, _)| *group);

        for (group, group_entries) in groups.iter().rev() {
            println!("{} ({} entries):", group.description(), group_entries.len());

            // Sort within group by p95 total cycles
            let mut sorted_entries: Vec<&CpuProcessEntry> = group_entries.to_vec().clone();
            sorted_entries.sort_by(|a, b| {
                let a_user_p95 = self.calculate_percentile(&a.user_cycles_hist, 95);
                let a_kernel_p95 = self.calculate_percentile(&a.kernel_cycles_hist, 95);
                let b_user_p95 = self.calculate_percentile(&b.user_cycles_hist, 95);
                let b_kernel_p95 = self.calculate_percentile(&b.kernel_cycles_hist, 95);

                let a_total = a_user_p95 + a_kernel_p95;
                let b_total = b_user_p95 + b_kernel_p95;

                b_total.cmp(&a_total)
            });

            // Show top 10
            let show_count = sorted_entries.len().min(10);
            let table_entries: Vec<&CpuProcessEntry> =
                sorted_entries.iter().take(show_count).copied().collect();

            self.print_process_table(&table_entries, collapsed, elapsed_secs);

            if sorted_entries.len() > show_count {
                println!("  ... and {} more\n", sorted_entries.len() - show_count);
            } else {
                println!();
            }
        }
    }

    fn should_include_process(&self, pid: &u32, comm: &str, filters: &CpuFilterOptions) -> bool {
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
}
