// src/rsched_stats.rs
// SPDX-License-Identifier: GPL-2.0
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

#[derive(Clone, Debug, Default)]
pub struct MetricGroups {
    pub latency: bool,
    pub cpu_latency: bool,
    pub slice: bool,
    pub sleep: bool,
    pub cpu_idle: bool,
    pub perf: bool,
    pub schedstat: bool,
    pub waking: bool,
}

pub struct FilterOptions {
    pub comm_regex: Option<Regex>,
    pub pid_filter: Option<u32>,
    pub min_latency_us: u64,
    pub metric_groups: MetricGroups,
}

// Generic stats data structure to replace all the specific ones
#[derive(Clone)]
struct StatsData<T: Clone + Default> {
    data: T,
    comm: String,
}

impl<T: Clone + Default> Default for StatsData<T> {
    fn default() -> Self {
        Self {
            data: T::default(),
            comm: String::new(),
        }
    }
}

// Type aliases for clarity
type HistogramStats = StatsData<Hist>;
type TimesliceStatsData = StatsData<TimesliceStats>;

pub struct RschedStats {
    // Use generic StatsData for all histogram-based stats
    pid_stats: HashMap<u32, HistogramStats>,
    cpu_stats: HashMap<u32, Hist>,
    cpu_idle_stats: HashMap<u32, Hist>,
    timeslice_stats: HashMap<u32, TimesliceStatsData>,
    nr_running_stats: HashMap<u32, HistogramStats>,
    waking_delay_stats: HashMap<u32, HistogramStats>,
    sleep_duration_stats: HashMap<u32, HistogramStats>,
    schedstat_data: Option<SchedstatData>,
}

// Represents either a single process or a collapsed group of processes
struct ProcessEntry {
    comm: String,
    hist: Hist,
    timeslice_stats: TimesliceStats,
    nr_running_hist: Hist,
    waking_delay_hist: Hist,
    sleep_duration_hist: Hist,
    pids: Vec<u32>,
}

// Trait for grouping by percentile
trait PercentileGroup: Sized + Ord + Copy {
    fn from_percentile(p90: u64) -> Self;
    fn description(&self) -> &'static str;
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

impl PercentileGroup for LatencyGroup {
    fn from_percentile(p90: u64) -> Self {
        match p90 {
            0..=9 => LatencyGroup::VeryLow,
            10..=99 => LatencyGroup::Low,
            100..=999 => LatencyGroup::Medium,
            1000..=9999 => LatencyGroup::High,
            _ => LatencyGroup::VeryHigh,
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

// Idle duration groups for CPU idle stats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum IdleDurationGroup {
    VeryShort, // < 100 us
    Short,     // 100us-1ms
    Medium,    // 1-10ms
    Long,      // 10-100ms
    VeryLong,  // > 100ms
}

impl PercentileGroup for IdleDurationGroup {
    fn from_percentile(p90: u64) -> Self {
        match p90 {
            0..=99 => IdleDurationGroup::VeryShort,
            100..=999 => IdleDurationGroup::Short,
            1000..=9999 => IdleDurationGroup::Medium,
            10000..=99999 => IdleDurationGroup::Long,
            _ => IdleDurationGroup::VeryLong,
        }
    }

    fn description(&self) -> &'static str {
        match self {
            IdleDurationGroup::VeryShort => "Very Short (<100μs)",
            IdleDurationGroup::Short => "Short (100μs-1ms)",
            IdleDurationGroup::Medium => "Medium (1-10ms)",
            IdleDurationGroup::Long => "Long (10-100ms)",
            IdleDurationGroup::VeryLong => "Very Long (>100ms)",
        }
    }
}

// Generic table column definition
struct TableColumn {
    header: &'static str,
    width: usize,
}

impl TableColumn {
    fn new(header: &'static str, width: usize) -> Self {
        Self { header, width }
    }
}

// Histogram operations trait
trait HistogramOps {
    fn merge_into(&mut self, other: &Self);
    fn total_count(&self) -> u64;
}

impl HistogramOps for Hist {
    fn merge_into(&mut self, other: &Self) {
        for i in 0..MAX_SLOTS {
            self.slots[i] += other.slots[i];
        }
    }

    fn total_count(&self) -> u64 {
        self.slots.iter().map(|&count| count as u64).sum()
    }
}

impl HistogramOps for TimesliceStats {
    fn merge_into(&mut self, other: &Self) {
        self.voluntary.merge_into(&other.voluntary);
        self.involuntary.merge_into(&other.involuntary);
        self.involuntary_count += other.involuntary_count;
    }

    fn total_count(&self) -> u64 {
        self.voluntary.total_count() + self.involuntary.total_count()
    }
}

impl RschedStats {
    pub fn new() -> Self {
        Self {
            pid_stats: HashMap::new(),
            cpu_stats: HashMap::new(),
            cpu_idle_stats: HashMap::new(),
            timeslice_stats: HashMap::new(),
            nr_running_stats: HashMap::new(),
            waking_delay_stats: HashMap::new(),
            sleep_duration_stats: HashMap::new(),
            schedstat_data: None,
        }
    }

    // Generic update function for histogram-based stats
    fn update_histogram_stats<T: HistogramOps + Clone + Default>(
        stats_map: &mut HashMap<u32, StatsData<T>>,
        updates: HashMap<u32, (T, String)>,
    ) {
        for (key, (data, comm)) in updates {
            let stats = stats_map.entry(key).or_default();

            if stats.comm != comm {
                stats.comm = comm;
            }

            stats.data.merge_into(&data);
        }
    }

    pub fn update(&mut self, histograms: HashMap<u32, (Hist, String)>) {
        Self::update_histogram_stats(&mut self.pid_stats, histograms);
    }

    pub fn update_cpu(&mut self, cpu_histograms: HashMap<u32, Hist>) {
        for (cpu, hist) in cpu_histograms {
            self.cpu_stats.entry(cpu).or_default().merge_into(&hist);
        }
    }

    pub fn update_cpu_idle(&mut self, cpu_idle_histograms: HashMap<u32, Hist>) {
        for (cpu, hist) in cpu_idle_histograms {
            self.cpu_idle_stats
                .entry(cpu)
                .or_default()
                .merge_into(&hist);
        }
    }

    pub fn update_schedstat(&mut self, schedstat_data: SchedstatData) {
        self.schedstat_data = Some(schedstat_data);
    }

    pub fn update_timeslices(&mut self, timeslice_data: HashMap<u32, (TimesliceStats, String)>) {
        Self::update_histogram_stats(&mut self.timeslice_stats, timeslice_data);
    }

    pub fn update_nr_running(&mut self, nr_running_data: HashMap<u32, (Hist, String)>) {
        Self::update_histogram_stats(&mut self.nr_running_stats, nr_running_data);
    }

    pub fn update_waking_delays(&mut self, waking_delays: HashMap<u32, (Hist, String)>) {
        Self::update_histogram_stats(&mut self.waking_delay_stats, waking_delays);
    }

    pub fn update_sleep_durations(&mut self, sleep_durations: HashMap<u32, (Hist, String)>) {
        Self::update_histogram_stats(&mut self.sleep_duration_stats, sleep_durations);
    }

    pub fn print_summary(&self, mode: OutputMode, filters: &FilterOptions) -> Result<()> {
        // Clear screen for better readability only if stdout is a TTY
        if atty::is(atty::Stream::Stdout) {
            print!("\x1B[2J\x1B[1;1H");
        }

        let detailed = matches!(mode, OutputMode::Detailed);
        let collapsed = matches!(mode, OutputMode::Collapsed);

        // Build process entries based on collapse mode
        let process_entries = self.build_process_entries(filters, collapsed);

        if process_entries.is_empty()
            && (filters.metric_groups.latency
                || filters.metric_groups.slice
                || filters.metric_groups.sleep
                || filters.metric_groups.waking)
        {
            println!("No processes match the specified filters.\n");
        }

        // Print each metric type based on selected groups
        if filters.metric_groups.latency {
            self.print_metric_section(
                &process_entries,
                "Scheduling Delays",
                "(microseconds)",
                |e| &e.hist,
                |s, h| s.calculate_percentile(h, 90),
                detailed,
                collapsed,
            )?;
        }

        if filters.metric_groups.waking {
            self.print_metric_section(
                &process_entries,
                "Waking Delay Statistics",
                "(Time from sched_waking to sched_switch)",
                |e| &e.waking_delay_hist,
                |s, h| s.calculate_percentile(h, 90),
                detailed,
                collapsed,
            )?;
        }

        if filters.metric_groups.slice {
            self.print_timeslice_stats(&process_entries, detailed, collapsed)?;
            println!();
        }

        if filters.metric_groups.sleep {
            self.print_metric_section(
                &process_entries,
                "Sleep Duration Statistics",
                "(Time spent sleeping between sched_switch and sched_wakeup)",
                |e| &e.sleep_duration_hist,
                |s, h| s.calculate_percentile(h, 90),
                detailed,
                collapsed,
            )?;
        }

        if filters.metric_groups.latency {
            self.print_nr_running_stats(&process_entries, detailed, collapsed)?;
        }

        if filters.metric_groups.schedstat {
            if let Some(data) = &self.schedstat_data {
                self.print_schedstat(data);
            }
        }

        // Print CPU stats based on selected groups
        if filters.metric_groups.cpu_latency {
            self.print_cpu_stats(filters, detailed)?;
        }

        if filters.metric_groups.cpu_idle {
            self.print_cpu_idle_stats(filters, detailed)?;
        }

        Ok(())
    }

    // Generic function to print histogram-based metrics
    fn print_metric_section<F, S>(
        &self,
        entries: &[ProcessEntry],
        title: &str,
        subtitle: &str,
        hist_getter: F,
        sort_key: S,
        detailed: bool,
        collapsed: bool,
    ) -> Result<()>
    where
        F: Fn(&ProcessEntry) -> &Hist + Copy,
        S: Fn(&Self, &Hist) -> u64 + Copy,
    {
        let title_prefix = if collapsed {
            "Collapsed"
        } else {
            "Per-Process"
        };
        println!("=== {} {} {} ===", title_prefix, title, subtitle);
        if !subtitle.is_empty() {
            println!();
        }

        // Filter entries with data
        let entries_with_data: Vec<&ProcessEntry> = entries
            .iter()
            .filter(|e| hist_getter(e).total_count() > 0)
            .collect();

        if entries_with_data.is_empty() {
            println!("No {} data collected yet.\n", title.to_lowercase());
            return Ok(());
        }

        if detailed {
            self.print_histogram_table(&entries_with_data, hist_getter, collapsed);
        } else {
            // Group by latency
            let mut groups: HashMap<LatencyGroup, Vec<&ProcessEntry>> = HashMap::new();

            for entry in &entries_with_data {
                let p90 = self.calculate_percentile(hist_getter(entry), 90);
                let group = LatencyGroup::from_percentile(p90);
                groups.entry(group).or_default().push(entry);
            }

            let mut sorted_groups: Vec<_> = groups.into_iter().collect();
            sorted_groups.sort_by_key(|(group, _)| *group);

            for (group, mut group_entries) in sorted_groups {
                println!("{} ({} entries):", group.description(), group_entries.len());

                // Sort by sort_key descending
                group_entries.sort_by(|a, b| {
                    let val_a = sort_key(self, hist_getter(a));
                    let val_b = sort_key(self, hist_getter(b));
                    val_b.cmp(&val_a)
                });

                let show_count = group_entries.len().min(10);
                let table_entries: Vec<&ProcessEntry> =
                    group_entries.iter().take(show_count).copied().collect();

                self.print_histogram_table(&table_entries, hist_getter, collapsed);

                if group_entries.len() > show_count {
                    println!("  ... and {} more\n", group_entries.len() - show_count);
                } else {
                    println!();
                }
            }
        }

        Ok(())
    }

    // Generic histogram table printer
    fn print_histogram_table<F>(&self, entries: &[&ProcessEntry], hist_getter: F, collapsed: bool)
    where
        F: Fn(&ProcessEntry) -> &Hist,
    {
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        // Define columns
        let columns = if collapsed {
            vec![
                TableColumn::new("COMMAND", max_comm_len),
                TableColumn::new("PROCS", 8),
                TableColumn::new("p50", 10),
                TableColumn::new("p90", 10),
                TableColumn::new("p99", 10),
                TableColumn::new("COUNT", 12),
                TableColumn::new("PIDs", 20),
            ]
        } else {
            vec![
                TableColumn::new("PID", 8),
                TableColumn::new("COMMAND", max_comm_len),
                TableColumn::new("p50", 10),
                TableColumn::new("p90", 10),
                TableColumn::new("p99", 10),
                TableColumn::new("COUNT", 12),
            ]
        };

        // Print header
        print!("  ");
        for col in &columns {
            print!("{:<width$} ", col.header, width = col.width);
        }
        println!();

        // Print rows
        for entry in entries {
            let hist = hist_getter(entry);
            let total_count = hist.total_count();

            if total_count == 0 {
                continue;
            }

            let p50 = self.calculate_percentile(hist, 50);
            let p90 = self.calculate_percentile(hist, 90);
            let p99 = self.calculate_percentile(hist, 99);

            print!("  ");
            if collapsed {
                print!("{:<width$} ", &entry.comm, width = columns[0].width);
                print!("{:<width$} ", entry.pids.len(), width = columns[1].width);
                print!("{:<width$} ", p50, width = columns[2].width);
                print!("{:<width$} ", p90, width = columns[3].width);
                print!("{:<width$} ", p99, width = columns[4].width);
                print!("{:<width$} ", total_count, width = columns[5].width);
                println!(
                    "{:<width$}",
                    self.format_pid_list(&entry.pids),
                    width = columns[6].width
                );
            } else {
                print!("{:<width$} ", entry.pids[0], width = columns[0].width);
                print!("{:<width$} ", &entry.comm, width = columns[1].width);
                print!("{:<width$} ", p50, width = columns[2].width);
                print!("{:<width$} ", p90, width = columns[3].width);
                print!("{:<width$} ", p99, width = columns[4].width);
                println!("{:<width$}", total_count, width = columns[5].width);
            }
        }
    }

    // Keep specialized functions only where the generic approach doesn't work well
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
            let entry_refs: Vec<&ProcessEntry> = entries.iter().collect();
            self.print_timeslice_table(&entry_refs, collapsed);
        } else {
            println!("Time slice statistics grouped by preemption rate:\n");

            let mut sorted_entries: Vec<&ProcessEntry> = entries.iter().collect();
            sorted_entries.sort_by(|a, b| {
                let a_rate = self.calculate_preemption_rate(&a.timeslice_stats);
                let b_rate = self.calculate_preemption_rate(&b.timeslice_stats);
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

    fn calculate_preemption_rate(&self, stats: &TimesliceStats) -> f64 {
        let total = stats.total_count();
        if total > 0 && stats.involuntary_count > 0 {
            stats.involuntary_count as f64 / total as f64
        } else {
            0.0
        }
    }

    fn print_timeslice_table(&self, entries: &[&ProcessEntry], collapsed: bool) {
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
            let vol_count = entry.timeslice_stats.voluntary.total_count();
            let invol_count = entry.timeslice_stats.involuntary.total_count();
            let total = vol_count + invol_count;

            let vol_str = if vol_count > 0 {
                let p50 = self.calculate_percentile(&entry.timeslice_stats.voluntary, 50);
                let p90 = self.calculate_percentile(&entry.timeslice_stats.voluntary, 90);
                format!("{}/{}", p50, p90)
            } else {
                "-".to_string()
            };

            let invol_str = if invol_count > 0 {
                let p50 = self.calculate_percentile(&entry.timeslice_stats.involuntary, 50);
                let p90 = self.calculate_percentile(&entry.timeslice_stats.involuntary, 90);
                format!("{}/{}", p50, p90)
            } else {
                "-".to_string()
            };

            let preempt_pct = if total > 0 {
                (entry.timeslice_stats.involuntary_count as f64 / total as f64) * 100.0
            } else {
                0.0
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

        let entries_with_data: Vec<&ProcessEntry> = entries
            .iter()
            .filter(|e| e.nr_running_hist.total_count() > 0)
            .collect();

        if entries_with_data.is_empty() {
            println!("No runqueue depth data collected yet.\n");
            return Ok(());
        }

        if detailed {
            self.print_nr_running_table(&entries_with_data, collapsed);
        } else {
            println!("Processes by runqueue depth at wakeup:\n");

            let mut sorted_entries = entries_with_data;
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
        // Use the generic histogram table printer with nr_running percentile calculation
        let max_comm_len = entries
            .iter()
            .map(|e| e.comm.len())
            .max()
            .unwrap_or(7)
            .max(7);

        // Print header
        if collapsed {
            println!(
                "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12}",
                "COMMAND",
                "PROCS",
                "p50",
                "p90",
                "p99",
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
                "p99",
                "COUNT",
                width = max_comm_len
            );
        }

        // Print rows with nr_running specific percentile calculation
        for entry in entries {
            let total_count = entry.nr_running_hist.total_count();
            if total_count == 0 {
                continue;
            }

            let p50 = self.calculate_nr_running_percentile(&entry.nr_running_hist, 50);
            let p90 = self.calculate_nr_running_percentile(&entry.nr_running_hist, 90);
            let p99 = self.calculate_nr_running_percentile(&entry.nr_running_hist, 99);

            if collapsed {
                println!(
                    "  {:<width$} {:<8} {:<10} {:<10} {:<10} {:<12}",
                    &entry.comm,
                    entry.pids.len(),
                    p50,
                    p90,
                    p99,
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
                    p99,
                    total_count,
                    width = max_comm_len
                );
            }
        }
    }

    fn print_cpu_stats(&self, filters: &FilterOptions, detailed: bool) -> Result<()> {
        self.print_cpu_metric_stats(
            &self.cpu_stats,
            "Per-CPU Scheduling Delays",
            filters,
            detailed,
            false,
        )
    }

    fn print_cpu_idle_stats(&self, filters: &FilterOptions, detailed: bool) -> Result<()> {
        self.print_cpu_metric_stats(
            &self.cpu_idle_stats,
            "Per-CPU Idle Duration",
            filters,
            detailed,
            true,
        )
    }

    // Generic CPU stats printer
    fn print_cpu_metric_stats(
        &self,
        cpu_stats: &HashMap<u32, Hist>,
        title: &str,
        filters: &FilterOptions,
        detailed: bool,
        is_idle: bool,
    ) -> Result<()> {
        let filtered_cpus: Vec<(u32, &Hist)> = cpu_stats
            .iter()
            .filter(|(_, hist)| {
                let total_count = hist.total_count();
                if total_count == 0 {
                    return false;
                }
                if !is_idle && filters.min_latency_us > 0 {
                    let p50 = self.calculate_percentile(hist, 50);
                    p50 >= filters.min_latency_us
                } else {
                    true
                }
            })
            .map(|(cpu, hist)| (*cpu, hist))
            .collect();

        if filtered_cpus.is_empty() {
            println!("\n=== {} (microseconds) ===", title);
            if is_idle {
                println!("No CPU idle data collected yet.\n");
            } else {
                println!("No CPUs match the specified filters.\n");
            }
            return Ok(());
        }

        println!("\n=== {} (microseconds) ===\n", title);

        if detailed {
            // Detailed mode: show all CPUs
            println!(
                "{:<8} {:<10} {:<10} {:<10} {:<12}",
                "CPU", "p50", "p90", "p99", "COUNT"
            );

            let mut sorted_cpus = filtered_cpus;
            sorted_cpus.sort_by_key(|(cpu, _)| *cpu);

            for (cpu, hist) in sorted_cpus {
                let total_count = hist.total_count();
                let p50 = self.calculate_percentile(hist, 50);
                let p90 = self.calculate_percentile(hist, 90);
                let p99 = self.calculate_percentile(hist, 99);

                println!(
                    "{:<8} {:<10} {:<10} {:<10} {:<12}",
                    cpu, p50, p90, p99, total_count
                );
            }
        } else {
            // Grouped mode
            if is_idle {
                self.print_grouped_cpu_stats::<IdleDurationGroup>(cpu_stats, &filtered_cpus);
            } else {
                self.print_grouped_cpu_stats::<LatencyGroup>(cpu_stats, &filtered_cpus);
            }
        }

        Ok(())
    }

    fn print_grouped_cpu_stats<G: PercentileGroup + Eq + std::hash::Hash>(
        &self,
        cpu_stats: &HashMap<u32, Hist>,
        filtered_cpus: &[(u32, &Hist)],
    ) {
        let mut cpu_groups: HashMap<G, Vec<u32>> = HashMap::new();
        let mut global_hist = Hist::default();

        for (cpu, hist) in filtered_cpus {
            let p90 = self.calculate_percentile(hist, 90);
            let group = G::from_percentile(p90);
            cpu_groups.entry(group).or_default().push(*cpu);
        }

        let mut groups: Vec<_> = cpu_groups.into_iter().collect();
        groups.sort_by_key(|(group, _)| *group);

        for (group, mut cpus) in groups {
            cpus.sort();
            println!("{}: CPUs ({}) {}", group.description(), cpus.len(), format_cpu_list(&cpus));

            // Show aggregate stats
            let mut total_hist = Hist::default();
            for cpu in &cpus {
                if let Some(hist) = cpu_stats.get(cpu) {
                    total_hist.merge_into(hist);
                    global_hist.merge_into(hist);
                }
            }

            let total_count = total_hist.total_count();
            let p50 = self.calculate_percentile(&total_hist, 50);
            let p90 = self.calculate_percentile(&total_hist, 90);
            let p99 = self.calculate_percentile(&total_hist, 99);

            println!(
                "  Group: p50={:<6} p90={:<6} p99={:<6} count={}\n",
                p50, p90, p99, total_count
            );
        }
        let total_count = global_hist.total_count();
        let p50 = self.calculate_percentile(&global_hist, 50);
        let p90 = self.calculate_percentile(&global_hist, 90);
        let p99 = self.calculate_percentile(&global_hist, 99);

        println!(
            "Global: p50={:<6} p90={:<6} p99={:<6} count={}\n",
            p50, p90, p99, total_count
        );
    }

    fn build_process_entries(&self, filters: &FilterOptions, collapse: bool) -> Vec<ProcessEntry> {
        if collapse {
            self.build_collapsed_entries(filters)
        } else {
            self.build_individual_entries(filters)
        }
    }

    fn create_default_process_entry(comm: String, pids: Vec<u32>) -> ProcessEntry {
        ProcessEntry {
            comm,
            hist: Hist::default(),
            timeslice_stats: TimesliceStats::default(),
            nr_running_hist: Hist::default(),
            waking_delay_hist: Hist::default(),
            sleep_duration_hist: Hist::default(),
            pids,
        }
    }

    fn build_collapsed_entries(&self, filters: &FilterOptions) -> Vec<ProcessEntry> {
        let mut comm_map: HashMap<String, ProcessEntry> = HashMap::new();

        // Process scheduling delay stats
        for (pid, stats) in &self.pid_stats {
            if !self.should_include_process(pid, &stats.comm, filters)
                || stats.data.total_count() == 0
            {
                continue;
            }

            let entry = comm_map.entry(stats.comm.clone()).or_insert_with(|| {
                Self::create_default_process_entry(stats.comm.clone(), Vec::new())
            });

            entry.hist.merge_into(&stats.data);
            if !entry.pids.contains(pid) {
                entry.pids.push(*pid);
            }
        }

        // Process timeslice stats
        for (pid, ts_data) in &self.timeslice_stats {
            if !self.should_include_process(pid, &ts_data.comm, filters)
                || ts_data.data.total_count() == 0
            {
                continue;
            }

            let entry = comm_map.entry(ts_data.comm.clone()).or_insert_with(|| {
                Self::create_default_process_entry(ts_data.comm.clone(), Vec::new())
            });

            entry.timeslice_stats.merge_into(&ts_data.data);
            if !entry.pids.contains(pid) {
                entry.pids.push(*pid);
            }
        }

        // Process nr_running stats
        for (pid, nr_data) in &self.nr_running_stats {
            if !self.should_include_process(pid, &nr_data.comm, filters)
                || nr_data.data.total_count() == 0
            {
                continue;
            }

            let entry = comm_map.entry(nr_data.comm.clone()).or_insert_with(|| {
                Self::create_default_process_entry(nr_data.comm.clone(), Vec::new())
            });

            entry.nr_running_hist.merge_into(&nr_data.data);
            if !entry.pids.contains(pid) {
                entry.pids.push(*pid);
            }
        }

        // Process waking delay stats
        for (pid, wd_data) in &self.waking_delay_stats {
            if !self.should_include_process(pid, &wd_data.comm, filters)
                || wd_data.data.total_count() == 0
            {
                continue;
            }

            let entry = comm_map.entry(wd_data.comm.clone()).or_insert_with(|| {
                Self::create_default_process_entry(wd_data.comm.clone(), Vec::new())
            });

            entry.waking_delay_hist.merge_into(&wd_data.data);
            if !entry.pids.contains(pid) {
                entry.pids.push(*pid);
            }
        }

        // Process sleep duration stats
        for (pid, sd_data) in &self.sleep_duration_stats {
            if !self.should_include_process(pid, &sd_data.comm, filters)
                || sd_data.data.total_count() == 0
            {
                continue;
            }

            let entry = comm_map.entry(sd_data.comm.clone()).or_insert_with(|| {
                Self::create_default_process_entry(sd_data.comm.clone(), Vec::new())
            });

            entry.sleep_duration_hist.merge_into(&sd_data.data);
            if !entry.pids.contains(pid) {
                entry.pids.push(*pid);
            }
        }

        comm_map.into_values().collect()
    }

    fn build_individual_entries(&self, filters: &FilterOptions) -> Vec<ProcessEntry> {
        let mut pid_entries: HashMap<u32, ProcessEntry> = HashMap::new();

        // Process scheduling delay stats
        for (pid, stats) in &self.pid_stats {
            if !self.should_include_process(pid, &stats.comm, filters)
                || stats.data.total_count() == 0
            {
                continue;
            }

            pid_entries
                .entry(*pid)
                .or_insert_with(|| {
                    Self::create_default_process_entry(stats.comm.clone(), vec![*pid])
                })
                .hist = stats.data.clone();
        }

        // Process timeslice stats
        for (pid, ts_data) in &self.timeslice_stats {
            if !self.should_include_process(pid, &ts_data.comm, filters)
                || ts_data.data.total_count() == 0
            {
                continue;
            }

            pid_entries
                .entry(*pid)
                .or_insert_with(|| {
                    Self::create_default_process_entry(ts_data.comm.clone(), vec![*pid])
                })
                .timeslice_stats = ts_data.data.clone();
        }

        // Process nr_running stats
        for (pid, nr_data) in &self.nr_running_stats {
            if !self.should_include_process(pid, &nr_data.comm, filters)
                || nr_data.data.total_count() == 0
            {
                continue;
            }

            pid_entries
                .entry(*pid)
                .or_insert_with(|| {
                    Self::create_default_process_entry(nr_data.comm.clone(), vec![*pid])
                })
                .nr_running_hist = nr_data.data.clone();
        }

        // Process waking delay stats
        for (pid, wd_data) in &self.waking_delay_stats {
            if !self.should_include_process(pid, &wd_data.comm, filters)
                || wd_data.data.total_count() == 0
            {
                continue;
            }

            pid_entries
                .entry(*pid)
                .or_insert_with(|| {
                    Self::create_default_process_entry(wd_data.comm.clone(), vec![*pid])
                })
                .waking_delay_hist = wd_data.data.clone();
        }

        // Process sleep duration stats
        for (pid, sd_data) in &self.sleep_duration_stats {
            if !self.should_include_process(pid, &sd_data.comm, filters)
                || sd_data.data.total_count() == 0
            {
                continue;
            }

            pid_entries
                .entry(*pid)
                .or_insert_with(|| {
                    Self::create_default_process_entry(sd_data.comm.clone(), vec![*pid])
                })
                .sleep_duration_hist = sd_data.data.clone();
        }

        pid_entries.into_values().collect()
    }

    // Keep existing helper methods
    fn should_include_process(&self, pid: &u32, comm: &str, filters: &FilterOptions) -> bool {
        if let Some(filter_pid) = filters.pid_filter {
            if *pid != filter_pid {
                return false;
            }
        }

        if let Some(ref regex) = filters.comm_regex {
            if !regex.is_match(comm) {
                return false;
            }
        }

        // Only apply latency filter if we're showing latency metrics
        if filters.metric_groups.latency && filters.min_latency_us > 0 {
            if let Some(stats) = self.pid_stats.get(pid) {
                let p50 = self.calculate_percentile(&stats.data, 50);
                if p50 < filters.min_latency_us {
                    return false;
                }
            }
        }

        true
    }

    fn calculate_percentile(&self, hist: &Hist, percentile: u8) -> u64 {
        let total_count = hist.total_count();
        if total_count == 0 {
            return 0;
        }

        let target_count = (total_count * percentile as u64) / 100;
        let mut cumulative_count = 0u64;

        for (slot, &count) in hist.slots.iter().enumerate() {
            let prev_cumulative = cumulative_count;
            cumulative_count += count as u64;

            if cumulative_count >= target_count {
                let count_in_bucket = count as u64;
                let position_in_bucket = target_count - prev_cumulative;
                let fraction = if count_in_bucket > 0 {
                    position_in_bucket as f64 / count_in_bucket as f64
                } else {
                    0.5
                };

                let (lower_bound, upper_bound) = self.get_slot_range(slot);
                let range = upper_bound - lower_bound + 1;
                return lower_bound + (fraction * range as f64) as u64;
            }
        }

        1u64 << 27
    }

    fn calculate_nr_running_percentile(&self, hist: &Hist, percentile: u8) -> u32 {
        let total_count = hist.total_count();
        if total_count == 0 {
            return 0;
        }

        let target_count = (total_count * percentile as u64) / 100;
        let mut cumulative_count = 0u64;

        for (slot, &count) in hist.slots.iter().enumerate() {
            cumulative_count += count as u64;
            if cumulative_count >= target_count {
                return slot as u32;
            }
        }

        63
    }

    fn get_slot_range(&self, slot: usize) -> (u64, u64) {
        if slot < LINEAR_SLOTS {
            let lower = slot as u64 * LINEAR_STEP;
            let upper = lower + LINEAR_STEP - 1;
            (lower, upper)
        } else if slot == LINEAR_SLOTS {
            (500, 511)
        } else {
            let log2_val = (slot - LINEAR_SLOTS - 1) + 9;
            let lower = 1u64 << log2_val;
            let upper = (1u64 << (log2_val + 1)) - 1;
            (lower, upper)
        }
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

    pub fn print_schedstat(&self, schedstat_data: &SchedstatData) {
        println!("\n=== System-wide Schedstat Metrics (deltas) ===");

        let mut metrics: Vec<(&String, &u64)> = schedstat_data.domain_totals.iter().collect();
        metrics.sort_by(|a, b| a.0.cmp(b.0));

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
                    if *field == "rq_run_delay usec" && i + 1 < schedstat_data.cpu_totals.len() {
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
            ranges.push(if start == end {
                format!("{}", start)
            } else {
                format!("{}-{}", start, end)
            });
            start = cpu;
            end = cpu;
        }
    }

    ranges.push(if start == end {
        format!("{}", start)
    } else {
        format!("{}-{}", start, end)
    });

    ranges.join(",")
}
