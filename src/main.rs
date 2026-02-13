// SPDX-License-Identifier: GPL-2.0
mod cpu_metrics;
mod perf;
mod rsched_collector;
mod rsched_stats;
mod schedstat;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use perf::PerfCounterSetup;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

// Include the generated skeleton file
include!(concat!(env!("OUT_DIR"), "/rsched.skel.rs"));

use cpu_metrics::CpuMetrics;
use rsched_collector::RschedCollector;
use rsched_stats::{FilterOptions, MetricGroups, OutputMode, RschedStats};
use schedstat::SchedstatCollector;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Show detailed per-process and per-CPU output
    #[arg(short, long)]
    detailed: bool,

    /// Update interval in seconds
    #[arg(short, long, default_value = "1")]
    interval: u64,

    /// Run for specified duration in seconds then exit
    #[arg(short, long)]
    run_time: Option<u64>,

    /// Filter by command name (regex) - can be specified multiple times
    #[arg(short, long)]
    comm: Vec<String>,

    /// Global command name filter (regex) - matches regardless of cgroup, OR'd with cgroup results
    #[arg(long)]
    global_comm: Vec<String>,

    /// Filter by cgroup name (regex) - can be specified multiple times
    #[arg(long)]
    cgroup: Vec<String>,

    /// Filter by specific PID
    #[arg(short, long)]
    pid: Option<u32>,

    /// Minimum latency threshold in microseconds (filters out lower values)
    #[arg(short = 'l', long)]
    min_latency: Option<u64>,

    /// Don't collapse/aggregate by command name
    #[arg(short = 'C', long)]
    no_collapse: bool,

    /// Select metric groups to display (comma-separated: latency,slice,sleep,perf,schedstat,waking,most,all)
    #[arg(short = 'g', long, default_value = "latency", value_delimiter = ',')]
    group: Vec<String>,
}

fn parse_metric_groups(groups: &[String]) -> Result<MetricGroups> {
    let mut metric_groups = MetricGroups::default();

    for group in groups {
        match group.as_str() {
            "all" => {
                metric_groups.latency = true;
                metric_groups.cpu_latency = true;
                metric_groups.slice = true;
                metric_groups.sleep = true;
                metric_groups.cpu_idle = true;
                metric_groups.perf = true;
                metric_groups.schedstat = true;
                metric_groups.waking = true;
            }
            "most" => {
                // just all minus waking
                metric_groups.latency = true;
                metric_groups.cpu_latency = true;
                metric_groups.slice = true;
                metric_groups.sleep = true;
                metric_groups.cpu_idle = true;
                metric_groups.perf = true;
                metric_groups.schedstat = true;
            }
            "latency" => {
                metric_groups.latency = true;
                metric_groups.cpu_latency = true;
            }
            "slice" => metric_groups.slice = true,
            "sleep" => {
                metric_groups.sleep = true;
                metric_groups.cpu_idle = true;
            }
            "perf" => metric_groups.perf = true,
            "schedstat" => metric_groups.schedstat = true,
            "waking" => metric_groups.waking = true,
            _ => anyhow::bail!("Unknown metric group: {}. Valid groups are: latency, slice, sleep, perf, schedstat, waking, most, all", group),
        }
    }

    Ok(metric_groups)
}

fn enable_schedstat() -> Result<()> {
    std::fs::write("/proc/sys/kernel/sched_schedstats", "1")?;
    Ok(())
}

fn collect_cgroup_children_recursive(path: &Path, cgroup_ids: &mut HashSet<u64>) -> Result<()> {
    // Get the inode (cgroup ID) of the current directory
    let metadata = fs::metadata(path)?;
    let cgroup_id = metadata.ino();
    cgroup_ids.insert(cgroup_id);

    // Recursively collect all children
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let child_path = entry.path();
            if child_path.is_dir() {
                collect_cgroup_children_recursive(&child_path, cgroup_ids)?;
            }
        }
    }

    Ok(())
}

fn resolve_cgroup_ids(cgroup_patterns: &[String]) -> Result<HashSet<u64>> {
    let mut all_cgroup_ids = HashSet::new();
    let cgroup_root = Path::new("/sys/fs/cgroup");

    for cgroup_pattern in cgroup_patterns {
        let regex = Regex::new(cgroup_pattern)?;
        let mut pattern_cgroup_ids = HashSet::new();

        // Handle exact "root" pattern specially - only add root cgroup itself
        if cgroup_pattern == "root" {
            let root_metadata = fs::metadata(cgroup_root)?;
            let root_id = root_metadata.ino();
            pattern_cgroup_ids.insert(root_id);
        } else if regex.is_match("root") {
            // If pattern contains "root" but isn't exactly "root", collect all cgroups
            collect_cgroup_children_recursive(cgroup_root, &mut pattern_cgroup_ids)?;
        } else {
            // Walk through all directories in /sys/fs/cgroup
            fn walk_cgroups(
                path: &Path,
                regex: &Regex,
                cgroup_ids: &mut HashSet<u64>,
            ) -> Result<()> {
                for entry in fs::read_dir(path)? {
                    let entry = entry?;
                    let child_path = entry.path();

                    if child_path.is_dir() {
                        if let Some(dir_name) = child_path.file_name() {
                            if let Some(name_str) = dir_name.to_str() {
                                if regex.is_match(name_str) {
                                    // This cgroup matches, collect it and all its children
                                    collect_cgroup_children_recursive(&child_path, cgroup_ids)?;
                                } else {
                                    // Continue searching in subdirectories
                                    walk_cgroups(&child_path, regex, cgroup_ids)?;
                                }
                            }
                        }
                    }
                }
                Ok(())
            }

            walk_cgroups(cgroup_root, &regex, &mut pattern_cgroup_ids)?;
        }

        // Merge pattern results into the combined set
        all_cgroup_ids.extend(pattern_cgroup_ids);
    }

    Ok(all_cgroup_ids)
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse metric groups
    let metric_groups = parse_metric_groups(&args.group)?;

    // command line comm regexes
    let comm_regexes = if !args.comm.is_empty() {
        let mut regexes = Vec::new();
        for pattern in &args.comm {
            regexes.push(Regex::new(pattern)?);
        }
        Some(regexes)
    } else {
        None
    };

    // global comm regexes (match regardless of cgroup)
    let global_comm_regexes = if !args.global_comm.is_empty() {
        let mut regexes = Vec::new();
        for pattern in &args.global_comm {
            regexes.push(Regex::new(pattern)?);
        }
        Some(regexes)
    } else {
        None
    };

    // resolve cgroup IDs if cgroup filters are specified
    let cgroup_filter = if !args.cgroup.is_empty() {
        Some(resolve_cgroup_ids(&args.cgroup)?)
    } else {
        None
    };

    println!("Starting rsched");

    // Print active options
    if comm_regexes.is_some()
        || global_comm_regexes.is_some()
        || !args.cgroup.is_empty()
        || args.pid.is_some()
        || args.min_latency.is_some()
        || args.no_collapse
        || args.run_time.is_some()
        || args.group != vec!["latency"]
    {
        println!("Options active:");
        if let Some(ref regexes) = comm_regexes {
            if regexes.len() == 1 {
                println!("  - Command pattern: {}", regexes[0].as_str());
            } else {
                let patterns: Vec<&str> = regexes.iter().map(|r| r.as_str()).collect();
                println!("  - Command patterns: {}", patterns.join(", "));
            }
        }
        if let Some(ref regexes) = global_comm_regexes {
            if regexes.len() == 1 {
                println!("  - Global command pattern: {}", regexes[0].as_str());
            } else {
                let patterns: Vec<&str> = regexes.iter().map(|r| r.as_str()).collect();
                println!("  - Global command patterns: {}", patterns.join(", "));
            }
        }
        if !args.cgroup.is_empty() {
            let count = cgroup_filter.as_ref().map(|s| s.len()).unwrap_or(0);
            if args.cgroup.len() == 1 {
                println!(
                    "  - Cgroup pattern: {} (matched {} cgroups)",
                    args.cgroup[0], count
                );
            } else {
                println!(
                    "  - Cgroup patterns: {} (matched {} cgroups)",
                    args.cgroup.join(", "),
                    count
                );
            }

            // Print the resolved cgroup IDs
            if let Some(ref cgroup_set) = cgroup_filter {
                let mut sorted_ids: Vec<u64> = cgroup_set.iter().copied().collect();
                sorted_ids.sort();
                println!("  - Resolved cgroup IDs: {:?}", sorted_ids);
            }
        }
        if let Some(pid) = args.pid {
            println!("  - PID: {}", pid);
        }
        if let Some(threshold) = args.min_latency {
            println!("  - Minimum latency: {}μs", threshold);
        }
        if args.no_collapse {
            println!("  - Not collapsing by command name");
        }
        if let Some(runtime) = args.run_time {
            println!("  - Runtime limit: {} seconds", runtime);
        }

        // Print active metric groups
        let active_groups: Vec<&str> = vec![
            if metric_groups.latency {
                Some("latency")
            } else {
                None
            },
            if metric_groups.slice {
                Some("slice")
            } else {
                None
            },
            if metric_groups.sleep {
                Some("sleep")
            } else {
                None
            },
            if metric_groups.perf {
                Some("perf")
            } else {
                None
            },
            if metric_groups.schedstat {
                Some("schedstat")
            } else {
                None
            },
            if metric_groups.waking {
                Some("waking")
            } else {
                None
            },
        ]
        .into_iter()
        .flatten()
        .collect();

        if !active_groups.is_empty() {
            println!("  - Metric groups: {}", active_groups.join(", "));
        }
    }

    let skel_builder = RschedSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;

    open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .unwrap()
        .trace_sched_waking = metric_groups.waking as u32;

    if !metric_groups.waking {
        // Disable both BTF and raw tracepoint versions to reduce overhead
        open_skel.progs.handle_sched_waking_btf.set_autoload(false);
        open_skel.progs.handle_sched_waking_raw.set_autoload(false);
    }

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let _perf_setup = if metric_groups.perf {
        let mut setup = PerfCounterSetup::new();
        setup.setup_and_attach(&skel.maps)?;
        println!("CPU performance counters enabled");
        Some(setup)
    } else {
        None
    };

    let maps = &skel.maps;
    let mut collector = RschedCollector::new(maps);
    let mut stats = RschedStats::new();
    let mut schedstat_collector = if metric_groups.schedstat {
        enable_schedstat()?;
        Some(SchedstatCollector::new()?)
    } else {
        None
    };

    // get initial schedstat numbers if it is enabled
    if let Some(ref mut schedstat) = schedstat_collector {
        let schedstat_data = schedstat.collect()?;
        stats.update_schedstat(schedstat_data);
    }

    let output_mode = if args.detailed {
        OutputMode::Detailed
    } else if !args.no_collapse {
        OutputMode::Collapsed
    } else {
        OutputMode::Grouped
    };

    let mut cpu_metrics = if metric_groups.perf {
        Some(CpuMetrics::new())
    } else {
        None
    };

    let filter_options = FilterOptions {
        comm_regexes,
        global_comm_regexes,
        pid_filter: args.pid,
        cgroup_filter,
        min_latency_us: args.min_latency.unwrap_or(0),
        metric_groups: metric_groups.clone(),
    };

    // Track start time for runtime limit
    let start_time = Instant::now();
    let runtime_limit = args.run_time.map(Duration::from_secs);

    loop {
        // Check runtime limit
        if let Some(limit) = runtime_limit {
            if start_time.elapsed() >= limit {
                println!("\nRuntime limit reached ({} seconds)", limit.as_secs());
                break;
            }
        }

        // Calculate sleep duration
        let sleep_duration = if let Some(limit) = runtime_limit {
            let elapsed = start_time.elapsed();
            let remaining = limit.saturating_sub(elapsed);
            let interval = Duration::from_secs(args.interval);
            std::cmp::min(remaining, interval)
        } else {
            Duration::from_secs(args.interval)
        };

        // Sleep for the calculated duration
        if sleep_duration.as_millis() > 0 {
            std::thread::sleep(sleep_duration);
        } else {
            // If no time left, break
            break;
        }

        // Check runtime limit again after sleep
        if let Some(limit) = runtime_limit {
            if start_time.elapsed() >= limit {
                println!("\nRuntime limit reached ({} seconds)", limit.as_secs());
                break;
            }
        }

        // Collect only the data we need based on active metric groups
        let histograms = if metric_groups.latency {
            collector.collect_histograms()?
        } else {
            HashMap::new()
        };

        let cpu_histograms = if metric_groups.cpu_latency {
            collector.collect_cpu_histograms()?
        } else {
            HashMap::new()
        };

        let timeslice_stats = if metric_groups.slice {
            collector.collect_timeslice_stats()?
        } else {
            HashMap::new()
        };

        let nr_running_hists = if metric_groups.latency {
            collector.collect_nr_running_hists()?
        } else {
            HashMap::new()
        };

        let waking_delays = if metric_groups.waking {
            collector.collect_waking_delays()?
        } else {
            HashMap::new()
        };

        let sleep_durations = if metric_groups.sleep {
            collector.collect_sleep_durations()?
        } else {
            HashMap::new()
        };

        let cpu_idle_histograms = if metric_groups.cpu_idle {
            collector.collect_cpu_idle_histograms()?
        } else {
            HashMap::new()
        };

        if let Some(ref mut schedstat) = schedstat_collector {
            let schedstat_data = schedstat.collect()?;
            stats.update_schedstat(schedstat_data);
        }

        let cpu_perf_data = if metric_groups.perf {
            collector.collect_cpu_perf()?
        } else {
            HashMap::new()
        };

        stats.update(histograms);
        stats.update_cpu(cpu_histograms);
        stats.update_timeslices(timeslice_stats);
        stats.update_nr_running(nr_running_hists);
        stats.update_waking_delays(waking_delays);
        stats.update_sleep_durations(sleep_durations);
        stats.update_cpu_idle(cpu_idle_histograms);

        if let Some(ref mut metrics) = cpu_metrics {
            metrics.update(cpu_perf_data);
        }

        stats.print_summary(output_mode, &filter_options)?;

        if let Some(ref mut metrics) = cpu_metrics {
            let cpu_filters = cpu_metrics::CpuFilterOptions {
                comm_regexes: filter_options.comm_regexes.clone(),
                pid_filter: filter_options.pid_filter,
                detailed: args.detailed,
                collapsed: !args.no_collapse,
            };
            metrics.print_summary(&cpu_filters);
        }
    }

    println!("\nShutting down rsched...");
    Ok(())
}
