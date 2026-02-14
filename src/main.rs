// SPDX-License-Identifier: GPL-2.0
mod cpu_metrics;
mod perf;
mod pmu;
mod rsched_collector;
mod rsched_stats;
mod schedstat;
mod topology;

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

    /// Select metric groups to display (comma-separated: latency,slice,sleep,perf[=events],schedstat,waking,migration,most,all)
    #[arg(short = 'g', long, default_value = "latency", value_delimiter = ',')]
    group: Vec<String>,

    /// List available performance counters and exit
    #[arg(long)]
    perf_list: bool,

    /// Load CPU topology from JSON file instead of detecting from sysfs
    #[arg(long)]
    topology: Option<String>,

    /// Detect CPU topology and print as JSON, then exit
    #[arg(long)]
    gen_topology: bool,
}

fn list_perf_events() -> Result<()> {
    // Show rsched built-in event aliases first
    pmu::list_builtin_events();
    println!();

    // Then show libpfm4 events
    println!("=== libpfm4 Events ===");
    use pfm_sys::*;
    use std::ffi::CStr;

    unsafe {
        let ret = pfm_initialize();
        if ret != PFM_SUCCESS {
            anyhow::bail!("Failed to initialize libpfm4");
        }
    }

    for pmu_id in 0..pfm_pmu_t::PFM_PMU_MAX as u32 {
        let mut pmu_info: pfm_pmu_info_t = unsafe { MaybeUninit::zeroed().assume_init() };
        pmu_info.size = std::mem::size_of::<pfm_pmu_info_t>();

        let pmu: pfm_pmu_t = unsafe { std::mem::transmute(pmu_id) };
        let ret = unsafe { pfm_get_pmu_info(pmu, &mut pmu_info) };
        if ret != PFM_SUCCESS {
            continue;
        }

        // Skip PMUs not present on this system
        if pmu_info.__bindgen_anon_1.is_present() == 0 {
            continue;
        }

        let pmu_name = if !pmu_info.name.is_null() {
            unsafe { CStr::from_ptr(pmu_info.name) }
                .to_str()
                .unwrap_or("?")
        } else {
            "?"
        };

        let pmu_desc = if !pmu_info.desc.is_null() {
            unsafe { CStr::from_ptr(pmu_info.desc) }
                .to_str()
                .unwrap_or("")
        } else {
            ""
        };

        println!(
            "PMU: {} - {} ({} events)",
            pmu_name, pmu_desc, pmu_info.nevents
        );

        // Iterate events for this PMU
        let mut idx = pmu_info.first_event;
        while idx >= 0 {
            let mut event_info: pfm_event_info_t = unsafe { MaybeUninit::zeroed().assume_init() };
            event_info.size = std::mem::size_of::<pfm_event_info_t>();

            let ret =
                unsafe { pfm_get_event_info(idx, pfm_os_t::PFM_OS_PERF_EVENT, &mut event_info) };
            if ret != PFM_SUCCESS {
                break;
            }

            let name = if !event_info.name.is_null() {
                unsafe { CStr::from_ptr(event_info.name) }
                    .to_str()
                    .unwrap_or("?")
            } else {
                "?"
            };

            let desc = if !event_info.desc.is_null() {
                unsafe { CStr::from_ptr(event_info.desc) }
                    .to_str()
                    .unwrap_or("")
            } else {
                ""
            };

            println!("  {:<40} {}", name, desc);

            idx = unsafe { pfm_get_event_next(idx) };
        }
    }

    unsafe {
        pfm_terminate();
    }

    Ok(())
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
                if metric_groups.perf_events.is_empty() {
                    metric_groups.perf_events.push("ipc".to_string());
                }
                metric_groups.schedstat = true;
                metric_groups.waking = true;
                metric_groups.migration = true;
            }
            "most" => {
                // just all minus waking
                metric_groups.latency = true;
                metric_groups.cpu_latency = true;
                metric_groups.slice = true;
                metric_groups.sleep = true;
                metric_groups.cpu_idle = true;
                metric_groups.perf = true;
                if metric_groups.perf_events.is_empty() {
                    metric_groups.perf_events.push("ipc".to_string());
                }
                metric_groups.schedstat = true;
                metric_groups.migration = true;
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
            s if s == "perf" || s.starts_with("perf=") => {
                metric_groups.perf = true;
                let event = s.strip_prefix("perf=").unwrap_or("ipc");
                // Validate event by resolving it (will bail with helpful message if invalid)
                pmu::resolve_event(event)?;
                if !metric_groups.perf_events.contains(&event.to_string()) {
                    metric_groups.perf_events.push(event.to_string());
                }
            }
            "schedstat" => metric_groups.schedstat = true,
            "waking" => metric_groups.waking = true,
            "migration" => metric_groups.migration = true,
            _ => {
                // Try resolving as a perf event name — allows e.g. -g l2-miss
                // or -g perf=ipc,l2-miss (clap comma-splits into ["perf=ipc", "l2-miss"])
                if pmu::resolve_event(group).is_ok() {
                    metric_groups.perf = true;
                    if !metric_groups.perf_events.contains(group) {
                        metric_groups.perf_events.push(group.clone());
                    }
                } else {
                    anyhow::bail!("Unknown metric group: {}. Valid groups are: latency, slice, sleep, perf[=events], schedstat, waking, migration, most, all", group);
                }
            }
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

    if args.perf_list {
        return list_perf_events();
    }

    if args.gen_topology {
        return topology::gen_topology();
    }

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
        let mut active_groups: Vec<String> = Vec::new();
        if metric_groups.latency {
            active_groups.push("latency".to_string());
        }
        if metric_groups.slice {
            active_groups.push("slice".to_string());
        }
        if metric_groups.sleep {
            active_groups.push("sleep".to_string());
        }
        if metric_groups.perf {
            active_groups.push(format!("perf={}", metric_groups.perf_events.join(",")));
        }
        if metric_groups.schedstat {
            active_groups.push("schedstat".to_string());
        }
        if metric_groups.waking {
            active_groups.push("waking".to_string());
        }
        if metric_groups.migration {
            active_groups.push("migration".to_string());
        }

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

    let topo = if metric_groups.migration {
        let topo = if let Some(ref path) = args.topology {
            topology::load_topology(path)?
        } else {
            topology::detect_topology()?
        };
        topology::print_topology(&topo);

        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        for i in 0..topology::MAX_CPUS {
            rodata.cpu_to_die[i] = topo.cpu_to_die[i];
            rodata.cpu_to_numa[i] = topo.cpu_to_numa[i];
        }

        Some(topo)
    } else {
        open_skel
            .progs
            .handle_sched_migrate_task_btf
            .set_autoload(false);
        open_skel
            .progs
            .handle_sched_migrate_task_raw
            .set_autoload(false);
        None
    };

    // Resolve perf events and determine how many generic slots we need
    let mut resolved_events: Vec<pmu::PmuEventSet> = Vec::new();
    let mut generic_event_names: Vec<String> = Vec::new();
    let mut generic_event_configs: Vec<(u32, u64)> = Vec::new();

    if metric_groups.perf {
        for event_name in &metric_groups.perf_events {
            let event_set = pmu::resolve_event(event_name)?;
            if !event_set.is_ipc {
                // Each non-IPC event set contributes one generic slot per event
                for ev in &event_set.events {
                    generic_event_names.push(event_set.name.clone());
                    generic_event_configs.push((ev.perf_type, ev.config));
                }
            }
            resolved_events.push(event_set);
        }

        if generic_event_configs.len() > pmu::MAX_GENERIC_EVENTS {
            anyhow::bail!(
                "Too many generic perf events ({}, max {})",
                generic_event_configs.len(),
                pmu::MAX_GENERIC_EVENTS
            );
        }

        // Set num_generic_events in BPF rodata before load
        open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .unwrap()
            .num_generic_events = generic_event_configs.len() as u32;
    }

    let has_ipc = resolved_events.iter().any(|e| e.is_ipc);

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let _perf_setup = if metric_groups.perf {
        let mut setup = PerfCounterSetup::new();

        // Setup IPC counters if ipc event is requested
        if has_ipc {
            setup.setup_and_attach(&skel.maps)?;
            println!("CPU performance counters enabled (IPC)");
        }

        // Setup generic event counters
        if !generic_event_configs.is_empty() {
            let generic_maps: Vec<&libbpf_rs::Map> = vec![
                &skel.maps.generic_perf_array_0,
                &skel.maps.generic_perf_array_1,
                &skel.maps.generic_perf_array_2,
                &skel.maps.generic_perf_array_3,
                &skel.maps.generic_perf_array_4,
                &skel.maps.generic_perf_array_5,
                &skel.maps.generic_perf_array_6,
                &skel.maps.generic_perf_array_7,
            ];

            let maps_slice = &generic_maps[..generic_event_configs.len()];
            setup.setup_generic_events(&generic_event_configs, maps_slice)?;

            println!("Generic perf events: {}", generic_event_names.join(", "));
        }

        Some(setup)
    } else {
        None
    };

    let maps = &skel.maps;
    let mut collector = RschedCollector::new(maps);
    let mut stats = RschedStats::new();
    if let Some(ref topo) = topo {
        stats.num_dies = topo.num_dies;
        stats.num_numa_nodes = topo.num_numa_nodes;
    }
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
        Some(CpuMetrics::new(generic_event_names.clone()))
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

    // When migration or generic perf events are active, tick every 1 second
    // to collect per-second counts for percentile computation.
    // Display at the normal interval boundary.
    let needs_per_second_tick = metric_groups.migration || !generic_event_configs.is_empty();
    let tick_interval = if needs_per_second_tick {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(args.interval)
    };
    let mut ticks_since_display = 0u64;

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
            std::cmp::min(remaining, tick_interval)
        } else {
            tick_interval
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

        ticks_since_display += 1;

        // Collect per-second data every tick (every 1 second)
        if metric_groups.migration {
            let migration_counts = collector.collect_migration_counts()?;
            stats.update_migrations(migration_counts);
        }

        if !generic_event_configs.is_empty() {
            let generic_perf_data = collector.collect_generic_perf()?;
            if let Some(ref mut metrics) = cpu_metrics {
                metrics.record_generic_tick(generic_perf_data);
            }
        }

        // Only do full collection and display at the interval boundary
        if !needs_per_second_tick || ticks_since_display >= args.interval {
            ticks_since_display = 0;

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

            let cpu_perf_data = if metric_groups.perf && has_ipc {
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
                if has_ipc {
                    metrics.update(cpu_perf_data);
                }
            }

            stats.print_summary(output_mode, &filter_options)?;

            if let Some(ref mut metrics) = cpu_metrics {
                metrics.print_summary(output_mode, &filter_options);
            }
        }
    }

    println!("\nShutting down rsched...");
    Ok(())
}
