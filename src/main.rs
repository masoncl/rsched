// SPDX-License-Identifier: GPL-2.0
mod cpu_metrics;
mod perf;
mod pmu;
mod rsched_collector;
mod rsched_stats;
mod schedstat;
mod topology;

use anyhow::Result;
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::programs::BtfTracePoint;
use aya::programs::RawTracePoint;
use aya::{include_bytes_aligned, Btf, EbpfLoader};
use clap::Parser;
use perf::PerfCounterSetup;
use regex::Regex;
use rsched_common::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

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
    pmu::list_builtin_events();
    println!();

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
                pmu::resolve_event(event)?;
                if !metric_groups.perf_events.contains(&event.to_string()) {
                    metric_groups.perf_events.push(event.to_string());
                }
            }
            "schedstat" => metric_groups.schedstat = true,
            "waking" => metric_groups.waking = true,
            "migration" => metric_groups.migration = true,
            _ => {
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
    let metadata = fs::metadata(path)?;
    let cgroup_id = metadata.ino();
    cgroup_ids.insert(cgroup_id);

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

        if cgroup_pattern == "root" {
            let root_metadata = fs::metadata(cgroup_root)?;
            let root_id = root_metadata.ino();
            pattern_cgroup_ids.insert(root_id);
        } else if regex.is_match("root") {
            collect_cgroup_children_recursive(cgroup_root, &mut pattern_cgroup_ids)?;
        } else {
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
                                    collect_cgroup_children_recursive(&child_path, cgroup_ids)?;
                                } else {
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

        all_cgroup_ids.extend(pattern_cgroup_ids);
    }

    Ok(all_cgroup_ids)
}

/// Try to attach a BTF tracepoint, returning Ok(link) or Err.
fn try_attach_btf(bpf: &mut aya::Ebpf, prog_name: &str, tp_name: &str, btf: &Btf) -> Result<bool> {
    let prog: &mut BtfTracePoint = bpf.program_mut(prog_name).unwrap().try_into()?;
    prog.load(tp_name, btf)?;
    match prog.attach() {
        Ok(_link) => Ok(true),
        Err(e) => {
            eprintln!("BTF tracepoint {} failed: {}, will use raw_tp", tp_name, e);
            Ok(false)
        }
    }
}

/// Attach a raw tracepoint.
fn attach_raw_tp(bpf: &mut aya::Ebpf, prog_name: &str, tp_name: &str) -> Result<()> {
    let prog: &mut RawTracePoint = bpf.program_mut(prog_name).unwrap().try_into()?;
    prog.load()?;
    prog.attach(tp_name)?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.perf_list {
        return list_perf_events();
    }

    if args.gen_topology {
        return topology::gen_topology();
    }

    let metric_groups = parse_metric_groups(&args.group)?;

    let comm_regexes = if !args.comm.is_empty() {
        let mut regexes = Vec::new();
        for pattern in &args.comm {
            regexes.push(Regex::new(pattern)?);
        }
        Some(regexes)
    } else {
        None
    };

    let global_comm_regexes = if !args.global_comm.is_empty() {
        let mut regexes = Vec::new();
        for pattern in &args.global_comm {
            regexes.push(Regex::new(pattern)?);
        }
        Some(regexes)
    } else {
        None
    };

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

    // Resolve perf events before loading BPF
    let mut resolved_events: Vec<pmu::PmuEventSet> = Vec::new();
    let mut generic_event_names: Vec<String> = Vec::new();
    let mut generic_event_configs: Vec<(u32, u64)> = Vec::new();

    if metric_groups.perf {
        for event_name in &metric_groups.perf_events {
            let event_set = pmu::resolve_event(event_name)?;
            if !event_set.is_ipc {
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
    }
    let has_ipc = resolved_events.iter().any(|e| e.is_ipc);

    // Detect topology if migration metrics are enabled
    let topo = if metric_groups.migration {
        let topo = if let Some(ref path) = args.topology {
            topology::load_topology(path)?
        } else {
            topology::detect_topology()?
        };
        topology::print_topology(&topo);
        Some(topo)
    } else {
        None
    };

    // Load the eBPF program using aya
    let ebpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rsched"));

    let mut loader = EbpfLoader::new();

    // Set global configuration before loading
    let waking_val = metric_groups.waking as u32;
    loader.set_global("TRACE_SCHED_WAKING", &waking_val, true);
    let n_generic_val = generic_event_configs.len() as u32;
    loader.set_global("NUM_GENERIC_EVENTS", &n_generic_val, true);

    // Set topology tables
    if let Some(ref topo) = topo {
        loader.set_global("CPU_TO_DIE", &topo.cpu_to_die, true);
        loader.set_global("CPU_TO_NUMA", &topo.cpu_to_numa, true);
    }

    let mut bpf = loader.load(ebpf_bytes)?;
    let btf = Btf::from_sys_fs()?;

    // Attach tracepoints - try BTF first, fall back to raw_tp
    // sched_wakeup
    let btf_ok = try_attach_btf(&mut bpf, "handle_sched_wakeup_btf", "sched_wakeup", &btf)?;
    if !btf_ok {
        attach_raw_tp(&mut bpf, "handle_sched_wakeup_raw", "sched_wakeup")?;
    }

    // sched_wakeup_new
    let btf_ok = try_attach_btf(
        &mut bpf,
        "handle_sched_wakeup_new_btf",
        "sched_wakeup_new",
        &btf,
    )?;
    if !btf_ok {
        attach_raw_tp(&mut bpf, "handle_sched_wakeup_new_raw", "sched_wakeup_new")?;
    }

    // sched_waking (only if enabled)
    if metric_groups.waking {
        let btf_ok = try_attach_btf(&mut bpf, "handle_sched_waking_btf", "sched_waking", &btf)?;
        if !btf_ok {
            attach_raw_tp(&mut bpf, "handle_sched_waking_raw", "sched_waking")?;
        }
    }

    // sched_switch
    let btf_ok = try_attach_btf(&mut bpf, "handle_sched_switch_btf", "sched_switch", &btf)?;
    if !btf_ok {
        attach_raw_tp(&mut bpf, "handle_sched_switch_raw", "sched_switch")?;
    }

    // sched_migrate_task (only if migration enabled)
    if metric_groups.migration {
        let btf_ok = try_attach_btf(
            &mut bpf,
            "handle_sched_migrate_task_btf",
            "sched_migrate_task",
            &btf,
        )?;
        if !btf_ok {
            attach_raw_tp(
                &mut bpf,
                "handle_sched_migrate_task_raw",
                "sched_migrate_task",
            )?;
        }
    }

    // sched_process_exit
    let btf_ok = try_attach_btf(
        &mut bpf,
        "handle_process_exit_btf",
        "sched_process_exit",
        &btf,
    )?;
    if !btf_ok {
        attach_raw_tp(&mut bpf, "handle_process_exit_raw", "sched_process_exit")?;
    }

    // Setup perf counters
    let _perf_setup = if metric_groups.perf {
        let mut setup = PerfCounterSetup::new();

        if has_ipc {
            // Extract MapData from PerfEventArray maps for direct fd access
            fn get_map_data(bpf: &mut aya::Ebpf, name: &str) -> MapData {
                match bpf.take_map(name).unwrap() {
                    aya::maps::Map::PerfEventArray(md) => md,
                    _ => panic!("{} is not a PerfEventArray", name),
                }
            }
            let mut uc_map = get_map_data(&mut bpf, "USER_CYCLES_ARRAY");
            let mut kc_map = get_map_data(&mut bpf, "KERNEL_CYCLES_ARRAY");
            let mut ui_map = get_map_data(&mut bpf, "USER_INSTRUCTIONS_ARRAY");
            let mut ki_map = get_map_data(&mut bpf, "KERNEL_INSTRUCTIONS_ARRAY");

            setup.setup_and_attach(&mut uc_map, &mut kc_map, &mut ui_map, &mut ki_map)?;
            println!("CPU performance counters enabled (IPC)");
        }

        if !generic_event_configs.is_empty() {
            let generic_map_names = [
                "GENERIC_PERF_ARRAY_0",
                "GENERIC_PERF_ARRAY_1",
                "GENERIC_PERF_ARRAY_2",
                "GENERIC_PERF_ARRAY_3",
                "GENERIC_PERF_ARRAY_4",
                "GENERIC_PERF_ARRAY_5",
                "GENERIC_PERF_ARRAY_6",
                "GENERIC_PERF_ARRAY_7",
            ];

            let mut generic_maps: Vec<MapData> = Vec::new();
            for name in &generic_map_names[..generic_event_configs.len()] {
                generic_maps.push(match bpf.take_map(name).unwrap() {
                    aya::maps::Map::PerfEventArray(md) => md,
                    _ => panic!("{} is not a PerfEventArray", name),
                });
            }

            let mut map_refs: Vec<&mut MapData> = generic_maps.iter_mut().collect();
            setup.setup_generic_events(&generic_event_configs, &mut map_refs)?;

            println!("Generic perf events: {}", generic_event_names.join(", "));
        }

        Some(setup)
    } else {
        None
    };

    let _collector = RschedCollector::new();
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

    let start_time = Instant::now();
    let runtime_limit = args.run_time.map(Duration::from_secs);

    let needs_per_second_tick = metric_groups.migration || !generic_event_configs.is_empty();
    let tick_interval = if needs_per_second_tick {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(args.interval)
    };
    let mut ticks_since_display = 0u64;

    loop {
        if let Some(limit) = runtime_limit {
            if start_time.elapsed() >= limit {
                println!("\nRuntime limit reached ({} seconds)", limit.as_secs());
                break;
            }
        }

        let sleep_duration = if let Some(limit) = runtime_limit {
            let elapsed = start_time.elapsed();
            let remaining = limit.saturating_sub(elapsed);
            std::cmp::min(remaining, tick_interval)
        } else {
            tick_interval
        };

        if sleep_duration.as_millis() > 0 {
            std::thread::sleep(sleep_duration);
        } else {
            break;
        }

        if let Some(limit) = runtime_limit {
            if start_time.elapsed() >= limit {
                println!("\nRuntime limit reached ({} seconds)", limit.as_secs());
                break;
            }
        }

        ticks_since_display += 1;

        // Collect per-second data every tick
        if metric_groups.migration {
            let mut map: AyaHashMap<_, u32, MigrationData> =
                AyaHashMap::try_from(bpf.map_mut("MIGRATION_COUNTS").unwrap())?;
            let migration_counts = RschedCollector::collect_migration_counts(&mut map)?;
            stats.update_migrations(migration_counts);
        }

        if !generic_event_configs.is_empty() {
            let mut map: AyaHashMap<_, u32, GenericPerfData> =
                AyaHashMap::try_from(bpf.map_mut("GENERIC_PERF_STATS").unwrap())?;
            let generic_perf_data = RschedCollector::collect_generic_perf(&mut map)?;
            if let Some(ref mut metrics) = cpu_metrics {
                metrics.record_generic_tick(generic_perf_data);
            }
        }

        // Only do full collection and display at the interval boundary
        if !needs_per_second_tick || ticks_since_display >= args.interval {
            ticks_since_display = 0;

            let histograms = if metric_groups.latency {
                let mut map: AyaHashMap<_, u32, HistData> =
                    AyaHashMap::try_from(bpf.map_mut("HISTS").unwrap())?;
                RschedCollector::collect_histograms(&mut map)?
            } else {
                HashMap::new()
            };

            let cpu_histograms = if metric_groups.cpu_latency {
                let mut map: AyaHashMap<_, u32, Hist> =
                    AyaHashMap::try_from(bpf.map_mut("CPU_HISTS").unwrap())?;
                RschedCollector::collect_cpu_histograms(&mut map)?
            } else {
                HashMap::new()
            };

            let timeslice_stats = if metric_groups.slice {
                let mut map: AyaHashMap<_, u32, TimesliceData> =
                    AyaHashMap::try_from(bpf.map_mut("TIMESLICE_HISTS").unwrap())?;
                RschedCollector::collect_timeslice_stats(&mut map)?
            } else {
                HashMap::new()
            };

            let nr_running_hists = if metric_groups.latency {
                let mut map: AyaHashMap<_, u32, NrRunningData> =
                    AyaHashMap::try_from(bpf.map_mut("NR_RUNNING_HISTS").unwrap())?;
                RschedCollector::collect_nr_running_hists(&mut map)?
            } else {
                HashMap::new()
            };

            let waking_delays = if metric_groups.waking {
                let mut map: AyaHashMap<_, u32, WakingData> =
                    AyaHashMap::try_from(bpf.map_mut("WAKING_DELAY").unwrap())?;
                RschedCollector::collect_waking_delays(&mut map)?
            } else {
                HashMap::new()
            };

            let sleep_durations = if metric_groups.sleep {
                let mut map: AyaHashMap<_, u32, HistData> =
                    AyaHashMap::try_from(bpf.map_mut("SLEEP_HISTS").unwrap())?;
                RschedCollector::collect_sleep_durations(&mut map)?
            } else {
                HashMap::new()
            };

            let cpu_idle_histograms = if metric_groups.cpu_idle {
                let mut map: AyaHashMap<_, u32, Hist> =
                    AyaHashMap::try_from(bpf.map_mut("CPU_IDLE_HISTS").unwrap())?;
                RschedCollector::collect_cpu_idle_histograms(&mut map)?
            } else {
                HashMap::new()
            };

            if let Some(ref mut schedstat) = schedstat_collector {
                let schedstat_data = schedstat.collect()?;
                stats.update_schedstat(schedstat_data);
            }

            let cpu_perf_data = if metric_groups.perf && has_ipc {
                let mut map: AyaHashMap<_, u32, CpuPerfDataFull> =
                    AyaHashMap::try_from(bpf.map_mut("CPU_PERF_STATS").unwrap())?;
                RschedCollector::collect_cpu_perf(&mut map)?
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
