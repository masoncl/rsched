// SPDX-License-Identifier: GPL-2.0
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

pub const MAX_CPUS: usize = 1024;

pub struct TopologyInfo {
    pub cpu_to_die: [i32; MAX_CPUS],
    pub cpu_to_numa: [i32; MAX_CPUS],
    pub num_dies: usize,
    pub num_numa_nodes: usize,
}

#[derive(Serialize, Deserialize)]
struct CpuTopo {
    die: i32,
    numa: i32,
}

#[derive(Serialize, Deserialize)]
struct TopologyJson {
    cpus: BTreeMap<String, CpuTopo>,
}

fn read_int_from_file(path: &Path) -> Option<i32> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
}

fn parse_cpu_list(list: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in list.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<usize>(), end.parse::<usize>()) {
                for cpu in s..=e {
                    cpus.push(cpu);
                }
            }
        } else if let Ok(cpu) = part.parse::<usize>() {
            cpus.push(cpu);
        }
    }
    cpus
}

pub fn detect_topology() -> Result<TopologyInfo> {
    let mut cpu_to_die = [-1i32; MAX_CPUS];
    let mut cpu_to_numa = [-1i32; MAX_CPUS];
    let mut die_ids = HashSet::new();
    let mut numa_ids = HashSet::new();

    // Detect die/CCX per CPU using die_cpus_list for globally unique groupings.
    // die_id alone wraps per-socket on multi-socket AMD systems, so we use
    // die_cpus_list to identify unique die groups and assign sequential IDs.
    // Two passes: first collect die group membership, then assign IDs sorted
    // by the lowest CPU in each group for deterministic numbering.
    let cpu_dir = Path::new("/sys/devices/system/cpu");

    // Pass 1: collect each CPU's die group (die_cpus_list string)
    let mut cpu_die_group: Vec<(usize, String)> = Vec::new();
    let mut fallback_cpus: Vec<(usize, i32)> = Vec::new();

    if let Ok(entries) = fs::read_dir(cpu_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("cpu") {
                continue;
            }
            let cpu_id: usize = match name_str[3..].parse() {
                Ok(id) => id,
                Err(_) => continue,
            };
            if cpu_id >= MAX_CPUS {
                continue;
            }

            let cpu_path = entry.path();

            // Check online status (cpu0 may not have online file)
            let online_path = cpu_path.join("online");
            if online_path.exists() {
                if let Some(online) = read_int_from_file(&online_path) {
                    if online != 1 {
                        continue;
                    }
                }
            }

            let die_cpus_path = cpu_path.join("topology/die_cpus_list");
            if let Ok(die_cpus) = fs::read_to_string(&die_cpus_path) {
                cpu_die_group.push((cpu_id, die_cpus.trim().to_string()));
            } else {
                // Fallback: try die_id, then physical_package_id
                let die_path = cpu_path.join("topology/die_id");
                let pkg_path = cpu_path.join("topology/physical_package_id");
                let die_id = read_int_from_file(&die_path)
                    .or_else(|| read_int_from_file(&pkg_path))
                    .unwrap_or(-1);
                fallback_cpus.push((cpu_id, die_id));
            }
        }
    }

    // Pass 2: assign die IDs sorted by lowest CPU in each group
    let mut die_group_map: BTreeMap<String, (i32, usize)> = BTreeMap::new();
    for &(cpu_id, ref group) in &cpu_die_group {
        die_group_map
            .entry(group.clone())
            .and_modify(|(_id, min_cpu)| {
                if cpu_id < *min_cpu {
                    *min_cpu = cpu_id;
                }
            })
            .or_insert((-1, cpu_id));
    }
    // Sort groups by lowest CPU and assign sequential IDs
    let mut groups: Vec<(String, usize)> = die_group_map
        .iter()
        .map(|(k, &(_id, min_cpu))| (k.clone(), min_cpu))
        .collect();
    groups.sort_by_key(|&(_, min_cpu)| min_cpu);
    let mut group_to_id: BTreeMap<String, i32> = BTreeMap::new();
    for (i, (group, _)) in groups.iter().enumerate() {
        group_to_id.insert(group.clone(), i as i32);
    }

    // Apply die IDs
    for &(cpu_id, ref group) in &cpu_die_group {
        let die_id = group_to_id[group];
        cpu_to_die[cpu_id] = die_id;
        die_ids.insert(die_id);
    }
    for &(cpu_id, die_id) in &fallback_cpus {
        cpu_to_die[cpu_id] = die_id;
        if die_id >= 0 {
            die_ids.insert(die_id);
        }
    }

    // Detect NUMA node per CPU
    let node_dir = Path::new("/sys/devices/system/node");
    if let Ok(entries) = fs::read_dir(node_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("node") {
                continue;
            }
            let node_id: i32 = match name_str[4..].parse() {
                Ok(id) => id,
                Err(_) => continue,
            };

            let cpulist_path = entry.path().join("cpulist");
            if let Ok(cpulist) = fs::read_to_string(&cpulist_path) {
                let cpus = parse_cpu_list(&cpulist);
                for cpu in cpus {
                    if cpu < MAX_CPUS {
                        cpu_to_numa[cpu] = node_id;
                        numa_ids.insert(node_id);
                    }
                }
            }
        }
    }

    Ok(TopologyInfo {
        cpu_to_die,
        cpu_to_numa,
        num_dies: die_ids.len(),
        num_numa_nodes: numa_ids.len(),
    })
}

pub fn gen_topology() -> Result<()> {
    let topo = detect_topology()?;
    let mut cpus = BTreeMap::new();

    for cpu in 0..MAX_CPUS {
        if topo.cpu_to_die[cpu] >= 0 || topo.cpu_to_numa[cpu] >= 0 {
            cpus.insert(
                cpu.to_string(),
                CpuTopo {
                    die: topo.cpu_to_die[cpu],
                    numa: topo.cpu_to_numa[cpu],
                },
            );
        }
    }

    let json = TopologyJson { cpus };
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

pub fn load_topology(path: &str) -> Result<TopologyInfo> {
    let contents = fs::read_to_string(path)?;
    let json: TopologyJson = serde_json::from_str(&contents)?;

    let mut cpu_to_die = [-1i32; MAX_CPUS];
    let mut cpu_to_numa = [-1i32; MAX_CPUS];
    let mut die_ids = HashSet::new();
    let mut numa_ids = HashSet::new();

    for (cpu_str, topo) in &json.cpus {
        let cpu_id: usize = cpu_str.parse()?;
        if cpu_id >= MAX_CPUS {
            continue;
        }
        cpu_to_die[cpu_id] = topo.die;
        cpu_to_numa[cpu_id] = topo.numa;
        if topo.die >= 0 {
            die_ids.insert(topo.die);
        }
        if topo.numa >= 0 {
            numa_ids.insert(topo.numa);
        }
    }

    Ok(TopologyInfo {
        cpu_to_die,
        cpu_to_numa,
        num_dies: die_ids.len(),
        num_numa_nodes: numa_ids.len(),
    })
}

pub fn print_topology(topo: &TopologyInfo) {
    println!(
        "CPU topology: {} dies/CCX, {} NUMA nodes",
        topo.num_dies, topo.num_numa_nodes
    );
}
