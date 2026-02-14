// SPDX-License-Identifier: GPL-2.0
use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub const MAX_CPUS: usize = 1024;

pub struct TopologyInfo {
    pub cpu_to_die: [i32; MAX_CPUS],
    pub cpu_to_numa: [i32; MAX_CPUS],
    pub num_dies: usize,
    pub num_numa_nodes: usize,
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

    // Detect die/CCX per CPU
    let cpu_dir = Path::new("/sys/devices/system/cpu");
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

            // Read die_id, fallback to physical_package_id
            let die_path = cpu_path.join("topology/die_id");
            let pkg_path = cpu_path.join("topology/physical_package_id");
            let die_id = read_int_from_file(&die_path)
                .or_else(|| read_int_from_file(&pkg_path))
                .unwrap_or(-1);

            cpu_to_die[cpu_id] = die_id;
            if die_id >= 0 {
                die_ids.insert(die_id);
            }
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

pub fn print_topology(topo: &TopologyInfo) {
    println!(
        "CPU topology: {} dies/CCX, {} NUMA nodes",
        topo.num_dies, topo.num_numa_nodes
    );
}
