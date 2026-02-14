// SPDX-License-Identifier: GPL-2.0
//
// PMU event resolution: built-in aliases, sysfs named events, raw event specs.

use anyhow::{bail, Result};
use std::fs;
use std::path::Path;

/// Maximum number of generic (non-IPC) perf event slots in BPF.
pub const MAX_GENERIC_EVENTS: usize = 8;

/// A single perf event to open via perf_event_open.
pub struct PmuEvent {
    pub perf_type: u32,
    pub config: u64,
}

/// A named set of events (e.g. "ipc" has 4 events, "l2-miss" has 1).
pub struct PmuEventSet {
    pub name: String,
    pub events: Vec<PmuEvent>,
    /// True for IPC which uses the existing dedicated BPF arrays.
    pub is_ipc: bool,
}

// perf_event_open type constants
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_HW_CACHE: u32 = 3;
const PERF_TYPE_RAW: u32 = 4;

// PERF_TYPE_HARDWARE configs
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;

// PERF_TYPE_HW_CACHE encoding: (cache_id) | (cache_op << 8) | (cache_result << 16)
const PERF_COUNT_HW_CACHE_L1D: u64 = 0;
const PERF_COUNT_HW_CACHE_OP_READ: u64 = 0;
const PERF_COUNT_HW_CACHE_RESULT_MISS: u64 = 1;

/// Encode an AMD raw event (event select + umask) into perf_event_attr.config.
///
/// AMD format (from /sys/devices/cpu/format/):
///   event:config:0-7,32-35  (event select low 8 bits in 0-7, high 4 bits in 32-35)
///   umask:config:8-15
pub fn encode_amd_raw(event: u32, umask: u8) -> u64 {
    let event_low = (event & 0xFF) as u64;
    let event_high = ((event >> 8) & 0xF) as u64;
    let umask_val = (umask as u64) << 8;
    event_low | umask_val | (event_high << 32)
}

/// Detect the PMU type from sysfs. Returns the type id (e.g. 4 for "cpu").
fn detect_pmu_type(pmu_name: &str) -> Result<u32> {
    let type_path = format!("/sys/devices/{}/type", pmu_name);
    let content = fs::read_to_string(&type_path)?;
    Ok(content.trim().parse()?)
}

/// Try to resolve a named event from /sys/devices/cpu/events/<name>.
/// Returns (event, umask) parsed from the event file content.
fn resolve_sysfs_event(name: &str) -> Result<(u32, u8)> {
    let event_path = format!("/sys/devices/cpu/events/{}", name);
    let path = Path::new(&event_path);
    if !path.exists() {
        bail!("sysfs event '{}' not found at {}", name, event_path);
    }

    let content = fs::read_to_string(path)?;
    parse_sysfs_event_config(content.trim())
}

/// Parse sysfs event config like "event=0x64,umask=0x09" into (event, umask).
fn parse_sysfs_event_config(config: &str) -> Result<(u32, u8)> {
    let mut event: u32 = 0;
    let mut umask: u8 = 0;

    for part in config.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("event=") {
            event = parse_hex_or_dec(val)?;
        } else if let Some(val) = part.strip_prefix("umask=") {
            umask = parse_hex_or_dec(val)? as u8;
        }
        // Ignore other fields (edge, inv, cmask, etc.) for now
    }

    Ok((event, umask))
}

fn parse_hex_or_dec(s: &str) -> Result<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u32::from_str_radix(hex, 16)?)
    } else {
        Ok(s.parse()?)
    }
}

/// List available sysfs events from /sys/devices/cpu/events/.
fn list_sysfs_events() -> Vec<String> {
    let events_dir = Path::new("/sys/devices/cpu/events");
    if !events_dir.exists() {
        return Vec::new();
    }

    let mut events = Vec::new();
    if let Ok(entries) = fs::read_dir(events_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                // Skip .unit and .scale suffixes
                if !name.contains('.') {
                    events.push(name.to_string());
                }
            }
        }
    }
    events.sort();
    events
}

/// Resolve a perf event name into a PmuEventSet.
///
/// Resolution order:
/// 1. Built-in aliases (ipc, l1d-miss, l2-miss, l1i-miss, l3-miss)
/// 2. Sysfs named events from /sys/devices/cpu/events/
/// 3. Raw event spec: r<hex> (e.g. r0964)
pub fn resolve_event(name: &str) -> Result<PmuEventSet> {
    // 1. Built-in aliases
    match name {
        "ipc" => {
            return Ok(PmuEventSet {
                name: "ipc".to_string(),
                events: vec![
                    PmuEvent {
                        perf_type: PERF_TYPE_HARDWARE,
                        config: PERF_COUNT_HW_CPU_CYCLES,
                    },
                    PmuEvent {
                        perf_type: PERF_TYPE_HARDWARE,
                        config: PERF_COUNT_HW_CPU_CYCLES,
                    },
                    PmuEvent {
                        perf_type: PERF_TYPE_HARDWARE,
                        config: PERF_COUNT_HW_INSTRUCTIONS,
                    },
                    PmuEvent {
                        perf_type: PERF_TYPE_HARDWARE,
                        config: PERF_COUNT_HW_INSTRUCTIONS,
                    },
                ],
                is_ipc: true,
            });
        }
        "l1d-miss" => {
            // L1 data cache read misses via PERF_TYPE_HW_CACHE
            let config = PERF_COUNT_HW_CACHE_L1D
                | (PERF_COUNT_HW_CACHE_OP_READ << 8)
                | (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
            return Ok(PmuEventSet {
                name: "L1D Read Misses".to_string(),
                events: vec![PmuEvent {
                    perf_type: PERF_TYPE_HW_CACHE,
                    config,
                }],
                is_ipc: false,
            });
        }
        "l2-miss" => {
            // AMD L2 cache misses: event=0x64, umask=0x09
            let config = encode_amd_raw(0x64, 0x09);
            return Ok(PmuEventSet {
                name: "L2 Cache Misses".to_string(),
                events: vec![PmuEvent {
                    perf_type: PERF_TYPE_RAW,
                    config,
                }],
                is_ipc: false,
            });
        }
        "l1i-miss" => {
            // AMD L1 instruction cache misses: event=0x18e, umask=0x18
            let config = encode_amd_raw(0x18e, 0x18);
            return Ok(PmuEventSet {
                name: "L1I Cache Misses".to_string(),
                events: vec![PmuEvent {
                    perf_type: PERF_TYPE_RAW,
                    config,
                }],
                is_ipc: false,
            });
        }
        "l3-miss" => {
            // AMD demand fills from DRAM/remote (L3 miss proxy): event=0x43, umask=0xd8
            let config = encode_amd_raw(0x43, 0xd8);
            return Ok(PmuEventSet {
                name: "L3 Misses (DRAM Fills)".to_string(),
                events: vec![PmuEvent {
                    perf_type: PERF_TYPE_RAW,
                    config,
                }],
                is_ipc: false,
            });
        }
        _ => {}
    }

    // 2. Raw event spec: r<hex>
    if let Some(hex_str) = name.strip_prefix('r') {
        if let Ok(raw_config) = u64::from_str_radix(hex_str, 16) {
            return Ok(PmuEventSet {
                name: format!("raw:0x{:x}", raw_config),
                events: vec![PmuEvent {
                    perf_type: PERF_TYPE_RAW,
                    config: raw_config,
                }],
                is_ipc: false,
            });
        }
    }

    // 3. Sysfs named events
    if let Ok((event, umask)) = resolve_sysfs_event(name) {
        let pmu_type = detect_pmu_type("cpu").unwrap_or(PERF_TYPE_RAW);
        let config = encode_amd_raw(event, umask);
        return Ok(PmuEventSet {
            name: name.to_string(),
            events: vec![PmuEvent {
                perf_type: pmu_type,
                config,
            }],
            is_ipc: false,
        });
    }

    // Nothing matched - provide helpful error
    let mut msg = format!("Unknown perf event: '{}'\n\nBuilt-in aliases:\n", name);
    msg.push_str("  ipc       - Instructions per cycle (user/kernel cycles + instructions)\n");
    msg.push_str("  l1d-miss  - L1 data cache read misses\n");
    msg.push_str("  l2-miss   - L2 cache misses (AMD: event=0x64, umask=0x09)\n");
    msg.push_str("  l1i-miss  - L1 instruction cache misses (AMD: event=0x18e, umask=0x18)\n");
    msg.push_str(
        "  l3-miss   - L3 miss proxy / demand fills from DRAM (AMD: event=0x43, umask=0xd8)\n",
    );
    msg.push_str("\nRaw event format: r<hex> (e.g. r0964 for event=0x64, umask=0x09)\n");

    let sysfs_events = list_sysfs_events();
    if !sysfs_events.is_empty() {
        msg.push_str("\nSysfs events (/sys/devices/cpu/events/):\n");
        for ev in &sysfs_events {
            msg.push_str(&format!("  {}\n", ev));
        }
    }

    bail!("{}", msg);
}

/// List all available events (for --perf-list enhancement).
pub fn list_builtin_events() {
    println!("Built-in perf event aliases:");
    println!("  {:<12} Instructions per cycle (user/kernel)", "ipc");
    println!(
        "  {:<12} L1 data cache read misses (PERF_TYPE_HW_CACHE)",
        "l1d-miss"
    );
    println!(
        "  {:<12} L2 cache misses (AMD: event=0x64, umask=0x09)",
        "l2-miss"
    );
    println!(
        "  {:<12} L1 instruction cache misses (AMD: event=0x18e, umask=0x18)",
        "l1i-miss"
    );
    println!(
        "  {:<12} L3 miss proxy / DRAM fills (AMD: event=0x43, umask=0xd8)",
        "l3-miss"
    );
    println!();
    println!("Raw event format: r<hex> (e.g. r0964 for event=0x64, umask=0x09)");

    let sysfs_events = list_sysfs_events();
    if !sysfs_events.is_empty() {
        println!();
        println!("Sysfs events (/sys/devices/cpu/events/):");
        for ev in &sysfs_events {
            // Try to read the event config
            let event_path = format!("/sys/devices/cpu/events/{}", ev);
            let config = fs::read_to_string(&event_path)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            println!("  {:<30} {}", ev, config);
        }
    }
}
