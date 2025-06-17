use anyhow::{bail, Result};
use std::collections::HashMap;
use std::fs;

#[derive(Debug)]
pub struct SchedstatData {
    pub _version: u32,
    pub domain_totals: HashMap<String, u64>,
    pub cpu_totals: Vec<u64>,
}

pub struct SchedstatCollector {
    last_domains: Option<HashMap<String, u64>>,
    last_cpus: Option<HashMap<String, Vec<u64>>>,
}

impl SchedstatCollector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            last_domains: None,
            last_cpus: None,
        })
    }

    pub fn collect(&mut self) -> Result<SchedstatData> {
        let (_version, domains, cpus) = read_schedstat()?;
        let domain_sum = sum_domains(&domains);
        let cpu_totals = sum_cpus(&cpus);

        // Calculate deltas for domains if we have previous data
        let domain_totals = if let Some(ref last) = self.last_domains {
            let mut deltas = HashMap::new();
            for (field, value) in &domain_sum {
                deltas.insert(field.clone(), value - last.get(field).unwrap_or(&0));
            }
            deltas
        } else {
            domain_sum.clone()
        };

        // Calculate deltas for CPU fields if we have previous data
        let cpu_deltas = if let Some(ref last_cpus) = self.last_cpus {
            cpu_delta(last_cpus, &cpus)
        } else {
            cpu_totals.clone()
        };

        self.last_domains = Some(domain_sum);
        self.last_cpus = Some(cpus);

        Ok(SchedstatData {
            _version,
            domain_totals,
            cpu_totals: cpu_deltas,
        })
    }
}

fn cpu_delta(
    start_cpus: &HashMap<String, Vec<u64>>,
    end_cpus: &HashMap<String, Vec<u64>>,
) -> Vec<u64> {
    if start_cpus.is_empty() || end_cpus.is_empty() {
        return Vec::new();
    }

    let num_fields = start_cpus.values().next().map(|v| v.len()).unwrap_or(0);
    let mut combined = vec![0u64; num_fields];

    for (cpu, start_vals) in start_cpus {
        if let Some(end_vals) = end_cpus.get(cpu) {
            for i in 0..num_fields.min(start_vals.len()).min(end_vals.len()) {
                combined[i] += end_vals[i].saturating_sub(start_vals[i]);
            }
        }
    }

    combined
}

fn detect_schedstat_version() -> Result<u32> {
    let content = fs::read_to_string("/proc/schedstat")?;
    for line in content.lines() {
        if line.starts_with("version") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Ok(parts[1].parse()?);
            }
        }
    }
    Ok(15) // Default to v15 if not specified
}

fn get_domain_fields(version: u32) -> Result<Vec<&'static str>> {
    match version {
        15 => Ok(vec![
            // CPU_IDLE
            "lb_count_idle",
            "lb_balance_idle",
            "lb_failed_idle",
            "lb_imbalance_idle",
            "lb_gained_idle",
            "lb_hot_gained_idle",
            "lb_nobusyq_idle",
            "lb_nobusyg_idle",
            // CPU_NOT_IDLE
            "lb_count_not_idle",
            "lb_balance_not_idle",
            "lb_failed_not_idle",
            "lb_imbalance_not_idle",
            "lb_gained_not_idle",
            "lb_hot_gained_not_idle",
            "lb_nobusyq_not_idle",
            "lb_nobusyg_not_idle",
            // CPU_NEWLY_IDLE
            "lb_count_newly_idle",
            "lb_balance_newly_idle",
            "lb_failed_newly_idle",
            "lb_imbalance_newly_idle",
            "lb_gained_newly_idle",
            "lb_hot_gained_newly_idle",
            "lb_nobusyq_newly_idle",
            "lb_nobusyg_newly_idle",
            // Other fields
            "alb_count",
            "alb_failed",
            "alb_pushed",
            "sbe_cnt",
            "sbe_balanced",
            "sbe_pushed",
            "sbf_cnt",
            "sbf_balanced",
            "sbf_pushed",
            "ttwu_wake_remote",
            "ttwu_move_affine",
            "ttwu_move_balance",
        ]),
        16 => Ok(vec![
            // CPU_NOT_IDLE (reordered in v16)
            "lb_count_not_idle",
            "lb_balance_not_idle",
            "lb_failed_not_idle",
            "lb_imbalance_not_idle",
            "lb_gained_not_idle",
            "lb_hot_gained_not_idle",
            "lb_nobusyq_not_idle",
            "lb_nobusyg_not_idle",
            // CPU_IDLE
            "lb_count_idle",
            "lb_balance_idle",
            "lb_failed_idle",
            "lb_imbalance_idle",
            "lb_gained_idle",
            "lb_hot_gained_idle",
            "lb_nobusyq_idle",
            "lb_nobusyg_idle",
            // CPU_NEWLY_IDLE
            "lb_count_newly_idle",
            "lb_balance_newly_idle",
            "lb_failed_newly_idle",
            "lb_imbalance_newly_idle",
            "lb_gained_newly_idle",
            "lb_hot_gained_newly_idle",
            "lb_nobusyq_newly_idle",
            "lb_nobusyg_newly_idle",
            // Other fields
            "alb_count",
            "alb_failed",
            "alb_pushed",
            "sbe_cnt",
            "sbe_balanced",
            "sbe_pushed",
            "sbf_cnt",
            "sbf_balanced",
            "sbf_pushed",
            "ttwu_wake_remote",
            "ttwu_move_affine",
            "ttwu_move_balance",
        ]),
        17 => Ok(vec![
            // CPU_NOT_IDLE
            "lb_count_not_idle",
            "lb_balance_not_idle",
            "lb_failed_not_idle",
            "lb_imbalance_load_not_idle",
            "lb_imbalance_util_not_idle",
            "lb_imbalance_task_not_idle",
            "lb_imbalance_misfit_not_idle",
            "lb_gained_not_idle",
            "lb_hot_gained_not_idle",
            "lb_nobusyq_not_idle",
            "lb_nobusyg_not_idle",
            // CPU_IDLE
            "lb_count_idle",
            "lb_balance_idle",
            "lb_failed_idle",
            "lb_imbalance_load_idle",
            "lb_imbalance_util_idle",
            "lb_imbalance_task_idle",
            "lb_imbalance_misfit_idle",
            "lb_gained_idle",
            "lb_hot_gained_idle",
            "lb_nobusyq_idle",
            "lb_nobusyg_idle",
            // CPU_NEWLY_IDLE
            "lb_count_newly_idle",
            "lb_balance_newly_idle",
            "lb_failed_newly_idle",
            "lb_imbalance_load_newly_idle",
            "lb_imbalance_util_newly_idle",
            "lb_imbalance_task_newly_idle",
            "lb_imbalance_misfit_newly_idle",
            "lb_gained_newly_idle",
            "lb_hot_gained_newly_idle",
            "lb_nobusyq_newly_idle",
            "lb_nobusyg_newly_idle",
            // Other fields
            "alb_count",
            "alb_failed",
            "alb_pushed",
            "sbe_cnt",
            "sbe_balanced",
            "sbe_pushed",
            "sbf_cnt",
            "sbf_balanced",
            "sbf_pushed",
            "ttwu_wake_remote",
            "ttwu_move_affine",
            "ttwu_move_balance",
        ]),
        _ => bail!("Unsupported schedstat version: {}", version),
    }
}

fn parse_domains(lines: &[String], version: u32) -> Result<Vec<HashMap<String, u64>>> {
    let mut domains = Vec::new();
    let fields = get_domain_fields(version)?;

    for line in lines {
        if line.starts_with("domain") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let values: Vec<u64> = if version == 17 {
                parts[3..].iter().map(|s| s.parse().unwrap_or(0)).collect()
            } else {
                parts[2..].iter().map(|s| s.parse().unwrap_or(0)).collect()
            };

            let mut domain = HashMap::new();
            for (i, field) in fields.iter().enumerate() {
                if i < values.len() {
                    domain.insert(field.to_string(), values[i]);
                }
            }
            domains.push(domain);
        }
    }

    Ok(domains)
}

fn parse_cpus(lines: &[String]) -> HashMap<String, Vec<u64>> {
    let mut cpus = HashMap::new();

    for line in lines {
        if line.starts_with("cpu") && !line.starts_with("cpufreq") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                let cpu_id = parts[0].to_string();
                let values: Vec<u64> = parts[1..].iter().map(|s| s.parse().unwrap_or(0)).collect();
                cpus.insert(cpu_id, values);
            }
        }
    }

    cpus
}

fn read_schedstat() -> Result<(u32, Vec<HashMap<String, u64>>, HashMap<String, Vec<u64>>)> {
    let version = detect_schedstat_version()?;
    let content = fs::read_to_string("/proc/schedstat")?;
    let lines: Vec<String> = content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with("version"))
        .map(|s| s.to_string())
        .collect();

    let domains = parse_domains(&lines, version)?;
    let cpus = parse_cpus(&lines);

    Ok((version, domains, cpus))
}

fn sum_domains(domains: &[HashMap<String, u64>]) -> HashMap<String, u64> {
    let mut summed = HashMap::new();

    for domain in domains {
        for (field, value) in domain {
            *summed.entry(field.clone()).or_insert(0) += value;
        }
    }

    summed
}

fn sum_cpus(cpus: &HashMap<String, Vec<u64>>) -> Vec<u64> {
    if cpus.is_empty() {
        return Vec::new();
    }

    let num_fields = cpus.values().next().map(|v| v.len()).unwrap_or(0);
    let mut totals = vec![0u64; num_fields];

    for values in cpus.values() {
        for (i, &val) in values.iter().enumerate() {
            if i < totals.len() {
                totals[i] += val;
            }
        }
    }

    totals
}
