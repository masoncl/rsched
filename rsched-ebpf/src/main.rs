#![no_std]
#![no_main]
#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    unused_imports
)]

mod bpf_helpers;
mod vmlinux;

use aya_ebpf::{
    bindings::{BPF_ANY, BPF_NOEXIST},
    macros::{btf_tracepoint, map, raw_tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::{BtfTracePointContext, RawTracePointContext},
    EbpfContext,
};
use bpf_helpers::{
    add_to_u32, add_to_u64, current_cpu, ktime_ns, read_perf_counter, read_volatile_i32,
    read_volatile_u32,
};
use rsched_common::*;
use vmlinux::task_struct;

// ── rodata ───────────────────────────────────────────────────────────────────
#[unsafe(no_mangle)]
#[unsafe(link_section = ".rodata")]
static TRACE_SCHED_WAKING: u32 = 0;
#[unsafe(no_mangle)]
#[unsafe(link_section = ".rodata")]
static NUM_GENERIC_EVENTS: u32 = 0;
#[unsafe(no_mangle)]
#[unsafe(link_section = ".rodata")]
static CPU_TO_DIE: [i32; MAX_CPUS] = [0i32; MAX_CPUS];
#[unsafe(no_mangle)]
#[unsafe(link_section = ".rodata")]
static CPU_TO_NUMA: [i32; MAX_CPUS] = [0i32; MAX_CPUS];

// ── maps ─────────────────────────────────────────────────────────────────────
#[map]
static ENQUEUE_TIME: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);
#[map]
static WAKING_TIME: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);
#[map]
static ONCPU_TIME: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);
#[map]
static SLEEP_TIME: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);
#[map]
static CPU_IDLE_TIME: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static HISTS: HashMap<u32, HistData> = HashMap::with_max_entries(10240, 0);
#[map]
static WAKING_DELAY: HashMap<u32, WakingData> = HashMap::with_max_entries(10240, 0);
#[map]
static TIMESLICE_HISTS: HashMap<u32, TimesliceData> = HashMap::with_max_entries(10240, 0);
#[map]
static SLEEP_HISTS: HashMap<u32, HistData> = HashMap::with_max_entries(10240, 0);
#[map]
static CPU_HISTS: HashMap<u32, Hist> = HashMap::with_max_entries(MAX_CPUS as u32, 0);
#[map]
static CPU_IDLE_HISTS: HashMap<u32, Hist> = HashMap::with_max_entries(MAX_CPUS as u32, 0);
#[map]
static NR_RUNNING_HISTS: HashMap<u32, NrRunningData> = HashMap::with_max_entries(10240, 0);
#[map]
static MIGRATION_COUNTS: HashMap<u32, MigrationData> = HashMap::with_max_entries(10240, 0);
#[map]
static CPU_PERF_STATS: HashMap<u32, CpuPerfDataFull> = HashMap::with_max_entries(10240, 0);
#[map]
static CPU_PERF_CONTEXT: PerCpuArray<CpuPerfCtx> = PerCpuArray::with_max_entries(1, 0);
#[map]
static GENERIC_PERF_STATS: HashMap<u32, GenericPerfData> = HashMap::with_max_entries(10240, 0);
#[map]
static GENERIC_PERF_CONTEXT: PerCpuArray<GenericPerfCtx> = PerCpuArray::with_max_entries(1, 0);

// Scratch maps to avoid putting large zero-init structs on stack
#[map]
static ZERO_HIST_DATA: PerCpuArray<HistData> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ZERO_TIMESLICE: PerCpuArray<TimesliceData> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ZERO_WAKING: PerCpuArray<WakingData> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ZERO_HIST: PerCpuArray<Hist> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ZERO_MIGRATION: PerCpuArray<MigrationData> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ZERO_CPU_PERF: PerCpuArray<CpuPerfDataFull> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ZERO_GENERIC_PERF: PerCpuArray<GenericPerfData> = PerCpuArray::with_max_entries(1, 0);
#[map]
static ZERO_NR_RUNNING: PerCpuArray<NrRunningData> = PerCpuArray::with_max_entries(1, 0);

// Perf event arrays - used with bpf_perf_event_read_value for HW counters
#[map]
static USER_CYCLES_ARRAY: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static KERNEL_CYCLES_ARRAY: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static USER_INSTRUCTIONS_ARRAY: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static KERNEL_INSTRUCTIONS_ARRAY: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_0: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_1: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_2: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_3: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_4: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_5: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_6: PerfEventArray<u32> = PerfEventArray::new(0);
#[map]
static GENERIC_PERF_ARRAY_7: PerfEventArray<u32> = PerfEventArray::new(0);

// ── helpers ──────────────────────────────────────────────────────────────────

/// Bounds-checked slot index that the BPF verifier can track.
/// Uses bitwise AND to clamp to [0, MAX_SLOTS-1].
#[inline(always)]
fn slot_idx(s: u32) -> usize {
    (s & (MAX_SLOTS as u32 - 1)) as usize
}

const TASK_RUNNING: u32 = 0;

// ── wakeup ───────────────────────────────────────────────────────────────────
#[inline(always)]
unsafe fn do_wakeup(t: *const task_struct) -> i32 {
    let pid = (*t).pid();
    let ts = ktime_ns();

    // Record nr_running on the target CPU's runqueue
    if pid != 0 {
        let nr = (*t).cfs_rq_nr_running();
        if nr > 0 {
            if NR_RUNNING_HISTS.get_ptr(&pid).is_none() {
                if let Some(z) = ZERO_NR_RUNNING.get_ptr(0) {
                    let _ = NR_RUNNING_HISTS.insert(&pid, &*z, BPF_NOEXIST as u64);
                }
                if let Some(p) = NR_RUNNING_HISTS.get_ptr_mut(&pid) {
                    (*t).read_comm(&mut (*p).comm);
                    (*p).cgroup_id = (*t).cgroup_id();
                }
            }
            if let Some(p) = NR_RUNNING_HISTS.get_ptr_mut(&pid) {
                let s = slot_idx(nr as u32);
                add_to_u32(&mut (*p).hist.slots[s], 1);
            }
        }
    }

    // Handle sleep duration calculation
    if pid != 0 {
        if let Some(ss) = SLEEP_TIME.get_ptr(&pid) {
            let dur = ts - *ss;
            if dur < 3_600_000_000_000 {
                if SLEEP_HISTS.get_ptr(&pid).is_none() {
                    if let Some(z) = ZERO_HIST_DATA.get_ptr(0) {
                        let _ = SLEEP_HISTS.insert(&pid, &*z, BPF_NOEXIST as u64);
                    }
                    if let Some(p) = SLEEP_HISTS.get_ptr_mut(&pid) {
                        (*t).read_comm(&mut (*p).comm);
                        (*p).cgroup_id = (*t).cgroup_id();
                    }
                }
                if let Some(p) = SLEEP_HISTS.get_ptr_mut(&pid) {
                    let s = slot_idx(hist_slot(dur));
                    add_to_u32(&mut (*p).hist.slots[s], 1);
                }
            }
            let _ = SLEEP_TIME.remove(&pid);
        }
    }
    if pid != 0 {
        let _ = ENQUEUE_TIME.insert(&pid, &ts, BPF_ANY as u64);
    }
    0
}

// ── waking ───────────────────────────────────────────────────────────────────
#[inline(always)]
unsafe fn do_waking(t: *const task_struct) -> i32 {
    if read_volatile_u32(&TRACE_SCHED_WAKING) == 0 {
        return 0;
    }
    let pid = (*t).pid();
    let ts = ktime_ns();
    let st = (*t).state();
    if st != TASK_RUNNING && st != 0x200 && pid != 0 {
        let _ = WAKING_TIME.insert(&pid, &ts, BPF_ANY as u64);
    }
    0
}

// ── switch ───────────────────────────────────────────────────────────────────
#[inline(always)]
unsafe fn do_switch(prev: *const task_struct, next: *const task_struct) -> i32 {
    let np = (*next).pid();
    let pp = (*prev).pid();
    let now = ktime_ns();
    let cpu = current_cpu();

    if pp == 0 && np != 0 {
        do_cpu_idle(cpu, now);
    } else if pp != 0 && np == 0 {
        if let Some(p) = CPU_IDLE_TIME.get_ptr_mut(0) {
            *p = now;
        }
    }

    let ps = (*prev).state();
    let inv = ps == TASK_RUNNING;
    if inv {
        if pp != 0 {
            let _ = ENQUEUE_TIME.insert(&pp, &now, BPF_ANY as u64);
        }
        if read_volatile_u32(&TRACE_SCHED_WAKING) != 0 && pp != 0 {
            let _ = WAKING_TIME.insert(&pp, &now, BPF_ANY as u64);
        }
    } else if pp != 0 {
        let _ = SLEEP_TIME.insert(&pp, &now, BPF_ANY as u64);
    }

    do_timeslice(pp, prev, now, inv);

    if np != 0 {
        let _ = ONCPU_TIME.insert(&np, &now, BPF_ANY as u64);
        do_queue_delay(np, next, now);
        do_waking_delay(np, next, now);
        let _ = ENQUEUE_TIME.remove(&np);
        if read_volatile_u32(&TRACE_SCHED_WAKING) != 0 {
            let _ = WAKING_TIME.remove(&np);
        }
    }

    do_cpu_perf(pp, np, prev);
    do_generic_perf(pp, np, prev);
    0
}

#[inline(always)]
unsafe fn do_timeslice(pp: u32, prev: *const task_struct, now: u64, inv: bool) {
    if pp == 0 {
        return;
    }
    let ots = match ONCPU_TIME.get_ptr(&pp) {
        Some(p) => *p,
        None => return,
    };
    let ts = now - ots;

    if TIMESLICE_HISTS.get_ptr(&pp).is_none() {
        if let Some(z) = ZERO_TIMESLICE.get_ptr(0) {
            let _ = TIMESLICE_HISTS.insert(&pp, &*z, BPF_NOEXIST as u64);
        }
        if let Some(p) = TIMESLICE_HISTS.get_ptr_mut(&pp) {
            (*prev).read_comm(&mut (*p).comm);
            (*p).cgroup_id = (*prev).cgroup_id();
        }
    }
    if ts < 10_000_000_000 {
        let s = slot_idx(hist_slot(ts));
        if let Some(p) = TIMESLICE_HISTS.get_ptr_mut(&pp) {
            if inv {
                add_to_u32(&mut (*p).stats.involuntary.slots[s], 1);
                add_to_u64(&mut (*p).stats.involuntary_count, 1);
            } else {
                add_to_u32(&mut (*p).stats.voluntary.slots[s], 1);
            }
        }
    }
    let _ = ONCPU_TIME.remove(&pp);
}

#[inline(always)]
unsafe fn do_queue_delay(np: u32, next: *const task_struct, now: u64) {
    let st = match ENQUEUE_TIME.get_ptr(&np) {
        Some(p) => *p,
        None => return,
    };
    let d = now - st;
    if d > 10_000_000_000 {
        return;
    }
    let s = slot_idx(hist_slot(d));

    if HISTS.get_ptr(&np).is_none() {
        if let Some(z) = ZERO_HIST_DATA.get_ptr(0) {
            let _ = HISTS.insert(&np, &*z, BPF_NOEXIST as u64);
        }
        if let Some(p) = HISTS.get_ptr_mut(&np) {
            (*next).read_comm(&mut (*p).comm);
            (*p).cgroup_id = (*next).cgroup_id();
        }
    }
    if let Some(p) = HISTS.get_ptr_mut(&np) {
        add_to_u32(&mut (*p).hist.slots[s], 1);
    }

    let cpu = current_cpu();
    if CPU_HISTS.get_ptr(&cpu).is_none() {
        if let Some(z) = ZERO_HIST.get_ptr(0) {
            let _ = CPU_HISTS.insert(&cpu, &*z, BPF_NOEXIST as u64);
        }
    }
    if let Some(p) = CPU_HISTS.get_ptr_mut(&cpu) {
        add_to_u32(&mut (*p).slots[s], 1);
    }
}

#[inline(always)]
unsafe fn do_waking_delay(np: u32, next: *const task_struct, now: u64) {
    if read_volatile_u32(&TRACE_SCHED_WAKING) == 0 {
        return;
    }
    let st = match WAKING_TIME.get_ptr(&np) {
        Some(p) => *p,
        None => return,
    };
    let d = now - st;
    if d > 10_000_000_000 {
        return;
    }

    if WAKING_DELAY.get_ptr(&np).is_none() {
        if let Some(z) = ZERO_WAKING.get_ptr(0) {
            let _ = WAKING_DELAY.insert(&np, &*z, BPF_NOEXIST as u64);
        }
        if let Some(p) = WAKING_DELAY.get_ptr_mut(&np) {
            (*next).read_comm(&mut (*p).comm);
            (*p).cgroup_id = (*next).cgroup_id();
        }
    }
    let s = slot_idx(hist_slot(d));
    if let Some(p) = WAKING_DELAY.get_ptr_mut(&np) {
        add_to_u32(&mut (*p).hist.slots[s], 1);
    }
}

#[inline(always)]
unsafe fn do_cpu_idle(cpu: u32, now: u64) {
    if let Some(is) = CPU_IDLE_TIME.get_ptr(0) {
        let v = *is;
        if v > 0 {
            let dur = now - v;
            if dur < 3_600_000_000_000 {
                if CPU_IDLE_HISTS.get_ptr(&cpu).is_none() {
                    if let Some(z) = ZERO_HIST.get_ptr(0) {
                        let _ = CPU_IDLE_HISTS.insert(&cpu, &*z, BPF_NOEXIST as u64);
                    }
                }
                if let Some(p) = CPU_IDLE_HISTS.get_ptr_mut(&cpu) {
                    let s = slot_idx(hist_slot(dur));
                    add_to_u32(&mut (*p).slots[s], 1);
                }
            }
            if let Some(p) = CPU_IDLE_TIME.get_ptr_mut(0) {
                *p = 0;
            }
        }
    }
}

#[inline(always)]
unsafe fn do_cpu_perf(pp: u32, np: u32, prev: *const task_struct) {
    let ctx = match CPU_PERF_CONTEXT.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let uc = read_perf_counter(&USER_CYCLES_ARRAY);
    let kc = read_perf_counter(&KERNEL_CYCLES_ARRAY);
    let ui = read_perf_counter(&USER_INSTRUCTIONS_ARRAY);
    let ki = read_perf_counter(&KERNEL_INSTRUCTIONS_ARRAY);

    if (*ctx).running_pid == pp && pp != 0 {
        let duc = if uc >= (*ctx).last_user_cycles {
            uc - (*ctx).last_user_cycles
        } else {
            0
        };
        let dkc = if kc >= (*ctx).last_kernel_cycles {
            kc - (*ctx).last_kernel_cycles
        } else {
            0
        };
        let dui = if ui >= (*ctx).last_user_instructions {
            ui - (*ctx).last_user_instructions
        } else {
            0
        };
        let dki = if ki >= (*ctx).last_kernel_instructions {
            ki - (*ctx).last_kernel_instructions
        } else {
            0
        };

        if CPU_PERF_STATS.get_ptr(&pp).is_none() {
            if let Some(z) = ZERO_CPU_PERF.get_ptr(0) {
                let _ = CPU_PERF_STATS.insert(&pp, &*z, BPF_NOEXIST as u64);
            }
            if let Some(p) = CPU_PERF_STATS.get_ptr_mut(&pp) {
                (*prev).read_comm(&mut (*p).comm);
                (*p).cgroup_id = (*prev).cgroup_id();
            }
        }
        if let Some(p) = CPU_PERF_STATS.get_ptr_mut(&pp) {
            if duc > 0 {
                let s = slot_idx(log2_slot(duc));
                add_to_u32(&mut (*p).data.user_cycles_hist.slots[s], 1);
            }
            if dkc > 0 {
                let s = slot_idx(log2_slot(dkc));
                add_to_u32(&mut (*p).data.kernel_cycles_hist.slots[s], 1);
            }
            add_to_u64(&mut (*p).data.total_user_cycles, duc);
            add_to_u64(&mut (*p).data.total_kernel_cycles, dkc);
            add_to_u64(&mut (*p).data.total_user_instructions, dui);
            add_to_u64(&mut (*p).data.total_kernel_instructions, dki);
            add_to_u64(&mut (*p).data.sample_count, 1);
        }
    }
    (*ctx).last_user_cycles = uc;
    (*ctx).last_kernel_cycles = kc;
    (*ctx).last_user_instructions = ui;
    (*ctx).last_kernel_instructions = ki;
    (*ctx).running_pid = np;
}

#[inline(always)]
unsafe fn do_generic_perf(pp: u32, np: u32, prev: *const task_struct) {
    let n = read_volatile_u32(&NUM_GENERIC_EVENTS) as usize;
    if n == 0 {
        return;
    }
    let ctx = match GENERIC_PERF_CONTEXT.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let has_prev = (*ctx).running_pid == pp && pp != 0;

    let mut data: Option<*mut GenericPerfData> = None;
    if has_prev {
        if GENERIC_PERF_STATS.get_ptr(&pp).is_none() {
            if let Some(z) = ZERO_GENERIC_PERF.get_ptr(0) {
                let _ = GENERIC_PERF_STATS.insert(&pp, &*z, BPF_NOEXIST as u64);
            }
            if let Some(p) = GENERIC_PERF_STATS.get_ptr_mut(&pp) {
                (*prev).read_comm(&mut (*p).comm);
                (*p).cgroup_id = (*prev).cgroup_id();
            }
        }
        data = GENERIC_PERF_STATS.get_ptr_mut(&pp);
    }

    macro_rules! slot {
        ($i:expr) => {
            if n > $i {
                let cur = match $i {
                    0 => read_perf_counter(&GENERIC_PERF_ARRAY_0),
                    1 => read_perf_counter(&GENERIC_PERF_ARRAY_1),
                    2 => read_perf_counter(&GENERIC_PERF_ARRAY_2),
                    3 => read_perf_counter(&GENERIC_PERF_ARRAY_3),
                    4 => read_perf_counter(&GENERIC_PERF_ARRAY_4),
                    5 => read_perf_counter(&GENERIC_PERF_ARRAY_5),
                    6 => read_perf_counter(&GENERIC_PERF_ARRAY_6),
                    7 => read_perf_counter(&GENERIC_PERF_ARRAY_7),
                    _ => 0,
                };
                if has_prev {
                    if let Some(p) = data {
                        let d = if cur >= (*ctx).last_values[$i] {
                            cur - (*ctx).last_values[$i]
                        } else {
                            0
                        };
                        if d > 0 {
                            add_to_u64(&mut (*p).counters[$i], d);
                        }
                    }
                }
                (*ctx).last_values[$i] = cur;
            }
        };
    }
    slot!(0);
    slot!(1);
    slot!(2);
    slot!(3);
    slot!(4);
    slot!(5);
    slot!(6);
    slot!(7);
    (*ctx).running_pid = np;
}

#[inline(always)]
unsafe fn do_migrate(t: *const task_struct, dest_cpu: i32) -> i32 {
    let pid = (*t).pid();
    if pid == 0 {
        return 0;
    }

    if MIGRATION_COUNTS.get_ptr(&pid).is_none() {
        if let Some(z) = ZERO_MIGRATION.get_ptr(0) {
            let _ = MIGRATION_COUNTS.insert(&pid, &*z, BPF_NOEXIST as u64);
        }
        if let Some(p) = MIGRATION_COUNTS.get_ptr_mut(&pid) {
            (*t).read_comm(&mut (*p).comm);
            (*p).cgroup_id = (*t).cgroup_id();
        }
    }
    if let Some(p) = MIGRATION_COUNTS.get_ptr_mut(&pid) {
        add_to_u64(&mut (*p).count, 1);
        let oc = (*t).wake_cpu();
        if oc >= 0 && oc < MAX_CPUS as i32 && dest_cpu >= 0 && dest_cpu < MAX_CPUS as i32 {
            let on = read_volatile_i32(&CPU_TO_NUMA[oc as usize]);
            let dn = read_volatile_i32(&CPU_TO_NUMA[dest_cpu as usize]);
            if on >= 0 && dn >= 0 && on != dn {
                add_to_u64(&mut (*p).cross_numa_count, 1);
            } else {
                let od = read_volatile_i32(&CPU_TO_DIE[oc as usize]);
                let dd = read_volatile_i32(&CPU_TO_DIE[dest_cpu as usize]);
                if od >= 0 && dd >= 0 && od != dd {
                    add_to_u64(&mut (*p).cross_ccx_count, 1);
                }
            }
        }
    }
    0
}

#[inline(always)]
unsafe fn do_exit(t: *const task_struct) -> i32 {
    let pid = (*t).pid();
    let _ = ENQUEUE_TIME.remove(&pid);
    if read_volatile_u32(&TRACE_SCHED_WAKING) != 0 {
        let _ = WAKING_TIME.remove(&pid);
        let _ = WAKING_DELAY.remove(&pid);
    }
    let _ = ONCPU_TIME.remove(&pid);
    let _ = SLEEP_TIME.remove(&pid);
    let _ = HISTS.remove(&pid);
    let _ = SLEEP_HISTS.remove(&pid);
    let _ = TIMESLICE_HISTS.remove(&pid);
    let _ = NR_RUNNING_HISTS.remove(&pid);
    let _ = MIGRATION_COUNTS.remove(&pid);
    let _ = CPU_PERF_STATS.remove(&pid);
    let _ = GENERIC_PERF_STATS.remove(&pid);
    0
}

// ── BTF tracepoints ──────────────────────────────────────────────────────────
#[btf_tracepoint(function = "sched_wakeup")]
pub fn handle_sched_wakeup_btf(ctx: BtfTracePointContext) -> i32 {
    unsafe { do_wakeup(ctx.arg(0)) }
}
#[btf_tracepoint(function = "sched_wakeup_new")]
pub fn handle_sched_wakeup_new_btf(ctx: BtfTracePointContext) -> i32 {
    unsafe { do_wakeup(ctx.arg(0)) }
}
#[btf_tracepoint(function = "sched_waking")]
pub fn handle_sched_waking_btf(ctx: BtfTracePointContext) -> i32 {
    unsafe { do_waking(ctx.arg(0)) }
}
#[btf_tracepoint(function = "sched_switch")]
pub fn handle_sched_switch_btf(ctx: BtfTracePointContext) -> i32 {
    unsafe { do_switch(ctx.arg(1), ctx.arg(2)) }
}
#[btf_tracepoint(function = "sched_migrate_task")]
pub fn handle_sched_migrate_task_btf(ctx: BtfTracePointContext) -> i32 {
    unsafe { do_migrate(ctx.arg(0), ctx.arg(1)) }
}
#[btf_tracepoint(function = "sched_process_exit")]
pub fn handle_process_exit_btf(ctx: BtfTracePointContext) -> i32 {
    unsafe { do_exit(ctx.arg(0)) }
}

// ── Raw tracepoints ──────────────────────────────────────────────────────────

// For pointer args we need special handling
#[inline(always)]
unsafe fn rarg_ptr(ctx: &RawTracePointContext, n: usize) -> *const task_struct {
    *((ctx.as_ptr() as *const u64).add(n)) as *const task_struct
}
#[inline(always)]
unsafe fn rarg_i32(ctx: &RawTracePointContext, n: usize) -> i32 {
    *((ctx.as_ptr() as *const u64).add(n)) as i32
}

#[raw_tracepoint(tracepoint = "sched_wakeup")]
pub fn handle_sched_wakeup_raw(ctx: RawTracePointContext) -> i32 {
    unsafe { do_wakeup(rarg_ptr(&ctx, 0)) }
}
#[raw_tracepoint(tracepoint = "sched_wakeup_new")]
pub fn handle_sched_wakeup_new_raw(ctx: RawTracePointContext) -> i32 {
    unsafe { do_wakeup(rarg_ptr(&ctx, 0)) }
}
#[raw_tracepoint(tracepoint = "sched_waking")]
pub fn handle_sched_waking_raw(ctx: RawTracePointContext) -> i32 {
    unsafe { do_waking(rarg_ptr(&ctx, 0)) }
}
#[raw_tracepoint(tracepoint = "sched_switch")]
pub fn handle_sched_switch_raw(ctx: RawTracePointContext) -> i32 {
    unsafe { do_switch(rarg_ptr(&ctx, 1), rarg_ptr(&ctx, 2)) }
}
#[raw_tracepoint(tracepoint = "sched_migrate_task")]
pub fn handle_sched_migrate_task_raw(ctx: RawTracePointContext) -> i32 {
    unsafe { do_migrate(rarg_ptr(&ctx, 0), rarg_i32(&ctx, 1)) }
}
#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn handle_process_exit_raw(ctx: RawTracePointContext) -> i32 {
    unsafe { do_exit(rarg_ptr(&ctx, 0)) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
