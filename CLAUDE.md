After making changes, always cargo fmt ; cargo clippy --all-targets ; cargo build --release
Fix all errors and all warnings, do not proceed until they are fixed

# rsched

BPF-based Linux scheduler latency and performance analysis tool written in Rust.
Attaches to scheduler tracepoints via BPF to collect per-process and per-CPU
scheduling metrics, then displays them as histogram percentiles in a
periodically-refreshing terminal UI.

## Architecture

**BPF layer** (`src/bpf/rsched.bpf.c`): Attaches to `sched_wakeup`,
`sched_wakeup_new`, `sched_waking`, `sched_switch`, and `sched_process_exit`
tracepoints (both BTF and raw_tp variants). Maintains per-PID hash maps for
each metric type using atomic updates. Histograms use a hybrid scheme: linear
10us buckets for 0-499us (50 slots), then log2 buckets for 500us+ (14 slots).
CPU performance counters (cycles, instructions) are read via
`bpf_perf_event_read_value` from perf event arrays attached per-CPU.

**Build** (`build.rs`): Uses `libbpf-cargo` SkeletonBuilder to compile the BPF
C program and generate Rust skeleton bindings at build time.

**Rust userspace**:
- `main.rs`: CLI argument parsing (clap), BPF skeleton load/attach, main
  collection loop. Handles cgroup ID resolution by walking `/sys/fs/cgroup`.
  Conditionally loads BPF programs and perf counters based on selected metric
  groups.
- `rsched_collector.rs`: Reads BPF maps each interval, deserializes C structs
  via the `plain` crate, and deletes consumed entries. Generic collection
  functions for histogram data with and without comm/cgroup_id metadata.
- `rsched_stats.rs`: Accumulates per-PID stats across intervals. Builds
  process entries (individual or collapsed by comm name). Computes percentiles
  with interpolation. Prints grouped or detailed tables for each metric type.
  Supports latency grouping (VeryLow through VeryHigh) and CPU idle duration
  grouping.
- `perf.rs`: Opens hardware perf events (cycles, instructions) per-CPU via
  raw `perf_event_open` syscall, split into user/kernel. Attaches FDs to BPF
  perf event array maps.
- `cpu_metrics.rs`: Processes per-PID CPU cycle/instruction histograms from
  BPF. Computes IPC (instructions per cycle), formats output as K/M/G. Groups
  processes by cycle usage.
- `schedstat.rs`: Parses `/proc/schedstat` (versions 15, 16, 17) to collect
  system-wide load balancing domain stats and per-CPU scheduler counters.
  Computes deltas between collection intervals.

## Metric Groups (selected via `-g`)

- `latency`: Scheduling delay (wakeup-to-switch), per-process and per-CPU,
  plus runqueue depth at wakeup time
- `slice`: Time slice durations, voluntary vs involuntary (preemption) with
  preemption rate
- `sleep`: Sleep duration (switch-to-wakeup) and CPU idle duration
- `perf`: Hardware performance counters (user/kernel cycles and instructions,
  IPC)
- `schedstat`: System-wide `/proc/schedstat` load balancing and CPU counters
- `migration`: CPU migration tracking via `sched_migrate_task` tracepoint.
  Counts migrations per second per process, with p50/p90/p99 of the
  per-second rates. Detects CPU topology at startup (die/CCX from sysfs
  `die_id`/`physical_package_id`, NUMA from `/sys/devices/system/node`)
  and classifies migrations as cross-CCX (different die, same NUMA node)
  or cross-NUMA (different NUMA node). Uses 1-second collection ticks
  regardless of display interval to capture burstiness.
- `waking`: Waking delay (sched_waking-to-switch), gated by command line flag
  for overhead reduction
- `most`: All except waking
- `all`: Everything

## Filtering

- `-c <regex>`: Filter by command name (multiple allowed, within cgroup scope)
- `--global-comm <regex>`: Match command name regardless of cgroup filter
- `--cgroup <regex>`: Filter by cgroup name (resolves to inode IDs,
  includes children recursively)
- `-p <pid>`: Filter by specific PID
- `-l <us>`: Minimum latency threshold (p50)

## Output Modes

- Default (collapsed): Aggregates by command name, shows p50/p90/p99/count
- `-C` (no-collapse): Individual per-PID rows
- `-d` (detailed): All processes/CPUs listed individually

## BPF Tracepoints and Data Collection

The BPF program attaches to five scheduler tracepoints. Each is attached in
both `tp_btf/` (BTF-typed, preferred) and `raw_tp/` (fallback) variants for
kernel compatibility. The tracepoints are all defined in
`include/trace/events/sched.h` and fired from `kernel/sched/core.c` and
`kernel/exit.c`.

### Tracepoints

**sched_waking** — `TP_PROTO(struct task_struct *p)`
Fired in `try_to_wake_up()` (core.c:4095,4111) while holding `p->pi_lock`,
before the task is actually enqueued. This is the earliest point in the wakeup
path, called from the waking context (the task calling wake_up, not the task
being woken). The kernel comment says: "this tracepoint is guaranteed to be
called from the waking context." rsched uses this to record the timestamp in
the `waking_time` map when the `trace_sched_waking` flag is enabled. Only
fires for tasks not already in TASK_RUNNING/TASK_WAKING state. This is the
most expensive tracepoint to enable because it fires on every wakeup attempt,
so it is gated behind the `--group waking` flag which sets the
`trace_sched_waking` rodata variable in the BPF program.

**sched_wakeup** — `TP_PROTO(struct task_struct *p)`
Fired in `ttwu_do_wakeup()` (core.c:3607) after `p->__state` has been set to
TASK_RUNNING. The kernel comment says: "called when the task is actually woken;
p->state == TASK_RUNNING. It is not always called from the waking context."
rsched uses this as the enqueue event: it records `bpf_ktime_get_ns()` in the
`enqueue_time` map for the PID. This timestamp is the start of the scheduling
delay measurement. Also handles sleep duration: if the PID has an entry in
`sleep_time` (set when the task went to sleep in sched_switch), the delta is
computed and recorded into the `sleep_hists` histogram. Also records
`rq->nr_running` (runqueue depth) at wakeup time into `nr_running_hists` by
calling `bpf_get_rq_from_task()` to find the task's target runqueue and
reading its `nr_running` field via CO-RE.

**sched_wakeup_new** — `TP_PROTO(struct task_struct *p)`
Fired in `wake_up_new_task()` (core.c:4759) for newly forked tasks after
`activate_task()`. Same event class as sched_wakeup (both are instances of
`sched_wakeup_template`). rsched handles it identically to sched_wakeup via
the shared `handle_wakeup()` function.

**sched_switch** — `TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)`
Fired in `__schedule()` (core.c:6864) at the actual context switch point,
after `rq->curr` is updated to `next` but before `context_switch()` runs. The
`preempt` bool is true when `sched_mode == SM_PREEMPT` (the task was
involuntarily preempted). `prev_state` is the raw `prev->__state` value.
This is the central tracepoint for rsched and drives multiple measurements via
`handle_switch()`:

1. **Scheduling delay** (queue delay): For `next_pid`, looks up `enqueue_time`
   and computes `now - enqueue_time` as the scheduling latency. Records into
   both the per-PID `hists` map and the per-CPU `cpu_hists` map. Entries with
   delay > 10 seconds are discarded as stale.

2. **Waking delay**: For `next_pid`, looks up `waking_time` and computes
   `now - waking_time`. Records into the `waking_delay` map. Only active when
   `trace_sched_waking` is enabled.

3. **Timeslice duration**: For `prev_pid`, looks up `oncpu_time` (set when the
   task was switched onto the CPU) and computes `now - oncpu_time`. Records
   into either the `voluntary` or `involuntary` histogram within
   `timeslice_hists` depending on whether `prev` is still TASK_RUNNING
   (preempted) or sleeping. Also increments `involuntary_count` for preempted
   switches. Entries > 10 seconds are discarded.

4. **Sleep tracking**: If `prev` is not TASK_RUNNING (going to sleep), records
   the current timestamp in `sleep_time` for later delta computation in
   sched_wakeup. If `prev` is still TASK_RUNNING (preempted), re-records it
   in `enqueue_time` so the next scheduling delay is measured from the
   preemption point.

5. **CPU idle tracking**: Tracks transitions between idle (pid 0) and
   non-idle. When a CPU goes from idle to running a task, computes the idle
   duration from `cpu_idle_time` and records into `cpu_idle_hists`. When a CPU
   goes idle, records the start time.

6. **CPU performance counters**: Calls `update_cpu_perf()` which reads the
   four perf event arrays (user_cycles, kernel_cycles, user_instructions,
   kernel_instructions) via `bpf_perf_event_read_value()`. Uses a per-CPU
   context (`cpu_perf_context`, PERCPU_ARRAY) to track which PID was running
   and what the counter values were at the last switch. Computes deltas for
   the outgoing `prev_pid` and records cycle counts into log2 histograms in
   `cpu_perf_stats`, plus accumulates totals for IPC calculation.

7. **oncpu tracking**: Records `now` in `oncpu_time` for `next_pid` so the
   next sched_switch can compute its timeslice.

**sched_process_exit** — `TP_PROTO(struct task_struct *p, bool group_dead)`
Fired in `do_exit()` (exit.c:942) when a task is exiting, after
`taskstats_exit()`. rsched uses this to clean up all per-PID map entries:
`enqueue_time`, `waking_time`, `waking_delay`, `oncpu_time`, `sleep_time`,
`hists`, `sleep_hists`, `timeslice_hists`, `nr_running_hists`, and
`cpu_perf_stats`. This prevents stale data from accumulating.

### Histogram Encoding

The BPF program uses a hybrid histogram with 64 slots (MAX_SLOTS):
- **Slots 0-49**: Linear buckets, 10us per slot, covering 0-499us. This gives
  fine-grained resolution in the range where most scheduling delays fall.
- **Slot 50**: Covers 500-511us (transition bucket).
- **Slots 51-63**: Log2 buckets starting at 2^9 (512us). Each slot covers
  `[2^n, 2^(n+1)-1]` where n = slot - 50 + 8. The last slot (63) covers
  everything above 2^21 us (~2 seconds) and caps there.

CPU performance counter histograms use pure log2 encoding (slot = log2 of
value).

Runqueue depth (`nr_running_hists`) uses direct linear indexing: slot N = N
tasks on the runqueue, capped at slot 63.

### BPF Helper Functions (core-helpers.h)

The BPF program uses custom CO-RE helpers defined in `src/bpf/core-helpers.h`:

- `bpf_get_rq_from_task(task)`: Gets the task's CPU via `bpf_task_cpu()`, then
  looks up the per-CPU runqueue via `bpf_per_cpu_ptr(&runqueues, cpu)` using
  the `runqueues` ksym. Tries three CO-RE methods to read the CPU number
  (thread_info.cpu, stack-based thread_info, task_struct___a.cpu) for
  portability across kernel versions and architectures.

- `bpf_rq_nr_running(rq)`: Reads `rq->nr_running` via `BPF_CORE_READ`.

- `get_task_state(task)`: Reads task state with CO-RE relocation, handling the
  rename from `task_struct::state` (pre-v5.14) to `task_struct::__state`
  (commit 2f064a59a1).

- `read_task_comm(dst, task)`: Reads `task->comm` via
  `bpf_probe_read_kernel_str()`.

- `get_task_cgroup_id(task)`: Reads `task->cgroups->dfl_cgrp->kn->id` under
  `bpf_rcu_read_lock()` to get the default cgroup2 inode ID.

### BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| enqueue_time | HASH(10240) | pid | u64 timestamp | Wakeup time for sched delay |
| waking_time | HASH(10240) | pid | u64 timestamp | sched_waking time |
| oncpu_time | HASH(10240) | pid | u64 timestamp | When task got on CPU |
| sleep_time | HASH(10240) | pid | u64 timestamp | When task went to sleep |
| cpu_idle_time | PERCPU_ARRAY(1) | 0 | u64 timestamp | When CPU went idle |
| hists | HASH(10240) | pid | hist_data | Sched delay histogram + comm + cgroup_id |
| waking_delay | HASH(10240) | pid | hist_data | Waking delay histogram |
| timeslice_hists | HASH(10240) | pid | timeslice_data | Vol/invol timeslice histograms |
| sleep_hists | HASH(10240) | pid | hist_data | Sleep duration histogram |
| cpu_hists | HASH(1024) | cpu | hist | Per-CPU sched delay histogram |
| cpu_idle_hists | HASH(1024) | cpu | hist | Per-CPU idle duration histogram |
| nr_running_hists | HASH(10240) | pid | nr_running_data | Runqueue depth at wakeup |
| cpu_perf_stats | HASH(10240) | pid | cpu_perf_data_full | Perf counter histograms + totals |
| cpu_perf_context | PERCPU_ARRAY(1) | 0 | cpu_perf_ctx | Last counter values per CPU |
| user_cycles_array | PERF_EVENT_ARRAY(1024) | cpu | fd | User-mode cycle counter FDs |
| kernel_cycles_array | PERF_EVENT_ARRAY(1024) | cpu | fd | Kernel-mode cycle counter FDs |
| user_instructions_array | PERF_EVENT_ARRAY(1024) | cpu | fd | User-mode instruction counter FDs |
| kernel_instructions_array | PERF_EVENT_ARRAY(1024) | cpu | fd | Kernel-mode instruction counter FDs |

## Status

Functional and actively developed. Current branch: `cpumetrics`. The BPF
program provides both BTF and raw tracepoint attachments for compatibility
across kernel versions. All core metrics (latency, timeslice, sleep, waking,
perf counters, schedstat) are implemented and working.
