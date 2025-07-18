# rsched - Rust Scheduling Delay Tracker

A BPF-based tool written in Rust that tracks kernel metrics related to
scheduling. The goal is to give a high level overview of kernel process
scheduling decisions with relatively low overhead.

## Overview

rsched uses tracepoints and performance counters to monitor:
- **Scheduling delays**: Time spent waiting in the runqueue
- **Time slice analysis**: Duration and preemption statistics
- **Runqueue depth**: Number of tasks waiting when processes are woken
- **Wakeup delays**: Time from sched_waking to sched_switch
- **Sleep duration**: Time spent sleeping between context switches
- **CPU idle duration**: How long CPUs remain idle
- **schedstats**: via /proc/schedstats
- **CPU cycles and instructions**: both user and kernel time

## Prerequisites

- Linux kernel 5.4+ with BPF support
- Rust toolchain
- libbpf development files
- Root privileges (required for BPF)

## Installation

```bash
# Install dependencies
sudo apt-get install libbpf-dev clang llvm

# Clone and build
git clone <repository>
cd rsched
cargo build --release
```

### Generate vmlinux.h

rsched ships with a vmlinux.h from libbpf-tools. If this is out of date, you
might need to regenerate:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

## Usage

```bash
sudo ./target/release/rsched [OPTIONS]
```

### Options

- `-d, --detailed`: Show detailed per-process and per-CPU output
- `-i, --interval <SECONDS>`: Update interval (default: 1)
- `-r, --run-time <SECONDS>`: Run for specified duration then exit
- `-c, --comm <REGEX>`: Filter by command name regex
- `-p, --pid <PID>`: Filter by specific PID
- `-l, --min-latency <MICROSECONDS>`: Minimum latency threshold
- `-C, --no-collapse`: Don't collapse/aggregate by command name
- `-g, --group <GROUPS>`: Select metric groups to display (comma-separated)
  - `latency`: Scheduling delays and runqueue depth (default)
  - `slice`: Time slice statistics
  - `sleep`: Sleep duration and CPU idle statistics
  - `perf`: CPU performance counters (cycles and IPC)
  - `schedstat`: /proc/schedstat metrics
  - `waking`: Waking delay tracking (adds overhead)
  - `most`: Enable most metric groups (all except waking)
  - `all`: Enable all metric groups

### Examples

```bash
# Basic usage - shows scheduling latency only
sudo ./target/release/rsched

# Show all metric groups
sudo ./target/release/rsched -g all

# Show time slice and sleep metrics
sudo ./target/release/rsched -g slice,sleep

# Run for 30 seconds with performance counters
sudo ./target/release/rsched -r 30 -g latency,perf

# Show detailed per-process statistics
sudo ./target/release/rsched -d

# Filter for processes with >100μs latency
sudo ./target/release/rsched -l 100

# Track only processes matching "schbench"
sudo ./target/release/rsched -c "schbench.*"

# Show all pids from schbench worker processes as separate entries
sudo ./target/release/rsched -C -c "schbench.*"

# Enable waking delay tracking for 60 seconds
sudo ./target/release/rsched -g waking -r 60

# Enable schedstats
sudo ./target/release/rsched -g schedstat
```

## Output Interpretation

The output varies based on the selected metric groups:

### Scheduling Delays (group: latency)

Shows time processes spend in the runqueue waiting to be scheduled:

- **p50/p90/p99**: Percentile latencies in microseconds
- **COUNT**: Number of scheduling events
- Grouped by latency ranges in default mode

```
High (1-10ms) (1 entries):
  COMMAND      PROCS    p50        p90        p99        COUNT        PIDs
  schbench-msg 4        5          1446       3879       43026        2190965,2190966,2190967,...(+1)

Very High (>10ms) (2 entries):
  COMMAND         PROCS    p50        p90        p99        COUNT        PIDs
  schbench-worker 1024     3479       20397      62750      483127       2190969,2190970,2190971,...(+1021)
  schbench        1        9          14563      24576      34           2190964
```

### Runqueue Depth (group: latency)

Shows `rq->nr_running` when each process was woken

```
  COMMAND         PROCS    p50        p90        p99        COUNT
  schbench-worker 1024     1          1          2          93226439
  schbench        1        1          1          1          20
```

### Time Slice Statistics (group: slice)

Tracks how long processes run before context switching:
- **VOLUNTARY**: Process yielded CPU voluntarily, along with p50 and p90 time slice length
- **PREEMPTED**: Process was forcibly preempted, with p50 and p90 time slice length
- **PREEMPT%**: Percentage of involuntary switches

```
  COMMAND         PROCS    INVOL_COUNT  VOLUNTARY(p50/p90)   PREEMPTED(p50/p90)   PREEMPT%
  schbench-msg    4        413          -                    94307/123612         100.0       %
  schbench-worker 1024     386          5/9                  14/19                0.0         %
  schbench        1        0            18/50                -                    0.0         %
```

### Sleep Duration Statistics (group: sleep)

Time spent sleeping between sched_switch and sched_wakeup

```
Medium (100μs-1ms) (1 entries):
  COMMAND         PROCS    p50        p90        p99        COUNT
  schbench-worker 1024     215        384        453        46712685

Very High (>10ms) (1 entries):
  COMMAND  PROCS    p50        p90        p99        COUNT
  schbench 1        757304     990321     990321     9
```

### Per-CPU idle duration (group: sleep)

```
Very Short (<100μs): CPUs 4-15,126-141
  Group: p50=6      p90=16     p99=39     count=26704057

Short (100μs-1ms): CPUs 16-125,142-251
  Group: p50=73     p90=270    p99=433    count=19646721

Global: p50=1194   p90=24824  p99=91466  count=48951
```

### CPU Performance Counters (group: perf)

Cycles per second

```
Global: User 5628.1M cycles/sec (IPC: 0.27), Kernel 24109.4M cycles/sec (IPC: 1.39)

CPU Performance by Usage Group (cycles are per timeslice):

Medium (100M-1G cycles p99) (1 entries):
  COMMAND      PROCS    USER CYC(p50/p99)    KERN CYC(p50/p99)    U-IPC    K-IPC    PIDs
  schbench-msg 4        24.4M/33.3M          192.2M/266.6M        0.12     0.71     3658281,3658282,3658283,...(+1)

Very Low (<10M cycles p99) (2 entries):
  COMMAND         PROCS    USER CYC(p50/p99)    KERN CYC(p50/p99)    U-IPC    K-IPC    PIDs
  schbench        1        52.4K/65.5K          14.3K/65.5K          3.49     3.32     3658280
  schbench-worker 1024     1.5K/3.9K            6.1K/11.5K           0.30     1.64     3658285,3658286,3658287,...(+1021)
```

### schedstats (group: schedstat)

System-wide scheduler statistics from /proc/schedstat:

schedstat deltas are per-interval -i N

```
=== System-wide Schedstat Metrics (deltas) ===
alb_count                              3 | lb_hot_gained_idle                     0 | lb_nobusyg_idle                   290796
alb_failed                             0 | lb_hot_gained_newly_idle               0 | lb_nobusyg_newly_idle               8625
alb_pushed                             3 | lb_hot_gained_not_idle                 0 | lb_nobusyg_not_idle                  329
lb_balance_idle                   302433 | lb_imbalance_load_idle                 0 | lb_nobusyq_idle                       32
lb_balance_newly_idle               8984 | lb_imbalance_load_newly_idle           0 | lb_nobusyq_newly_idle                 99
lb_balance_not_idle                  344 | lb_imbalance_load_not_idle             0 | lb_nobusyq_not_idle                    0
lb_count_idle                     303118 | lb_imbalance_misfit_idle               0 | sbe_balanced                           0
lb_count_newly_idle                12249 | lb_imbalance_misfit_newly_idle         0 | sbe_cnt                                0
lb_count_not_idle                    344 | lb_imbalance_misfit_not_idle           0 | sbe_pushed                             0
lb_failed_idle                       535 | lb_imbalance_task_idle              2328 | sbf_balanced                           0
lb_failed_newly_idle                3110 | lb_imbalance_task_newly_idle       39145 | sbf_cnt                                0
lb_failed_not_idle                     0 | lb_imbalance_task_not_idle             0 | sbf_pushed                             0
lb_gained_idle                       159 | lb_imbalance_util_idle                 0 | ttwu_move_affine                    3263
lb_gained_newly_idle                 159 | lb_imbalance_util_newly_idle           0 | ttwu_move_balance                      0
lb_gained_not_idle                     0 | lb_imbalance_util_not_idle             0 | ttwu_wake_remote                22703335

=== CPU Field Totals (deltas) ===
yld_count                 2329 | sched_count                  0 | sched_goidle          45296934
ttwu_count            22544931 | ttwu_local            22729275 | rq_cpu_time              25947
rq_run_delay usec            4 | rq_pcount          21582151769 |
```

### Waking Delays (group: waking)

Time from sched_waking to sched_switch (requires `-g waking`):

## Performance Notes

- Minimal overhead in default mode (latency group only)
- Enabling waking group adds overhead due to high event frequency
- CPU performance counters (perf group) require hardware support
- schedstats may impact scheduler performance slightly

## Output Modes

1. **Grouped** (default): Groups processes by latency/performance characteristics
2. **Collapsed** (default unless `-C` is used): Aggregates all PIDs with same command name
3. **Detailed** (`-d`): Shows all processes individually

## License

GPL-2.0 (includes code from the Linux kernel)
