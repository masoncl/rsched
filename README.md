# rsched - Rust Scheduling Delay Tracker

An BPF-based tool written in Rust that tracks runqueue scheduling delays,
time slices, and wakeup delays for processes.

## Overview

rsched uses BPF tracepoints to monitor:
- **Scheduling delays**: Time spent waiting in the runqueue
- **Time slice analysis**: Duration and preemption statistics
- **Runqueue depth**: Number of tasks waiting when processes are woken
- **Wakeup delays**: Time from sched_waking to sched_switch

## Prerequisites

- Linux kernel 5.4+ with BPF support
- Rust toolchain
- libbpf development files
- Root privileges (required for BPF)

## Installation

```bash
# Install dependencies

libbpf-dev clang llvm

# Clone and build
git clone <repository>
cd rsched
cargo build --release
```

### Generate vmlinux.h

rsched ships with a vmlinux.h from libbpf-tools.  If this is out of date, you
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
- `-w, --trace-sched-waking`: Trace sched_waking events (adds overhead)
- `-s, --schedstat`: Enable schedstats and output them
- `-m, --cpu-metrics`: report on cycles and IPC per process

### Examples

```bash
# Basic usage - shows grouped output
sudo ./target/release/rsched

# Run for 30 seconds then exit
sudo ./target/release/rsched -r 30

# Show detailed per-process statistics
sudo ./target/release/rsched -d

# Filter for processes with >100μs latency
sudo ./target/release/rsched -l 100

# Track only processes matching "schbench"
sudo ./target/release/rsched -c "schbench.*"

# Show all pids from schbench worker processes into one entry
sudo ./target/release/rsched -C -c "schbench.*"

# Enable waking delay tracking for 60 seconds
sudo ./target/release/rsched -w -r 60
```

## Output Interpretation

### Scheduling Delays
Shows time processes spend in the runqueue waiting to be scheduled:
- **p50/p90/p95**: Percentile latencies in microseconds
- **COUNT**: Number of scheduling events
- Grouped by latency ranges in default mode

### Time Slice Statistics
Tracks how long processes run before context switching:
- **VOLUNTARY**: Process yielded CPU voluntarily
- **PREEMPTED**: Process was forcibly preempted
- **PREEMPT%**: Percentage of involuntary switches

### Runqueue Depth
Shows `rq->nr_running` when each process was woken

### Per-CPU Statistics
Displays scheduling delays per CPU core

## Performance Notes

- Minimal overhead in default mode
- Enabling `-w` (sched_waking) might make this worse

## License
GPL-2.0 (with code from the Linux kernel)
