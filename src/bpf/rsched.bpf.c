// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include "core-helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_RUNNING 0
#define TASK_WAKING  0x00000200
#define MAX_CPUS 1024

// command line args
volatile const unsigned int trace_sched_waking = 0;

// histogram defines
#define MAX_SLOTS 64
#define LINEAR_THRESHOLD 500 // Use linear buckets up to 500μs
#define LINEAR_STEP 10 // 10μs per bucket in linear range (500/50 = 10μs)
#define LINEAR_SLOTS 50 // Number of linear slots (500μs / 10μs)

#define TASK_COMM_LEN 16
struct hist {
	__u32 slots[MAX_SLOTS];
};

// Time slice statistics
struct timeslice_stats {
	struct hist voluntary; // Time slices ending in voluntary switch
	struct hist involuntary; // Time slices ending in preemption
	__u64 involuntary_count; // Count of involuntary switches
};

// maps pid->wakeup time from sched_wakeup and sched_wakeup_new tracepoints
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64);
} enqueue_time SEC(".maps");

// maps pid->waking time for sched_waking tracepoint
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64);
} waking_time SEC(".maps");

// maps pid -> timeslice start time from sched_switch tracepoint
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, __u64);
} oncpu_time SEC(".maps");

// histogram of scheduler delay (sched_wakeup -> sched_switch)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct hist);
} hists SEC(".maps");

// histogram of waking delay (sched_waking -> sched_switch))
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct hist);
} waking_delay SEC(".maps");

// histogram of timeslice duration (sched_switch -> sched_switch)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct timeslice_stats);
} timeslice_hists SEC(".maps");

// histogram of scheduler delay per CPU (sched_wakeup -> sched_switch)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, struct hist);
} cpu_hists SEC(".maps");

static struct hist zero;
static struct timeslice_stats zero_ts;


// histogram of nr_running distribution when tasks are woken up
// note, this is a simple linear histogram
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32); // PID
	__type(value, struct hist); // Distribution of nr_running values
} nr_running_hists SEC(".maps");

static __always_inline void record_enqueue(__u32 pid, __u64 ts)
{
	if (pid) {
		bpf_map_update_elem(&enqueue_time, &pid, &ts, BPF_ANY);
	}
}

static __always_inline void record_waking(__u32 pid, __u64 ts)
{
	// this can be pretty expensive, so put it under a command line flag
	if (trace_sched_waking && pid) {
		bpf_map_update_elem(&waking_time, &pid, &ts, BPF_ANY);
	}
}

static __always_inline void record_oncpu(__u32 pid, __u64 ts)
{
	if (pid) {
		bpf_map_update_elem(&oncpu_time, &pid, &ts, BPF_ANY);
	}
}

/*
 * Calculate histogram slot for a given delay in nanoseconds
 * Using log2 implementation from libbpf-tools/bits.bpf.h
 */
static __always_inline __u64 log2(__u64 v)
{
	__u32 shift, r;

	r = (v > 0xFFFFFFFF) << 5;
	v >>= r;
	shift = (v > 0xFFFF) << 4;
	v >>= shift;
	r |= shift;
	shift = (v > 0xFF) << 3;
	v >>= shift;
	r |= shift;
	shift = (v > 0xF) << 2;
	v >>= shift;
	r |= shift;
	shift = (v > 0x3) << 1;
	v >>= shift;
	r |= shift;
	r |= (v >> 1);

	return r;
}

static __always_inline __u32 log2_u64(__u64 v)
{
	__u32 hi = v >> 32;
	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

/*
 * Refined histogram with better granularity for lower values:
 * - Slots 0-49: Linear buckets of 10μs each (0-499μs)
 * - Slots 50-63: Log2 buckets for values >= 500μs
 *
 * This gives us:
 * - 10μs resolution for delays 0-499μs (covers most scheduling delays)
 * - Log2 scaling for larger delays up to ~134 seconds
 */
static __always_inline __u32 hist_slot(__u64 delay_ns)
{
	__u64 delay_us = delay_ns / 1000;

	if (delay_us < LINEAR_THRESHOLD) {
		// Linear buckets: slot = delay_us / LINEAR_STEP
		__u32 slot = delay_us / LINEAR_STEP;
		return slot < LINEAR_SLOTS ? slot : LINEAR_SLOTS - 1;
	} else {
		// Log2 buckets for values >= 500μs
		// Find position of highest bit
		__u32 log2_val = log2_u64(delay_us);

		// log2(500) ≈ 8.97, but we'll map based on powers of 2
		// Starting from 512μs (2^9) for cleaner boundaries
		// This maps:
		// 500-511μs → slot 50
		// 512-1023μs → slot 50 (2^9 to 2^10-1)
		// 1024-2047μs → slot 51 (2^10 to 2^11-1)
		// etc.
		if (delay_us < 512) {
			return LINEAR_SLOTS; // slot 50 for 500-511μs
		}

		__u32 slot = LINEAR_SLOTS + (log2_val - 8);

		// Cap at MAX_SLOTS - 1
		return slot < MAX_SLOTS ? slot : MAX_SLOTS - 1;
	}
}

// sched_wakeup and sched_wakeup_new
// while we're here, record nr_running on the target CPU
static __always_inline int handle_wakeup(struct task_struct *p)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	__u64 nr_running = 0;
	__u64 ts = bpf_ktime_get_ns();
	__u32 slot;
	struct rq *rq = bpf_get_rq_from_task(p);

	if (!(rq && pid))
		goto cleanup;

	struct hist *hist = bpf_map_lookup_elem(&nr_running_hists, &pid);
	if (!hist) {
		bpf_map_update_elem(&nr_running_hists, &pid, &zero,
				    BPF_NOEXIST);
		hist = bpf_map_lookup_elem(&nr_running_hists, &pid);
		if (!hist)
			goto cleanup;
	}
	nr_running = bpf_rq_nr_running(rq);
	if (nr_running < MAX_SLOTS)
		slot = nr_running;
	else
		slot = MAX_SLOTS - 1;

	if (slot < MAX_SLOTS)
		__sync_fetch_and_add(&hist->slots[slot], 1);

cleanup:
	record_enqueue(pid, ts);
	return 0;
}

// sched_waking, which can happen really a lot.  Try and make it less
// expensive by checking task state
static __always_inline int handle_waking(struct task_struct *p)
{
	if (!trace_sched_waking)
		return 0;

	__u32 pid = BPF_CORE_READ(p, pid);
	__u64 ts = bpf_ktime_get_ns();
	__s64 state = get_task_state(p);

	if (state != TASK_RUNNING && state != TASK_WAKING) {
		record_waking(pid, ts);
	}
	return 0;
}

// calculate the timeslice when we get switched off the CPU.  Record histograms
// of both voluntary and involuntary timeslices.
static __always_inline void update_timeslices(__u32 next_pid, __u32 prev_pid,
					      __u64 now, int involuntary)
{
	__u64 *oncpu_ts;
	__u64 timeslice;

	if (prev_pid == 0)
		return;

	oncpu_ts = bpf_map_lookup_elem(&oncpu_time, &prev_pid);
	if (!oncpu_ts)
		return;

	timeslice = now - *oncpu_ts;

	// Update timeslice histogram
	struct timeslice_stats *ts_stats = bpf_map_lookup_elem(
		&timeslice_hists, &prev_pid);
	if (!ts_stats) {
		bpf_map_update_elem(&timeslice_hists, &prev_pid,
					&zero_ts, BPF_NOEXIST);
		ts_stats = bpf_map_lookup_elem(&timeslice_hists,
						&prev_pid);
	}

	if (ts_stats && timeslice < 10000000000ULL) { // Skip > 10 seconds
		__u32 slot = hist_slot(timeslice);
		if (slot < MAX_SLOTS) {
			if (involuntary) {
				// Involuntary context switch
				__sync_fetch_and_add(
					&ts_stats->involuntary
							.slots[slot],
					1);
				__sync_fetch_and_add(
					&ts_stats->involuntary_count,
					1);
			} else {
				// Voluntary context switch
				__sync_fetch_and_add(
					&ts_stats->voluntary
							.slots[slot],
					1);
			}
		}
	}

	bpf_map_delete_elem(&oncpu_time, &prev_pid);
}

static __always_inline void update_queue_delay(__u32 next_pid, __u64 now)
{
	__u64 *start_ts;
	__u64 delay;
	__u32 slot;
	__u32 cpu;
	struct hist *hist;

	// Handle scheduling latency for next task
	start_ts = bpf_map_lookup_elem(&enqueue_time, &next_pid);
	if (!start_ts)
		return;

	delay = now - *start_ts;

	// Skip if delay is unreasonably large (> 10 seconds) - likely stale data
	if (delay > 10000000000ULL)
		return;


	slot = hist_slot(delay);
	// Update regular scheduling delay histogram
	hist = bpf_map_lookup_elem(&hists, &next_pid);
	if (!hist) {
		bpf_map_update_elem(&hists, &next_pid, &zero, BPF_NOEXIST);
		hist = bpf_map_lookup_elem(&hists, &next_pid);
		if (!hist)
			goto update_cpu;
	}

	if (slot < MAX_SLOTS) {
		__sync_fetch_and_add(&hist->slots[slot], 1);
	}

update_cpu:
	// Update per-CPU histogram
	cpu = bpf_get_smp_processor_id();
	hist = bpf_map_lookup_elem(&cpu_hists, &cpu);
	if (!hist) {
		bpf_map_update_elem(&cpu_hists, &cpu, &zero, BPF_NOEXIST);
		hist = bpf_map_lookup_elem(&cpu_hists, &cpu);
		if (!hist)
			return;
	}
	if (slot < MAX_SLOTS) {
		__sync_fetch_and_add(&hist->slots[slot], 1);
	}

}

static __always_inline void update_waking_delay(__u32 next_pid, __u64 now)
{
	__u64 *start_ts;
	__u64 delay;
	__u32 slot;

	if (!trace_sched_waking)
		return;

	// Handle scheduling latency for next task
	start_ts = bpf_map_lookup_elem(&waking_time, &next_pid);
	if (!start_ts)
		return;

	delay = now - *start_ts;

	// Skip if delay is unreasonably large (> 10 seconds) - likely stale data
	if (delay > 10000000000ULL)
		return;

	// Update regular scheduling delay histogram
	struct hist *hist = bpf_map_lookup_elem(&waking_delay, &next_pid);
	if (!hist) {
		bpf_map_update_elem(&waking_delay, &next_pid, &zero, BPF_NOEXIST);
		hist = bpf_map_lookup_elem(&waking_delay, &next_pid);
		if (!hist)
			return;
	}

	slot = hist_slot(delay);
	if (slot < MAX_SLOTS) {
		__sync_fetch_and_add(&hist->slots[slot], 1);
	}
}

static __always_inline int handle_switch(bool preempt, struct task_struct *prev,
					 struct task_struct *next)
{
	__u32 next_pid = BPF_CORE_READ(next, pid);
	__u32 prev_pid = BPF_CORE_READ(prev, pid);
	__u64 now = bpf_ktime_get_ns();
	__u64 delay;
	int involuntary = 0;

	// Handle the previous task - if it's still runnable (preempted), record enqueue time
	if (get_task_state(prev) == TASK_RUNNING) {
		involuntary = 1;
		record_enqueue(prev_pid, now);
		record_waking(prev_pid, now);
	}

	// update the timeslice data for the previous task
	update_timeslices(next_pid, prev_pid, now, involuntary);

	// Skip idle task (PID 0)
	if (next_pid == 0)
		return 0;

	// Record when this task gets on CPU
	record_oncpu(next_pid, now);

	update_queue_delay(next_pid, now);
	update_waking_delay(next_pid, now);

	bpf_map_delete_elem(&enqueue_time, &next_pid);
	bpf_map_delete_elem(&waking_time, &next_pid);
	return 0;
}

static __always_inline int handle_exit(struct task_struct *p)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	bpf_map_delete_elem(&enqueue_time, &pid);
	bpf_map_delete_elem(&waking_time, &pid);
	bpf_map_delete_elem(&oncpu_time, &pid);
	bpf_map_delete_elem(&hists, &pid);
	bpf_map_delete_elem(&waking_delay, &pid);
	bpf_map_delete_elem(&timeslice_hists, &pid);
	bpf_map_delete_elem(&nr_running_hists, &pid);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_sched_wakeup_btf, struct task_struct *p)
{
	return handle_wakeup(p);
}

SEC("tp_btf/sched_waking")
int BPF_PROG(handle_sched_waking_btf, struct task_struct *p)
{
	return handle_waking(p);
}

SEC("raw_tp/sched_waking")
int BPF_PROG(handle_sched_waking_raw, struct task_struct *p)
{
	return handle_waking(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new_btf, struct task_struct *p)
{
	return handle_wakeup(p);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch_btf, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup_raw, struct task_struct *p)
{
	return handle_wakeup(p);
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new_raw, struct task_struct *p)
{
	return handle_wakeup(p);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch_raw, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

SEC("raw_tp/sched_process_exit")
int BPF_PROG(handle_process_exit_raw, struct task_struct *p)
{
	handle_exit(p);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_process_exit_bft, struct task_struct *p)
{
	handle_exit(p);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
