// SPDX-License-Identifier: GPL-2.0
// BPF map types
#define BPF_MAP_TYPE_HASH 1
// BPF map update flags
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
// Define missing types if not in vmlinux.h
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
// Define bool if not available
#ifndef bool
typedef _Bool bool;
#define true 1
#define false 0
#endif

struct task_struct___a {
	unsigned int cpu;
} __attribute__((preserve_access_index));

static __always_inline int bpf_task_cpu(const struct task_struct *task)
{
	int cpu = -1;

	/* Try method 1: thread_info directly in task_struct */
	if (bpf_core_field_exists(task->thread_info)) {
		cpu = BPF_CORE_READ(task, thread_info.cpu);
		if (cpu >= 0 && cpu < 1024)
			return cpu;
	}

	/* Try method 2: thread_info via stack pointer (x86_64 style) */
	if (bpf_core_field_exists(task->stack)) {
		void *stack = BPF_CORE_READ(task, stack);
		if (stack) {
			struct thread_info *ti = (struct thread_info *)stack;
			cpu = BPF_CORE_READ(ti, cpu);
			if (cpu >= 0 && cpu < 1024)
				return cpu;
		}
	}

	/* Try method 3: cpu field directly in task_struct (some architectures) */
	if (bpf_core_field_exists(((struct task_struct___a *)task)->cpu)) {
		cpu = BPF_CORE_READ(((struct task_struct___a *)task), cpu);
		if (cpu >= 0 && cpu < 1024)
			return cpu;
	}

	return -1;
}

static __always_inline struct rq *bpf_cpu_rq(int cpu)
{
	/* Validate CPU number */
	if (cpu < 0 || cpu >= 1024)
		return NULL;

	/*
     * Try to access runqueues using kernel symbols
     * The __ksym attribute tells BPF to resolve this at load time
     */
	extern struct rq runqueues __ksym __weak;

	if (&runqueues) {
		struct rq *rq = bpf_per_cpu_ptr(&runqueues, cpu);
		if (rq)
			return rq;
	}

	return NULL;
}

static __always_inline u64 bpf_rq_nr_running(struct rq *rq)
{
	if (!rq)
		return 0;
	return BPF_CORE_READ(rq, nr_running);
}

static __always_inline struct task_struct *bpf_rq_curr(struct rq *rq)
{
	if (!rq)
		return NULL;
	return BPF_CORE_READ(rq, curr);
}

/*
 * Helper to get the runqueue of the current CPU
 * This is often more reliable than getting arbitrary CPU's rq
 */
static __always_inline struct rq *bpf_this_cpu_rq(void)
{
	u32 cpu = bpf_get_smp_processor_id();
	return bpf_cpu_rq(cpu);
}

static __always_inline struct rq *bpf_get_rq_from_task(struct task_struct *task)
{
	int cpu;

	if (!task)
		return NULL;

	/* Get CPU the task is on */
	cpu = bpf_task_cpu(task); /* Using our previous helper */
	if (cpu < 0)
		return NULL;

	return bpf_cpu_rq(cpu);
}

/**
 * commit 2f064a59a1 ("sched: Change task_struct::state") changes
 * the name of task_struct::state to task_struct::__state
 * see:
 *     https://github.com/torvalds/linux/commit/2f064a59a1
 */
struct task_struct___o {
	volatile long int state;
} __attribute__((preserve_access_index));

struct task_struct___x {
	unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
	struct task_struct___x *t = task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ((struct task_struct___o *)task, state);
}
//
// Helper to read comm safely
static __always_inline void read_task_comm(char *dst, struct task_struct *task)
{
    bpf_probe_read_kernel_str(dst, TASK_COMM_LEN, task->comm);
}
