//! Wrappers around BPF helper functions.
//!
//! `probe_read` / `probe_read_str` are `unsafe` — they take raw pointers
//! whose validity cannot be checked at compile time. The safe boundary for
//! kernel struct reads is the `task_struct` method layer in `vmlinux.rs`.
//!
//! The remaining helpers (`ktime_ns`, `current_cpu`, `read_volatile_*`,
//! `read_perf_counter`) are genuinely safe: they either take no problematic
//! arguments or accept references that guarantee validity.

use aya_ebpf::{
    bindings::bpf_perf_event_value,
    helpers::{self, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel},
    maps::PerfEventArray,
};
use core::ffi::c_void;

/// Read a value from kernel memory via `bpf_probe_read_kernel`.
///
/// # Safety
///
/// `ptr` must point to readable kernel memory containing a valid `T`.
#[inline(always)]
pub unsafe fn probe_read<T: Copy>(ptr: *const T) -> Option<T> {
    bpf_probe_read_kernel(ptr).ok()
}

/// Read a null-terminated string from kernel memory into `dst`.
///
/// # Safety
///
/// `src` must point to a readable kernel string.
#[inline(always)]
pub unsafe fn probe_read_str(src: *const u8, dst: &mut [u8]) {
    let _ = helpers::bpf_probe_read_kernel_str_bytes(src, dst);
}

/// Get the current monotonic time in nanoseconds.
#[inline(always)]
pub fn ktime_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// Get the current CPU id.
#[inline(always)]
pub fn current_cpu() -> u32 {
    unsafe { bpf_get_smp_processor_id() }
}

/// Read a hardware performance counter from a `PerfEventArray` on the current CPU.
#[inline(always)]
pub fn read_perf_counter(map: &PerfEventArray<u32>) -> u64 {
    unsafe {
        let cpu = bpf_get_smp_processor_id();
        let mut val = bpf_perf_event_value {
            counter: 0,
            enabled: 0,
            running: 0,
        };
        let ret = helpers::gen::bpf_perf_event_read_value(
            map as *const _ as *mut c_void,
            cpu as u64,
            &mut val as *mut _ as *mut _,
            core::mem::size_of::<bpf_perf_event_value>() as u32,
        );
        if ret == 0 {
            val.counter
        } else {
            0
        }
    }
}

/// Volatile read of a `u32` (used for `.rodata` globals set by userspace).
#[inline(always)]
pub fn read_volatile_u32(ptr: &u32) -> u32 {
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Volatile read of an `i32` (used for `.rodata` topology arrays).
#[inline(always)]
pub fn read_volatile_i32(ptr: &i32) -> i32 {
    unsafe { core::ptr::read_volatile(ptr) }
}
