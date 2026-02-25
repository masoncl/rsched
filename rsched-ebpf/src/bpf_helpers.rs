//! Safe wrappers around BPF helper functions.
//!
//! Each function contains a single `unsafe` block internally so callers
//! in `main.rs` and `vmlinux.rs` read as safe Rust.

use aya_ebpf::{
    bindings::bpf_perf_event_value,
    helpers::{self, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel},
    maps::PerfEventArray,
};
use core::ffi::c_void;

/// Read a value from kernel memory via `bpf_probe_read_kernel`.
#[inline(always)]
pub fn probe_read<T: Copy>(ptr: *const T) -> Option<T> {
    unsafe { bpf_probe_read_kernel(ptr).ok() }
}

/// Read a null-terminated string from kernel memory into `dst`.
#[inline(always)]
pub fn probe_read_str(src: *const u8, dst: &mut [u8]) {
    unsafe {
        let _ = helpers::bpf_probe_read_kernel_str_bytes(src, dst);
    }
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

/// Add `val` to the `u32` at `ptr` using volatile read/write.
#[inline(always)]
pub fn add_to_u32(ptr: *mut u32, val: u32) {
    unsafe {
        let o = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, o.wrapping_add(val));
    }
}

/// Add `val` to the `u64` at `ptr` using volatile read/write.
#[inline(always)]
pub fn add_to_u64(ptr: *mut u64, val: u64) {
    unsafe {
        let o = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, o.wrapping_add(val));
    }
}
